"""
Interactive chat exclusion manager — browse synced chats and mark
which ones the syncer should skip.

Runnable as::

    python -m syncer.manage_chats          # from src/
    telelocal manage-chats                   # via CLI wrapper

Fetches chats from Telegram using the existing encrypted session when
available (falls back to PostgreSQL ``chats`` table), then writes
exclusions to ``config/excluded_chats.json``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from shared.db import get_connection_pool
from shared.secrets import decrypt_session_file, get_secret
from syncer.readonly_client import ReadOnlyTelegramClient

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for older local envs
    import tomli as tomllib

logger = logging.getLogger("syncer.manage_chats")
_VALID_CHAT_TYPES = {"group", "channel", "user"}
_CHAT_TYPE_ORDER = ("group", "channel", "user")
_FRESHEST_CHAT_LIMIT = 250
_CHAT_SELECTION_KEYBINDINGS = {
    "toggle-all-false": [
        {"key": "c-d"},
        {"key": "alt-d"},
    ],
}

# Re-use load_config from syncer.main to keep config handling consistent.
# Imported lazily to avoid circular issues at module level.
_DEFAULT_CONFIG_PATH = Path("/etc/tg-assistant/settings.toml")
_EXCLUDED_CHATS_FILENAME = "excluded_chats.json"


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_config(path: Path | None = None) -> Dict[str, Any]:
    """Load settings.toml — lightweight copy to avoid importing syncer.main."""
    if path is None:
        env_path = os.environ.get("TG_ASSISTANT_CONFIG")
        if env_path:
            path = Path(env_path)
        else:
            # Try local dev path first, then system path
            local = Path(__file__).resolve().parent.parent.parent / "config" / "settings.toml"
            path = local if local.exists() else _DEFAULT_CONFIG_PATH
    with open(path, "rb") as handle:
        config = tomllib.load(handle)
    config["_meta_config_path"] = str(path)
    return config


def get_excluded_chats_path(config: Dict[str, Any]) -> Path:
    """Resolve the path to ``excluded_chats.json``.

    Preference order:
      1) ``syncer.excluded_chats_path`` in settings.toml
      2) alongside loaded settings.toml path
      3) ``/etc/tg-assistant/excluded_chats.json``
    """
    configured = config.get("syncer", {}).get("excluded_chats_path")
    if configured:
        return Path(configured)

    cfg_path = config.get("_meta_config_path")
    if cfg_path:
        return Path(cfg_path).resolve().parent / _EXCLUDED_CHATS_FILENAME

    return Path("/etc/tg-assistant") / _EXCLUDED_CHATS_FILENAME


def load_excluded_ids(config: Dict[str, Any]) -> set[int]:
    """Load excluded chat IDs from the JSON file.

    Returns:
        A set of chat IDs that should be skipped during sync.
        Returns an empty set if the file doesn't exist or is invalid.
    """
    return set(load_excluded_chats(config).keys())


def load_excluded_chats(config: Dict[str, Any]) -> dict[int, str]:
    """Load excluded chats as ``{chat_id: chat_title}``."""
    path = get_excluded_chats_path(config)
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        excluded = data.get("excluded", {})
        parsed: dict[int, str] = {}
        for raw_id, raw_title in excluded.items():
            chat_id = int(raw_id)
            title = str(raw_title).strip() if raw_title is not None else ""
            parsed[chat_id] = title or f"Chat {chat_id}"
        return parsed
    except (json.JSONDecodeError, ValueError, TypeError):
        logger.warning("Invalid excluded_chats.json at %s, ignoring", path)
        return {}


def save_excluded_chats(config: Dict[str, Any], excluded: dict[int, str]) -> Path:
    """Write the exclusion dict to ``excluded_chats.json``.

    Args:
        config: Parsed configuration (used to resolve path).
        excluded: Mapping of ``{chat_id: chat_title}`` for excluded chats.

    Returns:
        The path written to.
    """
    path = get_excluded_chats_path(config)
    payload = {"excluded": {str(k): v for k, v in sorted(excluded.items())}}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def compute_keyword_excluded_ids(chats: list[dict], keyword: str) -> set[int]:
    """Return chat IDs to exclude when title does not match *keyword*.

    Matching is case-insensitive and uses substring semantics.
    Empty keyword => no automatic exclusions.
    """
    needle = (keyword or "").strip().lower()
    if not needle:
        return set()

    excluded: set[int] = set()
    for chat in chats:
        chat_id = int(chat.get("chat_id"))
        title = str(chat.get("title") or "").lower()
        if needle not in title:
            excluded.add(chat_id)
    return excluded


def chat_freshness_sort_key(chat: dict) -> tuple[float, str]:
    """Sort chats by freshest activity first, then title."""
    dt = chat.get("last_activity")
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt.timestamp(), str(chat.get("title", "")))
    return (0.0, str(chat.get("title", "")))


def resolve_include_chat_types(config: Dict[str, Any]) -> set[str]:
    """Resolve sync-eligible chat types from config.

    Missing/invalid values default to all types for backwards compatibility.
    """
    raw = config.get("syncer", {}).get("include_chat_types")
    if raw is None:
        return set(_VALID_CHAT_TYPES)

    if isinstance(raw, str):
        items = [part.strip().lower() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(part).strip().lower() for part in raw]
    else:
        return set(_VALID_CHAT_TYPES)

    resolved = {item for item in items if item in _VALID_CHAT_TYPES}
    return resolved or set(_VALID_CHAT_TYPES)


def _format_include_chat_types(include_types: set[str]) -> str:
    ordered = [t for t in _CHAT_TYPE_ORDER if t in include_types]
    return "[" + ", ".join(f'"{t}"' for t in ordered) + "]"


def save_include_chat_types(config: Dict[str, Any], include_types: set[str]) -> Path:
    """Persist ``syncer.include_chat_types`` back to settings.toml."""
    if not include_types:
        raise ValueError("include_types must not be empty")

    cfg_path = Path(config.get("_meta_config_path") or _DEFAULT_CONFIG_PATH)
    text = cfg_path.read_text(encoding="utf-8")
    replacement = f"include_chat_types = {_format_include_chat_types(include_types)}"

    # Replace existing key if present.
    updated, count = re.subn(
        r"(?m)^include_chat_types\s*=\s*\[[^\]]*\]\s*$",
        replacement,
        text,
        count=1,
    )

    # Otherwise insert below max_active_chats in [syncer].
    if count == 0:
        updated, count = re.subn(
            r"(?m)^(max_active_chats\s*=\s*[^\n]+)\s*$",
            r"\1\n" + replacement,
            text,
            count=1,
        )
    if count == 0:
        # Last resort append.
        if not updated.endswith("\n"):
            updated += "\n"
        updated += replacement + "\n"

    cfg_path.write_text(updated, encoding="utf-8")
    return cfg_path


# ---------------------------------------------------------------------------
# Interactive CLI
# ---------------------------------------------------------------------------


async def _fetch_chats(config: Dict[str, Any]) -> list[dict]:
    """Fetch all known chats from the database."""
    db_config = dict(config["database"])
    db_config["user"] = config["syncer"].get("db_user", "tg_syncer")
    pool = await get_connection_pool(db_config)

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT chat_id, title, chat_type, updated_at AS last_activity
                FROM chats
                ORDER BY updated_at DESC NULLS LAST, title
                """
            )
        return [dict(r) for r in rows]
    finally:
        await pool.close()


def _decrypt_credstore_secret(key_name: str) -> str | None:
    """Best-effort fallback: decrypt a credential directly from credstore."""
    cred_path = Path("/etc/credstore.encrypted") / key_name
    if not cred_path.exists():
        return None
    try:
        result = subprocess.run(
            ["systemd-creds", "decrypt", str(cred_path), "-"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        value = result.stdout.strip()
        return value or None
    except Exception:
        logger.debug("Could not decrypt credstore secret: %s", key_name, exc_info=True)
        return None


def _get_secret_for_manage_chats(key_name: str) -> str:
    """Resolve secret for interactive chat management."""
    try:
        return get_secret(key_name)
    except Exception:
        fallback = _decrypt_credstore_secret(key_name)
        if fallback:
            return fallback
    raise RuntimeError(f"Unable to load required secret: {key_name}")


async def _fetch_chats_from_telegram(config: Dict[str, Any]) -> list[dict]:
    """Fetch dialogs directly from Telegram using the existing session."""
    from telethon import TelegramClient as TelethonClient

    api_id = int(_get_secret_for_manage_chats("tg-assistant-api-id"))
    api_hash = _get_secret_for_manage_chats("tg-assistant-api-hash")
    session_key = _get_secret_for_manage_chats("session_encryption_key")
    session_path = Path(config["syncer"]["session_path"])

    session_bytes = decrypt_session_file(session_path, session_key)
    shm_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
    fd, tmp_path = tempfile.mkstemp(suffix=".session", dir=shm_dir)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(session_bytes)
            handle.flush()
        os.chmod(tmp_path, 0o600)
        session_base = tmp_path.removesuffix(".session")

        raw_client = TelethonClient(session_base, api_id, api_hash)
        chats: list[dict] = []
        async with ReadOnlyTelegramClient(raw_client) as client:
            dialogs = await client.get_dialogs()
            for dialog in dialogs:
                chat_type = "user"
                if getattr(dialog, "is_group", False):
                    chat_type = "group"
                elif getattr(dialog, "is_channel", False):
                    chat_type = "channel"

                title = getattr(dialog, "title", None) or getattr(dialog, "name", None)
                if not title:
                    title = f"Chat {dialog.id}"

                chats.append(
                    {
                        "chat_id": int(dialog.id),
                        "title": title,
                        "chat_type": chat_type,
                        "last_activity": getattr(dialog, "date", None),
                    }
                )
        return chats
    finally:
        for path in (
            tmp_path,
            tmp_path + "-journal",
            tmp_path + "-wal",
            tmp_path + "-shm",
        ):
            if os.path.exists(path):
                os.remove(path)


def _chat_label(chat: dict) -> str:
    """Format a single chat dict as a human-readable label."""
    title = chat["title"] or "(untitled)"
    chat_type = chat["chat_type"] or "unknown"
    last_activity = chat.get("last_activity")
    if isinstance(last_activity, datetime):
        activity_str = last_activity.strftime("%Y-%m-%d")
    else:
        activity_str = "unknown"
    return f"[{chat_type}] {title} (last: {activity_str}, id: {chat['chat_id']})"


def _show_diff_and_save(
    config: Dict[str, Any],
    chats: list[dict],
    current_excluded_map: dict[int, str],
    new_excluded_ids: set[int],
) -> None:
    """Print what changed and save the new exclusion set."""
    current_excluded = set(current_excluded_map.keys())
    title_map = {c["chat_id"]: c["title"] or "(untitled)" for c in chats}
    new_excluded = {
        cid: title_map.get(cid, current_excluded_map.get(cid, f"Chat {cid}"))
        for cid in new_excluded_ids
    }

    newly_excluded = new_excluded_ids - current_excluded
    newly_included = current_excluded - new_excluded_ids

    print()
    if newly_excluded:
        print(f"Newly excluded ({len(newly_excluded)}):")
        for cid in sorted(newly_excluded):
            print(f"  - {title_map.get(cid, str(cid))}")
    if newly_included:
        print(f"Newly included ({len(newly_included)}):")
        for cid in sorted(newly_included):
            print(f"  + {title_map.get(cid, str(cid))}")
    if not newly_excluded and not newly_included:
        print("No changes.")
        return

    path = save_excluded_chats(config, new_excluded)
    print()
    print(f"Saved {len(new_excluded)} exclusion(s) to {path}")
    print("The syncer will skip these chats on the next sync pass.")


async def _prompt_chat_types(inquirer: Any, config: Dict[str, Any]) -> set[str]:
    """Run the 3 chat-type confirm prompts and save if changed.

    Returns the (possibly updated) include_chat_types set.
    """
    include_chat_types = resolve_include_chat_types(config)
    include_user_dms = await inquirer.confirm(
        message="Include user DMs in sync?",
        default=("user" in include_chat_types),
    ).execute_async()
    include_channels = await inquirer.confirm(
        message="Include channels in sync?",
        default=("channel" in include_chat_types),
    ).execute_async()
    include_groups = await inquirer.confirm(
        message="Include groups in sync?",
        default=("group" in include_chat_types),
    ).execute_async()

    new_types: set[str] = set()
    if include_groups:
        new_types.add("group")
    if include_channels:
        new_types.add("channel")
    if include_user_dms:
        new_types.add("user")
    if not new_types:
        new_types = {"group"}
        print("No chat types selected; defaulting to group-only.")

    original_include_types = resolve_include_chat_types(config)
    if new_types != original_include_types:
        settings_path = save_include_chat_types(config, new_types)
        config.setdefault("syncer", {})["include_chat_types"] = sorted(new_types)
        print(
            "Saved include_chat_types "
            f"({_format_include_chat_types(new_types)}) to {settings_path}"
        )
        print()

    return new_types


def _apply_type_filter(chats: list[dict], include_chat_types: set[str]) -> list[dict]:
    """Filter chats by type and print summary. Exits if none remain."""
    if include_chat_types == _VALID_CHAT_TYPES:
        return chats

    before = len(chats)
    filtered = [
        c for c in chats
        if (str(c.get("chat_type") or "user").lower() in include_chat_types)
    ]
    hidden = before - len(filtered)
    print(
        "Applying include_chat_types filter "
        f"({', '.join(sorted(include_chat_types))}); hidden {hidden} chat(s)."
    )
    if not filtered:
        print("No chats remain after chat-type filtering.")
        print("Adjust syncer.include_chat_types in settings.toml and retry.")
        sys.exit(1)
    return filtered


def _sort_and_cap(chats: list[dict]) -> tuple[list[dict], int]:
    """Sort by freshness and cap to _FRESHEST_CHAT_LIMIT.

    Returns (capped_chats, hidden_count).
    """
    chats = sorted(chats, key=chat_freshness_sort_key, reverse=True)
    hidden = 0
    if len(chats) > _FRESHEST_CHAT_LIMIT:
        hidden = len(chats) - _FRESHEST_CHAT_LIMIT
        chats = chats[:_FRESHEST_CHAT_LIMIT]
    return chats, hidden


# ---------------------------------------------------------------------------
# Setup flow (full wizard — used by setup.sh --setup)
# ---------------------------------------------------------------------------


async def _run_setup_flow(
    inquirer: Any,
    config: Dict[str, Any],
    chats: list[dict],
    source: str,
) -> None:
    """Full setup wizard: chat-type prompts, keyword filter, full checkbox."""
    include_chat_types = await _prompt_chat_types(inquirer, config)
    chats = _apply_type_filter(chats, include_chat_types)
    chats, hidden_older_chats = _sort_and_cap(chats)

    current_excluded_map = load_excluded_chats(config)
    current_excluded = set(current_excluded_map.keys())

    keyword = (
        await inquirer.text(
            message=(
                "Optional keyword include filter "
                "(strict mode: non-matching chats are auto-excluded):"
            ),
            default="",
        ).execute_async()
    ).strip()
    keyword_excluded = compute_keyword_excluded_ids(chats, keyword)
    visible_chats = chats
    if keyword:
        visible_chats = [
            c for c in chats
            if int(c.get("chat_id")) not in keyword_excluded
        ]
        print(
            f'Keyword "{keyword}" auto-excludes {len(keyword_excluded)} chat(s). '
            "Only matching chats are shown for selection."
        )
        print()

    choices = []
    for chat in visible_chats:
        choices.append({
            "name": _chat_label(chat),
            "value": chat["chat_id"],
            "enabled": (chat["chat_id"] not in current_excluded),
        })

    print()
    print(f"Loaded {len(chats)} freshest chat(s) from {source}.")
    if hidden_older_chats > 0:
        print(
            f"Showing top {_FRESHEST_CHAT_LIMIT} freshest chats "
            f"(hidden {hidden_older_chats} older chat(s))."
        )
    if keyword:
        print(
            f'Keyword "{keyword}" narrowed visible list to {len(visible_chats)} chat(s).'
        )
    print(f"Currently excluding: {len(current_excluded)} chat(s).")
    print()
    print("Use arrow keys to navigate, SPACE to toggle, ENTER to confirm.")
    print("TAB toggles current and moves down; SHIFT+TAB toggles and moves up.")
    print("Ctrl+A selects all, Ctrl+D clears all, Ctrl+R inverts all.")
    print("Checked = INCLUDED in sync, Unchecked = EXCLUDED from sync.")
    print()

    if choices:
        included_ids = await inquirer.checkbox(
            message="Select chats to INCLUDE in sync:",
            choices=choices,
            cycle=True,
            keybindings=_CHAT_SELECTION_KEYBINDINGS,
        ).execute_async()
    else:
        included_ids = []

    all_ids = {c["chat_id"] for c in chats}
    included_set = set(included_ids)
    new_excluded_ids = (all_ids - included_set) | (current_excluded - all_ids)
    _show_diff_and_save(config, chats, current_excluded_map, new_excluded_ids)


# ---------------------------------------------------------------------------
# Manage flow (quick action menu — default for standalone use)
# ---------------------------------------------------------------------------


async def _run_manage_flow(
    inquirer: Any,
    config: Dict[str, Any],
    chats: list[dict],
    source: str,
) -> None:
    """Quick action menu for returning users."""
    include_chat_types = resolve_include_chat_types(config)
    chats = _apply_type_filter(chats, include_chat_types)
    chats, _hidden = _sort_and_cap(chats)

    current_excluded_map = load_excluded_chats(config)
    current_excluded = set(current_excluded_map.keys())
    included_count = len(chats) - sum(1 for c in chats if c["chat_id"] in current_excluded)
    excluded_count = len(current_excluded)
    types_str = ", ".join(sorted(include_chat_types))

    print()
    print(f"Syncing {included_count} chats ({excluded_count} excluded) | Types: {types_str}")
    print()

    action = await inquirer.select(
        message="What would you like to do?",
        choices=[
            {"name": "Exclude chats — hide chats from sync", "value": "exclude"},
            {"name": "Re-include chats — bring back excluded chats", "value": "reinclude"},
            {"name": "Edit chat types — change which types sync (DMs/channels/groups)", "value": "types"},
            {"name": "Full reconfigure — run the complete setup wizard", "value": "full"},
        ],
    ).execute_async()

    if action == "full":
        await _run_setup_flow(inquirer, config, chats, source)
        return

    if action == "types":
        await _prompt_chat_types(inquirer, config)
        return

    if action == "exclude":
        # Show only currently-included chats
        included_chats = [c for c in chats if c["chat_id"] not in current_excluded]
        if not included_chats:
            print("All chats are already excluded.")
            return

        choices = []
        for chat in included_chats:
            choices.append({
                "name": _chat_label(chat),
                "value": chat["chat_id"],
                "enabled": True,  # checked = keep included
            })

        print()
        print(f"Showing {len(included_chats)} currently included chat(s).")
        print("Uncheck chats to EXCLUDE them from sync. Press ENTER to confirm.")
        print()

        keep_ids = await inquirer.checkbox(
            message="Included chats (uncheck to exclude):",
            choices=choices,
            cycle=True,
            keybindings=_CHAT_SELECTION_KEYBINDINGS,
        ).execute_async()

        keep_set = set(keep_ids)
        all_included_ids = {c["chat_id"] for c in included_chats}
        newly_excluded_ids = all_included_ids - keep_set
        new_excluded_ids = current_excluded | newly_excluded_ids
        _show_diff_and_save(config, chats, current_excluded_map, new_excluded_ids)
        return

    if action == "reinclude":
        # Show only currently-excluded chats that exist in the fetched list
        excluded_chats = [c for c in chats if c["chat_id"] in current_excluded]
        # Also include excluded chats not in fetched list (from excluded_chats.json)
        fetched_ids = {c["chat_id"] for c in chats}
        orphan_excluded = {
            cid: title for cid, title in current_excluded_map.items()
            if cid not in fetched_ids
        }

        if not excluded_chats and not orphan_excluded:
            print("No chats are currently excluded.")
            return

        choices = []
        for chat in excluded_chats:
            choices.append({
                "name": _chat_label(chat),
                "value": chat["chat_id"],
                "enabled": False,  # unchecked = stays excluded
            })
        for cid, title in sorted(orphan_excluded.items(), key=lambda x: x[1]):
            choices.append({
                "name": f"[?] {title} (id: {cid})",
                "value": cid,
                "enabled": False,
            })

        print()
        print(f"Showing {len(choices)} currently excluded chat(s).")
        print("Check chats to RE-INCLUDE them in sync. Press ENTER to confirm.")
        print()

        reinclude_ids = await inquirer.checkbox(
            message="Excluded chats (check to re-include):",
            choices=choices,
            cycle=True,
            keybindings=_CHAT_SELECTION_KEYBINDINGS,
        ).execute_async()

        reinclude_set = set(reinclude_ids)
        new_excluded_ids = current_excluded - reinclude_set
        _show_diff_and_save(config, chats, current_excluded_map, new_excluded_ids)
        return


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


async def interactive_main(setup_mode: bool = False) -> None:
    """Run the interactive exclusion manager."""
    try:
        from InquirerPy import inquirer
    except ImportError:
        print("Error: InquirerPy is required. Install with: pip install InquirerPy")
        sys.exit(1)

    config = _load_config()
    chats: list[dict] = []
    source = "telegram"
    try:
        chats = await _fetch_chats_from_telegram(config)
    except Exception:
        logger.warning("Could not fetch chats from Telegram", exc_info=True)
        source = "database"
        try:
            chats = await _fetch_chats(config)
        except Exception:
            logger.warning("Could not fetch chats from database", exc_info=True)
            chats = []

    if not chats:
        print("No chats found.")
        print("Could not load chats from Telegram session or database.")
        print("Check credentials/session and try again.")
        sys.exit(1)

    if setup_mode:
        await _run_setup_flow(inquirer, config, chats, source)
    else:
        await _run_manage_flow(inquirer, config, chats, source)


def main() -> None:
    """Synchronous entry point."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="Manage chat sync exclusions")
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run full setup wizard (used by setup.sh)",
    )
    args = parser.parse_args()
    asyncio.run(interactive_main(setup_mode=args.setup))


if __name__ == "__main__":
    main()
