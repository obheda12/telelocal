"""
Interactive chat exclusion manager — browse synced chats and mark
which ones the syncer should skip.

Runnable as::

    python -m syncer.manage_chats          # from src/
    telenad manage-chats                   # via CLI wrapper

Reads chats from the PostgreSQL ``chats`` table (no Telegram connection
needed) and writes exclusions to ``config/excluded_chats.json``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
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
    path = get_excluded_chats_path(config)
    if not path.exists():
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        excluded = data.get("excluded", {})
        return {int(k) for k in excluded}
    except (json.JSONDecodeError, ValueError, TypeError):
        logger.warning("Invalid excluded_chats.json at %s, ignoring", path)
        return set()


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
                "SELECT chat_id, title, chat_type FROM chats ORDER BY title"
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


async def interactive_main() -> None:
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

    # Load current exclusions
    current_excluded = load_excluded_ids(config)

    # Newest chats first for faster triage when there are many.
    def _sort_key(chat: dict) -> tuple[float, str]:
        dt = chat.get("last_activity")
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (dt.timestamp(), str(chat.get("title", "")))
        return (0.0, str(chat.get("title", "")))

    chats = sorted(chats, key=_sort_key, reverse=True)

    # Build choices: pre-checked = included (NOT excluded)
    choices = []
    for chat in chats:
        chat_id = chat["chat_id"]
        title = chat["title"] or "(untitled)"
        chat_type = chat["chat_type"] or "unknown"
        last_activity = chat.get("last_activity")
        if isinstance(last_activity, datetime):
            activity_str = last_activity.strftime("%Y-%m-%d")
        else:
            activity_str = "unknown"
        label = f"[{chat_type}] {title} (last: {activity_str}, id: {chat_id})"
        choices.append({
            "name": label,
            "value": chat_id,
            "enabled": chat_id not in current_excluded,
        })

    print()
    print(f"Found {len(chats)} chats from {source}.")
    print(f"Currently excluding: {len(current_excluded)} chat(s).")
    print()
    print("Use arrow keys to navigate, SPACE to toggle, ENTER to confirm.")
    print("Checked = INCLUDED in sync, Unchecked = EXCLUDED from sync.")
    print()

    included_ids = await inquirer.checkbox(
        message="Select chats to INCLUDE in sync:",
        choices=choices,
        cycle=True,
    ).execute_async()

    # Compute new exclusion set
    all_ids = {c["chat_id"] for c in chats}
    included_set = set(included_ids)
    new_excluded_ids = all_ids - included_set

    # Build the exclusion dict with titles for readability
    title_map = {c["chat_id"]: c["title"] or "(untitled)" for c in chats}
    new_excluded = {cid: title_map[cid] for cid in new_excluded_ids}

    # Show diff
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

    # Save
    path = save_excluded_chats(config, new_excluded)
    print()
    print(f"Saved {len(new_excluded)} exclusion(s) to {path}")
    print(f"The syncer will skip these chats on the next sync pass.")


def main() -> None:
    """Synchronous entry point."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    asyncio.run(interactive_main())


if __name__ == "__main__":
    main()
