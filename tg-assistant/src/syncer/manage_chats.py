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
import sys
from pathlib import Path
from typing import Any, Dict

import toml

from shared.db import get_connection_pool

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
        # Try local dev path first, then system path
        local = Path(__file__).resolve().parent.parent.parent / "config" / "settings.toml"
        path = local if local.exists() else _DEFAULT_CONFIG_PATH
    return toml.load(path)


def get_excluded_chats_path(config: Dict[str, Any]) -> Path:
    """Resolve the path to ``excluded_chats.json``.

    The file lives alongside ``settings.toml`` — either the local
    ``config/`` directory (development) or ``/etc/tg-assistant/``
    (production).
    """
    # Prefer local dev config dir
    local_dir = Path(__file__).resolve().parent.parent.parent / "config"
    system_dir = Path("/etc/tg-assistant")

    config_dir = local_dir if local_dir.exists() else system_dir
    return config_dir / _EXCLUDED_CHATS_FILENAME


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


async def interactive_main() -> None:
    """Run the interactive exclusion manager."""
    try:
        from InquirerPy import inquirer
    except ImportError:
        print("Error: InquirerPy is required. Install with: pip install InquirerPy")
        sys.exit(1)

    config = _load_config()
    chats = await _fetch_chats(config)

    if not chats:
        print("No chats found in the database.")
        print("Run a sync first so the chats table is populated.")
        sys.exit(0)

    # Load current exclusions
    current_excluded = load_excluded_ids(config)

    # Build choices: pre-checked = included (NOT excluded)
    choices = []
    for chat in chats:
        chat_id = chat["chat_id"]
        title = chat["title"] or "(untitled)"
        chat_type = chat["chat_type"] or "unknown"
        label = f"[{chat_type}] {title} (id: {chat_id})"
        choices.append({
            "name": label,
            "value": chat_id,
            "enabled": chat_id not in current_excluded,
        })

    print()
    print(f"Found {len(chats)} chats in the database.")
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
