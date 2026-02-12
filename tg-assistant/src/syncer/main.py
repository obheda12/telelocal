"""
Syncer entry point — connects to Telegram (read-only), iterates dialogs
and messages, and stores everything in PostgreSQL.

Runs as a long-lived systemd service under the ``tg-syncer`` user.

Key behaviours:
    - Loads configuration from ``/etc/tg-assistant/settings.toml``.
    - All Telegram access goes through ``ReadOnlyTelegramClient``.
    - Rate-limits API calls to stay within Telegram's flood thresholds.
    - Handles SIGTERM / SIGINT for graceful shutdown.
    - Logs every sync cycle to the audit log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import toml
from telethon import TelegramClient as TelethonClient

from syncer.readonly_client import ReadOnlyTelegramClient
from syncer.message_store import MessageStore
from syncer.embeddings import EmbeddingProvider, create_embedding_provider
from shared.audit import AuditLogger
from shared.db import get_connection_pool, init_database
from shared.secrets import get_secret, decrypt_session_file

logger = logging.getLogger("syncer.main")

# Default paths — overridable via settings.toml
_DEFAULT_CONFIG_PATH = Path("/etc/tg-assistant/settings.toml")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config(path: Path = _DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Load and validate settings from a TOML file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        KeyError: If required keys are missing.
    """
    config = toml.load(path)

    # Validate required keys
    required = [
        ("syncer", "api_id"),
        ("syncer", "api_hash"),
        ("syncer", "session_path"),
        ("database",),
    ]
    for keys in required:
        obj = config
        for k in keys:
            if k not in obj:
                raise KeyError(f"Missing required config key: {'.'.join(keys)}")
            obj = obj[k]

    return config


# ---------------------------------------------------------------------------
# Rate limiting helper
# ---------------------------------------------------------------------------


async def rate_limit_delay(seconds: float = 1.0) -> None:
    """Sleep between API calls to avoid Telegram FloodWaitError.

    Args:
        seconds: Minimum delay between consecutive API calls.
    """
    await asyncio.sleep(seconds + random.uniform(0.1, 1.5))


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------


async def sync_once(
    client: ReadOnlyTelegramClient,
    store: MessageStore,
    embedder: EmbeddingProvider,
    audit: AuditLogger,
    config: Dict[str, Any],
) -> int:
    """Run a single sync pass: iterate dialogs, fetch new messages, store.

    Args:
        client: The read-only Telegram client.
        store: Message storage backend.
        embedder: Embedding provider for generating vectors.
        audit: Audit logger instance.
        config: Parsed configuration.

    Returns:
        Total number of new messages stored in this pass.
    """
    syncer_config = config.get("syncer", {})
    batch_size = syncer_config.get("batch_size", 100)
    rate_seconds = syncer_config.get("rate_limit_seconds", 2)
    max_history_days = syncer_config.get("max_history_days", 365)
    use_vectors = embedder.dimension == 1024

    total_new = 0

    dialogs = await client.get_dialogs()
    for dialog in dialogs:
        chat_id = dialog.id
        chat_title = getattr(dialog, "title", None) or getattr(dialog, "name", str(chat_id))

        last_id = await store.get_last_synced_id(chat_id)

        # Build get_messages kwargs
        fetch_kwargs: Dict[str, Any] = {"limit": batch_size}
        if last_id:
            # Incremental sync — only fetch newer messages
            fetch_kwargs["min_id"] = last_id
        elif max_history_days > 0:
            # Initial sync — limit how far back we go
            cutoff = datetime.now(timezone.utc) - timedelta(days=max_history_days)
            fetch_kwargs["offset_date"] = cutoff
            logger.info(
                "Initial sync for chat %s (%s): fetching messages since %s",
                chat_id, chat_title, cutoff.date(),
            )

        messages = await client.get_messages(dialog, **fetch_kwargs)

        if not messages:
            continue

        # Build message dicts
        batch = []
        texts_for_embedding = []
        for msg in messages:
            text = getattr(msg, "text", None) or getattr(msg, "message", None)
            sender = getattr(msg, "sender", None)
            sender_id = getattr(sender, "id", None) if sender else None
            sender_name = None
            if sender:
                first = getattr(sender, "first_name", "") or ""
                last = getattr(sender, "last_name", "") or ""
                sender_name = f"{first} {last}".strip() or str(sender_id)

            try:
                raw = msg.to_dict() if hasattr(msg, "to_dict") else {}
            except Exception:
                raw = {}

            msg_dict = {
                "message_id": msg.id,
                "chat_id": chat_id,
                "sender_id": sender_id,
                "sender_name": sender_name,
                "timestamp": msg.date,
                "text": text,
                "raw_json": json.dumps(raw, default=str),
                "embedding": None,
            }
            batch.append(msg_dict)
            if text and use_vectors:
                texts_for_embedding.append(text)

        # Generate embeddings for texts (if provider produces 1024-dim)
        if texts_for_embedding and use_vectors:
            try:
                embeddings = await embedder.batch_generate(texts_for_embedding)
                emb_idx = 0
                for msg_dict in batch:
                    if msg_dict["text"] and emb_idx < len(embeddings):
                        msg_dict["embedding"] = embeddings[emb_idx]
                        emb_idx += 1
            except Exception:
                logger.warning("Failed to generate embeddings for batch", exc_info=True)

        new_count = await store.store_messages_batch(batch)
        total_new += new_count

        # Determine chat type
        chat_type = "user"
        if hasattr(dialog, "is_group") and dialog.is_group:
            chat_type = "group"
        elif hasattr(dialog, "is_channel") and dialog.is_channel:
            chat_type = "channel"

        await store.update_chat_metadata(
            chat_id=chat_id,
            title=chat_title,
            chat_type=chat_type,
        )

        await audit.log(
            "syncer",
            "sync_chat",
            {
                "chat_id": chat_id,
                "chat_title": chat_title,
                "new_messages": new_count,
                "batch_size": len(batch),
            },
            success=True,
        )

        await rate_limit_delay(rate_seconds)

    return total_new


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event: asyncio.Event = asyncio.Event()


def _handle_signal(sig: int, frame: Any) -> None:
    """Signal handler — sets the shutdown event so the main loop exits cleanly."""
    logger.info("Received signal %s, initiating graceful shutdown...", sig)
    _shutdown_event.set()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    """Top-level async entry point for the syncer service."""
    # --- config & secrets ---
    config = load_config()
    api_id: int = int(config["syncer"]["api_id"])
    api_hash: str = config["syncer"]["api_hash"]

    # Session file is encrypted at rest; decrypt into memory only
    session_path = Path(config["syncer"]["session_path"])
    session_key = get_secret("session_encryption_key")
    session = decrypt_session_file(session_path, session_key)

    # --- database ---
    pool = await get_connection_pool(config["database"])
    await init_database(pool)
    store = MessageStore(pool)
    audit = AuditLogger(pool)

    # --- embeddings ---
    embedder = create_embedding_provider(config.get("embeddings", {}))

    # --- Telegram (read-only) ---
    raw_client = TelethonClient(session, api_id, api_hash)
    async with ReadOnlyTelegramClient(raw_client) as client:
        me = await client.get_me()
        logger.info("Logged in as %s (id=%s)", me.username, me.id)
        await audit.log("syncer", "startup", {"user_id": me.id}, success=True)

        sync_interval: float = config.get("syncer", {}).get(
            "sync_interval_seconds", 300.0
        )

        # --- main loop ---
        while not _shutdown_event.is_set():
            try:
                count = await sync_once(client, store, embedder, audit, config)
                logger.info("Sync pass complete: %d new messages", count)
                await audit.log(
                    "syncer",
                    "sync_pass",
                    {"new_messages": count},
                    success=True,
                )
            except Exception:
                logger.exception("Error during sync pass")
                await audit.log(
                    "syncer", "sync_pass", {"error": "see logs"}, success=False
                )

            # Wait for the next cycle or a shutdown signal
            try:
                await asyncio.wait_for(
                    _shutdown_event.wait(), timeout=sync_interval
                )
            except asyncio.TimeoutError:
                pass  # normal — timeout means it's time to sync again

    # --- cleanup ---
    await pool.close()
    logger.info("Syncer shut down cleanly.")


def run() -> None:
    """Synchronous entry point (called from ``__main__`` or systemd)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    asyncio.run(main())


if __name__ == "__main__":
    run()
