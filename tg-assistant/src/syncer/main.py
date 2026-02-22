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
from syncer.progress import ChatProgress, PassProgress
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
# Pre-scan: get estimated message counts per chat
# ---------------------------------------------------------------------------


async def prescan_dialogs(
    client: ReadOnlyTelegramClient,
    dialogs: list,
) -> Dict[int, int]:
    """Get estimated message counts per chat for progress tracking.

    Calls ``get_messages(dialog, limit=0)`` for each dialog to retrieve
    the ``.total`` attribute — a lightweight metadata-only call.

    Args:
        client: The read-only Telegram client.
        dialogs: List of dialogs from ``get_dialogs()``.

    Returns:
        Dict mapping chat_id to estimated total message count.
    """
    logger.info("Pre-scanning %d chats for message counts...", len(dialogs))
    counts: Dict[int, int] = {}

    for dialog in dialogs:
        try:
            result = await client.get_messages(dialog, limit=0)
            total = getattr(result, "total", 0) or 0
            counts[dialog.id] = total
        except Exception:
            logger.debug(
                "Pre-scan failed for chat %s", dialog.id, exc_info=True
            )
            counts[dialog.id] = 0
        await asyncio.sleep(0.5)

    grand_total = sum(counts.values())
    logger.info(
        "Pre-scan complete: ~%d total messages across %d chats",
        grand_total,
        len(dialogs),
    )
    return counts


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
    use_vectors = embedder.dimension is not None and embedder.dimension > 0

    total_new = 0

    async def _flush_batch(
        batch: list[Dict[str, Any]],
        texts_for_embedding: list[str],
    ) -> int:
        if not batch:
            return 0

        if texts_for_embedding and use_vectors:
            try:
                embeddings = await embedder.batch_generate(texts_for_embedding)
                emb_idx = 0
                for msg_dict in batch:
                    if msg_dict.get("text") and emb_idx < len(embeddings):
                        msg_dict["embedding"] = embeddings[emb_idx]
                        emb_idx += 1
            except Exception:
                logger.warning("Failed to generate embeddings for batch", exc_info=True)

        return await store.store_messages_batch(batch)

    dialogs = await client.get_dialogs()
    total_dialogs = len(dialogs)

    await audit.log(
        "syncer",
        "sync_pass_start",
        {"total_dialogs": total_dialogs},
        success=True,
    )

    # Pre-scan for message count estimates
    msg_counts = await prescan_dialogs(client, dialogs)
    grand_total = sum(msg_counts.values())

    pass_progress = PassProgress(
        estimated_total=grand_total, total_chats=total_dialogs
    )

    for chat_idx, dialog in enumerate(dialogs):
        chat_id = dialog.id
        chat_title = getattr(dialog, "title", None) or getattr(dialog, "name", str(chat_id))
        estimated = msg_counts.get(chat_id, 0)

        logger.info(
            "Syncing chat %d/%d: %s (~%d messages)",
            chat_idx + 1,
            total_dialogs,
            chat_title,
            estimated,
        )

        chat_progress = ChatProgress(
            chat_index=chat_idx + 1,
            total_chats=total_dialogs,
            chat_title=chat_title,
            estimated_total=estimated,
        )

        last_id = await store.get_last_synced_id(chat_id)

        # Iterator for messages (paginated)
        cutoff: datetime | None = None
        if last_id:
            iterator = client.iter_messages(dialog, min_id=last_id, reverse=True)
        else:
            if max_history_days > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(days=max_history_days)
                logger.info(
                    "Initial sync for chat %s (%s): fetching messages since %s",
                    chat_id, chat_title, cutoff.isoformat(),
                )
            iterator = client.iter_messages(dialog, reverse=False)

        batch: list[Dict[str, Any]] = []
        texts_for_embedding: list[str] = []
        new_count = 0
        processed_count = 0

        async for msg in iterator:
            if cutoff and msg.date < cutoff:
                break

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
                logger.debug("to_dict() failed for message_id=%s", msg.id, exc_info=True)
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

            if len(batch) >= batch_size:
                stored = await _flush_batch(batch, texts_for_embedding)
                new_count += stored
                processed_count += len(batch)
                chat_progress.update(len(batch), stored)
                chat_progress.log_batch()
                batch = []
                texts_for_embedding = []
                await rate_limit_delay(rate_seconds)

        # Flush remaining
        if batch:
            stored = await _flush_batch(batch, texts_for_embedding)
            new_count += stored
            processed_count += len(batch)
            chat_progress.update(len(batch), stored)

        chat_progress.log_complete()

        total_new += new_count

        # Accumulate pass-level progress
        pass_progress.update_from_chat(chat_progress)

        # Log pass progress every 5 chats
        if (chat_idx + 1) % 5 == 0:
            pass_progress.log_pass_progress()

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
                "chat_index": chat_idx + 1,
                "total_chats": total_dialogs,
                "initial_sync": last_id is None,
                "new_messages": new_count,
                "messages_processed": processed_count,
                "estimated_total": estimated,
                "elapsed_seconds": round(chat_progress.elapsed_seconds, 1),
                "rate_msg_per_sec": round(chat_progress.rate, 1),
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
    api_id: int = int(get_secret("tg-assistant-api-id"))
    api_hash: str = get_secret("tg-assistant-api-hash")

    # Session file is encrypted at rest; decrypt to RAM-backed tmpfs only.
    # Telethon needs an SQLite file path — we write to /dev/shm (tmpfs)
    # so decrypted session never touches persistent storage.
    session_path = Path(config["syncer"]["session_path"])
    session_key = get_secret("session_encryption_key")
    session_bytes = decrypt_session_file(session_path, session_key)

    import tempfile, os  # noqa: E401
    shm_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".session", dir=shm_dir)
    try:
        os.write(tmp_fd, session_bytes)
        os.close(tmp_fd)
        os.chmod(tmp_path, 0o600)
        # Telethon appends ".session" to the path, so strip the suffix
        session_base = tmp_path.removesuffix(".session")

        # --- database (Unix socket + peer auth) ---
        db_config = dict(config["database"])
        db_config["user"] = config["syncer"].get("db_user", "tg_syncer")
        pool = await get_connection_pool(db_config)
        await init_database(pool)
        # --- embeddings ---
        embedder = create_embedding_provider(config.get("embeddings", {}))

        store = MessageStore(pool, embedding_dim=embedder.dimension)
        audit = AuditLogger(pool)

        # --- Telegram (read-only) ---
        raw_client = TelethonClient(session_base, api_id, api_hash)
        async with ReadOnlyTelegramClient(raw_client) as client:
            me = await client.get_me()
            logger.info("Logged in as %s (id=%s)", me.username, me.id)
            await audit.log("syncer", "startup", {"user_id": me.id}, success=True)

            sync_interval: float = config.get("syncer", {}).get(
                "sync_interval_seconds", 300.0
            )

            # --- main loop ---
            pass_number = 0
            while not _shutdown_event.is_set():
                pass_number += 1
                try:
                    count = await sync_once(client, store, embedder, audit, config)
                    logger.info(
                        "Sync pass #%d complete: %d new messages",
                        pass_number,
                        count,
                    )
                    await audit.log(
                        "syncer",
                        "sync_pass",
                        {"new_messages": count, "pass_number": pass_number},
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
    finally:
        # Shred the decrypted session from tmpfs
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        # Telethon may also create a -journal file
        journal = tmp_path + "-journal"
        if os.path.exists(journal):
            os.remove(journal)


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
