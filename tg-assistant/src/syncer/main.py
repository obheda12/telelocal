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
import logging
import os
import random
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import toml
from telethon import TelegramClient as TelethonClient

from syncer.readonly_client import ReadOnlyTelegramClient
from syncer.message_store import MessageStore
from syncer.embeddings import EmbeddingProvider, create_embedding_provider
from syncer.manage_chats import load_excluded_ids
from syncer.progress import ChatProgress, PassProgress
from shared.audit import AuditLogger
from shared.db import get_connection_pool, init_database
from shared.secrets import get_secret, decrypt_session_file

logger = logging.getLogger("syncer.main")
_VALID_CHAT_TYPES = {"group", "channel", "user"}

# Default paths — overridable via settings.toml
_DEFAULT_CONFIG_PATH = Path(
    os.environ.get("TG_ASSISTANT_CONFIG", "/etc/tg-assistant/settings.toml")
)

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
    delay = max(0.0, seconds) + random.uniform(0.1, 1.5)
    await _sleep_with_shutdown(delay)


def _get_dialog_chat_type(dialog: Any) -> str:
    """Classify a Telethon dialog into ``group``, ``channel``, or ``user``."""
    if bool(getattr(dialog, "is_group", False)):
        return "group"
    if bool(getattr(dialog, "is_channel", False)):
        return "channel"
    return "user"


def _normalize_include_chat_types(value: Any) -> set[str]:
    """Normalize ``syncer.include_chat_types`` to a validated set.

    Missing/invalid values default to all chat types for backwards compatibility.
    """
    if value is None:
        return set(_VALID_CHAT_TYPES)

    if isinstance(value, str):
        raw_items = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        raw_items = [str(part).strip() for part in value]
    else:
        logger.warning(
            "Invalid include_chat_types config type (%s); defaulting to all types",
            type(value).__name__,
        )
        return set(_VALID_CHAT_TYPES)

    normalized = {
        item.lower() for item in raw_items
        if item and item.lower() in _VALID_CHAT_TYPES
    }
    if not normalized:
        logger.warning(
            "include_chat_types has no valid values; defaulting to all types"
        )
        return set(_VALID_CHAT_TYPES)
    return normalized


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
        if _shutdown_event.is_set():
            logger.info("Pre-scan interrupted by shutdown request.")
            break
        try:
            result = await client.get_messages(dialog, limit=0)
            total = getattr(result, "total", 0) or 0
            counts[dialog.id] = total
        except Exception:
            logger.warning(
                "Pre-scan failed for chat %s", dialog.id, exc_info=True
            )
            counts[dialog.id] = 0
        if _shutdown_event.is_set():
            logger.info("Pre-scan interrupted by shutdown request.")
            break
        await _sleep_with_shutdown(0.5)

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


class DeferredEmbeddingWorker:
    """Background worker for deferred embedding generation.

    This lets the sync loop persist messages immediately, then backfill
    embeddings concurrently in batches.
    """

    def __init__(
        self,
        store: MessageStore,
        embedder: EmbeddingProvider,
        batch_size: int = 256,
        queue_size: int = 4096,
    ) -> None:
        self._store = store
        self._embedder = embedder
        self._batch_size = max(1, batch_size)
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=max(1, queue_size))
        self._stop_token = object()
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self._queued = 0
        self._updated = 0
        self._failed = 0

    def _start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(
                self._run(),
                name="tg-assistant-embedding-worker",
            )

    async def enqueue_many(self, rows: list[tuple[int, int, str]]) -> None:
        """Queue ``(message_id, chat_id, text)`` rows for embedding backfill."""
        if self._closed or not rows:
            return
        self._start()
        for row in rows:
            await self._queue.put(row)
        self._queued += len(rows)

    async def _flush_pending(self, pending: list[tuple[int, int, str]]) -> None:
        texts = [text for _, _, text in pending]
        try:
            vectors = await self._embedder.batch_generate(texts)
        except Exception:
            self._failed += len(pending)
            logger.warning("Deferred embedding batch generation failed", exc_info=True)
            return

        if len(vectors) != len(pending):
            logger.warning(
                "Deferred embedding size mismatch: vectors=%d pending=%d",
                len(vectors),
                len(pending),
            )

        updates: list[tuple[list[float], int, int]] = []
        expected_dim = self._embedder.dimension
        for (message_id, chat_id, _), vector in zip(pending, vectors):
            if expected_dim and len(vector) != expected_dim:
                self._failed += 1
                logger.debug(
                    "Skipping embedding with mismatched dimension for message_id=%s chat_id=%s",
                    message_id,
                    chat_id,
                )
                continue
            updates.append((vector, message_id, chat_id))

        skipped = len(pending) - len(updates)
        if skipped > 0:
            self._failed += skipped

        if not updates:
            return

        try:
            updated = await self._store.update_embeddings_batch(updates)
            self._updated += updated
        except Exception:
            self._failed += len(updates)
            logger.warning("Deferred embedding DB update failed", exc_info=True)

    async def _run(self) -> None:
        pending: list[tuple[int, int, str]] = []
        stop = False

        while True:
            item = await self._queue.get()
            if item is self._stop_token:
                self._queue.task_done()
                stop = True
            else:
                pending.append(item)

            if pending and (stop or len(pending) >= self._batch_size):
                await self._flush_pending(pending)
                for _ in pending:
                    self._queue.task_done()
                pending = []

            if stop:
                break

    async def close(self) -> Dict[str, int]:
        """Flush remaining rows and stop worker."""
        self._closed = True
        if self._task is not None:
            await self._queue.put(self._stop_token)
            await self._task
            self._task = None
        return {
            "queued": self._queued,
            "updated": self._updated,
            "failed": self._failed,
        }


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
    max_active_chats = syncer_config.get("max_active_chats", 500)
    enable_prescan_progress = syncer_config.get("enable_prescan_progress", False)
    store_raw_json = syncer_config.get("store_raw_json", False)
    idle_chat_delay_seconds = syncer_config.get("idle_chat_delay_seconds", 0.1)
    log_batch_progress = syncer_config.get("log_batch_progress", False)
    progress_heartbeat_seconds = syncer_config.get("progress_heartbeat_seconds", 30)
    defer_embeddings = syncer_config.get("defer_embeddings", False)
    include_chat_types = _normalize_include_chat_types(
        syncer_config.get("include_chat_types")
    )
    embedding_update_batch_size = max(
        1, int(syncer_config.get("embedding_update_batch_size", batch_size))
    )
    embedding_queue_size = max(
        1, int(syncer_config.get("embedding_queue_size", batch_size * 8))
    )
    use_vectors = embedder.dimension is not None and embedder.dimension > 0
    try:
        max_active_chats = int(max_active_chats)
    except (TypeError, ValueError):
        max_active_chats = 500
    max_active_chats = max(0, max_active_chats)
    try:
        progress_heartbeat_seconds = float(progress_heartbeat_seconds)
    except (TypeError, ValueError):
        progress_heartbeat_seconds = 30.0
    progress_heartbeat_seconds = max(0.0, progress_heartbeat_seconds)

    total_new = 0
    if _shutdown_event.is_set():
        logger.info("Shutdown already requested; skipping sync pass start.")
        return total_new

    embedding_worker: DeferredEmbeddingWorker | None = None
    if use_vectors and defer_embeddings:
        embedding_worker = DeferredEmbeddingWorker(
            store=store,
            embedder=embedder,
            batch_size=embedding_update_batch_size,
            queue_size=embedding_queue_size,
        )
        logger.info(
            "Deferred embeddings enabled (update_batch_size=%d queue_size=%d)",
            embedding_update_batch_size,
            embedding_queue_size,
        )

    async def _flush_batch(
        batch: list[Dict[str, Any]],
        texts_for_embedding: list[str],
    ) -> int:
        if not batch:
            return 0

        if embedding_worker is not None:
            rows_for_deferred: list[tuple[int, int, str]] = []
            if hasattr(store, "store_messages_batch_returning"):
                rows_for_deferred = await store.store_messages_batch_returning(batch)
                inserted = len(rows_for_deferred)
            else:
                # Backward-compatible fallback for older MessageStore implementations.
                inserted = await store.store_messages_batch(batch)
                if inserted > 0:
                    for msg_dict in batch:
                        text = msg_dict.get("text")
                        if text:
                            rows_for_deferred.append(
                                (
                                    int(msg_dict["message_id"]),
                                    int(msg_dict["chat_id"]),
                                    str(text),
                                )
                            )

            if rows_for_deferred:
                await embedding_worker.enqueue_many(rows_for_deferred)
            return inserted

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

    # Filter to dialogs with activity within max_history_days
    if max_history_days > 0:
        filter_cutoff = datetime.now(timezone.utc) - timedelta(days=max_history_days)
        active_dialogs = [
            d for d in dialogs
            if getattr(d, "date", None) is None  # include if no date (conservative)
            or d.date >= filter_cutoff
        ]
    else:
        active_dialogs = dialogs

    logger.info(
        "Filtered dialogs: %d active (of %d total) within %d days",
        len(active_dialogs), total_dialogs, max_history_days,
    )

    # Auto-filter by chat type (e.g., group-only ingestion).
    chat_type_filtered_count = 0
    if include_chat_types != _VALID_CHAT_TYPES:
        before_type_filter = len(active_dialogs)
        active_dialogs = [
            d for d in active_dialogs
            if _get_dialog_chat_type(d) in include_chat_types
        ]
        chat_type_filtered_count = before_type_filter - len(active_dialogs)
        logger.info(
            "Chat-type filter applied: include=%s, filtered_out=%d, remaining=%d",
            ",".join(sorted(include_chat_types)),
            chat_type_filtered_count,
            len(active_dialogs),
        )

    # Apply manual exclusions from excluded_chats.json
    excluded_ids = load_excluded_ids(config)
    excluded_count = 0
    if excluded_ids:
        before_exclude = len(active_dialogs)
        active_dialogs = [d for d in active_dialogs if d.id not in excluded_ids]
        excluded_count = before_exclude - len(active_dialogs)
        logger.info(
            "Excluded %d manually-excluded chats (%d remaining)",
            excluded_count, len(active_dialogs),
        )

    # Prioritize recently active chats so freshest context is available first.
    def _dialog_sort_key(dialog: Any) -> datetime:
        dt = getattr(dialog, "date", None)
        if not isinstance(dt, datetime):
            return datetime.min.replace(tzinfo=timezone.utc)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    active_dialogs.sort(key=_dialog_sort_key, reverse=True)
    capped_chats = 0
    if max_active_chats > 0 and len(active_dialogs) > max_active_chats:
        capped_chats = len(active_dialogs) - max_active_chats
        active_dialogs = active_dialogs[:max_active_chats]
        logger.info(
            "Capped active chats to %d freshest (skipped %d older active chats)",
            max_active_chats,
            capped_chats,
        )

    await audit.log(
        "syncer",
        "sync_pass_start",
        {
            "total_dialogs": total_dialogs,
            "active_dialogs": len(active_dialogs),
            "include_chat_types": sorted(include_chat_types),
            "chat_type_filtered_count": chat_type_filtered_count,
            "excluded_count": excluded_count,
            "max_history_days": max_history_days,
            "max_active_chats": max_active_chats,
            "capped_chats": capped_chats,
        },
        success=True,
    )

    # Pre-scan for estimated message counts (optional, adds extra API roundtrips)
    if enable_prescan_progress:
        msg_counts = await prescan_dialogs(client, active_dialogs)
        grand_total = sum(msg_counts.values())
        if _shutdown_event.is_set():
            logger.info("Shutdown requested during pre-scan; ending sync pass early.")
            return total_new
    else:
        msg_counts = {d.id: 0 for d in active_dialogs}
        grand_total = 0

    active_count = len(active_dialogs)
    pass_progress = PassProgress(
        estimated_total=grand_total, total_chats=active_count
    )

    # Reduce DB round-trips: fetch per-chat high-water marks in one query.
    last_synced_map: Dict[int, int] = {}
    prefetched_last_ids = False
    try:
        maybe_map = await store.get_last_synced_ids([d.id for d in active_dialogs])
        if isinstance(maybe_map, dict):
            last_synced_map = maybe_map
            prefetched_last_ids = True
    except AttributeError:
        # Backward-compatible fallback for older store implementations.
        logger.debug("MessageStore.get_last_synced_ids unavailable; using per-chat lookup")

    for chat_idx, dialog in enumerate(active_dialogs):
        if _shutdown_event.is_set():
            logger.info(
                "Shutdown requested; stopping sync pass after %d/%d chats.",
                chat_idx,
                active_count,
            )
            break

        chat_id = dialog.id
        chat_title = getattr(dialog, "title", None) or getattr(dialog, "name", str(chat_id))
        estimated = msg_counts.get(chat_id, 0)

        logger.info(
            "Syncing chat %d/%d: %s (~%d messages)",
            chat_idx + 1,
            active_count,
            chat_title,
            estimated,
        )

        chat_progress = ChatProgress(
            chat_index=chat_idx + 1,
            total_chats=active_count,
            chat_title=chat_title,
            estimated_total=estimated,
        )

        if prefetched_last_ids:
            last_id = last_synced_map.get(chat_id)
        else:
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
        scanned_count = 0
        last_heartbeat_at = time.monotonic()

        async for msg in iterator:
            if _shutdown_event.is_set():
                logger.info(
                    "Shutdown requested while syncing chat %s (%s); flushing partial batch.",
                    chat_id,
                    chat_title,
                )
                break

            msg_date = msg.date
            if msg_date and msg_date.tzinfo is None:
                msg_date = msg_date.replace(tzinfo=timezone.utc)

            if cutoff and msg_date and msg_date < cutoff:
                break

            scanned_count += 1

            text = getattr(msg, "text", None) or getattr(msg, "message", None)
            sender_id = getattr(msg, "sender_id", None)
            sender_name = None
            raw_reply_to_msg_id = getattr(msg, "reply_to_msg_id", None)
            reply_to_msg_id = (
                int(raw_reply_to_msg_id)
                if isinstance(raw_reply_to_msg_id, int)
                else None
            )
            raw_thread_top_msg_id = getattr(msg, "reply_to_top_id", None)
            thread_top_msg_id = (
                int(raw_thread_top_msg_id)
                if isinstance(raw_thread_top_msg_id, int)
                else None
            )
            is_topic_message = False

            # Prefer cached sender data attached to the message object to avoid
            # triggering extra entity lookups in the hot ingest loop.
            sender = getattr(msg, "_sender", None) or getattr(msg, "sender", None)
            if sender:
                sender_id = sender_id or getattr(sender, "id", None)
                first = getattr(sender, "first_name", "") or ""
                last = getattr(sender, "last_name", "") or ""
                sender_name = f"{first} {last}".strip() or str(sender_id)
            elif sender_id is not None:
                sender_name = str(sender_id)

            reply_to = getattr(msg, "reply_to", None)
            if reply_to is not None:
                if reply_to_msg_id is None:
                    raw = getattr(reply_to, "reply_to_msg_id", None)
                    if isinstance(raw, int):
                        reply_to_msg_id = int(raw)
                if thread_top_msg_id is None:
                    raw = getattr(reply_to, "reply_to_top_id", None)
                    if isinstance(raw, int):
                        thread_top_msg_id = int(raw)
                forum_topic = getattr(reply_to, "forum_topic", False)
                if isinstance(forum_topic, bool):
                    is_topic_message = forum_topic

            # Topic-style replies often use top-msg id as thread key.
            if thread_top_msg_id is None and is_topic_message and reply_to_msg_id is not None:
                thread_top_msg_id = reply_to_msg_id

            raw = None
            if store_raw_json:
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
                "reply_to_msg_id": reply_to_msg_id,
                "thread_top_msg_id": thread_top_msg_id,
                "is_topic_message": is_topic_message,
                "timestamp": msg_date,
                "text": text,
                "raw_json": raw,
                "embedding": None,
            }
            batch.append(msg_dict)
            if text and use_vectors and embedding_worker is None:
                texts_for_embedding.append(text)

            if len(batch) >= batch_size:
                stored = await _flush_batch(batch, texts_for_embedding)
                new_count += stored
                processed_count += len(batch)
                chat_progress.update(len(batch), stored)
                if log_batch_progress:
                    chat_progress.log_batch()
                batch = []
                texts_for_embedding = []

            # Emit an in-flight heartbeat so status tools can distinguish
            # long-running chat scans from stalled sync loops.
            if progress_heartbeat_seconds > 0:
                now = time.monotonic()
                if (now - last_heartbeat_at) >= progress_heartbeat_seconds:
                    elapsed = max(0.0, now - chat_progress._start)
                    rate = (scanned_count / elapsed) if elapsed > 0 else 0.0
                    await audit.log(
                        "syncer",
                        "sync_chat_progress",
                        {
                            "chat_id": chat_id,
                            "chat_title": chat_title,
                            "chat_index": chat_idx + 1,
                            "total_chats": active_count,
                            "messages_scanned": scanned_count,
                            "messages_flushed": processed_count,
                            "messages_buffered": len(batch),
                            "new_messages": new_count,
                            "elapsed_seconds": round(elapsed, 1),
                            "rate_msg_per_sec": round(rate, 1),
                        },
                        success=True,
                    )
                    last_heartbeat_at = now

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
        chat_type = _get_dialog_chat_type(dialog)

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
                "total_chats": active_count,
                "initial_sync": last_id is None,
                "new_messages": new_count,
                "messages_processed": processed_count,
                "estimated_total": estimated,
                "elapsed_seconds": round(chat_progress.elapsed_seconds, 1),
                "rate_msg_per_sec": round(chat_progress.rate, 1),
            },
            success=True,
        )

        # Keep idle chat probes fast; full delay only when data was processed.
        await rate_limit_delay(rate_seconds if processed_count > 0 else idle_chat_delay_seconds)
        if _shutdown_event.is_set():
            logger.info("Shutdown requested during inter-chat delay; ending sync pass.")
            break

    if embedding_worker is not None:
        embed_stats = await embedding_worker.close()
        logger.info(
            "Deferred embedding worker complete: queued=%d updated=%d failed=%d",
            embed_stats["queued"],
            embed_stats["updated"],
            embed_stats["failed"],
        )
        await audit.log(
            "syncer",
            "deferred_embedding_flush",
            embed_stats,
            success=embed_stats["failed"] == 0,
        )

    return total_new


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event: threading.Event = threading.Event()


async def _sleep_with_shutdown(seconds: float) -> bool:
    """Sleep for up to ``seconds`` while remaining responsive to shutdown."""
    if _shutdown_event.is_set():
        return True

    remaining = max(0.0, seconds)
    while remaining > 0:
        if _shutdown_event.is_set():
            return True
        tick = min(0.5, remaining)
        await asyncio.sleep(tick)
        remaining -= tick
    return _shutdown_event.is_set()


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

    import tempfile  # noqa: E401
    shm_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".session", dir=shm_dir)
    pool = None
    audit = None
    try:
        with os.fdopen(tmp_fd, "wb") as tmp_handle:
            tmp_handle.write(session_bytes)
            tmp_handle.flush()
        # Drop plaintext session bytes as soon as they're materialized in tmpfs.
        session_bytes = b""
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
                await _sleep_with_shutdown(sync_interval)
    finally:
        if audit is not None:
            try:
                await audit.close()
            except Exception:
                logger.exception("Failed to flush/close audit logger")
        if pool is not None:
            try:
                await pool.close()
            except Exception:
                logger.exception("Failed to close database pool")
        logger.info("Syncer shut down cleanly.")

        # Shred the decrypted session from tmpfs
        for path in (
            tmp_path,
            tmp_path + "-journal",
            tmp_path + "-wal",
            tmp_path + "-shm",
        ):
            if os.path.exists(path):
                os.remove(path)


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
