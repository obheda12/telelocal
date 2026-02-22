"""
Structured audit logging — writes security-relevant events to both
a JSON log file and a PostgreSQL ``audit_log`` table.

Every significant action (sync pass, query, auth check, blocked call)
is recorded with a timestamp, service name, action, details dict,
and success flag.

The log file uses one JSON object per line (JSON Lines format) for
easy ingestion by log aggregation tools.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import asyncpg

logger = logging.getLogger("shared.audit")

_DEFAULT_LOG_PATH = Path("/var/log/tg-assistant/audit.log")
_INSERT_AUDIT_SQL = (
    "INSERT INTO audit_log (service, action, details, success) "
    "VALUES ($1, $2, $3::jsonb, $4)"
)


@dataclass(slots=True)
class _AuditRecord:
    """Single audit event prepared for async batch flushing."""

    json_line: str
    service: str
    action: str
    details_json: str
    success: bool


class AuditLogger:
    """Buffered audit logger that writes to both file and database.

    Args:
        pool: ``asyncpg`` connection pool (needs INSERT on ``audit_log``).
        log_path: Path to the JSON Lines audit log file.
        queue_size: Max queued events before producers backpressure.
        flush_batch_size: Number of queued events to flush per write batch.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        log_path: Path = _DEFAULT_LOG_PATH,
        queue_size: int = 1024,
        flush_batch_size: int = 64,
    ) -> None:
        self._pool = pool
        self._log_path = log_path
        self._queue: asyncio.Queue[_AuditRecord | None] = asyncio.Queue(
            maxsize=max(1, queue_size)
        )
        self._flush_batch_size = max(1, flush_batch_size)
        self._worker_task: asyncio.Task[None] | None = None
        self._closed = False
        self._lifecycle_lock = asyncio.Lock()

    def _ensure_worker(self) -> None:
        if self._worker_task is None:
            loop = asyncio.get_running_loop()
            self._worker_task = loop.create_task(
                self._worker(),
                name="tg-assistant-audit-writer",
            )

    async def _write_batch(self, batch: list[_AuditRecord]) -> None:
        if not batch:
            return

        # 1. File write (one append for the full batch)
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a", encoding="utf-8") as handle:
                handle.write("".join(item.json_line for item in batch))
        except OSError:
            logger.exception("Failed to write audit log file")

        # 2. DB insert (single round-trip via executemany)
        try:
            async with self._pool.acquire() as conn:
                await conn.executemany(
                    _INSERT_AUDIT_SQL,
                    [
                        (
                            item.service,
                            item.action,
                            item.details_json,
                            item.success,
                        )
                        for item in batch
                    ],
                )
        except Exception:
            logger.exception("Failed to write audit log to database")

    async def _worker(self) -> None:
        """Drain queue and flush records in small batches."""
        stop = False
        while True:
            record = await self._queue.get()
            if record is None:
                self._queue.task_done()
                break

            batch = [record]

            while len(batch) < self._flush_batch_size:
                try:
                    maybe_next = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                if maybe_next is None:
                    self._queue.task_done()
                    stop = True
                    break
                batch.append(maybe_next)

            await self._write_batch(batch)
            for _ in batch:
                self._queue.task_done()

            if stop:
                break

    async def log(
        self,
        service: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Record an audit event.

        Writes to **both** the log file and the database table.  If the
        database write fails, the file write still succeeds (and the DB
        failure is logged to the standard logger).

        Args:
            service: Originating service (``"syncer"`` or ``"querybot"``).
            action: Action identifier (e.g. ``"sync_pass"``, ``"query"``,
                    ``"blocked_method"``, ``"unauthorized_access"``).
            details: Arbitrary JSON-serialisable metadata.
            success: Whether the action succeeded.
        """
        details_payload = details or {}
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": service,
            "action": action,
            "details": details_payload,
            "success": success,
        }
        record = _AuditRecord(
            json_line=json.dumps(event) + "\n",
            service=service,
            action=action,
            details_json=json.dumps(details_payload),
            success=success,
        )
        async with self._lifecycle_lock:
            if self._closed:
                logger.debug(
                    "Dropping audit event after logger close: service=%s action=%s",
                    service,
                    action,
                )
                return
            self._ensure_worker()
            await self._queue.put(record)

    async def close(self) -> None:
        """Flush queued events and stop the background writer."""
        worker: asyncio.Task[None] | None = None
        async with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            worker = self._worker_task
            if worker is not None:
                await self._queue.put(None)

        if worker is not None:
            await worker
