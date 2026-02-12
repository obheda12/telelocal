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

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import asyncpg

logger = logging.getLogger("shared.audit")

_DEFAULT_LOG_PATH = Path("/var/log/tg-assistant/audit.log")


class AuditLogger:
    """Async-safe audit logger that writes to both file and database.

    Args:
        pool: ``asyncpg`` connection pool (needs INSERT on ``audit_log``).
        log_path: Path to the JSON Lines audit log file.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        log_path: Path = _DEFAULT_LOG_PATH,
    ) -> None:
        self._pool = pool
        self._log_path = log_path

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
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": service,
            "action": action,
            "details": details or {},
            "success": success,
        }

        # 1. Write to file (append, one JSON object per line)
        try:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except OSError:
            logger.exception("Failed to write audit log file")

        # 2. Write to database (parameterized query)
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO audit_log (service, action, details, success) "
                    "VALUES ($1, $2, $3::jsonb, $4)",
                    service,
                    action,
                    json.dumps(details or {}),
                    success,
                )
        except Exception:
            logger.exception("Failed to write audit log to database")
