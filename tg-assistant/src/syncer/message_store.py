"""
PostgreSQL message storage for the syncer.

Uses ``asyncpg`` for async database access.  All queries use parameterized
placeholders ($1, $2, ...) — **never** string interpolation — to prevent
SQL injection.

The syncer's DB role (``syncer_role``) has INSERT and SELECT privileges
only; it cannot UPDATE or DELETE message rows.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import asyncpg

logger = logging.getLogger("syncer.message_store")

_INSERT_SQL = """
    INSERT INTO messages (message_id, chat_id, sender_id, sender_name,
                          timestamp, text, raw_json, embedding)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
    ON CONFLICT (message_id, chat_id) DO NOTHING
"""

_INSERT_RETURNING_SQL = """
    INSERT INTO messages (message_id, chat_id, sender_id, sender_name,
                          timestamp, text, raw_json, embedding)
    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
    ON CONFLICT (message_id, chat_id) DO NOTHING
    RETURNING message_id
"""

_UPSERT_CHAT_SQL = """
    INSERT INTO chats (chat_id, title, chat_type, participant_count, updated_at)
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (chat_id)
    DO UPDATE SET title = $2, chat_type = $3, participant_count = $4,
                  updated_at = NOW()
"""



class MessageStore:
    """Manages message persistence in PostgreSQL.

    Args:
        pool: An ``asyncpg`` connection pool (created via
              :func:`shared.db.get_connection_pool`).
    """

    def __init__(self, pool: asyncpg.Pool, embedding_dim: Optional[int] = None) -> None:
        self._pool = pool
        self._embedding_dim = embedding_dim

    # ------------------------------------------------------------------
    # Write operations (syncer_role needs INSERT on messages table)
    # ------------------------------------------------------------------

    def _msg_params(self, msg: Dict[str, Any]) -> tuple:
        """Extract ordered parameters from a message dict."""
        embedding = msg.get("embedding")
        # Store NULL for embeddings that don't match the configured dimension
        if embedding is not None and self._embedding_dim:
            if len(embedding) != self._embedding_dim:
                logger.warning(
                    "Embedding dimension mismatch: got=%d expected=%d; storing NULL",
                    len(embedding),
                    self._embedding_dim,
                )
                embedding = None
        raw_json = msg.get("raw_json")
        if raw_json is not None and not isinstance(raw_json, str):
            raw_json = json.dumps(raw_json)
        return (
            msg["message_id"],
            msg["chat_id"],
            msg.get("sender_id"),
            msg.get("sender_name"),
            msg["timestamp"],
            msg.get("text"),
            raw_json,
            embedding,
        )

    async def store_message(self, msg: Dict[str, Any]) -> None:
        """Insert a single Telegram message into the database.

        Args:
            msg: A dictionary with at least the following keys:
                 ``message_id``, ``chat_id``, ``sender_id``,
                 ``timestamp`` (datetime), ``text`` (str | None),
                 ``raw_json`` (dict).
        """
        params = self._msg_params(msg)
        await self._pool.execute(_INSERT_SQL, *params)
        logger.debug("Stored message_id=%d chat_id=%d", msg["message_id"], msg["chat_id"])

    async def store_messages_batch(self, messages: List[Dict[str, Any]]) -> int:
        """Insert a batch of messages efficiently.

        Returns:
            Number of rows actually inserted (excluding conflicts).
        """
        if not messages:
            return 0

        async with self._pool.acquire() as conn:
            params: List[Any] = []
            values_sql: List[str] = []
            for idx, msg in enumerate(messages):
                row_params = self._msg_params(msg)
                params.extend(row_params)
                base = idx * len(row_params)
                placeholders = ", ".join(f"${base + i}" for i in range(1, len(row_params) + 1))
                values_sql.append(f"({placeholders})")

            sql = (
                "INSERT INTO messages (message_id, chat_id, sender_id, sender_name, "
                "timestamp, text, raw_json, embedding) VALUES "
                + ", ".join(values_sql)
                + " ON CONFLICT (message_id, chat_id) DO NOTHING RETURNING 1"
            )
            rows = await conn.fetch(sql, *params)

        inserted = len(rows)
        logger.debug("Batch insert: %d/%d new rows", inserted, len(messages))
        return inserted

    # ------------------------------------------------------------------
    # Read operations (syncer_role needs SELECT on messages table)
    # ------------------------------------------------------------------

    async def get_last_synced_id(self, chat_id: int) -> Optional[int]:
        """Return the highest ``message_id`` stored for a given chat.

        Returns:
            The maximum message_id, or ``None`` if the chat has never
            been synced.
        """
        return await self._pool.fetchval(
            "SELECT MAX(message_id) FROM messages WHERE chat_id = $1",
            chat_id,
        )

    # ------------------------------------------------------------------
    # Metadata operations
    # ------------------------------------------------------------------

    async def update_chat_metadata(
        self,
        chat_id: int,
        title: str,
        chat_type: str,
        participant_count: Optional[int] = None,
    ) -> None:
        """Upsert chat/dialog metadata."""
        await self._pool.execute(
            _UPSERT_CHAT_SQL,
            chat_id,
            title,
            chat_type,
            participant_count,
        )

    async def get_sync_stats(self) -> Dict[str, Any]:
        """Return summary statistics for monitoring."""
        async with self._pool.acquire() as conn:
            total_messages = await conn.fetchval("SELECT COUNT(*) FROM messages")
            total_chats = await conn.fetchval("SELECT COUNT(*) FROM chats")
            last_sync_time = await conn.fetchval(
                "SELECT MAX(timestamp) FROM messages"
            )
            oldest_message = await conn.fetchval(
                "SELECT MIN(timestamp) FROM messages"
            )

        return {
            "total_messages": total_messages or 0,
            "total_chats": total_chats or 0,
            "last_sync_time": last_sync_time.isoformat() if last_sync_time else None,
            "oldest_message": oldest_message.isoformat() if oldest_message else None,
        }
