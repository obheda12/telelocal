"""
PostgreSQL message storage for the syncer.

Uses ``asyncpg`` for async database access.  All queries use parameterized
placeholders ($1, $2, ...) — **never** string interpolation — to prevent
SQL injection.

The syncer's DB role (``syncer_role``) has INSERT and SELECT privileges,
plus optional UPDATE on the ``embedding`` column only (for deferred
embedding backfill). It cannot UPDATE message text/metadata or DELETE rows.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import asyncpg

logger = logging.getLogger("syncer.message_store")

_INSERT_SQL = """
    INSERT INTO messages (
        message_id, chat_id, sender_id, sender_name,
        reply_to_msg_id, thread_top_msg_id, is_topic_message,
        timestamp, text, raw_json, embedding
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
    ON CONFLICT (message_id, chat_id) DO NOTHING
"""

_UPSERT_CHAT_SQL = """
    INSERT INTO chats (chat_id, title, chat_type, participant_count, updated_at)
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (chat_id)
    DO UPDATE SET
        title = EXCLUDED.title,
        chat_type = EXCLUDED.chat_type,
        participant_count = EXCLUDED.participant_count,
        updated_at = NOW()
    WHERE
        chats.title IS DISTINCT FROM EXCLUDED.title
        OR chats.chat_type IS DISTINCT FROM EXCLUDED.chat_type
        OR chats.participant_count IS DISTINCT FROM EXCLUDED.participant_count
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
        self._batch_insert_sql_cache: Dict[int, str] = {}
        self._batch_insert_returning_sql_cache: Dict[int, str] = {}
        self._batch_update_embedding_sql_cache: Dict[int, str] = {}

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
            msg.get("reply_to_msg_id"),
            msg.get("thread_top_msg_id"),
            bool(msg.get("is_topic_message", False)),
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

        row_count = len(messages)
        sql = self._batch_insert_sql_cache.get(row_count)
        if sql is None:
            sql = self._build_batch_insert_sql(row_count, returning=False)
            self._batch_insert_sql_cache[row_count] = sql

        async with self._pool.acquire() as conn:
            params: List[Any] = []
            for msg in messages:
                row_params = self._msg_params(msg)
                params.extend(row_params)

            status = await conn.execute(sql, *params)

        # asyncpg command status format: "INSERT 0 <rowcount>"
        try:
            inserted = int(status.rsplit(" ", 1)[-1])
        except (ValueError, IndexError):
            logger.debug("Unexpected INSERT status string: %s", status)
            inserted = 0
        logger.debug("Batch insert: %d/%d new rows", inserted, len(messages))
        return inserted

    async def store_messages_batch_returning(
        self,
        messages: List[Dict[str, Any]],
    ) -> List[tuple[int, int, str]]:
        """Insert a batch and return newly inserted rows that have text.

        Returns:
            List of ``(message_id, chat_id, text)`` for rows actually inserted.
            This is used by deferred embedding mode to avoid embedding rows that
            already existed in the database.
        """
        if not messages:
            return []

        row_count = len(messages)
        sql = self._batch_insert_returning_sql_cache.get(row_count)
        if sql is None:
            sql = self._build_batch_insert_sql(row_count, returning=True)
            self._batch_insert_returning_sql_cache[row_count] = sql

        text_by_key: Dict[tuple[int, int], str] = {}
        params: List[Any] = []
        for msg in messages:
            row_params = self._msg_params(msg)
            params.extend(row_params)
            text = msg.get("text")
            if text:
                text_by_key[(int(msg["message_id"]), int(msg["chat_id"]))] = str(text)

        rows = await self._pool.fetch(sql, *params)
        inserted_with_text: List[tuple[int, int, str]] = []
        for row in rows:
            message_id = int(row["message_id"])
            chat_id = int(row["chat_id"])
            text = text_by_key.get((message_id, chat_id))
            if text:
                inserted_with_text.append((message_id, chat_id, text))

        logger.debug(
            "Batch insert returning: %d inserted, %d with text",
            len(rows),
            len(inserted_with_text),
        )
        return inserted_with_text

    def _build_batch_insert_sql(self, row_count: int, returning: bool) -> str:
        row_width = 11
        values_sql: List[str] = []
        for idx in range(row_count):
            base = idx * row_width
            placeholders = ", ".join(
                f"${base + i}" for i in range(1, row_width + 1)
            )
            values_sql.append(f"({placeholders})")
        sql = (
            "INSERT INTO messages ("
            "message_id, chat_id, sender_id, sender_name, "
            "reply_to_msg_id, thread_top_msg_id, is_topic_message, "
            "timestamp, text, raw_json, embedding"
            ") VALUES "
            + ", ".join(values_sql)
            + " ON CONFLICT (message_id, chat_id) DO NOTHING"
        )
        if returning:
            sql += " RETURNING message_id, chat_id"
        return sql

    async def update_embeddings_batch(
        self,
        rows: List[tuple[list[float], int, int]],
    ) -> int:
        """Backfill embeddings for existing rows.

        Args:
            rows: ``[(embedding, message_id, chat_id), ...]``.

        Returns:
            Number of rows updated.
        """
        if not rows:
            return 0

        row_count = len(rows)
        sql = self._batch_update_embedding_sql_cache.get(row_count)
        if sql is None:
            row_width = 3  # embedding, message_id, chat_id
            values_sql: List[str] = []
            for idx in range(row_count):
                base = idx * row_width
                placeholders = ", ".join(
                    f"${base + i}" for i in range(1, row_width + 1)
                )
                values_sql.append(f"({placeholders})")

            sql = (
                "UPDATE messages AS m SET embedding = v.embedding "
                "FROM (VALUES "
                + ", ".join(values_sql)
                + ") AS v(embedding, message_id, chat_id) "
                "WHERE m.message_id = v.message_id "
                "AND m.chat_id = v.chat_id "
                "AND m.embedding IS NULL"
            )
            self._batch_update_embedding_sql_cache[row_count] = sql

        params: List[Any] = []
        for embedding, message_id, chat_id in rows:
            params.extend((embedding, message_id, chat_id))

        status = await self._pool.execute(sql, *params)
        try:
            updated = int(status.rsplit(" ", 1)[-1])
        except (ValueError, IndexError):
            logger.debug("Unexpected UPDATE status string: %s", status)
            updated = 0
        return updated

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
            """
            SELECT message_id
            FROM messages
            WHERE chat_id = $1
            ORDER BY message_id DESC
            LIMIT 1
            """,
            chat_id,
        )

    async def get_last_synced_ids(self, chat_ids: List[int]) -> Dict[int, int]:
        """Return highest message_id for multiple chats in one query."""
        if not chat_ids:
            return {}
        rows = await self._pool.fetch(
            """
            SELECT DISTINCT ON (chat_id)
                   chat_id,
                   message_id AS last_message_id
            FROM messages
            WHERE chat_id = ANY($1::bigint[])
            ORDER BY chat_id, message_id DESC
            """,
            chat_ids,
        )
        return {
            int(row["chat_id"]): int(row["last_message_id"])
            for row in rows
            if row["last_message_id"] is not None
        }

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
