"""
Database helpers — connection pool management, schema initialisation,
and health checks.

Uses ``asyncpg`` for async PostgreSQL access.  The database has two roles:

- **syncer_role**: INSERT + SELECT on ``messages`` and ``chats``.
- **querybot_role**: SELECT only on ``messages`` and ``chats``.

This separation ensures the query bot can never modify synced data,
even if compromised.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

import asyncpg

logger = logging.getLogger("shared.db")


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------


async def get_connection_pool(config: Dict[str, Any]) -> asyncpg.Pool:
    """Create and return an ``asyncpg`` connection pool.

    Args:
        config: Database configuration dict with keys:
                ``host``, ``port``, ``database``, ``user``, ``password``,
                and optionally ``min_size``, ``max_size``.

    Returns:
        An ``asyncpg.Pool`` instance.

    Raises:
        asyncpg.PostgresError: If the connection cannot be established.
    """
    # TODO: implement
    #   pool = await asyncpg.create_pool(
    #       host=config["host"],
    #       port=config.get("port", 5432),
    #       database=config["database"],
    #       user=config["user"],
    #       password=config["password"],
    #       min_size=config.get("min_size", 2),
    #       max_size=config.get("max_size", 10),
    #   )
    #   logger.info("Database pool created: %s@%s/%s",
    #               config["user"], config["host"], config["database"])
    #   return pool
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


async def init_database(pool: asyncpg.Pool) -> None:
    """Create tables and extensions if they do not exist.

    Executed once at service startup.  Idempotent (uses IF NOT EXISTS).

    Tables:
        - ``messages``: synced Telegram messages with text, metadata,
          tsvector column, and pgvector embedding column.
        - ``chats``: chat/dialog metadata.
        - ``audit_log``: structured audit events.
        - ``sync_state``: per-chat sync cursor (last_synced_id).

    Extensions:
        - ``pgvector``: for embedding storage and cosine similarity.

    Security note:
        This function should be run by a privileged role (e.g. postgres
        or a migration role), NOT by syncer_role or querybot_role.
    """
    # TODO: implement
    #   async with pool.acquire() as conn:
    #       await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    #       await conn.execute("""
    #           CREATE TABLE IF NOT EXISTS messages (
    #               message_id    BIGINT NOT NULL,
    #               chat_id       BIGINT NOT NULL,
    #               sender_id     BIGINT,
    #               sender_name   TEXT,
    #               timestamp     TIMESTAMPTZ NOT NULL,
    #               text          TEXT,
    #               raw_json      JSONB,
    #               embedding     vector(1024),
    #               text_search_vector TSVECTOR
    #                   GENERATED ALWAYS AS (to_tsvector('english', COALESCE(text, ''))) STORED,
    #               PRIMARY KEY (message_id, chat_id)
    #           );
    #       """)
    #       await conn.execute("""
    #           CREATE TABLE IF NOT EXISTS chats (
    #               chat_id           BIGINT PRIMARY KEY,
    #               title             TEXT,
    #               chat_type         TEXT,
    #               participant_count INTEGER,
    #               updated_at        TIMESTAMPTZ DEFAULT NOW()
    #           );
    #       """)
    #       await conn.execute("""
    #           CREATE TABLE IF NOT EXISTS audit_log (
    #               id        BIGSERIAL PRIMARY KEY,
    #               timestamp TIMESTAMPTZ DEFAULT NOW(),
    #               service   TEXT NOT NULL,
    #               action    TEXT NOT NULL,
    #               details   JSONB,
    #               success   BOOLEAN NOT NULL
    #           );
    #       """)
    #       -- Indexes:
    #       await conn.execute("""
    #           CREATE INDEX IF NOT EXISTS idx_messages_fts
    #           ON messages USING GIN (text_search_vector);
    #       """)
    #       await conn.execute("""
    #           CREATE INDEX IF NOT EXISTS idx_messages_embedding
    #           ON messages USING ivfflat (embedding vector_cosine_ops)
    #           WITH (lists = 100);
    #       """)
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


async def health_check(pool: asyncpg.Pool) -> bool:
    """Verify the database is reachable and responsive.

    Returns:
        ``True`` if a simple query succeeds, ``False`` otherwise.
    """
    # TODO: implement
    #   try:
    #       async with pool.acquire() as conn:
    #           result = await conn.fetchval("SELECT 1;")
    #           return result == 1
    #   except Exception:
    #       logger.exception("Database health check failed")
    #       return False
    raise NotImplementedError
