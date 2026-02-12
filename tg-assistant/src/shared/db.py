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


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Per-connection initialisation callback for the pool.

    Registers the pgvector type so asyncpg can handle vector columns.
    """
    from pgvector.asyncpg import register_vector

    await register_vector(conn)


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------


async def get_connection_pool(config: Dict[str, Any]) -> asyncpg.Pool:
    """Create and return an ``asyncpg`` connection pool.

    Args:
        config: Database configuration dict with keys:
                ``host``, ``port``, ``database``, ``user``, ``password``,
                and optionally ``min_size``, ``max_size``, or ``url``.

    Returns:
        An ``asyncpg.Pool`` instance.

    Raises:
        asyncpg.PostgresError: If the connection cannot be established.
    """
    if "url" in config:
        pool = await asyncpg.create_pool(
            dsn=config["url"],
            min_size=config.get("min_size", 2),
            max_size=config.get("max_size", config.get("pool_size", 10)),
            init=_init_connection,
        )
    else:
        pool = await asyncpg.create_pool(
            host=config.get("host", "localhost"),
            port=config.get("port", 5432),
            database=config["database"],
            user=config["user"],
            password=config.get("password"),
            min_size=config.get("min_size", 2),
            max_size=config.get("max_size", config.get("pool_size", 10)),
            init=_init_connection,
        )
    logger.info(
        "Database pool created (min=%d, max=%d)",
        config.get("min_size", 2),
        config.get("max_size", config.get("pool_size", 10)),
    )
    return pool


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

    Extensions:
        - ``pgvector``: for embedding storage and cosine similarity.

    Security note:
        This function should be run by a privileged role (e.g. postgres
        or a migration role), NOT by syncer_role or querybot_role.
        When called by an unprivileged role, it logs a debug message
        and returns — the tables must already exist from setup.
    """
    async with pool.acquire() as conn:
        try:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    message_id         BIGINT NOT NULL,
                    chat_id            BIGINT NOT NULL,
                    sender_id          BIGINT,
                    sender_name        TEXT,
                    timestamp          TIMESTAMPTZ NOT NULL,
                    text               TEXT,
                    raw_json           JSONB,
                    embedding          vector(1024),
                    text_search_vector TSVECTOR
                        GENERATED ALWAYS AS (
                            to_tsvector('english', COALESCE(text, ''))
                        ) STORED,
                    PRIMARY KEY (message_id, chat_id)
                );
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS chats (
                    chat_id           BIGINT PRIMARY KEY,
                    title             TEXT,
                    chat_type         TEXT,
                    participant_count INTEGER,
                    updated_at        TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id        BIGSERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ DEFAULT NOW(),
                    service   TEXT NOT NULL,
                    action    TEXT NOT NULL,
                    details   JSONB,
                    success   BOOLEAN NOT NULL
                );
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_fts
                ON messages USING GIN (text_search_vector);
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_embedding
                ON messages USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
            """)
        except asyncpg.exceptions.InsufficientPrivilegeError:
            logger.debug(
                "Skipping schema init (unprivileged role) — "
                "tables must already exist from setup"
            )

        # Indexes for filtered search (chat + time, time-only)
        # Note: idx_messages_chat_timestamp covers chat_id-only queries too
        # (chat_id is the leading column), so a standalone chat_id index
        # is not needed.
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_chat_timestamp
            ON messages (chat_id, timestamp DESC);
        """)

        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp
            ON messages (timestamp DESC);
        """)

    logger.info("Database schema initialised.")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


async def health_check(pool: asyncpg.Pool) -> bool:
    """Verify the database is reachable and responsive.

    Returns:
        ``True`` if a simple query succeeds, ``False`` otherwise.
    """
    try:
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT 1;")
            return result == 1
    except Exception:
        logger.exception("Database health check failed")
        return False
