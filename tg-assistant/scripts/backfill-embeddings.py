#!/usr/bin/env python3
"""
Backfill missing embeddings for existing messages.

Usage:
  /opt/tg-assistant/venv/bin/python3 /opt/tg-assistant/scripts/backfill-embeddings.py
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import toml
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.db import get_connection_pool
from syncer.embeddings import create_embedding_provider
from syncer.message_store import MessageStore

logger = logging.getLogger("backfill.embeddings")

_DEFAULT_CONFIG_PATH = Path(os.environ.get("TG_ASSISTANT_CONFIG", "/etc/tg-assistant/settings.toml"))


def load_config(path: Path = _DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    return toml.load(path)


async def fetch_missing(
    pool, limit: int
) -> List[Tuple[int, int, str]]:
    rows = await pool.fetch(
        """
        SELECT message_id, chat_id, text
        FROM messages
        WHERE embedding IS NULL AND text IS NOT NULL AND text != ''
        ORDER BY timestamp DESC
        LIMIT $1
        """,
        limit,
    )
    return [(r["message_id"], r["chat_id"], r["text"]) for r in rows]


async def backfill(batch_size: int = 200) -> None:
    config = load_config()
    db_config = dict(config["database"])
    db_config["user"] = os.environ.get("TG_ASSISTANT_DB_USER") or "postgres"
    pool = await get_connection_pool(db_config)

    try:
        can_update = await pool.fetchval(
            "SELECT has_table_privilege(current_user, 'messages', 'UPDATE')"
        )
        if not can_update:
            raise PermissionError(
                "Current DB role cannot UPDATE messages. "
                "Re-run with TG_ASSISTANT_DB_USER=postgres or a migration role."
            )

        embedder = create_embedding_provider(config.get("embeddings", {}))
        expected_dim = embedder.dimension
        store = MessageStore(pool, embedding_dim=expected_dim)

        total = 0

        while True:
            rows = await fetch_missing(pool, batch_size)
            if not rows:
                break

            texts = [r[2] for r in rows]
            try:
                embeddings = await embedder.batch_generate(texts)
            except Exception:
                logger.exception("Embedding batch failed; aborting")
                break

            updates: list[tuple[list[float], int, int]] = []
            for (message_id, chat_id, _), embedding in zip(rows, embeddings):
                if expected_dim and len(embedding) != expected_dim:
                    raise ValueError(
                        f"Embedding dimension mismatch: got={len(embedding)} expected={expected_dim}"
                    )
                updates.append((embedding, message_id, chat_id))

            updated = await store.update_embeddings_batch(updates)

            total += updated
            logger.info("Backfilled %d embeddings", total)

        logger.info("Backfill complete. Total updated: %d", total)
    finally:
        await pool.close()


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    asyncio.run(backfill())


if __name__ == "__main__":
    run()
