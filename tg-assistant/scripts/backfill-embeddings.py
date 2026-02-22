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
    db_config["user"] = os.environ.get("TG_ASSISTANT_DB_USER") or config["syncer"].get("db_user", "tg_syncer")
    pool = await get_connection_pool(db_config)

    embedder = create_embedding_provider(config.get("embeddings", {}))
    store = MessageStore(pool, embedding_dim=embedder.dimension)

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

        for (message_id, chat_id, _), embedding in zip(rows, embeddings):
            if store._embedding_dim and len(embedding) != store._embedding_dim:
                raise ValueError(
                    f"Embedding dimension mismatch: got={len(embedding)} expected={store._embedding_dim}"
                )
            await pool.execute(
                "UPDATE messages SET embedding = $1 WHERE message_id = $2 AND chat_id = $3",
                embedding,
                message_id,
                chat_id,
            )

        total += len(rows)
        logger.info("Backfilled %d embeddings", total)

    await pool.close()
    logger.info("Backfill complete. Total updated: %d", total)


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    asyncio.run(backfill())


if __name__ == "__main__":
    run()
