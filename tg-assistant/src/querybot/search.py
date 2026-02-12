"""
Hybrid search module — combines PostgreSQL full-text search (BM25-like
ranking via ``ts_rank``) with pgvector cosine-similarity search.

Supports filtered search by chat, sender, and time range via
``QueryIntent`` — extracted from the user's natural-language question
by the LLM layer before search is invoked.

The query bot's DB role (``querybot_role``) has SELECT-only access to the
``messages`` and ``chats`` tables.  All queries use parameterized
placeholders to prevent SQL injection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg

from syncer.embeddings import EmbeddingProvider

logger = logging.getLogger("querybot.search")

# Cache TTL for chat list (seconds) — chats don't change often
_CHAT_CACHE_TTL = 300


@dataclass
class SearchResult:
    """A single search result with metadata and relevance score."""

    message_id: int
    chat_id: int
    chat_title: str
    sender_name: str
    timestamp: str
    text: str
    score: float


@dataclass
class QueryIntent:
    """Structured search parameters extracted from a user's question."""

    search_terms: Optional[str] = None
    chat_ids: Optional[List[int]] = None
    sender_name: Optional[str] = None
    days_back: Optional[int] = None


class MessageSearch:
    """Hybrid search over the synced message corpus.

    Args:
        pool: ``asyncpg`` connection pool (querybot_role, SELECT only).
        embedding_provider: An :class:`EmbeddingProvider` for vector search.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        embedding_provider: EmbeddingProvider,
    ) -> None:
        self._pool = pool
        self._embedder = embedding_provider
        # Chat list cache
        self._chat_cache: Optional[List[Dict[str, Any]]] = None
        self._chat_cache_time: float = 0.0

    # ------------------------------------------------------------------
    # Chat list (cached for intent extraction context)
    # ------------------------------------------------------------------

    async def get_chat_list(self) -> List[Dict[str, Any]]:
        """Return all synced chats with metadata. Cached for 5 minutes."""
        now = time.monotonic()
        if self._chat_cache is not None and (now - self._chat_cache_time) < _CHAT_CACHE_TTL:
            return self._chat_cache

        rows = await self._pool.fetch(
            "SELECT chat_id, title, chat_type FROM chats ORDER BY title"
        )
        self._chat_cache = [dict(r) for r in rows]
        self._chat_cache_time = time.monotonic()
        return self._chat_cache

    # ------------------------------------------------------------------
    # Filtered search (intent-driven)
    # ------------------------------------------------------------------

    async def filtered_search(
        self,
        search_terms: Optional[str] = None,
        chat_ids: Optional[List[int]] = None,
        sender_name: Optional[str] = None,
        days_back: Optional[int] = None,
        limit: int = 20,
    ) -> List[SearchResult]:
        """Search messages with optional filters for chat, sender, and time.

        Builds a dynamic WHERE clause using parameterized placeholders.
        If ``search_terms`` is provided, results are ranked by FTS relevance.
        Otherwise, results are ordered by timestamp (most recent first).
        """
        params: list = []
        conditions: list = []
        has_fts = bool(search_terms and search_terms.strip())

        if has_fts:
            params.append(search_terms)
            fts_idx = len(params)
            conditions.append(
                f"m.text_search_vector @@ plainto_tsquery('english', ${fts_idx})"
            )

        if chat_ids:
            params.append(chat_ids)
            conditions.append(f"m.chat_id = ANY(${len(params)}::bigint[])")

        if sender_name:
            # Escape LIKE metacharacters to prevent pattern injection
            escaped = sender_name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
            conditions.append(f"m.sender_name ILIKE ${len(params)}")

        if days_back is not None and days_back > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
            params.append(cutoff)
            conditions.append(f"m.timestamp >= ${len(params)}")

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        # FTS results ranked by relevance; browse results by recency
        if has_fts:
            score_expr = (
                f"ts_rank(m.text_search_vector, "
                f"plainto_tsquery('english', ${fts_idx}))"
            )
            order_expr = "score DESC"
        else:
            score_expr = "1.0"
            order_expr = "m.timestamp DESC"

        params.append(limit)
        limit_idx = len(params)

        sql = f"""
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.timestamp, m.text,
                   {score_expr} AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id
            WHERE {where_clause}
            ORDER BY {order_expr}
            LIMIT ${limit_idx}
        """

        rows = await self._pool.fetch(sql, *params)
        return self._rows_to_results(rows)

    # ------------------------------------------------------------------
    # Full-text search (PostgreSQL tsvector / tsquery)
    # ------------------------------------------------------------------

    async def full_text_search(
        self,
        query: str,
        limit: int = 20,
    ) -> List[SearchResult]:
        """Search messages using PostgreSQL full-text search.

        Uses ``plainto_tsquery`` for safe query parsing (no raw tsquery
        syntax from user input — prevents injection via crafted operators).
        """
        rows = await self._pool.fetch(
            """
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.timestamp, m.text,
                   ts_rank(m.text_search_vector, query) AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id,
                 plainto_tsquery('english', $1) query
            WHERE m.text_search_vector @@ query
            ORDER BY score DESC
            LIMIT $2
            """,
            query,
            limit,
        )
        return self._rows_to_results(rows)

    # ------------------------------------------------------------------
    # Vector search (pgvector cosine similarity)
    # ------------------------------------------------------------------

    async def vector_search(
        self,
        query: str,
        limit: int = 20,
    ) -> List[SearchResult]:
        """Search messages using pgvector cosine similarity."""
        # Skip vector search if embedder doesn't produce 1024-dim vectors
        if self._embedder.dimension != 1024:
            return []

        query_embedding = await self._embedder.generate_embedding(query)

        rows = await self._pool.fetch(
            """
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.timestamp, m.text,
                   1 - (m.embedding <=> $1::vector) AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id
            WHERE m.embedding IS NOT NULL
            ORDER BY m.embedding <=> $1::vector
            LIMIT $2
            """,
            str(query_embedding),
            limit,
        )
        return self._rows_to_results(rows)

    # ------------------------------------------------------------------
    # Hybrid search (Reciprocal Rank Fusion)
    # ------------------------------------------------------------------

    async def hybrid_search(
        self,
        query: str,
        limit: int = 10,
        fts_weight: float = 0.4,
        vector_weight: float = 0.6,
    ) -> List[SearchResult]:
        """Combine full-text and vector search using Reciprocal Rank Fusion.

        RRF score for each document::

            score = fts_weight / (k + fts_rank) + vector_weight / (k + vec_rank)

        where ``k`` is a constant (typically 60).
        """
        k = 60
        fetch_limit = limit * 2

        fts_results, vec_results = await asyncio.gather(
            self.full_text_search(query, fetch_limit),
            self.vector_search(query, fetch_limit),
        )

        # If only one source has results, return those directly
        if not fts_results and not vec_results:
            return []
        if not vec_results:
            return fts_results[:limit]
        if not fts_results:
            return vec_results[:limit]

        # Build rank maps (1-indexed)
        fts_ranks: Dict[Tuple[int, int], int] = {}
        fts_map: Dict[Tuple[int, int], SearchResult] = {}
        for rank, r in enumerate(fts_results, 1):
            key = (r.message_id, r.chat_id)
            fts_ranks[key] = rank
            fts_map[key] = r

        vec_ranks: Dict[Tuple[int, int], int] = {}
        vec_map: Dict[Tuple[int, int], SearchResult] = {}
        for rank, r in enumerate(vec_results, 1):
            key = (r.message_id, r.chat_id)
            vec_ranks[key] = rank
            vec_map[key] = r

        # Merge all unique keys
        all_keys = set(fts_ranks.keys()) | set(vec_ranks.keys())
        missing_rank = fetch_limit + 1

        scored: List[Tuple[float, Tuple[int, int]]] = []
        for key in all_keys:
            fts_r = fts_ranks.get(key, missing_rank)
            vec_r = vec_ranks.get(key, missing_rank)
            rrf_score = fts_weight / (k + fts_r) + vector_weight / (k + vec_r)
            scored.append((rrf_score, key))

        scored.sort(key=lambda x: x[0], reverse=True)

        results = []
        for rrf_score, key in scored[:limit]:
            result = fts_map.get(key) or vec_map[key]
            result.score = rrf_score
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rows_to_results(rows: list) -> List[SearchResult]:
        """Convert asyncpg rows to SearchResult objects."""
        return [
            SearchResult(
                message_id=row["message_id"],
                chat_id=row["chat_id"],
                chat_title=row["title"] or "",
                sender_name=row["sender_name"] or "",
                timestamp=row["timestamp"].isoformat() if row["timestamp"] else "",
                text=row["text"] or "",
                score=float(row["score"]),
            )
            for row in rows
        ]
