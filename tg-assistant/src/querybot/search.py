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
import re
import time
from collections import OrderedDict
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
    reply_to_msg_id: Optional[int] = None
    thread_top_msg_id: Optional[int] = None
    is_topic_message: bool = False


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
        *,
        hybrid_min_terms: int = 2,
        hybrid_min_term_length: int = 3,
    ) -> None:
        self._pool = pool
        self._embedder = embedding_provider
        self._hybrid_min_terms = max(1, hybrid_min_terms)
        self._hybrid_min_term_length = max(1, hybrid_min_term_length)
        # Chat list cache
        self._chat_cache: Optional[List[Dict[str, Any]]] = None
        self._chat_cache_time: float = 0.0
        # Query-embedding cache for repeated prompts.
        self._embedding_cache: "OrderedDict[str, List[float]]" = OrderedDict()
        self._embedding_cache_max = 256

    def _should_use_hybrid(self, search_terms: str) -> bool:
        """Use vector+FTS only for multi-term queries where it adds value."""
        tokens = [
            tok
            for tok in re.findall(r"[A-Za-z0-9_]+", search_terms.lower())
            if len(tok) >= self._hybrid_min_term_length
        ]
        return len(tokens) >= self._hybrid_min_terms

    async def _get_query_embedding(self, text: str) -> List[float]:
        key = " ".join(text.split()).strip().lower()
        if key in self._embedding_cache:
            emb = self._embedding_cache.pop(key)
            self._embedding_cache[key] = emb
            return emb

        emb = await self._embedder.generate_embedding(text)
        self._embedding_cache[key] = emb
        if len(self._embedding_cache) > self._embedding_cache_max:
            self._embedding_cache.popitem(last=False)
        return emb

    def _append_filter_conditions(
        self,
        params: List[Any],
        conditions: List[str],
        *,
        chat_ids: Optional[List[int]],
        sender_name: Optional[str],
        days_back: Optional[int],
        alias: str = "m",
    ) -> None:
        """Append dynamic filter clauses to *conditions* with bound params."""
        if chat_ids:
            params.append(chat_ids)
            conditions.append(f"{alias}.chat_id = ANY(${len(params)}::bigint[])")

        if sender_name:
            # Escape LIKE metacharacters to prevent pattern injection
            escaped = sender_name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
            conditions.append(f"{alias}.sender_name ILIKE ${len(params)} ESCAPE '\\\\'")

        if days_back is not None and days_back > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
            params.append(cutoff)
            conditions.append(f"{alias}.timestamp >= ${len(params)}")

    async def _filtered_hybrid_search(
        self,
        search_terms: str,
        chat_ids: Optional[List[int]],
        sender_name: Optional[str],
        days_back: Optional[int],
        limit: int,
        fts_weight: float = 0.4,
        vector_weight: float = 0.6,
    ) -> List[SearchResult]:
        """Single-query hybrid search (FTS + vector) with optional filters."""
        fetch_limit = max(limit * 2, limit)
        k = 60
        missing_rank = fetch_limit + 1

        try:
            query_embedding = await self._get_query_embedding(search_terms)
        except Exception:
            logger.warning("Embedding generation failed; falling back to filtered FTS", exc_info=True)
            return await self._filtered_fts_search(
                search_terms=search_terms,
                chat_ids=chat_ids,
                sender_name=sender_name,
                days_back=days_back,
                limit=limit,
            )

        params: List[Any] = [search_terms, str(query_embedding)]
        conditions: List[str] = []
        self._append_filter_conditions(
            params,
            conditions,
            chat_ids=chat_ids,
            sender_name=sender_name,
            days_back=days_back,
            alias="m",
        )
        where_filters = " AND ".join(conditions) if conditions else "TRUE"

        params.append(fetch_limit)
        fts_limit_idx = len(params)
        params.append(fetch_limit)
        vec_limit_idx = len(params)
        params.append(fts_weight)
        fts_weight_idx = len(params)
        params.append(vector_weight)
        vec_weight_idx = len(params)
        params.append(k)
        k_idx = len(params)
        params.append(missing_rank)
        missing_rank_idx = len(params)
        params.append(limit)
        limit_idx = len(params)

        sql = f"""
            WITH q AS (
                SELECT plainto_tsquery('english', $1) AS query_en,
                       plainto_tsquery('simple', $1) AS query_simple
            ),
            fts AS (
                SELECT m.message_id, m.chat_id,
                       ROW_NUMBER() OVER (
                           ORDER BY GREATEST(
                               ts_rank(m.text_search_vector, q.query_en),
                               ts_rank(m.text_search_vector_simple, q.query_simple)
                           ) DESC
                       ) AS fts_rank
                FROM messages m
                CROSS JOIN q
                WHERE (
                    m.text_search_vector @@ q.query_en
                    OR m.text_search_vector_simple @@ q.query_simple
                )
                  AND {where_filters}
                ORDER BY GREATEST(
                    ts_rank(m.text_search_vector, q.query_en),
                    ts_rank(m.text_search_vector_simple, q.query_simple)
                ) DESC
                LIMIT ${fts_limit_idx}
            ),
            vec AS (
                SELECT m.message_id, m.chat_id,
                       ROW_NUMBER() OVER (ORDER BY m.embedding <=> $2::vector) AS vec_rank
                FROM messages m
                WHERE m.embedding IS NOT NULL
                  AND {where_filters}
                ORDER BY m.embedding <=> $2::vector
                LIMIT ${vec_limit_idx}
            ),
            candidates AS (
                SELECT message_id, chat_id FROM fts
                UNION
                SELECT message_id, chat_id FROM vec
            )
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.reply_to_msg_id, m.thread_top_msg_id, m.is_topic_message,
                   m.timestamp, m.text,
                   (
                       ${fts_weight_idx}::float8
                       / (${k_idx} + COALESCE(fts.fts_rank, ${missing_rank_idx}))
                   ) + (
                       ${vec_weight_idx}::float8
                       / (${k_idx} + COALESCE(vec.vec_rank, ${missing_rank_idx}))
                   ) AS score
            FROM candidates k
            JOIN messages m ON m.message_id = k.message_id AND m.chat_id = k.chat_id
            JOIN chats c ON c.chat_id = m.chat_id
            LEFT JOIN fts ON fts.message_id = k.message_id AND fts.chat_id = k.chat_id
            LEFT JOIN vec ON vec.message_id = k.message_id AND vec.chat_id = k.chat_id
            ORDER BY score DESC
            LIMIT ${limit_idx}
        """

        rows = await self._pool.fetch(sql, *params)
        return self._rows_to_results(rows)

    async def _filtered_fts_search(
        self,
        search_terms: str,
        chat_ids: Optional[List[int]],
        sender_name: Optional[str],
        days_back: Optional[int],
        limit: int,
    ) -> List[SearchResult]:
        """Filtered FTS-only search (used for fallback or no embeddings)."""
        params: List[Any] = [search_terms]
        fts_idx = len(params)
        conditions: List[str] = [
            "("
            f"m.text_search_vector @@ plainto_tsquery('english', ${fts_idx}) "
            "OR "
            f"m.text_search_vector_simple @@ plainto_tsquery('simple', ${fts_idx})"
            ")"
        ]
        self._append_filter_conditions(
            params,
            conditions,
            chat_ids=chat_ids,
            sender_name=sender_name,
            days_back=days_back,
            alias="m",
        )

        where_clause = " AND ".join(conditions)
        score_expr = (
            "GREATEST("
            f"ts_rank(m.text_search_vector, plainto_tsquery('english', ${fts_idx})), "
            f"ts_rank(m.text_search_vector_simple, plainto_tsquery('simple', ${fts_idx}))"
            ")"
        )

        params.append(limit)
        limit_idx = len(params)
        sql = f"""
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.reply_to_msg_id, m.thread_top_msg_id, m.is_topic_message,
                   m.timestamp, m.text,
                   {score_expr} AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id
            WHERE {where_clause}
            ORDER BY score DESC
            LIMIT ${limit_idx}
        """
        rows = await self._pool.fetch(sql, *params)
        return self._rows_to_results(rows)

    # ------------------------------------------------------------------
    # Chat list (cached for intent extraction context)
    # ------------------------------------------------------------------

    async def get_chat_list(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return synced chats with metadata. Cached for 5 minutes."""
        now = time.monotonic()
        if self._chat_cache is not None and (now - self._chat_cache_time) < _CHAT_CACHE_TTL:
            return self._chat_cache[:limit] if limit and limit > 0 else self._chat_cache

        rows = await self._pool.fetch(
            "SELECT chat_id, title, chat_type FROM chats ORDER BY updated_at DESC NULLS LAST, title"
        )
        self._chat_cache = [dict(r) for r in rows]
        self._chat_cache_time = time.monotonic()
        return self._chat_cache[:limit] if limit and limit > 0 else self._chat_cache

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
        has_fts = bool(search_terms and search_terms.strip())

        # Fast path for semantic relevance with a single DB roundtrip.
        if (
            has_fts
            and self._embedder.dimension
            and self._should_use_hybrid(search_terms or "")
        ):
            return await self._filtered_hybrid_search(
                search_terms=search_terms or "",
                chat_ids=chat_ids,
                sender_name=sender_name,
                days_back=days_back,
                limit=limit,
            )

        if has_fts:
            return await self._filtered_fts_search(
                search_terms=search_terms or "",
                chat_ids=chat_ids,
                sender_name=sender_name,
                days_back=days_back,
                limit=limit,
            )

        params: list = []
        conditions: list = []
        self._append_filter_conditions(
            params,
            conditions,
            chat_ids=chat_ids,
            sender_name=sender_name,
            days_back=days_back,
            alias="m",
        )

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        score_expr = "1.0"
        order_expr = "m.timestamp DESC"

        params.append(limit)
        limit_idx = len(params)

        sql = f"""
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.reply_to_msg_id, m.thread_top_msg_id, m.is_topic_message,
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

    async def recent_chat_summary_context(
        self,
        *,
        chat_limit: int = 20,
        per_chat_messages: int = 2,
        days_back: Optional[int] = 30,
    ) -> List[SearchResult]:
        """Return recent messages grouped from the freshest chats.

        This powers "summarize freshest chats" style requests where breadth
        across chats is more important than per-message relevance ranking.
        """
        chat_limit = max(1, int(chat_limit))
        per_chat_messages = max(1, int(per_chat_messages))

        params: List[Any] = [chat_limit, per_chat_messages]
        freshness_condition = ""
        message_condition = ""
        if days_back is not None and days_back > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
            params.append(cutoff)
            cutoff_idx = len(params)
            freshness_condition = f"AND m.timestamp >= ${cutoff_idx}"
            message_condition = f"AND m.timestamp >= ${cutoff_idx}"

        sql = f"""
            WITH freshest AS (
                SELECT m.chat_id, MAX(m.timestamp) AS last_ts
                FROM messages m
                WHERE TRUE {freshness_condition}
                GROUP BY m.chat_id
                ORDER BY last_ts DESC
                LIMIT $1
            ),
            ranked AS (
                SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                       m.reply_to_msg_id, m.thread_top_msg_id, m.is_topic_message,
                       m.timestamp, m.text, f.last_ts,
                       ROW_NUMBER() OVER (
                           PARTITION BY m.chat_id
                           ORDER BY m.timestamp DESC, m.message_id DESC
                       ) AS rn
                FROM messages m
                JOIN freshest f ON f.chat_id = m.chat_id
                JOIN chats c ON c.chat_id = m.chat_id
                WHERE TRUE {message_condition}
            )
            SELECT message_id, chat_id, title, sender_name,
                   reply_to_msg_id, thread_top_msg_id, is_topic_message,
                   timestamp, text,
                   1.0 AS score
            FROM ranked
            WHERE rn <= $2
            ORDER BY last_ts DESC, timestamp DESC
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
                   m.reply_to_msg_id, m.thread_top_msg_id, m.is_topic_message,
                   m.timestamp, m.text,
                   GREATEST(
                       ts_rank(m.text_search_vector, query),
                       ts_rank(m.text_search_vector_simple, query_simple)
                   ) AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id,
                 plainto_tsquery('english', $1) query,
                 plainto_tsquery('simple', $1) query_simple
            WHERE m.text_search_vector @@ query
               OR m.text_search_vector_simple @@ query_simple
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
        if not self._embedder.dimension:
            return []

        query_embedding = await self._get_query_embedding(query)

        rows = await self._pool.fetch(
            """
            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.reply_to_msg_id, m.thread_top_msg_id, m.is_topic_message,
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
                reply_to_msg_id=row["reply_to_msg_id"],
                thread_top_msg_id=row["thread_top_msg_id"],
                is_topic_message=bool(row["is_topic_message"]),
            )
            for row in rows
        ]
