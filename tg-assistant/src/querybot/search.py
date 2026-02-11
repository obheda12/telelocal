"""
Hybrid search module — combines PostgreSQL full-text search (BM25-like
ranking via ``ts_rank``) with pgvector cosine-similarity search.

The query bot's DB role (``querybot_role``) has SELECT-only access to the
``messages`` and ``chats`` tables.  All queries use parameterized
placeholders to prevent SQL injection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

import asyncpg

from syncer.embeddings import EmbeddingProvider

logger = logging.getLogger("querybot.search")


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

        SQL sketch::

            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.timestamp, m.text,
                   ts_rank(m.text_search_vector, query) AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id,
                 plainto_tsquery('english', $1) query
            WHERE m.text_search_vector @@ query
            ORDER BY score DESC
            LIMIT $2;

        Args:
            query: User's natural-language search query.
            limit: Maximum results to return.

        Returns:
            List of :class:`SearchResult` ordered by relevance.
        """
        # TODO: implement
        #   - Use self._pool.fetch() with parameterized query
        #   - Convert rows to SearchResult dataclass instances
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Vector search (pgvector cosine similarity)
    # ------------------------------------------------------------------

    async def vector_search(
        self,
        query: str,
        limit: int = 20,
    ) -> List[SearchResult]:
        """Search messages using pgvector cosine similarity.

        Steps:
            1. Generate an embedding for the query text.
            2. Find the closest stored message embeddings.

        SQL sketch::

            SELECT m.message_id, m.chat_id, c.title, m.sender_name,
                   m.timestamp, m.text,
                   1 - (m.embedding <=> $1::vector) AS score
            FROM messages m
            JOIN chats c ON c.chat_id = m.chat_id
            WHERE m.embedding IS NOT NULL
            ORDER BY m.embedding <=> $1::vector
            LIMIT $2;

        Args:
            query: User's natural-language search query.
            limit: Maximum results to return.

        Returns:
            List of :class:`SearchResult` ordered by cosine similarity.
        """
        # TODO: implement
        #   1. query_embedding = await self._embedder.generate_embedding(query)
        #   2. Execute parameterized pgvector query
        #   3. Convert rows to SearchResult
        raise NotImplementedError

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

        Args:
            query: User's natural-language search query.
            limit: Maximum results to return.
            fts_weight: Weight for full-text search ranking.
            vector_weight: Weight for vector search ranking.

        Returns:
            De-duplicated list of :class:`SearchResult` ordered by
            combined RRF score.
        """
        # TODO: implement
        #   1. Run full_text_search and vector_search in parallel
        #      (asyncio.gather)
        #   2. Assign rank positions to each result set
        #   3. Merge by message_id, compute RRF score
        #   4. Sort by combined score descending
        #   5. Return top `limit` results
        raise NotImplementedError
