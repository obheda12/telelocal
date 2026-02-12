"""
Unit tests for querybot search: RRF merge logic, edge cases.

These tests exercise the pure-Python merge logic without needing a database.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from querybot.search import MessageSearch, SearchResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(msg_id: int, chat_id: int = 1, score: float = 0.5) -> SearchResult:
    return SearchResult(
        message_id=msg_id,
        chat_id=chat_id,
        chat_title="TestChat",
        sender_name="Alice",
        timestamp="2024-01-15T10:00:00Z",
        text=f"Message {msg_id}",
        score=score,
    )


# ---------------------------------------------------------------------------
# RRF merge logic
# ---------------------------------------------------------------------------


class TestHybridSearchRRF:
    @pytest.mark.asyncio
    async def test_both_sources_with_overlap(self):
        """Results appearing in both FTS and vector should get higher RRF scores."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 1024

        search = MessageSearch(mock_pool, mock_embedder)

        fts_results = [_make_result(1, score=0.9), _make_result(2, score=0.8)]
        vec_results = [_make_result(2, score=0.95), _make_result(3, score=0.85)]

        with patch.object(search, "full_text_search", new_callable=AsyncMock) as mock_fts, \
             patch.object(search, "vector_search", new_callable=AsyncMock) as mock_vec:
            mock_fts.return_value = fts_results
            mock_vec.return_value = vec_results

            results = await search.hybrid_search("test query", limit=10)

        # Message 2 appears in both lists, should rank highest
        assert results[0].message_id == 2

    @pytest.mark.asyncio
    async def test_empty_results(self):
        """Should return empty list when both sources return nothing."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 1024

        search = MessageSearch(mock_pool, mock_embedder)

        with patch.object(search, "full_text_search", new_callable=AsyncMock) as mock_fts, \
             patch.object(search, "vector_search", new_callable=AsyncMock) as mock_vec:
            mock_fts.return_value = []
            mock_vec.return_value = []

            results = await search.hybrid_search("test query")

        assert results == []

    @pytest.mark.asyncio
    async def test_fts_only(self):
        """When vector search returns empty, should return FTS results."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384  # < 1024, vector search skipped

        search = MessageSearch(mock_pool, mock_embedder)

        fts_results = [_make_result(1), _make_result(2)]

        with patch.object(search, "full_text_search", new_callable=AsyncMock) as mock_fts, \
             patch.object(search, "vector_search", new_callable=AsyncMock) as mock_vec:
            mock_fts.return_value = fts_results
            mock_vec.return_value = []

            results = await search.hybrid_search("test query", limit=5)

        assert len(results) == 2
        assert results[0].message_id == 1

    @pytest.mark.asyncio
    async def test_vector_only(self):
        """When FTS returns empty, should return vector results."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 1024

        search = MessageSearch(mock_pool, mock_embedder)

        vec_results = [_make_result(5), _make_result(6)]

        with patch.object(search, "full_text_search", new_callable=AsyncMock) as mock_fts, \
             patch.object(search, "vector_search", new_callable=AsyncMock) as mock_vec:
            mock_fts.return_value = []
            mock_vec.return_value = vec_results

            results = await search.hybrid_search("test query", limit=5)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_limit_respected(self):
        """Should return at most `limit` results."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 1024

        search = MessageSearch(mock_pool, mock_embedder)

        fts_results = [_make_result(i) for i in range(10)]
        vec_results = [_make_result(i + 10) for i in range(10)]

        with patch.object(search, "full_text_search", new_callable=AsyncMock) as mock_fts, \
             patch.object(search, "vector_search", new_callable=AsyncMock) as mock_vec:
            mock_fts.return_value = fts_results
            mock_vec.return_value = vec_results

            results = await search.hybrid_search("test query", limit=3)

        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_no_duplicates(self):
        """Should not return duplicate results."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 1024

        search = MessageSearch(mock_pool, mock_embedder)

        # Same results in both lists
        fts_results = [_make_result(1), _make_result(2)]
        vec_results = [_make_result(1), _make_result(2)]

        with patch.object(search, "full_text_search", new_callable=AsyncMock) as mock_fts, \
             patch.object(search, "vector_search", new_callable=AsyncMock) as mock_vec:
            mock_fts.return_value = fts_results
            mock_vec.return_value = vec_results

            results = await search.hybrid_search("test query", limit=10)

        msg_ids = [(r.message_id, r.chat_id) for r in results]
        assert len(msg_ids) == len(set(msg_ids)), "Should not have duplicates"


class TestVectorSearchDimensionCheck:
    @pytest.mark.asyncio
    async def test_skips_vector_search_for_384_dim(self):
        """Vector search should return empty when embedder is 384-dim."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        search = MessageSearch(mock_pool, mock_embedder)
        results = await search.vector_search("test query")

        assert results == []
        mock_embedder.generate_embedding.assert_not_called()
