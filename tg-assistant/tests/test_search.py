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
    async def test_vector_search_runs_for_384_dim(self):
        """Vector search should run when embedder has a valid dimension."""
        mock_pool = MagicMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_embedder.generate_embedding = AsyncMock(return_value=[0.0] * 384)

        search = MessageSearch(mock_pool, mock_embedder)
        with patch.object(search._pool, "fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = []
            results = await search.vector_search("test query")

        assert results == []
        mock_embedder.generate_embedding.assert_called_once()


class TestFilteredSearchOptimized:
    @pytest.mark.asyncio
    async def test_filtered_search_uses_single_query_hybrid(self):
        """FTS queries should use one hybrid SQL query instead of Python-side merge."""
        mock_pool = MagicMock()
        mock_pool.fetch = AsyncMock(return_value=[])

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_embedder.generate_embedding = AsyncMock(return_value=[0.0] * 384)

        search = MessageSearch(mock_pool, mock_embedder)
        results = await search.filtered_search(
            search_terms="launch update",
            chat_ids=[1, 2],
            sender_name="Ali_ce%",
            days_back=7,
            limit=5,
        )

        assert results == []
        mock_embedder.generate_embedding.assert_called_once_with("launch update")
        mock_pool.fetch.assert_called_once()
        sql = mock_pool.fetch.call_args[0][0]
        assert "WITH q AS" in sql
        assert "FROM candidates k" in sql

    @pytest.mark.asyncio
    async def test_filtered_search_falls_back_to_fts_if_embedding_fails(self):
        """If embedding generation fails, filtered_search should still return FTS results."""
        mock_pool = MagicMock()
        mock_pool.fetch = AsyncMock(return_value=[])

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_embedder.generate_embedding = AsyncMock(side_effect=RuntimeError("boom"))

        search = MessageSearch(mock_pool, mock_embedder)
        results = await search.filtered_search(
            search_terms="test query",
            limit=10,
        )

        assert results == []
        mock_pool.fetch.assert_called_once()
        sql = mock_pool.fetch.call_args[0][0]
        assert "ORDER BY score DESC" in sql

    @pytest.mark.asyncio
    async def test_filtered_search_browse_mode_skips_embedding(self):
        """Browse mode (no search terms) should order by recency without embedding work."""
        mock_pool = MagicMock()
        mock_pool.fetch = AsyncMock(return_value=[])

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_embedder.generate_embedding = AsyncMock(return_value=[0.0] * 384)

        search = MessageSearch(mock_pool, mock_embedder)
        results = await search.filtered_search(
            search_terms=None,
            chat_ids=[42],
            limit=10,
        )

        assert results == []
        mock_embedder.generate_embedding.assert_not_called()
        mock_pool.fetch.assert_called_once()
        sql = mock_pool.fetch.call_args[0][0]
        assert "ORDER BY m.timestamp DESC" in sql

    @pytest.mark.asyncio
    async def test_filtered_search_short_keyword_uses_fts_only(self):
        """Single-keyword queries should skip hybrid vector work for lower latency."""
        mock_pool = MagicMock()
        mock_pool.fetch = AsyncMock(return_value=[])

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_embedder.generate_embedding = AsyncMock(return_value=[0.0] * 384)

        search = MessageSearch(
            mock_pool,
            mock_embedder,
            hybrid_min_terms=2,
            hybrid_min_term_length=3,
        )
        results = await search.filtered_search(
            search_terms="budget",
            limit=10,
        )

        assert results == []
        mock_embedder.generate_embedding.assert_not_called()
        mock_pool.fetch.assert_called_once()
        sql = mock_pool.fetch.call_args[0][0]
        assert "ORDER BY score DESC" in sql


class TestChatListCaching:
    @pytest.mark.asyncio
    async def test_get_chat_list_limit_uses_cached_rows(self):
        """get_chat_list(limit=...) should return a sliced cached list."""
        mock_pool = MagicMock()
        mock_pool.fetch = AsyncMock(return_value=[
            {"chat_id": 3, "title": "C", "chat_type": "group"},
            {"chat_id": 2, "title": "B", "chat_type": "group"},
            {"chat_id": 1, "title": "A", "chat_type": "group"},
        ])
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        search = MessageSearch(mock_pool, mock_embedder)
        first = await search.get_chat_list(limit=2)
        second = await search.get_chat_list(limit=1)

        assert len(first) == 2
        assert len(second) == 1
        mock_pool.fetch.assert_called_once()


class TestEmbeddingCaching:
    @pytest.mark.asyncio
    async def test_reuses_cached_query_embedding(self):
        """Repeated identical queries should not regenerate embeddings."""
        mock_pool = MagicMock()
        mock_pool.fetch = AsyncMock(return_value=[])
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_embedder.generate_embedding = AsyncMock(return_value=[0.0] * 384)

        search = MessageSearch(mock_pool, mock_embedder)
        await search.vector_search("Launch status")
        await search.vector_search("  launch   status  ")

        # Normalization + cache => one embed call total.
        mock_embedder.generate_embedding.assert_called_once()


class TestThreadMetadataMapping:
    def test_rows_to_results_maps_reply_thread_fields(self):
        """rows_to_results should preserve reply/thread metadata for LLM context."""
        row = {
            "message_id": 10,
            "chat_id": 2,
            "title": "Thread Chat",
            "sender_name": "Alice",
            "reply_to_msg_id": 9,
            "thread_top_msg_id": 7,
            "is_topic_message": True,
            "timestamp": None,
            "text": "Reply message",
            "score": 0.5,
        }
        results = MessageSearch._rows_to_results([row])
        assert len(results) == 1
        result = results[0]
        assert result.reply_to_msg_id == 9
        assert result.thread_top_msg_id == 7
        assert result.is_topic_message is True
