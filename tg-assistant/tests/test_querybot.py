"""
Unit tests for querybot: handlers, message splitting, owner_only filter, LLM.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from querybot.handlers import _split_message, handle_message, handle_start, owner_only
from querybot.llm import ClaudeAssistant
from querybot.search import QueryIntent, SearchResult


# ---------------------------------------------------------------------------
# Message splitting
# ---------------------------------------------------------------------------


class TestSplitMessage:
    def test_short_message_no_split(self):
        """Messages under 4096 chars should not be split."""
        text = "Short message"
        result = _split_message(text)
        assert result == [text]

    def test_long_message_splits(self):
        """Messages over 4096 chars should be split into chunks."""
        text = "x" * 10000
        result = _split_message(text)
        assert len(result) > 1
        for chunk in result:
            assert len(chunk) <= 4096

    def test_splits_at_newline(self):
        """Should prefer splitting at newlines."""
        # Create a message where there's a newline just before the limit
        line1 = "a" * 4000
        line2 = "b" * 4000
        text = line1 + "\n" + line2

        result = _split_message(text)
        assert len(result) == 2
        assert result[0] == line1

    def test_exact_4096(self):
        """Exactly 4096 chars should not be split."""
        text = "x" * 4096
        result = _split_message(text)
        assert result == [text]

    def test_empty_message(self):
        """Empty string should return single empty chunk."""
        result = _split_message("")
        assert result == [""]

    def test_all_chunks_non_empty(self):
        """No chunk should be empty (except for genuinely empty input)."""
        text = "x" * 8000
        result = _split_message(text)
        for chunk in result:
            assert len(chunk) > 0


# ---------------------------------------------------------------------------
# Owner-only decorator
# ---------------------------------------------------------------------------


class TestOwnerOnlyDecorator:
    @pytest.mark.asyncio
    async def test_allows_owner(self):
        """Should call the wrapped function for the owner."""
        called = False

        @owner_only
        async def handler(update, context):
            nonlocal called
            called = True

        update = MagicMock()
        update.effective_user.id = 12345
        context = MagicMock()
        context.bot_data = {"owner_id": 12345}

        await handler(update, context)
        assert called

    @pytest.mark.asyncio
    async def test_blocks_non_owner(self):
        """Should silently drop messages from non-owners."""
        called = False

        @owner_only
        async def handler(update, context):
            nonlocal called
            called = True

        update = MagicMock()
        update.effective_user.id = 99999
        context = MagicMock()
        context.bot_data = {"owner_id": 12345, "audit": None}

        await handler(update, context)
        assert not called

    @pytest.mark.asyncio
    async def test_blocks_no_user(self):
        """Should silently drop messages with no effective_user."""
        called = False

        @owner_only
        async def handler(update, context):
            nonlocal called
            called = True

        update = MagicMock()
        update.effective_user = None
        context = MagicMock()
        context.bot_data = {"owner_id": 12345, "audit": None}

        await handler(update, context)
        assert not called

    @pytest.mark.asyncio
    async def test_audit_logs_unauthorized(self):
        """Should audit-log unauthorized access attempts."""
        @owner_only
        async def handler(update, context):
            pass

        mock_audit = AsyncMock()
        update = MagicMock()
        update.effective_user.id = 99999
        context = MagicMock()
        context.bot_data = {"owner_id": 12345, "audit": mock_audit}

        await handler(update, context)
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][1] == "unauthorized_access"
        assert call_args[1]["success"] is False


# ---------------------------------------------------------------------------
# handle_message flow (intent extraction → filtered search → Claude)
# ---------------------------------------------------------------------------


def _make_handler_context(
    search_results=None,
    fallback_results=None,
    llm_answer="Test answer",
    intent=None,
    chat_list=None,
):
    """Build mock objects for handler tests."""
    update = MagicMock()
    update.effective_user.id = 12345
    update.message.text = "What happened yesterday?"
    update.message.reply_text = AsyncMock()

    mock_search = AsyncMock()
    mock_search.get_chat_list.return_value = chat_list or [
        {"chat_id": 1, "title": "Engineering <> Acme", "chat_type": "group"},
    ]
    mock_search.filtered_search.return_value = search_results or []
    mock_search.full_text_search.return_value = fallback_results or []

    mock_llm = AsyncMock()
    mock_llm.extract_query_intent.return_value = intent or QueryIntent(
        search_terms="happened"
    )
    mock_llm.query.return_value = llm_answer

    mock_audit = AsyncMock()

    context = MagicMock()
    context.bot_data = {
        "owner_id": 12345,
        "search": mock_search,
        "llm": mock_llm,
        "audit": mock_audit,
    }

    return update, context, mock_search, mock_llm, mock_audit


class TestHandleMessage:
    @pytest.mark.asyncio
    async def test_no_results(self):
        """Should reply with 'no results' when search returns nothing."""
        update, context, mock_search, mock_llm, _ = _make_handler_context(
            search_results=[],
            intent=QueryIntent(search_terms="something"),
        )

        await handle_message(update, context)

        mock_search.get_chat_list.assert_called_once()
        mock_llm.extract_query_intent.assert_called_once()
        mock_search.filtered_search.assert_called_once()
        # Should not call LLM query when there are no results
        mock_llm.query.assert_not_called()
        reply_text = update.message.reply_text.call_args[0][0]
        assert "No relevant messages found" in reply_text

    @pytest.mark.asyncio
    async def test_full_pipeline(self):
        """Should extract intent, search, call LLM, and reply with answer."""
        result = SearchResult(
            message_id=1,
            chat_id=1,
            chat_title="Engineering <> Acme",
            sender_name="Alice",
            timestamp="2024-01-15T10:00:00Z",
            text="Hello there",
            score=0.9,
        )
        update, context, mock_search, mock_llm, mock_audit = _make_handler_context(
            search_results=[result],
            llm_answer="Alice said hello.",
            intent=QueryIntent(search_terms="hello", chat_ids=[1]),
        )
        update.message.text = "What did Alice say in engineering?"

        await handle_message(update, context)

        # Intent extraction should receive chat list and question
        mock_llm.extract_query_intent.assert_called_once()
        call_args = mock_llm.extract_query_intent.call_args[0]
        assert call_args[0] == "What did Alice say in engineering?"

        # Filtered search should receive intent parameters
        mock_search.filtered_search.assert_called_once_with(
            search_terms="hello",
            chat_ids=[1],
            sender_name=None,
            days_back=None,
            limit=20,
        )

        mock_llm.query.assert_called_once()
        update.message.reply_text.assert_called_once_with("Alice said hello.")
        mock_audit.log.assert_called_once()

    @pytest.mark.asyncio
    async def test_fallback_to_unfiltered_fts(self):
        """Should fall back to unfiltered FTS when filtered search returns nothing."""
        result = SearchResult(
            message_id=1,
            chat_id=2,
            chat_title="Sales <> Acme",
            sender_name="Bob",
            timestamp="2024-01-15T10:00:00Z",
            text="Meeting notes",
            score=0.7,
        )
        update, context, mock_search, mock_llm, _ = _make_handler_context(
            search_results=[],  # filtered search returns nothing
            fallback_results=[result],  # but unfiltered FTS finds something
            intent=QueryIntent(search_terms="meeting", chat_ids=[99]),  # wrong chat
        )

        await handle_message(update, context)

        # Should have called unfiltered FTS as fallback
        mock_search.full_text_search.assert_called_once()
        mock_llm.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_browse_query_uses_higher_limit(self):
        """Browse queries (no search_terms) should use limit=50."""
        result = SearchResult(
            message_id=1,
            chat_id=1,
            chat_title="Chat",
            sender_name="User",
            timestamp="2024-01-15T10:00:00Z",
            text="Some text",
            score=1.0,
        )
        update, context, mock_search, mock_llm, _ = _make_handler_context(
            search_results=[result],
            intent=QueryIntent(search_terms=None, chat_ids=[1], days_back=1),
        )

        await handle_message(update, context)

        # No search terms → browse → limit should be 50
        call_kwargs = mock_search.filtered_search.call_args[1]
        assert call_kwargs["limit"] == 50

    @pytest.mark.asyncio
    async def test_audit_includes_intent_metadata(self):
        """Audit log should include intent metadata for debugging."""
        result = SearchResult(
            message_id=1,
            chat_id=1,
            chat_title="Chat",
            sender_name="User",
            timestamp="2024-01-15T10:00:00Z",
            text="Text",
            score=0.8,
        )
        update, context, mock_search, mock_llm, mock_audit = _make_handler_context(
            search_results=[result],
            intent=QueryIntent(search_terms="topic", chat_ids=[1], days_back=7),
        )

        await handle_message(update, context)

        audit_details = mock_audit.log.call_args[0][2]
        assert audit_details["intent_chat_ids"] == [1]
        assert audit_details["intent_has_search_terms"] is True
        assert audit_details["intent_days_back"] == 7


# ---------------------------------------------------------------------------
# LLM context formatting
# ---------------------------------------------------------------------------


class TestClaudeAssistantFormatContext:
    def test_format_context_groups_by_chat(self):
        """Should group results by chat title with headers."""
        results = [
            SearchResult(
                message_id=1,
                chat_id=1,
                chat_title="Dev Chat",
                sender_name="Bob",
                timestamp="2024-01-15T10:00:00Z",
                text="The deployment is tomorrow",
                score=0.9,
            ),
            SearchResult(
                message_id=2,
                chat_id=2,
                chat_title="Sales Chat",
                sender_name="Alice",
                timestamp="2024-01-15T11:00:00Z",
                text="Client meeting at 3pm",
                score=0.8,
            ),
            SearchResult(
                message_id=3,
                chat_id=1,
                chat_title="Dev Chat",
                sender_name="Carol",
                timestamp="2024-01-15T10:30:00Z",
                text="I will prepare the release",
                score=0.7,
            ),
        ]
        context = ClaudeAssistant._format_context(results)

        # Should contain chat headers
        assert "=== Dev Chat ===" in context
        assert "=== Sales Chat ===" in context
        # Should contain message content
        assert "Bob" in context
        assert "deployment is tomorrow" in context
        assert "Alice" in context
        assert "Client meeting" in context

    def test_format_context_empty(self):
        """Should return placeholder for empty results."""
        context = ClaudeAssistant._format_context([])
        assert "No relevant messages" in context

    def test_format_context_truncates(self):
        """Should stop adding results when max_chars is reached."""
        results = [
            SearchResult(
                message_id=i,
                chat_id=1,
                chat_title="Chat",
                sender_name="User",
                timestamp="2024-01-15T10:00:00Z",
                text="x" * 500,
                score=0.5,
            )
            for i in range(100)
        ]
        context = ClaudeAssistant._format_context(results, max_chars=1000)
        assert len(context) <= 1500  # generous bound


class TestClaudeAssistantUsageStats:
    def test_initial_stats(self):
        """Initial usage stats should be zero."""
        with patch("querybot.llm.anthropic"):
            assistant = ClaudeAssistant(api_key="test-key")
        stats = assistant.get_usage_stats()
        assert stats["input_tokens"] == 0
        assert stats["output_tokens"] == 0
        assert stats["estimated_cost_usd"] == 0.0


# ---------------------------------------------------------------------------
# QueryIntent
# ---------------------------------------------------------------------------


class TestQueryIntent:
    def test_default_intent(self):
        """Default intent should have all None fields."""
        intent = QueryIntent()
        assert intent.search_terms is None
        assert intent.chat_ids is None
        assert intent.sender_name is None
        assert intent.days_back is None

    def test_intent_with_all_fields(self):
        """Should store all search parameters."""
        intent = QueryIntent(
            search_terms="deployment",
            chat_ids=[1, 2],
            sender_name="Alice",
            days_back=7,
        )
        assert intent.search_terms == "deployment"
        assert intent.chat_ids == [1, 2]
        assert intent.sender_name == "Alice"
        assert intent.days_back == 7
