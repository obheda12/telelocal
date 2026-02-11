"""
Claude API integration — sends user questions (with retrieved message
context) to the Anthropic API and returns the assistant's response.

Security considerations:
    - **Data minimisation**: only relevant message snippets (from search
      results) are sent as context — never the full database.
    - **System prompt**: loaded from a file on disk, not hard-coded, so
      the owner can review and modify it.
    - **Rate limiting**: enforces a configurable maximum number of queries
      per minute to control costs.
    - **Token counting**: tracks input/output tokens for cost monitoring.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import anthropic

from querybot.search import SearchResult

logger = logging.getLogger("querybot.llm")


class ClaudeAssistant:
    """Wrapper around the Anthropic Python SDK for query answering.

    Args:
        api_key: Anthropic API key (loaded from system keychain).
        system_prompt_path: Path to the system prompt markdown file.
        model: Claude model identifier.
        max_queries_per_minute: Rate limit for outgoing API calls.
    """

    def __init__(
        self,
        api_key: str,
        system_prompt_path: Path = Path("/etc/tg-assistant/system_prompt.md"),
        model: str = "claude-sonnet-4-20250514",
        max_queries_per_minute: int = 10,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._max_qpm = max_queries_per_minute
        self._system_prompt: Optional[str] = None
        self._system_prompt_path = system_prompt_path

        # Rate limiting state
        self._call_timestamps: List[float] = []

        # Cost tracking
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0

    # ------------------------------------------------------------------
    # System prompt
    # ------------------------------------------------------------------

    def _load_system_prompt(self) -> str:
        """Load the system prompt from disk (cached after first load).

        Returns:
            The system prompt string.

        Raises:
            FileNotFoundError: If the prompt file doesn't exist.
        """
        # TODO: implement
        #   - Read self._system_prompt_path
        #   - Cache in self._system_prompt
        #   - Return cached value on subsequent calls
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _enforce_rate_limit(self) -> None:
        """Block until a query slot is available within the QPM budget.

        Uses a sliding-window approach: discard timestamps older than
        60 seconds, then check if the window is full.
        """
        # TODO: implement
        #   - Remove entries from self._call_timestamps older than 60s
        #   - If len >= self._max_qpm, sleep until the oldest entry expires
        #   - Append current timestamp
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Context formatting (data minimisation)
    # ------------------------------------------------------------------

    @staticmethod
    def _format_context(results: List[SearchResult], max_chars: int = 8000) -> str:
        """Format search results into a context string for the LLM.

        Only includes the most relevant snippets, truncated to
        ``max_chars`` to minimise data sent to the API.

        Each message is formatted as::

            [2024-01-15 14:30] ChatName | SenderName:
            Message text here...

        Args:
            results: Ranked search results from hybrid search.
            max_chars: Maximum total characters for the context block.

        Returns:
            Formatted context string.
        """
        # TODO: implement
        #   - Iterate results in order of relevance
        #   - Format each as shown above
        #   - Stop adding once max_chars is reached
        #   - Return the assembled string
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def query(
        self,
        user_question: str,
        context_results: List[SearchResult],
    ) -> str:
        """Send a question with context to Claude and return the response.

        Args:
            user_question: The owner's natural-language question.
            context_results: Search results to include as context.

        Returns:
            Claude's response text.

        Raises:
            anthropic.RateLimitError: If the Anthropic API rate-limits us.
            RuntimeError: If our own QPM limit is exceeded after retries.
        """
        # TODO: implement
        #   1. await self._enforce_rate_limit()
        #   2. system_prompt = self._load_system_prompt()
        #   3. context = self._format_context(context_results)
        #   4. Build messages:
        #        [{"role": "user", "content": f"Context:\n{context}\n\nQuestion: {user_question}"}]
        #   5. Call self._client.messages.create(
        #          model=self._model,
        #          max_tokens=1024,
        #          system=system_prompt,
        #          messages=messages,
        #      )
        #   6. Track tokens:
        #        self._total_input_tokens += response.usage.input_tokens
        #        self._total_output_tokens += response.usage.output_tokens
        #   7. Return response.content[0].text
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Cost tracking
    # ------------------------------------------------------------------

    def get_usage_stats(self) -> Dict[str, Any]:
        """Return cumulative token usage and estimated cost.

        Returns:
            Dict with ``input_tokens``, ``output_tokens``,
            ``estimated_cost_usd``.
        """
        # TODO: implement
        #   - Calculate cost based on model pricing
        #   - Return stats dict
        raise NotImplementedError
