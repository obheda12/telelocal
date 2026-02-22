"""
Claude API integration — sends user questions (with retrieved message
context) to the Anthropic API and returns the assistant's response.

Includes a lightweight intent-extraction step (using Haiku) that parses
the user's natural-language question into structured search filters
before the main search + synthesis call (using Sonnet).

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

import asyncio
import json
import logging
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

import anthropic

from querybot.search import QueryIntent, SearchResult

logger = logging.getLogger("querybot.llm")

# Sonnet pricing (per million tokens) as of 2025
_SONNET_INPUT_COST_PER_M = 3.00
_SONNET_OUTPUT_COST_PER_M = 15.00

# Haiku for fast/cheap intent extraction
_INTENT_MODEL = "claude-haiku-4-5-20251001"
_HAIKU_INPUT_COST_PER_M = 0.0  # set in config if you want precise cost estimates
_HAIKU_OUTPUT_COST_PER_M = 0.0

_INTENT_SYSTEM_PROMPT = """\
You extract search parameters from questions about the user's Telegram messages.

Available chats (format: ID | Title | Type):
{chat_list}

Given the user's question, return ONLY a JSON object with these fields:
- "search_terms": keywords to search message text (null if the user wants to \
browse/summarize all messages in a chat or time range)
- "chat_ids": array of integer chat IDs from the list above that match the \
user's request (null if not targeting specific chats)
- "sender_name": sender first or last name to filter by (null if not specific)
- "days_back": integer number of days to look back (null for all time)

Rules:
- Match chat names liberally: if the user says "acme", match any chat with \
"Acme" in the title. Chat names often follow the pattern "TeamName <> CompanyName".
- For time: "today"=1, "yesterday"=2, "last week"=7, "last month"=30, \
"recently"=7, "this week"=7
- search_terms should contain ONLY the topic keywords — exclude chat names, \
sender names, and time references
- If the question is a general summary request for a specific chat (e.g. \
"summarize the acme chat"), set search_terms to null and chat_ids to the \
matching chat(s)
- Return valid JSON only. No markdown fences, no explanation."""


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
        model: str = "claude-sonnet-4-5-20250929",
        max_queries_per_minute: int = 10,
        haiku_input_cost_per_m: float = _HAIKU_INPUT_COST_PER_M,
        haiku_output_cost_per_m: float = _HAIKU_OUTPUT_COST_PER_M,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._max_qpm = max_queries_per_minute
        self._haiku_in_cost = haiku_input_cost_per_m
        self._haiku_out_cost = haiku_output_cost_per_m
        self._system_prompt: Optional[str] = None
        self._system_prompt_path = system_prompt_path

        # Rate limiting state
        self._call_timestamps: List[float] = []

        # Cost tracking (separate intent vs synthesis)
        self._intent_input_tokens: int = 0
        self._intent_output_tokens: int = 0
        self._synthesis_input_tokens: int = 0
        self._synthesis_output_tokens: int = 0

    # ------------------------------------------------------------------
    # System prompt
    # ------------------------------------------------------------------

    def _load_system_prompt(self) -> str:
        """Load the system prompt from disk (cached after first load)."""
        if self._system_prompt is None:
            self._system_prompt = self._system_prompt_path.read_text()
        return self._system_prompt

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _enforce_rate_limit(self) -> None:
        """Block until a query slot is available within the QPM budget.

        Uses a sliding-window approach: discard timestamps older than
        60 seconds, then check if the window is full.
        """
        now = time.monotonic()

        # Remove entries older than 60 seconds
        self._call_timestamps = [
            ts for ts in self._call_timestamps if now - ts < 60
        ]

        # If at capacity, wait for the oldest entry to expire
        if len(self._call_timestamps) >= self._max_qpm:
            sleep_time = 60 - (now - self._call_timestamps[0])
            if sleep_time > 0:
                logger.info("Rate limit reached, sleeping %.1fs", sleep_time)
                await asyncio.sleep(sleep_time)

        self._call_timestamps.append(time.monotonic())

    # ------------------------------------------------------------------
    # Intent extraction (Haiku — fast and cheap)
    # ------------------------------------------------------------------

    async def extract_query_intent(
        self,
        user_question: str,
        chat_list: List[Dict[str, Any]],
    ) -> QueryIntent:
        """Parse a natural-language question into structured search filters.

        Uses Haiku for speed (~200ms) and low cost. Falls back to a
        default intent (full question as search terms) on any failure.
        """
        formatted_chats = "\n".join(
            f"{c['chat_id']} | {c.get('title', 'Unknown')} | {c.get('chat_type', '')}"
            for c in chat_list
        )
        # Use .replace() instead of .format() — chat titles may contain braces
        system = _INTENT_SYSTEM_PROMPT.replace("{chat_list}", formatted_chats)

        known_chat_ids = {c["chat_id"] for c in chat_list}

        response = None
        try:
            response = await self._client.messages.create(
                model=_INTENT_MODEL,
                max_tokens=256,
                system=system,
                messages=[{"role": "user", "content": user_question}],
            )

            if not response.content:
                raise ValueError("Empty response from intent extraction")

            raw_text = response.content[0].text.strip()
            self._intent_input_tokens += response.usage.input_tokens
            self._intent_output_tokens += response.usage.output_tokens

            # Strip markdown code fences if Claude wraps the JSON
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[-1]  # remove ```json line
                raw_text = raw_text.rsplit("```", 1)[0]  # remove closing ```
                raw_text = raw_text.strip()

            logger.debug("Intent raw response: %s", raw_text[:200])

            data = json.loads(raw_text)

            # Validate and coerce types
            chat_ids = data.get("chat_ids")
            if chat_ids is not None:
                # Coerce to int and filter to known chats only
                chat_ids = [int(cid) for cid in chat_ids if int(cid) in known_chat_ids]
                chat_ids = chat_ids or None

            days_back = data.get("days_back")
            if days_back is not None:
                days_back = max(1, int(days_back))

            search_terms = data.get("search_terms")
            if isinstance(search_terms, list):
                search_terms = " ".join(str(t) for t in search_terms)

            intent = QueryIntent(
                search_terms=search_terms or None,
                chat_ids=chat_ids,
                sender_name=data.get("sender_name") or None,
                days_back=days_back,
            )
            logger.info(
                "Extracted intent: has_terms=%s, chat_count=%s, sender=%s, days=%s",
                intent.search_terms is not None,
                len(intent.chat_ids) if intent.chat_ids else 0,
                intent.sender_name is not None,
                intent.days_back,
            )
            return intent

        except (
            json.JSONDecodeError, anthropic.APIError,
            KeyError, ValueError, IndexError,
        ) as exc:
            raw_resp = "<not received>"
            if response and getattr(response, "content", None):
                try:
                    raw_resp = response.content[0].text[:200]
                except Exception:
                    pass
            logger.warning(
                "Intent extraction failed (%s), using raw question as search terms. "
                "Raw response: %s",
                exc, raw_resp,
            )
            return QueryIntent(search_terms=user_question)

    # ------------------------------------------------------------------
    # Context formatting (data minimisation)
    # ------------------------------------------------------------------

    @staticmethod
    def _escape_xml(text: str) -> str:
        """Escape < and > in untrusted text to prevent XML tag injection."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _format_context(results: List[SearchResult], max_chars: int = 8000) -> str:
        """Format search results grouped by chat for better LLM comprehension.

        Groups messages by chat title, then lists them chronologically
        within each group. Wrapped in XML boundary markers with
        ``trust_level="untrusted"`` to clearly separate synced content
        from the system prompt. Truncated to ``max_chars``.
        """
        if not results:
            return "(No relevant messages found in synced chats.)"

        # Group by chat_id + title to avoid collisions
        chat_groups: OrderedDict[tuple[int, str], List[SearchResult]] = OrderedDict()
        for r in results:
            title = r.chat_title or "Unknown Chat"
            chat_groups.setdefault((r.chat_id, title), []).append(r)

        parts: List[str] = [
            '<message_context source="synced_telegram_messages" trust_level="untrusted">\n'
        ]
        total_len = len(parts[0])

        for (_, chat_title), msgs in chat_groups.items():
            safe_title = ClaudeAssistant._escape_xml(chat_title)
            header = f"=== {safe_title} ===\n"
            if total_len + len(header) > max_chars:
                break
            parts.append(header)
            total_len += len(header)

            for r in msgs:
                safe_sender = ClaudeAssistant._escape_xml(r.sender_name or "")
                safe_text = ClaudeAssistant._escape_xml(r.text or "")
                entry = f"[{r.timestamp}] {safe_sender}: {safe_text}\n"
                if total_len + len(entry) > max_chars:
                    break
                parts.append(entry)
                total_len += len(entry)

            parts.append("\n")
            total_len += 1

        parts.append("</message_context>")
        return "".join(parts)

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
        """
        await self._enforce_rate_limit()

        system_prompt = self._load_system_prompt()
        context = self._format_context(context_results)

        response = await self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Context:\n{context}\n\nQuestion: {user_question}",
                }
            ],
        )

        # Track tokens
        self._synthesis_input_tokens += response.usage.input_tokens
        self._synthesis_output_tokens += response.usage.output_tokens

        return response.content[0].text

    # ------------------------------------------------------------------
    # Cost tracking
    # ------------------------------------------------------------------

    def get_usage_stats(self) -> Dict[str, Any]:
        """Return cumulative token usage and estimated cost."""
        intent_input_cost = (self._intent_input_tokens / 1_000_000) * self._haiku_in_cost
        intent_output_cost = (self._intent_output_tokens / 1_000_000) * self._haiku_out_cost
        synthesis_input_cost = (self._synthesis_input_tokens / 1_000_000) * _SONNET_INPUT_COST_PER_M
        synthesis_output_cost = (self._synthesis_output_tokens / 1_000_000) * _SONNET_OUTPUT_COST_PER_M
        return {
            "intent_input_tokens": self._intent_input_tokens,
            "intent_output_tokens": self._intent_output_tokens,
            "synthesis_input_tokens": self._synthesis_input_tokens,
            "synthesis_output_tokens": self._synthesis_output_tokens,
            "input_tokens": self._intent_input_tokens + self._synthesis_input_tokens,
            "output_tokens": self._intent_output_tokens + self._synthesis_output_tokens,
            "estimated_cost_usd": round(
                intent_input_cost + intent_output_cost + synthesis_input_cost + synthesis_output_cost,
                4,
            ),
        }
