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
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

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
        max_tokens: int = 4096,
        temperature: float = 0.3,
        haiku_input_cost_per_m: float = _HAIKU_INPUT_COST_PER_M,
        haiku_output_cost_per_m: float = _HAIKU_OUTPUT_COST_PER_M,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._max_qpm = max_queries_per_minute
        self._max_tokens = max(256, int(max_tokens))
        self._temperature = float(temperature)
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
            f"{c['chat_id']} | {ClaudeAssistant._escape_xml((c.get('title') or 'Unknown').replace(chr(10), ' ')[:80])} | {c.get('chat_type', '')}"
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
                days_back = min(180, max(1, int(days_back)))

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

    _ET = ZoneInfo("America/New_York")

    @staticmethod
    def _escape_xml(text: str) -> str:
        """Escape < and > in untrusted text to prevent XML tag injection."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _chat_deep_link(chat_id: int) -> Optional[str]:
        """Generate a t.me deep link for supergroups/channels."""
        s = str(chat_id)
        if s.startswith("-100") and len(s) > 4:
            return f"https://t.me/c/{s[4:]}/1"
        return None

    @staticmethod
    def _chat_header(safe_title: str, chat_id: int) -> str:
        """Build a context header line, including a deep link when available."""
        link = ClaudeAssistant._chat_deep_link(chat_id)
        if link:
            return f"=== {safe_title} | {link} ===\n"
        return f"=== {safe_title} ===\n"

    # Pattern to strip common org prefixes from chat titles
    _COUNTERPARTY_RE = re.compile(
        r"^(?:Monad(?:\s+Foundation)?\s*(?:<>|x|×|—|-)\s*)", re.IGNORECASE,
    )

    @classmethod
    def _counterparty_name(cls, title: str) -> Optional[str]:
        """Extract the counterparty portion of a chat title, if any."""
        stripped = cls._COUNTERPARTY_RE.sub("", title).strip()
        return stripped if stripped and stripped != title else None

    @staticmethod
    def _inject_chat_links(text: str, link_map: Dict[str, str]) -> str:
        """Inject clickable deep links around chat names in LLM output.

        Handles <b>Name</b>, bare Name, and case variations.
        Processes longest names first to avoid partial matches.
        """
        sorted_items = sorted(
            link_map.items(), key=lambda kv: len(kv[0]), reverse=True,
        )
        for name, url in sorted_items:
            escaped = re.escape(name)

            # Already linked for this name? skip
            if re.search(
                r'<a\s+href="[^"]*">\s*<b>' + escaped + r'</b>',
                text, re.IGNORECASE,
            ):
                continue

            # Replace bolded form: <b>Name</b> → <a href><b>Name</b></a>
            bold_pat = re.compile(
                r'<b>(' + escaped + r')</b>', re.IGNORECASE,
            )
            text = bold_pat.sub(
                lambda m, u=url: f'<a href="{u}"><b>{m.group(1)}</b></a>',
                text,
            )

            # Also replace bare occurrences not inside HTML tags.
            # (?<![>\w]) prevents matching right after a tag like <b>.
            # (?![<\w]) prevents matching right before a closing tag.
            bare_pat = re.compile(
                r'(?<![>\w])(' + escaped + r')(?![<\w])', re.IGNORECASE,
            )
            text = bare_pat.sub(
                lambda m, u=url: f'<a href="{u}"><b>{m.group(1)}</b></a>',
                text,
            )
        return text

    @staticmethod
    def _to_et(iso_ts: str) -> str:
        """Convert an ISO-format UTC timestamp to ET (e.g. '2025-03-01 14:30 ET')."""
        if not iso_ts:
            return iso_ts
        try:
            dt = datetime.fromisoformat(iso_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            et_dt = dt.astimezone(ClaudeAssistant._ET)
            return et_dt.strftime("%Y-%m-%d %H:%M ET")
        except (ValueError, TypeError):
            return iso_ts  # pass through if unparseable

    @staticmethod
    def _format_entry(
        r: SearchResult,
        per_message_chars: int,
        owner_user_id: Optional[int],
    ) -> str:
        """Format a single search result into a context line."""
        safe_sender = ClaudeAssistant._escape_xml(r.sender_name or "")
        safe_text = ClaudeAssistant._escape_xml(r.text or "")
        if per_message_chars > 0 and len(safe_text) > per_message_chars:
            safe_text = safe_text[: per_message_chars - 3].rstrip() + "..."
        thread_tags: List[str] = []
        if r.sender_id is not None:
            thread_tags.append(f"sender_id={r.sender_id}")
        if owner_user_id is not None and r.sender_id == owner_user_id:
            thread_tags.append("owner_message=true")
        if r.thread_top_msg_id is not None:
            thread_tags.append(f"thread={r.thread_top_msg_id}")
        if r.reply_to_msg_id is not None:
            thread_tags.append(f"reply_to={r.reply_to_msg_id}")
        if r.is_topic_message:
            thread_tags.append("topic_message=true")
        tag_suffix = f" ({', '.join(thread_tags)})" if thread_tags else ""
        ts_et = ClaudeAssistant._to_et(r.timestamp)
        return f"[{ts_et}] {safe_sender}{tag_suffix}: {safe_text}\n"

    @staticmethod
    def _format_context(
        results: List[SearchResult],
        max_chars: int = 8000,
        per_message_chars: int = 320,
        owner_user_id: Optional[int] = None,
        min_messages_per_group: int = 0,
    ) -> str:
        """Format search results grouped by chat for better LLM comprehension.

        Groups messages by chat title, then lists them chronologically
        within each group. Wrapped in XML boundary markers with
        ``trust_level="untrusted"`` to clearly separate synced content
        from the system prompt. Truncated to ``max_chars``.

        When *min_messages_per_group* > 0, uses a two-pass approach:

        - **Pass 1**: include up to *min_messages_per_group* messages per
          chat, guaranteeing every chat is represented.
        - **Pass 2**: round-robin through remaining messages to fill the
          budget.

        Default ``0`` preserves the original single-pass behavior.
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

        if min_messages_per_group <= 0:
            # Original single-pass behavior
            for (chat_id, chat_title), msgs in chat_groups.items():
                safe_title = ClaudeAssistant._escape_xml(chat_title)
                header = ClaudeAssistant._chat_header(safe_title, chat_id)
                if total_len + len(header) > max_chars:
                    break
                parts.append(header)
                total_len += len(header)

                for r in msgs:
                    entry = ClaudeAssistant._format_entry(
                        r, per_message_chars, owner_user_id,
                    )
                    if total_len + len(entry) > max_chars:
                        break
                    parts.append(entry)
                    total_len += len(entry)

                parts.append("\n")
                total_len += 1
        else:
            # Two-pass breadth-first: guarantee every chat gets representation
            #
            # Pass 1 — up to min_messages_per_group per chat
            remaining: OrderedDict[tuple[int, str], List[SearchResult]] = OrderedDict()
            for key, msgs in chat_groups.items():
                chat_id, chat_title = key
                safe_title = ClaudeAssistant._escape_xml(chat_title)
                header = ClaudeAssistant._chat_header(safe_title, chat_id)
                if total_len + len(header) > max_chars:
                    break
                parts.append(header)
                total_len += len(header)

                included = 0
                leftover: List[SearchResult] = []
                for r in msgs:
                    if included < min_messages_per_group:
                        entry = ClaudeAssistant._format_entry(
                            r, per_message_chars, owner_user_id,
                        )
                        if total_len + len(entry) > max_chars:
                            leftover.append(r)
                            leftover.extend(msgs[msgs.index(r) + 1 :])
                            break
                        parts.append(entry)
                        total_len += len(entry)
                        included += 1
                    else:
                        leftover.append(r)
                if leftover:
                    remaining[key] = leftover

                parts.append("\n")
                total_len += 1

            # Pass 2 — round-robin remaining messages across chats
            while remaining and total_len < max_chars:
                exhausted_keys: List[tuple[int, str]] = []
                for key, msgs in remaining.items():
                    if not msgs:
                        exhausted_keys.append(key)
                        continue
                    r = msgs.pop(0)
                    chat_id_r, chat_title = key
                    safe_title = ClaudeAssistant._escape_xml(chat_title)
                    # Re-emit the header so the message lands under the right chat
                    header = ClaudeAssistant._chat_header(safe_title, chat_id_r)
                    entry = ClaudeAssistant._format_entry(
                        r, per_message_chars, owner_user_id,
                    )
                    if total_len + len(header) + len(entry) > max_chars:
                        exhausted_keys.append(key)
                        continue
                    parts.append(header)
                    total_len += len(header)
                    parts.append(entry)
                    total_len += len(entry)
                    parts.append("\n")
                    total_len += 1
                    if not msgs:
                        exhausted_keys.append(key)
                for key in exhausted_keys:
                    remaining.pop(key, None)

        parts.append("</message_context>")
        return "".join(parts)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def query(
        self,
        user_question: str,
        context_results: List[SearchResult],
        *,
        context_max_chars: int = 8000,
        max_tokens_override: Optional[int] = None,
        owner_user_id: Optional[int] = None,
        owner_aliases: Optional[List[str]] = None,
        model_override: Optional[str] = None,
        min_messages_per_group: int = 0,
    ) -> str:
        """Send a question with context to Claude and return the response.

        Args:
            user_question: The owner's natural-language question.
            context_results: Search results to include as context.

        Returns:
            Claude's response text.
        """
        await self._enforce_rate_limit()

        effective_model = model_override if model_override else self._model
        system_prompt = self._load_system_prompt()
        try:
            context_max_chars = int(context_max_chars)
        except (TypeError, ValueError):
            context_max_chars = 8000
        context_max_chars = max(2000, context_max_chars)
        if max_tokens_override is None:
            max_tokens = self._max_tokens
        else:
            try:
                max_tokens = max(256, int(max_tokens_override))
            except (TypeError, ValueError):
                max_tokens = self._max_tokens
        context = self._format_context(
            context_results,
            max_chars=context_max_chars,
            owner_user_id=owner_user_id,
            min_messages_per_group=min_messages_per_group,
        )
        identity_lines: List[str] = []
        if owner_user_id is not None:
            identity_lines.append(f"- owner_telegram_user_id: {owner_user_id}")
        aliases = [a.strip() for a in (owner_aliases or []) if a and a.strip()]
        if aliases:
            identity_lines.append(f"- owner_aliases: {', '.join(aliases)}")
        identity_block = ""
        if identity_lines:
            identity_block = (
                "Owner identity (for pronoun grounding):\n"
                + "\n".join(identity_lines)
                + "\n"
                + "- In the user's requests, 'I/me/my/myself' refers to the owner.\n"
                + "- In context rows, owner_message=true marks the owner's own messages.\n\n"
            )

        # Build name → URL mapping for deterministic post-processing
        chat_link_map: Dict[str, str] = {}
        seen_chat_ids: set[int] = set()
        for r in context_results:
            if r.chat_id in seen_chat_ids:
                continue
            link = self._chat_deep_link(r.chat_id)
            if link:
                seen_chat_ids.add(r.chat_id)
                title = r.chat_title or "Unknown Chat"
                # Map both the full title and the counterparty-only form
                chat_link_map[title] = link
                cp = self._counterparty_name(title)
                if cp:
                    chat_link_map[cp] = link

        response = await self._client.messages.create(
            model=effective_model,
            max_tokens=max_tokens,
            temperature=self._temperature,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"{identity_block}"
                        f"Context:\n{context}\n\n"
                        f"Question: {user_question}"
                    ),
                }
            ],
        )

        # Track tokens
        self._synthesis_input_tokens += response.usage.input_tokens
        self._synthesis_output_tokens += response.usage.output_tokens
        if model_override:
            logger.debug(
                "Synthesis used override %s (%d in / %d out)",
                model_override,
                response.usage.input_tokens,
                response.usage.output_tokens,
            )

        answer = response.content[0].text
        if chat_link_map:
            answer = self._inject_chat_links(answer, chat_link_map)
        return answer

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
