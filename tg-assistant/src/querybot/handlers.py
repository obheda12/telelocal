"""
Telegram bot handler functions for the query bot.

All handlers that access user data are guarded by the owner-only filter
(configured in ``querybot.main``).  The bot silently ignores messages
from non-owner users.
"""

from __future__ import annotations

import html
import logging
import re
from functools import wraps
from typing import Any, Callable, Coroutine, List, Optional, Tuple

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import asyncpg

from querybot.llm import ClaudeAssistant
from querybot.search import MessageSearch
from shared.audit import AuditLogger
from shared.safety import ContentSanitizer, InputValidator

logger = logging.getLogger("querybot.handlers")

# Type alias for handler functions
HandlerFunc = Callable[
    [Update, ContextTypes.DEFAULT_TYPE],
    Coroutine[Any, Any, None],
]

# Telegram message length limit
_TG_MAX_LEN = 4096
_RECENT_CHAT_LIMIT_RE = re.compile(
    r"\b(?:top\s+)?(\d{1,3})\s+(?:most\s+)?(?:fresh(?:est)?|recent|latest)\s+chats?\b",
    re.IGNORECASE,
)
_PENDING_RESPONSE_CHUNKS_KEY = "pending_response_chunks"
_LAST_RESPONSE_STATUS_KEY = "last_response_status"
_WINDOW_TO_DAYS = {
    "1d": 1,
    "24h": 1,
    "3d": 3,
    "72h": 3,
    "1w": 7,
    "7d": 7,
}
_DETAIL_ALIASES = {
    "quick": "quick",
    "brief": "quick",
    "detailed": "detailed",
    "detail": "detailed",
}
_FRESH_CHAT_CHOICES = {10, 25, 50}
_WINDOW_DAY_RE = re.compile(
    r"\b(?:(?:past|last)\s+)?(\d{1,3})\s*(day|days|d|week|weeks|w)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Owner-only decorator (defence-in-depth — complements the filter in main.py)
# ---------------------------------------------------------------------------


def owner_only(func: HandlerFunc) -> HandlerFunc:
    """Decorator that verifies the message sender is the configured owner.

    This is a **defence-in-depth** check — the primary owner filter is
    applied at the handler-registration level in ``main.py``.  This
    decorator provides a second layer in case the filter is misconfigured.

    If the sender is not the owner, the message is silently dropped
    (no response sent, to avoid information leakage).
    """

    @wraps(func)
    async def wrapper(
        update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        owner_id: int = context.bot_data.get("owner_id", 0)
        user_id = update.effective_user.id if update.effective_user else None

        if user_id != owner_id:
            logger.warning(
                "owner_only: blocked user_id=%s (owner_id=%s) on handler=%s",
                user_id,
                owner_id,
                func.__name__,
            )
            # Audit log the rejected access attempt
            audit: AuditLogger | None = context.bot_data.get("audit")
            if audit:
                await audit.log(
                    "querybot",
                    "unauthorized_access",
                    {"user_id": user_id, "handler": func.__name__},
                    success=False,
                )
            return  # silently drop

        return await func(update, context)

    return wrapper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_message(text: str) -> List[str]:
    """Split a long message into Telegram-safe chunks (<= 4096 chars).

    Prefers splitting at newlines for readability.
    """
    if len(text) <= _TG_MAX_LEN:
        return [text]

    chunks: List[str] = []
    while text:
        if len(text) <= _TG_MAX_LEN:
            chunks.append(text)
            break

        # Try to split at last newline within limit
        split_pos = text.rfind("\n", 0, _TG_MAX_LEN)
        if split_pos == -1 or split_pos < _TG_MAX_LEN // 2:
            split_pos = _TG_MAX_LEN

        chunks.append(text[:split_pos])
        text = text[split_pos:].lstrip("\n")

    return chunks


def _extract_recent_chat_summary_target(
    question: str,
    *,
    default_count: int = 20,
    max_count: int = 75,
) -> int | None:
    """Return requested chat count for "freshest chats" summary queries.

    This detects high-level summary prompts like
    "quick synopsis of the 50 freshest chats".
    """
    q = (question or "").lower()
    if "chat" not in q:
        return None

    summary_hint = any(
        hint in q for hint in (
            "summary",
            "summarize",
            "synopsis",
            "recap",
            "briefing",
            "overview",
            "digest",
            "what happened",
        )
    )
    recency_hint = any(
        hint in q for hint in (
            "freshest chat",
            "freshest chats",
            "latest chat",
            "latest chats",
            "recent chat",
            "recent chats",
            "most recent chats",
        )
    )
    if not (summary_hint and recency_hint):
        return None

    match = _RECENT_CHAT_LIMIT_RE.search(question)
    count = int(match.group(1)) if match else int(default_count)
    count = max(1, min(int(max_count), count))
    return count


# Regex matching Telegram-supported HTML tags that must be preserved.
_ALLOWED_TAG_RE = re.compile(
    r"</?(?:b|strong|i|em|u|ins|s|strike|del|code|pre|blockquote|tg-spoiler)"
    r"(?:\s[^>]*)?>|"
    r'<a\s+href="[^"]*">|</a>|'
    r'<span\s+class="tg-spoiler">|</span>',
    re.IGNORECASE,
)


def _sanitize_telegram_html(text: str) -> str:
    """Escape stray HTML entities while preserving allowed Telegram tags.

    Telegram's HTML parser rejects the entire message if it encounters
    invalid HTML (e.g. ``<$12``, ``P&L``).  This function:

    1. Finds all allowed Telegram HTML tags and replaces them with
       unique placeholders.
    2. Escapes ``&``, ``<``, ``>`` in the remaining text.
    3. Restores the original tags from their placeholders.
    """
    # Normalize pre-escaped entities so we don't double-escape "&lt;&gt;".
    text = html.unescape(text or "")
    placeholders: list[tuple[str, str]] = []

    def _replace_tag(match: re.Match) -> str:
        tag = match.group(0)
        placeholder = f"\x00TAG{len(placeholders)}\x00"
        placeholders.append((placeholder, tag))
        return placeholder

    text = _ALLOWED_TAG_RE.sub(_replace_tag, text)

    # Escape HTML-special characters in the remaining text
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")

    # Restore preserved tags
    for placeholder, tag in placeholders:
        text = text.replace(placeholder, tag)

    return text


def _parse_window_and_detail_args(
    args: List[str],
    *,
    default_days: int,
) -> Tuple[int, str, Optional[str]]:
    """Parse command args into ``days`` and ``detail_mode``.

    Accepted windows: ``1d``, ``3d``, ``1w`` (plus 24h/72h/7d aliases).
    Accepted detail modes: ``quick`` or ``detailed``.
    """
    days = int(default_days)
    detail_mode = "quick"
    unknown: List[str] = []

    for raw in args:
        token = (raw or "").strip().lower()
        if not token:
            continue
        if token in _WINDOW_TO_DAYS:
            days = _WINDOW_TO_DAYS[token]
            continue
        if token in _DETAIL_ALIASES:
            detail_mode = _DETAIL_ALIASES[token]
            continue
        unknown.append(raw)

    if unknown:
        return days, detail_mode, f"Unknown option(s): {' '.join(unknown)}"
    return days, detail_mode, None


def _parse_fresh_args(
    args: List[str],
    *,
    default_count: int = 25,
) -> Tuple[int, str, Optional[str]]:
    """Parse `/fresh` args into ``chat_count`` and ``detail_mode``."""
    chat_count = int(default_count)
    detail_mode = "quick"
    unknown: List[str] = []

    for raw in args:
        token = (raw or "").strip().lower()
        if not token:
            continue
        if token in _DETAIL_ALIASES:
            detail_mode = _DETAIL_ALIASES[token]
            continue
        if token.isdigit():
            value = int(token)
            if value in _FRESH_CHAT_CHOICES:
                chat_count = value
            else:
                unknown.append(raw)
            continue
        unknown.append(raw)

    if unknown:
        return chat_count, detail_mode, f"Unknown option(s): {' '.join(unknown)}"
    return chat_count, detail_mode, None


def _detail_params(
    detail_mode: str,
    *,
    quick_limit: int,
    detailed_limit: int,
    quick_ctx_chars: int,
    detailed_ctx_chars: int,
    quick_max_tokens: int,
    detailed_max_tokens: int,
) -> Tuple[int, int, int]:
    """Return ``(result_limit, context_max_chars, max_tokens)`` by detail mode."""
    if detail_mode == "detailed":
        return detailed_limit, detailed_ctx_chars, detailed_max_tokens
    return quick_limit, quick_ctx_chars, quick_max_tokens


def _resolve_owner_mention_aliases(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> List[str]:
    aliases = list(context.bot_data.get("owner_mention_aliases", []) or [])
    username = (
        (update.effective_user.username or "").strip()
        if update.effective_user
        else ""
    )
    if username:
        aliases.append(f"@{username}")

    # Deduplicate aliases while preserving order.
    seen: set[str] = set()
    normalized_aliases: List[str] = []
    for alias in aliases:
        value = alias.strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized_aliases.append(value)
    return normalized_aliases


def _resolve_owner_user_id(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> int:
    """Resolve the owner identity used for mentions/self-reference grounding."""
    override = context.bot_data.get("self_user_id")
    if isinstance(override, int) and override > 0:
        return override
    if isinstance(override, str) and override.isdigit():
        return int(override)

    configured = context.bot_data.get("owner_id")
    if isinstance(configured, int) and configured > 0:
        return configured
    if isinstance(configured, str) and configured.isdigit():
        return int(configured)

    if update.effective_user and update.effective_user.id:
        return int(update.effective_user.id)
    return 0


def _extract_mentions_window_days(question: str) -> int | None:
    """Detect mention/reply triage requests from free text."""
    q = " ".join((question or "").lower().split())
    if not q:
        return None

    mention_hints = (
        "my mentions",
        "show me my mentions",
        "mentions over",
        "mentions in",
        "mentions from",
        "mention me",
        "mentioned me",
        "tagged me",
        "who mentioned me",
        "who tagged me",
        "replied to me",
        "replies to me",
        "reply to me",
    )
    if not any(hint in q for hint in mention_hints):
        return None

    if any(token in q for token in ("today", "past day", "last day")):
        return 1
    if "yesterday" in q:
        return 2
    if any(token in q for token in ("past week", "last week", "this week")):
        return 7
    if any(token in q for token in ("past month", "last month", "this month")):
        return 30

    match = _WINDOW_DAY_RE.search(q)
    if match:
        amount = max(1, int(match.group(1)))
        unit = match.group(2).lower()
        days = amount * 7 if unit.startswith("w") else amount
        return min(180, days)

    # Mention triage intent with no explicit window -> sensible default.
    return 7


def _extract_open_questions_window_days(question: str) -> int | None:
    """Detect free-text requests for unanswered/open questions."""
    q = " ".join((question or "").lower().split())
    if not q:
        return None

    open_question_hints = (
        "open question",
        "open questions",
        "unanswered question",
        "unanswered questions",
        "questions unanswered",
        "pending question",
        "pending questions",
        "questions need reply",
        "questions needing reply",
    )
    if not any(hint in q for hint in open_question_hints):
        return None

    if any(token in q for token in ("today", "past day", "last day")):
        return 1
    if "yesterday" in q:
        return 2
    if any(token in q for token in ("past week", "last week", "this week")):
        return 7
    if any(token in q for token in ("past month", "last month", "this month")):
        return 30

    match = _WINDOW_DAY_RE.search(q)
    if match:
        amount = max(1, int(match.group(1)))
        unit = match.group(2).lower()
        days = amount * 7 if unit.startswith("w") else amount
        return min(180, days)

    return 1


async def _reply_chunks(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    chunks: List[str],
) -> None:
    """Send chunked output, storing overflow for `/more`."""
    if not chunks:
        return

    auto_chunks = context.bot_data.get("response_auto_chunks", 2)
    try:
        auto_chunks = int(auto_chunks)
    except (TypeError, ValueError):
        auto_chunks = 2
    auto_chunks = max(1, min(4, auto_chunks))

    to_send = chunks[:auto_chunks]
    pending = chunks[auto_chunks:]

    for chunk in to_send:
        try:
            await update.message.reply_text(chunk, parse_mode=ParseMode.HTML)
        except Exception:
            logger.debug("HTML parse failed for chunk, retrying as plain text")
            await update.message.reply_text(chunk)

    if pending:
        context.user_data[_PENDING_RESPONSE_CHUNKS_KEY] = pending
        context.user_data[_LAST_RESPONSE_STATUS_KEY] = "has_more"
        await update.message.reply_text(
            f"<i>{len(pending)} more part(s) available. Send /more to continue.</i>",
            parse_mode=ParseMode.HTML,
        )
    else:
        context.user_data.pop(_PENDING_RESPONSE_CHUNKS_KEY, None)
        context.user_data[_LAST_RESPONSE_STATUS_KEY] = "complete"


async def _reply_answer(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    answer: str,
) -> None:
    """Sanitize, split, and send an assistant answer."""
    chunks = _split_message(_sanitize_telegram_html(answer))
    await _reply_chunks(update, context, chunks)


async def _get_sync_status_context(pool: asyncpg.Pool) -> str:
    """Check message/chat counts and return a sync-aware no-results message.

    Uses only ``messages`` and ``chats`` tables (querybot_role has SELECT on
    these but NOT on ``audit_log``).
    """
    msg_count = await pool.fetchval("SELECT COUNT(*) FROM messages")
    chat_count = await pool.fetchval("SELECT COUNT(*) FROM chats")

    if msg_count == 0:
        return (
            "The initial sync is still in progress — no messages have been "
            "stored yet. This usually takes 10–30 minutes after first setup.\n\n"
            "Check progress on the server with: telelocal sync-status"
        )

    if chat_count <= 3:
        return (
            f"The initial sync may still be in progress "
            f"({msg_count:,} messages across {chat_count} chat(s) so far). "
            f"More messages are being pulled — try again shortly."
        )

    return (
        "No relevant messages found. Try broadening your search "
        "or check that the chat has been synced."
    )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


@owner_only
async def handle_start(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the ``/start`` command."""
    await update.message.reply_text(
        "Welcome! I'm your personal Telegram assistant.\n\n"
        "Ask me anything about your synced messages and I'll search "
        "through them and provide answers using Claude.\n\n"
        "Use /help to see available commands."
    )
    audit: AuditLogger | None = context.bot_data.get("audit")
    if audit:
        await audit.log("querybot", "command_start", success=True)


@owner_only
async def handle_iam(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Bind/display owner identity used for self-referential grounding."""
    audit: AuditLogger = context.bot_data["audit"]
    effective_id = int(update.effective_user.id) if update.effective_user else 0
    args = context.args or []

    if not args:
        bound_id = _resolve_owner_user_id(update, context)
        aliases = _resolve_owner_mention_aliases(update, context)
        alias_text = ", ".join(aliases) if aliases else "(none)"
        await update.message.reply_text(
            "Current identity binding:\n"
            f"  owner_user_id: {bound_id or '(unset)'}\n"
            f"  aliases: {alias_text}\n\n"
            "Usage: /iam [telegram_user_id] [@alias1 @alias2 ...]"
        )
        await audit.log(
            "querybot",
            "command_iam_show",
            {"owner_user_id": bound_id, "alias_count": len(aliases)},
            success=True,
        )
        return

    idx = 0
    bound_id = effective_id or _resolve_owner_user_id(update, context)
    if args and args[0].isdigit():
        bound_id = int(args[0])
        idx = 1

    alias_inputs = [a.strip() for a in args[idx:] if a and a.strip()]
    if not alias_inputs:
        alias_inputs = _resolve_owner_mention_aliases(update, context)

    username = (
        (update.effective_user.username or "").strip()
        if update.effective_user
        else ""
    )
    if username:
        alias_inputs.append(f"@{username}")

    seen: set[str] = set()
    aliases: List[str] = []
    for alias in alias_inputs:
        key = alias.lower()
        if key in seen:
            continue
        seen.add(key)
        aliases.append(alias)

    context.bot_data["self_user_id"] = bound_id
    context.bot_data["owner_mention_aliases"] = aliases
    alias_text = ", ".join(aliases) if aliases else "(none)"
    await update.message.reply_text(
        "Updated identity binding:\n"
        f"  owner_user_id: {bound_id}\n"
        f"  aliases: {alias_text}"
    )
    await audit.log(
        "querybot",
        "command_iam_set",
        {"owner_user_id": bound_id, "alias_count": len(aliases)},
        success=True,
    )


@owner_only
async def handle_help(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the ``/help`` command."""
    help_text = (
        "Available commands:\n"
        "  /start - Welcome message\n"
        "  /help  - This help text\n"
        "  /iam   - Show/set owner identity binding\n"
        "  /stats - Sync and usage statistics\n\n"
        "  /mentions [1d|3d|1w] [quick|detailed] - Items likely needing your reply\n"
        "  /bd [1d|3d|1w] [quick|detailed] - Likely unanswered open questions\n"
        "  /summary  [1d|3d|1w] [quick|detailed] - Cross-chat time-window recap\n"
        "  /fresh    [10|25|50] [quick|detailed] - Snapshot of freshest chats\n"
        "  /more - Continue the previous long response\n\n"
        "How to use:\n"
        "  Just send me a question in plain text! I'll search your "
        "synced Telegram messages and answer using Claude.\n\n"
        "Tips for effective queries:\n"
        '  - Identity binding: "/iam 123456789 @yourusername"\n'
        '  - Mentions triage: "/mentions 1d quick"\n'
        '  - Open questions: "/bd 3d quick"\n'
        '  - Daily recap: "/summary 1d quick"\n'
        '  - Freshest chats: "/fresh 25 quick"\n'
        '  - Be specific: "What did Alice say about the project deadline?"\n'
        '  - Ask for summaries: "Summarise the discussion in DevChat yesterday"\n'
        '  - Search by topic: "Find messages about Python deployment"\n'
        '  - Cross-chat brief: "Quick synopsis of the 50 freshest chats"'
    )
    await update.message.reply_text(help_text)


@owner_only
async def handle_stats(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the ``/stats`` command."""
    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]

    msg_count = await search._pool.fetchval("SELECT COUNT(*) FROM messages")
    chat_count = await search._pool.fetchval("SELECT COUNT(*) FROM chats")
    last_sync = await search._pool.fetchval("SELECT MAX(timestamp) FROM messages")

    # Determine sync status line
    if msg_count == 0:
        sync_line = "Sync: initial sync in progress (no messages yet)"
    elif last_sync:
        sync_line = f"Sync: active (last message: {last_sync.strftime('%Y-%m-%d %H:%M')})"
    else:
        sync_line = "Sync: unknown"

    usage = llm.get_usage_stats()

    stats_text = (
        f"Sync statistics:\n"
        f"  {sync_line}\n"
        f"  Messages: {msg_count or 0}\n"
        f"  Chats: {chat_count or 0}\n"
        f"  Last message: {last_sync.isoformat() if last_sync else 'Never'}\n\n"
        f"LLM usage (this session):\n"
        f"  Intent tokens: {usage['intent_input_tokens']} in / {usage['intent_output_tokens']} out\n"
        f"  Synthesis tokens: {usage['synthesis_input_tokens']} in / {usage['synthesis_output_tokens']} out\n"
        f"  Total tokens: {usage['input_tokens']} in / {usage['output_tokens']} out\n"
        f"  Estimated cost: ${usage['estimated_cost_usd']}"
    )
    await update.message.reply_text(stats_text)


# ---------------------------------------------------------------------------
# Scaffolding command handlers (simple UX presets)
# ---------------------------------------------------------------------------


@owner_only
async def handle_mentions(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle `/mentions` for attention triage."""
    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]
    audit: AuditLogger = context.bot_data["audit"]

    days, detail_mode, parse_err = _parse_window_and_detail_args(
        context.args or [],
        default_days=1,
    )
    if parse_err:
        await update.message.reply_text(
            f"{parse_err}\nUsage: /mentions [1d|3d|1w] [quick|detailed]"
        )
        return

    owner_id = _resolve_owner_user_id(update, context)
    normalized_aliases = _resolve_owner_mention_aliases(update, context)

    limit, context_max_chars, max_tokens = _detail_params(
        detail_mode,
        quick_limit=80,
        detailed_limit=160,
        quick_ctx_chars=12000,
        detailed_ctx_chars=22000,
        quick_max_tokens=1200,
        detailed_max_tokens=2600,
    )
    results = await search.mentions_needing_attention(
        owner_id=owner_id,
        mention_aliases=normalized_aliases,
        days_back=days,
        limit=limit,
    )

    if not results:
        await update.message.reply_text(
            f"No mention or reply-to-you items found in the last {days} day(s)."
        )
        return

    prompt = (
        f"Create a {detail_mode} triage briefing for the last {days} day(s). "
        "These messages are likely direct mentions or replies to me. "
        "Prioritize what needs my action. "
        "Use sections: "
        "<b>Act Now</b>, <b>Reply Soon</b>, <b>FYI</b>. "
        "For each item include chat, sender, and timestamp. "
        "If a section has no items, state 'none'."
    )
    answer = await llm.query(
        prompt,
        results,
        context_max_chars=context_max_chars,
        max_tokens_override=max_tokens,
        owner_user_id=owner_id,
        owner_aliases=normalized_aliases,
    )
    await _reply_answer(update, context, answer)

    await audit.log(
        "querybot",
        "command_mentions",
        {
            "days_back": days,
            "detail_mode": detail_mode,
            "results_count": len(results),
            "alias_count": len(normalized_aliases),
        },
        success=True,
    )


@owner_only
async def handle_bd(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle `/bd` unanswered-question triage command."""
    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]
    audit: AuditLogger = context.bot_data["audit"]

    days, detail_mode, parse_err = _parse_window_and_detail_args(
        context.args or [],
        default_days=1,
    )
    if parse_err:
        await update.message.reply_text(
            f"{parse_err}\nUsage: /bd [1d|3d|1w] [quick|detailed]"
        )
        return

    owner_id = _resolve_owner_user_id(update, context)
    owner_aliases = _resolve_owner_mention_aliases(update, context)
    limit, context_max_chars, max_tokens = _detail_params(
        detail_mode,
        quick_limit=80,
        detailed_limit=160,
        quick_ctx_chars=12000,
        detailed_ctx_chars=22000,
        quick_max_tokens=1200,
        detailed_max_tokens=2600,
    )
    results = await search.open_questions_needing_reply(
        owner_id=owner_id,
        days_back=days,
        limit=limit,
    )
    if not results:
        await update.message.reply_text(
            f"No likely-open unanswered questions found in the last {days} day(s)."
        )
        return

    total_candidates = len(results)
    prompt = (
        f"Create a {detail_mode} briefing of likely unanswered questions from the last {days} day(s). "
        f"There are {total_candidates} candidate question messages in context. "
        "These are questions that appear not to have a reply from me yet. "
        "Use sections: <b>Need My Reply</b>, <b>Could Wait</b>, <b>Low Priority</b>. "
        "Include as many concrete items as possible (not just one), each with chat, sender, timestamp, "
        "and key question text. If you cannot list everything due length, add a final line saying "
        "'More items not shown'."
    )
    answer = await llm.query(
        prompt,
        results,
        context_max_chars=context_max_chars,
        max_tokens_override=max_tokens,
        owner_user_id=owner_id,
        owner_aliases=owner_aliases,
    )
    await _reply_answer(update, context, answer)

    await audit.log(
        "querybot",
        "command_bd",
        {
            "days_back": days,
            "detail_mode": detail_mode,
            "results_count": len(results),
        },
        success=True,
    )


@owner_only
async def handle_summary(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle `/summary` for time-window cross-chat recaps."""
    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]
    audit: AuditLogger = context.bot_data["audit"]

    days, detail_mode, parse_err = _parse_window_and_detail_args(
        context.args or [],
        default_days=1,
    )
    if parse_err:
        await update.message.reply_text(
            f"{parse_err}\nUsage: /summary [1d|3d|1w] [quick|detailed]"
        )
        return

    if detail_mode == "detailed":
        chat_limit = 50
        per_chat_messages = 3
        context_max_chars = 24000
        max_tokens = 2800
    else:
        chat_limit = 25
        per_chat_messages = 2
        context_max_chars = 14000
        max_tokens = 1400

    results = await search.recent_chat_summary_context(
        chat_limit=chat_limit,
        per_chat_messages=per_chat_messages,
        days_back=days,
    )
    if not results:
        no_results_msg = await _get_sync_status_context(search._pool)
        await update.message.reply_text(no_results_msg)
        return

    prompt = (
        f"Create a {detail_mode} summary for the last {days} day(s) across my chats. "
        "Focus on what changed, key decisions, blockers, and action items for me. "
        "Start with the highest-priority actions first, then major updates. "
        "Include chat, sender, and time for each important point."
    )
    owner_id = _resolve_owner_user_id(update, context)
    owner_aliases = _resolve_owner_mention_aliases(update, context)
    answer = await llm.query(
        prompt,
        results,
        context_max_chars=context_max_chars,
        max_tokens_override=max_tokens,
        owner_user_id=owner_id,
        owner_aliases=owner_aliases,
    )
    await _reply_answer(update, context, answer)

    await audit.log(
        "querybot",
        "command_summary",
        {
            "days_back": days,
            "detail_mode": detail_mode,
            "chat_limit": chat_limit,
            "per_chat_messages": per_chat_messages,
            "results_count": len(results),
        },
        success=True,
    )


@owner_only
async def handle_fresh(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle `/fresh` for freshest-chat snapshots."""
    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]
    audit: AuditLogger = context.bot_data["audit"]

    chat_count, detail_mode, parse_err = _parse_fresh_args(
        context.args or [],
        default_count=25,
    )
    if parse_err:
        await update.message.reply_text(
            f"{parse_err}\nUsage: /fresh [10|25|50] [quick|detailed]"
        )
        return

    per_chat_messages, context_max_chars, max_tokens = (
        (4, 32000, 3600)
        if detail_mode == "detailed"
        else (2, 22000, 1700)
    )
    results = await search.recent_chat_summary_context(
        chat_limit=chat_count,
        per_chat_messages=per_chat_messages,
        days_back=30,
    )
    if not results:
        no_results_msg = await _get_sync_status_context(search._pool)
        await update.message.reply_text(no_results_msg)
        return

    prompt = (
        f"Give me a {detail_mode} synopsis of my {chat_count} freshest chats. "
        "For each chat, capture the current status, key updates, and whether I need to act. "
        "Prioritize chats with actionable items first. "
        "Keep each chat summary concise and include timestamps for important events."
    )
    owner_id = _resolve_owner_user_id(update, context)
    owner_aliases = _resolve_owner_mention_aliases(update, context)
    answer = await llm.query(
        prompt,
        results,
        context_max_chars=context_max_chars,
        max_tokens_override=max_tokens,
        owner_user_id=owner_id,
        owner_aliases=owner_aliases,
    )
    await _reply_answer(update, context, answer)

    await audit.log(
        "querybot",
        "command_fresh",
        {
            "chat_count": chat_count,
            "detail_mode": detail_mode,
            "per_chat_messages": per_chat_messages,
            "results_count": len(results),
        },
        success=True,
    )


@owner_only
async def handle_more(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle `/more` by sending the next chunk(s) of a long response."""
    pending = context.user_data.get(_PENDING_RESPONSE_CHUNKS_KEY, [])
    if not pending:
        status = context.user_data.get(_LAST_RESPONSE_STATUS_KEY)
        if status == "complete":
            await update.message.reply_text(
                "No pending response. That was the full previous response. "
                "For deeper coverage, rerun with detailed mode "
                "(e.g. /bd 3d detailed or /mentions 1w detailed)."
            )
        else:
            await update.message.reply_text("No pending response. Ask a new question first.")
        return
    await _reply_chunks(update, context, pending)


# ---------------------------------------------------------------------------
# Free-text message handler (the main query flow)
# ---------------------------------------------------------------------------


@owner_only
async def handle_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle a free-text message — the main query-answer pipeline.

    Flow:
        0. Validate user input (length, null bytes, whitespace).
        0.5 Route mentions/open-question triage prompts to dedicated pipelines.
        1. Fetch chat list (cached) for intent extraction context.
        2. Use Haiku to parse the question into structured filters.
        3. Run filtered search using extracted intent.
        4. Fall back to unfiltered FTS if filtered search returns nothing.
        5. Scan search results for prompt-injection patterns (detect + log).
        6. Send results + question to Sonnet for synthesis.
    """
    question = update.message.text

    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]
    audit: AuditLogger = context.bot_data["audit"]
    sanitizer: ContentSanitizer = context.bot_data["sanitizer"]
    validator: InputValidator = context.bot_data["input_validator"]

    # 0. Input validation
    validation = validator.validate(question)
    if not validation.valid:
        await update.message.reply_text(validation.error_message)
        return
    # New question supersedes any leftover /more backlog.
    context.user_data.pop(_PENDING_RESPONSE_CHUNKS_KEY, None)
    context.user_data.pop(_LAST_RESPONSE_STATUS_KEY, None)

    # 0.5 Natural-language mentions/replies triage mode.
    mention_days = _extract_mentions_window_days(question)
    if mention_days is not None:
        detail_mode = "detailed" if "detail" in question.lower() else "quick"
        owner_id = _resolve_owner_user_id(update, context)
        aliases = _resolve_owner_mention_aliases(update, context)
        limit, context_max_chars, max_tokens = _detail_params(
            detail_mode,
            quick_limit=80,
            detailed_limit=160,
            quick_ctx_chars=12000,
            detailed_ctx_chars=22000,
            quick_max_tokens=1200,
            detailed_max_tokens=2600,
        )
        mention_results = await search.mentions_needing_attention(
            owner_id=owner_id,
            mention_aliases=aliases,
            days_back=mention_days,
            limit=limit,
        )
        if not mention_results:
            await update.message.reply_text(
                f"No mention or reply-to-you items found in the last {mention_days} day(s)."
            )
            return

        prompt = (
            f"Create a {detail_mode} triage briefing for the last {mention_days} day(s). "
            "These messages are likely direct mentions or replies to me. "
            "Prioritize what needs my action. "
            "Use sections: "
            "<b>Act Now</b>, <b>Reply Soon</b>, <b>FYI</b>. "
            "For each item include chat, sender, and timestamp. "
            "If a section has no items, state 'none'."
        )
        answer = await llm.query(
            prompt,
            mention_results,
            context_max_chars=context_max_chars,
            max_tokens_override=max_tokens,
            owner_user_id=owner_id,
            owner_aliases=aliases,
        )
        await _reply_answer(update, context, answer)
        await audit.log(
            "querybot",
            "query_mentions",
            {
                "question_length": len(question),
                "days_back": mention_days,
                "detail_mode": detail_mode,
                "results_count": len(mention_results),
                "alias_count": len(aliases),
            },
            success=True,
        )
        return

    # 0.6 Natural-language unanswered/open-questions mode.
    bd_days = _extract_open_questions_window_days(question)
    if bd_days is not None:
        detail_mode = "detailed" if "detail" in question.lower() else "quick"
        owner_id = _resolve_owner_user_id(update, context)
        owner_aliases = _resolve_owner_mention_aliases(update, context)
        limit, context_max_chars, max_tokens = _detail_params(
            detail_mode,
            quick_limit=80,
            detailed_limit=160,
            quick_ctx_chars=12000,
            detailed_ctx_chars=22000,
            quick_max_tokens=1200,
            detailed_max_tokens=2600,
        )
        open_questions = await search.open_questions_needing_reply(
            owner_id=owner_id,
            days_back=bd_days,
            limit=limit,
        )
        if not open_questions:
            await update.message.reply_text(
                f"No likely-open unanswered questions found in the last {bd_days} day(s)."
            )
            return

        total_candidates = len(open_questions)
        prompt = (
            f"Create a {detail_mode} briefing of likely unanswered questions from the last {bd_days} day(s). "
            f"There are {total_candidates} candidate question messages in context. "
            "These are questions that appear not to have a reply from me yet. "
            "Use sections: <b>Need My Reply</b>, <b>Could Wait</b>, <b>Low Priority</b>. "
            "Include as many concrete items as possible (not just one), each with chat, sender, timestamp, "
            "and key question text. If you cannot list everything due length, add a final line saying "
            "'More items not shown'."
        )
        answer = await llm.query(
            prompt,
            open_questions,
            context_max_chars=context_max_chars,
            max_tokens_override=max_tokens,
            owner_user_id=owner_id,
            owner_aliases=owner_aliases,
        )
        await _reply_answer(update, context, answer)
        await audit.log(
            "querybot",
            "query_bd",
            {
                "question_length": len(question),
                "days_back": bd_days,
                "detail_mode": detail_mode,
                "results_count": len(open_questions),
            },
            success=True,
        )
        return

    # 1. Get chat list + extract intent
    max_intent_chats = context.bot_data.get("max_intent_chats")
    chat_list_limit = (
        max_intent_chats
        if isinstance(max_intent_chats, int) and max_intent_chats > 0
        else None
    )
    chat_list = await search.get_chat_list(limit=chat_list_limit)
    intent = await llm.extract_query_intent(question, chat_list)

    recent_summary_default = context.bot_data.get(
        "recent_summary_default_chat_count", 20
    )
    recent_summary_max = context.bot_data.get(
        "recent_summary_max_chat_count", 75
    )
    recent_summary_per_chat_messages = context.bot_data.get(
        "recent_summary_per_chat_messages", 2
    )
    recent_summary_context_max_chars = context.bot_data.get(
        "recent_summary_context_max_chars", 22000
    )
    recent_chat_target = _extract_recent_chat_summary_target(
        question,
        default_count=recent_summary_default,
        max_count=recent_summary_max,
    )
    try:
        recent_summary_per_chat_messages = max(
            1, int(recent_summary_per_chat_messages)
        )
    except (TypeError, ValueError):
        recent_summary_per_chat_messages = 2
    recent_summary_mode = (
        recent_chat_target is not None
        and not intent.chat_ids
        and intent.sender_name is None
    )

    # 2. Filtered search using extracted intent
    if recent_summary_mode:
        days_back = intent.days_back if intent.days_back is not None else 30
        results = await search.recent_chat_summary_context(
            chat_limit=recent_chat_target,
            per_chat_messages=recent_summary_per_chat_messages,
            days_back=days_back,
        )
    else:
        # Use higher limit for browse queries (no search terms = summarize)
        browse_limit = 50 if not intent.search_terms else 20
        results = await search.filtered_search(
            search_terms=intent.search_terms,
            chat_ids=intent.chat_ids,
            sender_name=intent.sender_name,
            days_back=intent.days_back,
            limit=browse_limit,
        )

    # 3. Fallback: if filtered search found nothing but had filters,
    #    try unfiltered FTS with the original question
    if (
        not results
        and not recent_summary_mode
        and (intent.chat_ids or intent.sender_name or intent.days_back)
    ):
        logger.info("Filtered search empty, falling back to unfiltered FTS")
        results = await search.full_text_search(question)

    if not results:
        no_results_msg = await _get_sync_status_context(search._pool)
        await update.message.reply_text(no_results_msg)
        return

    # 3.5. Enforce max context size (track truncation)
    max_ctx = context.bot_data.get("max_context_messages")
    if recent_summary_mode and isinstance(max_ctx, int) and max_ctx > 0:
        target_msgs = recent_chat_target * recent_summary_per_chat_messages
        max_ctx = max(max_ctx, min(target_msgs, 400))
    context_truncated = False
    if isinstance(max_ctx, int) and max_ctx > 0 and len(results) > max_ctx:
        results = results[:max_ctx]
        context_truncated = True

    # 4. Scan search results for injection patterns (detect + log only)
    injection_warnings_count = 0
    for r in results:
        if r.text:
            scan = sanitizer.sanitize(r.text)
            if scan.flagged:
                injection_warnings_count += len(scan.warnings)

    # 5. Ask Claude
    context_max_chars = (
        recent_summary_context_max_chars if recent_summary_mode else 8000
    )
    owner_id = _resolve_owner_user_id(update, context)
    owner_aliases = _resolve_owner_mention_aliases(update, context)
    answer = await llm.query(
        question,
        results,
        context_max_chars=context_max_chars,
        owner_user_id=owner_id,
        owner_aliases=owner_aliases,
    )

    # 6. Reply
    await _reply_answer(update, context, answer)

    # 7. Audit (metadata only — never log message content)
    await audit.log(
        "querybot",
        "query",
        {
            "question_length": len(question),
            "results_count": len(results),
            "answer_length": len(answer),
            "intent_chat_ids": intent.chat_ids,
            "intent_has_search_terms": intent.search_terms is not None,
            "intent_days_back": intent.days_back,
            "injection_warnings_count": injection_warnings_count,
            "context_truncated": context_truncated,
            "max_context_messages": max_ctx,
            "recent_summary_mode": recent_summary_mode,
            "recent_summary_target_chats": recent_chat_target if recent_summary_mode else 0,
        },
        success=True,
    )


# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------


async def error_handler(
    update: object, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Global error handler for unhandled exceptions in handlers."""
    logger.exception("Unhandled error", exc_info=context.error)

    # Notify the user with a generic message if possible
    if isinstance(update, Update) and update.effective_chat:
        try:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="An error occurred. Please try again.",
            )
        except Exception:
            logger.exception("Failed to send error message to user")

    # Audit log
    audit: AuditLogger | None = context.bot_data.get("audit")
    if audit:
        await audit.log(
            "querybot",
            "unhandled_error",
            {"error": str(context.error)},
            success=False,
        )
