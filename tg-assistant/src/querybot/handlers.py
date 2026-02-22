"""
Telegram bot handler functions for the query bot.

All handlers that access user data are guarded by the owner-only filter
(configured in ``querybot.main``).  The bot silently ignores messages
from non-owner users.
"""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable, Coroutine, List

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
            "Check progress on the server with: telenad sync-status"
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
async def handle_help(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle the ``/help`` command."""
    help_text = (
        "Available commands:\n"
        "  /start - Welcome message\n"
        "  /help  - This help text\n"
        "  /stats - Sync and usage statistics\n\n"
        "How to use:\n"
        "  Just send me a question in plain text! I'll search your "
        "synced Telegram messages and answer using Claude.\n\n"
        "Tips for effective queries:\n"
        '  - Be specific: "What did Alice say about the project deadline?"\n'
        '  - Ask for summaries: "Summarise the discussion in DevChat yesterday"\n'
        '  - Search by topic: "Find messages about Python deployment"'
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
# Free-text message handler (the main query flow)
# ---------------------------------------------------------------------------


@owner_only
async def handle_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Handle a free-text message — the main query-answer pipeline.

    Flow:
        0. Validate user input (length, null bytes, whitespace).
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

    # 1. Get chat list + extract intent
    chat_list = await search.get_chat_list()
    intent = await llm.extract_query_intent(question, chat_list)

    # 2. Filtered search using extracted intent
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
    if not results and (intent.chat_ids or intent.sender_name or intent.days_back):
        logger.info("Filtered search empty, falling back to unfiltered FTS")
        results = await search.full_text_search(question)

    if not results:
        no_results_msg = await _get_sync_status_context(search._pool)
        await update.message.reply_text(no_results_msg)
        return

    # 3.5. Enforce max context size (track truncation)
    max_ctx = context.bot_data.get("max_context_messages")
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
    answer = await llm.query(question, results)

    # 6. Reply (split if > 4096 chars — Telegram message limit)
    for chunk in _split_message(answer):
        try:
            await update.message.reply_text(
                chunk, parse_mode=ParseMode.HTML
            )
        except Exception:
            # Claude may produce malformed HTML tags; fall back to plain text
            logger.debug("HTML parse failed for chunk, retrying as plain text")
            await update.message.reply_text(chunk)

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
