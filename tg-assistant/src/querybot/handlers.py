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
from telegram.ext import ContextTypes

from querybot.llm import ClaudeAssistant
from querybot.search import MessageSearch
from shared.audit import AuditLogger

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

    sync_stats = await search._pool.fetchval("SELECT COUNT(*) FROM messages")
    chat_count = await search._pool.fetchval("SELECT COUNT(*) FROM chats")
    last_sync = await search._pool.fetchval("SELECT MAX(timestamp) FROM messages")

    usage = llm.get_usage_stats()

    stats_text = (
        f"Sync statistics:\n"
        f"  Messages: {sync_stats or 0}\n"
        f"  Chats: {chat_count or 0}\n"
        f"  Last sync: {last_sync.isoformat() if last_sync else 'Never'}\n\n"
        f"LLM usage (this session):\n"
        f"  Input tokens: {usage['input_tokens']}\n"
        f"  Output tokens: {usage['output_tokens']}\n"
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
        1. Fetch chat list (cached) for intent extraction context.
        2. Use Haiku to parse the question into structured filters.
        3. Run filtered search using extracted intent.
        4. Fall back to unfiltered FTS if filtered search returns nothing.
        5. Send results + question to Sonnet for synthesis.
    """
    question = update.message.text

    search: MessageSearch = context.bot_data["search"]
    llm: ClaudeAssistant = context.bot_data["llm"]
    audit: AuditLogger = context.bot_data["audit"]

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
        await update.message.reply_text(
            "No relevant messages found. Try broadening your search "
            "or check that the chat has been synced."
        )
        return

    # 4. Ask Claude
    answer = await llm.query(question, results)

    # 5. Reply (split if > 4096 chars — Telegram message limit)
    for chunk in _split_message(answer):
        await update.message.reply_text(chunk)

    # 6. Audit (metadata only — never log message content)
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
