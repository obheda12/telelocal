"""
Query bot entry point — starts the Telegram bot that answers
natural-language questions about synced messages.

Runs as a long-lived systemd service under the ``tg-querybot`` user.

Key behaviours:
    - Loads configuration from ``/etc/tg-assistant/settings.toml``.
    - Uses ``python-telegram-bot`` (Bot API, not MTProto).
    - Owner-only: silently drops every message not from ``owner_id``.
    - Registers command and message handlers.
    - Starts long-polling (webhook mode is possible but not default).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict

import toml
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
)

from querybot.handlers import (
    handle_help,
    handle_message,
    handle_start,
    handle_stats,
    error_handler,
)
from querybot.llm import ClaudeAssistant
from querybot.search import MessageSearch
from shared.audit import AuditLogger
from shared.db import get_connection_pool, init_database
from shared.safety import ContentSanitizer, InputValidator
from shared.secrets import get_secret
from syncer.embeddings import create_embedding_provider

logger = logging.getLogger("querybot.main")

_DEFAULT_CONFIG_PATH = Path(
    os.environ.get("TG_ASSISTANT_CONFIG", "/etc/tg-assistant/settings.toml")
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config(path: Path = _DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Load and validate settings from a TOML file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        KeyError: If required keys are missing.
    """
    config = toml.load(path)

    # Validate required keys
    required = [
        ("querybot", "owner_telegram_id"),
        ("querybot", "bot_token_keychain_key"),
        ("database",),
        ("querybot", "claude"),
    ]
    for keys in required:
        obj = config
        for k in keys:
            if k not in obj:
                raise KeyError(f"Missing required config key: {'.'.join(keys)}")
            obj = obj[k]

    return config


# ---------------------------------------------------------------------------
# Owner-only filter
# ---------------------------------------------------------------------------


def build_owner_filter(owner_id: int) -> filters.BaseFilter:
    """Return a ``python-telegram-bot`` filter that passes only for *owner_id*.

    Messages from any other user are silently dropped — no error reply
    is sent (to avoid revealing the bot's existence to strangers).
    """
    return filters.User(user_id=owner_id)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def build_application(config: Dict[str, Any]) -> Application:
    """Construct and configure the ``python-telegram-bot`` Application.

    Wires up:
        - Database connection pool (SELECT-only role for querybot).
        - Audit logger.
        - LLM client (Claude).
        - Search module.
        - Command handlers (``/start``, ``/help``, ``/stats``).
        - Free-text message handler (owner-only).
        - Global error handler.

    Async initialisation (DB pool, etc.) is deferred to ``post_init``
    so that ``run_polling()`` manages the single event loop — required
    for Python 3.12+ where ``asyncio.get_event_loop()`` raises
    ``RuntimeError`` when no loop is running.
    """
    # 1. Retrieve bot token from keychain
    bot_token = get_secret(config["querybot"]["bot_token_keychain_key"])

    async def _post_init(app: Application) -> None:
        """Called by python-telegram-bot inside the running event loop."""
        # 3. Initialise infrastructure (Unix socket + peer auth)
        db_config = dict(config["database"])
        db_config["user"] = config["querybot"].get("db_user", "tg_querybot")
        pool = await get_connection_pool(db_config)
        await init_database(pool)

        audit_log_path = Path(
            config.get("security", {}).get("log_file", "/var/log/tg-assistant/audit.log")
        )
        audit = AuditLogger(pool, log_path=audit_log_path)

        embedder = create_embedding_provider(config.get("embeddings", {}))
        search = MessageSearch(
            pool,
            embedder,
            hybrid_min_terms=config["querybot"].get("hybrid_min_terms", 2),
            hybrid_min_term_length=config["querybot"].get(
                "hybrid_min_term_length", 3
            ),
        )

        claude_config = config["querybot"]["claude"]
        claude_api_key = get_secret(claude_config["api_key_keychain_key"])
        llm = ClaudeAssistant(
            api_key=claude_api_key,
            model=claude_config.get("model", "claude-sonnet-4-5-20250929"),
            max_queries_per_minute=config["querybot"].get("max_queries_per_minute", 20),
            haiku_input_cost_per_m=claude_config.get("haiku_input_cost_per_m", 0.0),
            haiku_output_cost_per_m=claude_config.get("haiku_output_cost_per_m", 0.0),
        )

        owner_id = config["querybot"]["owner_telegram_id"]
        max_context_messages = config["querybot"].get("max_context_messages", 50)
        max_intent_chats = config["querybot"].get("max_intent_chats", 200)

        security_config = config.get("security", {})
        sanitizer = ContentSanitizer(
            enabled=security_config.get("detect_prompt_injection", True),
        )
        input_validator = InputValidator(
            max_length=security_config.get("max_input_length", 4000),
        )

        # 4. Store in bot_data for handler access
        app.bot_data["owner_id"] = owner_id
        app.bot_data["max_context_messages"] = max_context_messages
        app.bot_data["max_intent_chats"] = max_intent_chats
        app.bot_data["search"] = search
        app.bot_data["llm"] = llm
        app.bot_data["audit"] = audit
        app.bot_data["pool"] = pool
        app.bot_data["sanitizer"] = sanitizer
        app.bot_data["input_validator"] = input_validator

    async def _post_shutdown(app: Application) -> None:
        audit = app.bot_data.get("audit")
        if audit:
            await audit.close()
        pool = app.bot_data.get("pool")
        if pool:
            await pool.close()

    # 2. Create Application with post_init for async setup
    app = Application.builder().token(bot_token).post_init(_post_init).post_shutdown(_post_shutdown).build()

    # 5. Register handlers with owner filter
    owner_id = config["querybot"]["owner_telegram_id"]
    owner_filter = build_owner_filter(owner_id)
    app.add_handler(CommandHandler("start", handle_start, filters=owner_filter))
    app.add_handler(CommandHandler("help", handle_help, filters=owner_filter))
    app.add_handler(CommandHandler("stats", handle_stats, filters=owner_filter))
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND & owner_filter,
            handle_message,
        )
    )
    app.add_error_handler(error_handler)

    return app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> None:
    """Synchronous entry point (called from ``__main__`` or systemd)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    config = load_config()

    # python-telegram-bot manages the event loop via run_polling();
    # async init (DB pool, etc.) happens in post_init callback.
    app = build_application(config)
    # Restrict the update surface to plain messages and commands.
    app.run_polling(allowed_updates=[Update.MESSAGE])


if __name__ == "__main__":
    run()
