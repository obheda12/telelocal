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

import asyncio
import logging
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
from shared.secrets import get_secret
from syncer.embeddings import create_embedding_provider

logger = logging.getLogger("querybot.main")

_DEFAULT_CONFIG_PATH = Path("/etc/tg-assistant/settings.toml")


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


async def build_application(config: Dict[str, Any]) -> Application:
    """Construct and configure the ``python-telegram-bot`` Application.

    Wires up:
        - Database connection pool (SELECT-only role for querybot).
        - Audit logger.
        - LLM client (Claude).
        - Search module.
        - Command handlers (``/start``, ``/help``, ``/stats``).
        - Free-text message handler (owner-only).
        - Global error handler.
    """
    # 1. Retrieve bot token from keychain
    bot_token = get_secret(config["querybot"]["bot_token_keychain_key"])

    # 2. Create Application
    app = Application.builder().token(bot_token).build()

    # 3. Initialise infrastructure
    pool = await get_connection_pool(config["database"])
    await init_database(pool)

    audit_log_path = Path(
        config.get("security", {}).get("log_file", "/var/log/tg-assistant/audit.log")
    )
    audit = AuditLogger(pool, log_path=audit_log_path)

    embedder = create_embedding_provider(config.get("embeddings", {}))
    search = MessageSearch(pool, embedder)

    claude_config = config["querybot"]["claude"]
    claude_api_key = get_secret(claude_config["api_key_keychain_key"])
    llm = ClaudeAssistant(
        api_key=claude_api_key,
        model=claude_config.get("model", "claude-sonnet-4-5-20250929"),
        max_queries_per_minute=config["querybot"].get("max_queries_per_minute", 20),
    )

    owner_id = config["querybot"]["owner_telegram_id"]

    # 4. Store in bot_data for handler access
    app.bot_data["owner_id"] = owner_id
    app.bot_data["search"] = search
    app.bot_data["llm"] = llm
    app.bot_data["audit"] = audit
    app.bot_data["pool"] = pool

    # 5. Register handlers with owner filter
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

    # python-telegram-bot manages its own event loop via run_polling()
    app = asyncio.run(build_application(config))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    run()
