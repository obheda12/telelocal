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
from shared.audit import AuditLogger
from shared.db import get_connection_pool
from shared.secrets import get_secret

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
        KeyError: If required keys are missing (e.g. ``bot.owner_id``).
    """
    # TODO: implement — load TOML, validate required keys
    #   (bot.token via keychain, bot.owner_id, database.*, claude.*)
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Owner-only filter
# ---------------------------------------------------------------------------


def build_owner_filter(owner_id: int) -> filters.BaseFilter:
    """Return a ``python-telegram-bot`` filter that passes only for *owner_id*.

    Messages from any other user are silently dropped — no error reply
    is sent (to avoid revealing the bot's existence to strangers).

    Args:
        owner_id: Telegram user ID of the bot owner.
    """
    # TODO: implement
    #   - Return filters.User(user_id=owner_id)
    raise NotImplementedError


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

    Args:
        config: Parsed configuration dictionary.

    Returns:
        A fully configured ``Application`` instance (not yet running).
    """
    # TODO: implement
    #   1. Retrieve bot token from keychain:  get_secret("bot_token")
    #   2. Create Application via Application.builder().token(token).build()
    #   3. Initialise DB pool, audit, search, LLM — store in bot_data
    #   4. Register handlers:
    #        app.add_handler(CommandHandler("start", handle_start))
    #        app.add_handler(CommandHandler("help", handle_help))
    #        app.add_handler(CommandHandler("stats", handle_stats))
    #        owner_filter = build_owner_filter(config["bot"]["owner_id"])
    #        app.add_handler(MessageHandler(
    #            filters.TEXT & ~filters.COMMAND & owner_filter,
    #            handle_message,
    #        ))
    #        app.add_error_handler(error_handler)
    #   5. Return app
    raise NotImplementedError


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
    # TODO: implement
    #   app = asyncio.run(build_application(config))
    #   app.run_polling(allowed_updates=Update.ALL_TYPES)
    raise NotImplementedError


if __name__ == "__main__":
    run()
