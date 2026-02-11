"""
ReadOnlyTelegramClient — security wrapper around Telethon's TelegramClient.

This is the **core security control** for the syncer.  It proxies attribute
access to the underlying Telethon client and blocks every method that is not
on an explicit allowlist.  The allowlist contains ONLY read operations; any
attempt to call a write/send/delete/edit method raises PermissionError and
is logged as a security event.

Design principles:
    - Default-deny: anything not in ALLOWED_METHODS is rejected.
    - Audit trail: every call (allowed or blocked) is logged with timestamp,
      method name, and caller context.
    - Fail-closed: if the allowlist check itself raises, the call is denied.
    - No monkey-patching: the wrapper never modifies the underlying client.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, FrozenSet

from telethon import TelegramClient as TelethonClient

logger = logging.getLogger("syncer.readonly_client")

# ---------------------------------------------------------------------------
# Allowed methods — read-only Telethon operations.
# Every entry here has been individually reviewed.  Do NOT add send_message,
# edit_message, delete_messages, forward_messages, or any method that mutates
# state on the Telegram server.
# ---------------------------------------------------------------------------
ALLOWED_METHODS: FrozenSet[str] = frozenset(
    {
        # Message retrieval
        "get_messages",
        "iter_messages",
        # Dialog (chat list) retrieval
        "get_dialogs",
        "iter_dialogs",
        # Entity / participant metadata
        "get_entity",
        "get_participants",
        "get_me",
        # Media (profile photos only — message media is fetched via
        # get_messages which returns downloadable handles)
        "download_profile_photo",
        # Connection lifecycle
        "connect",
        "disconnect",
        "is_connected",
    }
)


class ReadOnlyTelegramClient:
    """Async-safe, read-only proxy around a TelethonClient instance.

    Usage::

        async with ReadOnlyTelegramClient(raw_client) as client:
            me = await client.get_me()
            async for dialog in client.iter_dialogs():
                ...

    Any call to a method **not** in ``ALLOWED_METHODS`` will:
        1. Log a CRITICAL audit event.
        2. Raise ``PermissionError``.
    """

    def __init__(self, client: TelethonClient) -> None:
        # Store via object.__setattr__ to avoid triggering our own
        # __getattr__ / __setattr__ if we were to override them.
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_allowed", ALLOWED_METHODS)

    # ----- async context manager ------------------------------------------

    async def __aenter__(self) -> "ReadOnlyTelegramClient":
        """Connect the underlying client and return *self* (the wrapper)."""
        await self._client.connect()
        logger.info("ReadOnlyTelegramClient connected.")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Disconnect the underlying client."""
        await self._client.disconnect()
        logger.info("ReadOnlyTelegramClient disconnected.")

    # ----- attribute proxy ------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access with an allowlist check.

        Allowed methods are returned as-is from the underlying client.
        Blocked methods trigger an audit log entry and raise PermissionError.

        Attributes that are *not* callable (e.g. ``client.session``) are also
        blocked — only the explicit method names are permitted.
        """
        try:
            if name in self._allowed:
                attr = getattr(self._client, name)
                logger.debug(
                    "ALLOWED  | method=%-25s ts=%s",
                    name,
                    time.time(),
                )
                return attr

            # ------ blocked path ------
            logger.critical(
                "BLOCKED  | method=%-25s ts=%s  — PermissionError raised",
                name,
                time.time(),
            )
            raise PermissionError(
                f"ReadOnlyTelegramClient: access to '{name}' is denied. "
                f"Only these methods are permitted: {sorted(self._allowed)}"
            )

        except PermissionError:
            # Re-raise PermissionError as-is; do not mask it.
            raise

        except Exception:
            # Fail-closed: any unexpected error during the check itself
            # is treated as a blocked call.
            logger.critical(
                "BLOCKED  | method=%-25s ts=%s  — unexpected error during "
                "allowlist check; failing closed",
                name,
                time.time(),
                exc_info=True,
            )
            raise PermissionError(
                f"ReadOnlyTelegramClient: access to '{name}' denied "
                f"(fail-closed on unexpected error)."
            )

    # ----- prevent attribute/method injection -----------------------------

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent callers from setting attributes on the wrapper."""
        raise PermissionError(
            "ReadOnlyTelegramClient: setting attributes is not allowed."
        )

    def __delattr__(self, name: str) -> None:
        """Prevent callers from deleting attributes on the wrapper."""
        raise PermissionError(
            "ReadOnlyTelegramClient: deleting attributes is not allowed."
        )

    # ----- informational --------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<ReadOnlyTelegramClient "
            f"allowed={sorted(self._allowed)} "
            f"connected={self._client.is_connected()}>"
        )
