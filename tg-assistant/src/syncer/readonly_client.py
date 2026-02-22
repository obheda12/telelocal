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

import logging
import time
from weakref import WeakKeyDictionary
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

# Keep internal state out of instance attributes so simple
# ``object.__getattribute__(wrapper, "_client")`` bypasses fail closed.
_CLIENT_MAP: "WeakKeyDictionary[ReadOnlyTelegramClient, TelethonClient]" = WeakKeyDictionary()
_ALLOWED_MAP: "WeakKeyDictionary[ReadOnlyTelegramClient, FrozenSet[str]]" = WeakKeyDictionary()


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

    __slots__ = ("__weakref__",)

    def __init__(self, client: TelethonClient) -> None:
        _CLIENT_MAP[self] = client
        _ALLOWED_MAP[self] = ALLOWED_METHODS

    @staticmethod
    def _state(self: "ReadOnlyTelegramClient") -> tuple[TelethonClient, FrozenSet[str]]:
        client = _CLIENT_MAP.get(self)
        allowed = _ALLOWED_MAP.get(self)
        if client is None or allowed is None:
            raise PermissionError("ReadOnlyTelegramClient: internal state unavailable.")
        return client, allowed

    # ----- async context manager ------------------------------------------

    async def __aenter__(self) -> "ReadOnlyTelegramClient":
        """Connect the underlying client and return *self* (the wrapper)."""
        client, _ = ReadOnlyTelegramClient._state(self)
        await client.connect()
        logger.info("ReadOnlyTelegramClient connected.")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Disconnect the underlying client."""
        client, _ = ReadOnlyTelegramClient._state(self)
        await client.disconnect()
        logger.info("ReadOnlyTelegramClient disconnected.")

    # ----- attribute proxy ------------------------------------------------

    def __getattribute__(self, name: str) -> Any:
        """Proxy attribute access with an allowlist check.

        Allowed methods are returned as-is from the underlying client.
        Blocked methods trigger an audit log entry and raise PermissionError.

        Attributes that are *not* callable (e.g. ``client.session``) are also
        blocked — only the explicit method names are permitted.
        """
        # Always allow access to the wrapper's own public protocol methods.
        if name in {
            "__class__",
            "__repr__",
            "__aenter__",
            "__aexit__",
            "__setattr__",
            "__delattr__",
            "__getattribute__",
            "_state",
        }:
            return object.__getattribute__(self, name)

        # Block direct access to internals to prevent bypassing the allowlist.
        if name in {"_client", "_allowed", "__dict__", "__weakref__"} or name.startswith("_"):
            logger.critical(
                "BLOCKED  | attr=%-27s ts=%s  — internal attribute access denied",
                name,
                time.time(),
            )
            raise PermissionError(
                f"ReadOnlyTelegramClient: internal attribute access to '{name}' is denied."
            )

        try:
            client, allowed = ReadOnlyTelegramClient._state(self)

            if name in allowed:
                attr = getattr(client, name)
                if not callable(attr):
                    raise PermissionError(
                        f"ReadOnlyTelegramClient: allowed member '{name}' is not callable."
                    )
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
                f"Only these methods are permitted: {sorted(allowed)}"
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
        client, allowed = ReadOnlyTelegramClient._state(self)
        return (
            f"<ReadOnlyTelegramClient "
            f"allowed={sorted(allowed)} "
            f"connected={client.is_connected()}>"
        )
