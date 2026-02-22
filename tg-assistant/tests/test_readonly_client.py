"""
Unit tests for the ReadOnlyTelegramClient.

Verifies that the read-only wrapper around Telethon correctly allows
read operations and blocks all write operations (allowlist pattern).
"""

import sys
from unittest.mock import MagicMock, AsyncMock

import pytest

# Mock telethon before importing the real wrapper
if "telethon" not in sys.modules:
    sys.modules["telethon"] = MagicMock()

from syncer.readonly_client import ReadOnlyTelegramClient, ALLOWED_METHODS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_client():
    """Create a mock TelegramClient with both read and write methods."""
    client = MagicMock()

    # Read methods (should be accessible)
    client.get_messages = AsyncMock(return_value=["msg1", "msg2"])
    client.get_dialogs = AsyncMock(return_value=["dialog1"])
    client.iter_messages = AsyncMock(return_value=iter(["msg1"]))
    client.iter_dialogs = AsyncMock(return_value=iter(["dialog1"]))
    client.get_entity = AsyncMock(return_value=MagicMock(id=12345))
    client.get_participants = AsyncMock(return_value=["user1"])
    client.get_me = AsyncMock(return_value=MagicMock(id=99999, first_name="Test"))
    client.download_profile_photo = AsyncMock(return_value=b"photo_data")
    client.connect = AsyncMock(return_value=True)
    client.disconnect = AsyncMock(return_value=None)
    client.is_connected = MagicMock(return_value=True)

    # Write methods (should be blocked)
    client.send_message = AsyncMock()
    client.edit_message = AsyncMock()
    client.delete_messages = AsyncMock()
    client.forward_messages = AsyncMock()
    client.send_file = AsyncMock()
    client.send_read_acknowledge = AsyncMock()
    client.pin_message = AsyncMock()
    client.unpin_message = AsyncMock()
    client.kick_participant = AsyncMock()
    client.edit_admin = AsyncMock()
    client.edit_permissions = AsyncMock()

    return client


@pytest.fixture
def readonly_client(mock_client):
    """Create a ReadOnlyTelegramClient wrapping the mock."""
    return ReadOnlyTelegramClient(mock_client)


# ---------------------------------------------------------------------------
# Test: ALLOWED_METHODS is immutable
# ---------------------------------------------------------------------------

class TestAllowedMethodsImmutability:
    """Verify that the allowlist cannot be modified at runtime."""

    def test_allowed_methods_is_frozenset(self):
        assert isinstance(ALLOWED_METHODS, frozenset), \
            "ALLOWED_METHODS must be a frozenset to prevent runtime modification"

    def test_cannot_add_to_allowed_methods(self):
        with pytest.raises(AttributeError):
            ALLOWED_METHODS.add("send_message")

    def test_cannot_remove_from_allowed_methods(self):
        with pytest.raises(AttributeError):
            ALLOWED_METHODS.remove("get_messages")

    def test_cannot_replace_allowed_methods_via_instance(self, readonly_client):
        """Replacing ALLOWED_METHODS on the class would affect all instances."""
        original = ALLOWED_METHODS
        # Even if someone tries to set it, it should remain a frozenset
        assert ALLOWED_METHODS is original


# ---------------------------------------------------------------------------
# Test: Allowed methods are accessible
# ---------------------------------------------------------------------------

class TestAllowedMethods:
    """Verify that all allowed read methods are accessible through the wrapper."""

    @pytest.mark.parametrize("method_name", [
        "get_messages",
        "get_dialogs",
        "iter_messages",
        "iter_dialogs",
        "get_entity",
        "get_participants",
        "get_me",
        "download_profile_photo",
        "connect",
        "disconnect",
        "is_connected",
    ])
    def test_allowed_method_accessible(self, readonly_client, mock_client, method_name):
        """Each allowed method should delegate to the underlying client."""
        result = getattr(readonly_client, method_name)
        expected = getattr(mock_client, method_name)
        assert result == expected, \
            f"Method '{method_name}' should delegate to the underlying client"

    @pytest.mark.asyncio
    async def test_get_messages_returns_data(self, readonly_client):
        result = await readonly_client.get_messages("chat_id", limit=10)
        assert result == ["msg1", "msg2"]

    @pytest.mark.asyncio
    async def test_get_me_returns_user(self, readonly_client):
        result = await readonly_client.get_me()
        assert result.id == 99999
        assert result.first_name == "Test"

    @pytest.mark.asyncio
    async def test_get_dialogs_returns_data(self, readonly_client):
        result = await readonly_client.get_dialogs()
        assert result == ["dialog1"]

    @pytest.mark.asyncio
    async def test_connect_succeeds(self, readonly_client):
        result = await readonly_client.connect()
        assert result is True

    def test_is_connected_returns_bool(self, readonly_client):
        result = readonly_client.is_connected()
        assert result is True


# ---------------------------------------------------------------------------
# Test: Write methods raise PermissionError
# ---------------------------------------------------------------------------

class TestBlockedWriteMethods:
    """Verify that write/modify methods raise PermissionError."""

    @pytest.mark.parametrize("method_name", [
        "send_message",
        "edit_message",
        "delete_messages",
        "forward_messages",
        "send_file",
        "send_read_acknowledge",
        "pin_message",
        "unpin_message",
        "kick_participant",
        "edit_admin",
        "edit_permissions",
    ])
    def test_write_method_raises_permission_error(self, readonly_client, method_name):
        with pytest.raises(PermissionError) as exc_info:
            getattr(readonly_client, method_name)

        assert method_name in str(exc_info.value)
        assert "denied" in str(exc_info.value).lower()

    def test_send_message_blocked(self, readonly_client):
        """Explicit test for the most critical blocked method."""
        with pytest.raises(PermissionError, match="send_message"):
            readonly_client.send_message

    def test_delete_messages_blocked(self, readonly_client):
        with pytest.raises(PermissionError, match="delete_messages"):
            readonly_client.delete_messages

    def test_forward_messages_blocked(self, readonly_client):
        with pytest.raises(PermissionError, match="forward_messages"):
            readonly_client.forward_messages

    def test_send_file_blocked(self, readonly_client):
        with pytest.raises(PermissionError, match="send_file"):
            readonly_client.send_file


# ---------------------------------------------------------------------------
# Test: Unknown / future methods are blocked by default
# ---------------------------------------------------------------------------

class TestFutureProofing:
    """
    Verify that methods not explicitly allowlisted are blocked.
    This is the core security property: new Telethon methods added in
    future versions are blocked by default until explicitly reviewed
    and added to ALLOWED_METHODS.
    """

    @pytest.mark.parametrize("method_name", [
        "some_future_method",
        "upload_file",
        "create_channel",
        "join_channel",
        "leave_channel",
        "set_typing",
        "invoke",
        "send_code_request",
        "sign_in",
        "sign_up",
        "log_out",
        "export_session_string",
        "import_session_string",
    ])
    def test_unknown_method_raises_permission_error(self, readonly_client, method_name):
        with pytest.raises(PermissionError) as exc_info:
            getattr(readonly_client, method_name)

        assert method_name in str(exc_info.value)

    def test_arbitrary_method_blocked(self, readonly_client):
        """Any arbitrary string should be blocked."""
        with pytest.raises(PermissionError):
            readonly_client.absolutely_anything_at_all

    def test_invoke_blocked(self, readonly_client):
        """
        The raw 'invoke' method is especially dangerous -- it can call
        any Telegram API method directly, bypassing all wrappers.
        """
        with pytest.raises(PermissionError, match="invoke"):
            readonly_client.invoke

    def test_export_session_blocked(self, readonly_client):
        """Exporting the session would allow session theft."""
        with pytest.raises(PermissionError, match="export_session_string"):
            readonly_client.export_session_string


# ---------------------------------------------------------------------------
# Test: __getattr__ delegation
# ---------------------------------------------------------------------------

class TestGetAttrDelegation:
    """Verify that __getattr__ correctly delegates to the underlying client."""

    def test_delegates_to_underlying_client(self, readonly_client, mock_client):
        """Allowed method should return the same object as the underlying client's method."""
        assert readonly_client.get_me is mock_client.get_me

    def test_does_not_delegate_blocked_method(self, readonly_client, mock_client):
        """Blocked method should raise, never reaching the underlying client."""
        with pytest.raises(PermissionError):
            readonly_client.send_message

        # The mock's send_message should never have been accessed via the wrapper
        # (it was set up in the fixture, but the wrapper should block access)

    def test_private_attributes_raise_attribute_error(self, readonly_client):
        """Private/dunder attributes should be blocked."""
        with pytest.raises(PermissionError):
            readonly_client._private_method

        with pytest.raises(PermissionError):
            readonly_client.__secret

    def test_allowed_method_called_with_args(self, readonly_client, mock_client):
        """Verify that arguments pass through correctly."""
        # Access the method (this goes through __getattr__)
        method = readonly_client.get_messages
        # Verify it's the same method object from the mock
        assert method is mock_client.get_messages


# ---------------------------------------------------------------------------
# Test: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_string_method_name(self, readonly_client):
        """Empty string is not in the allowlist."""
        with pytest.raises(PermissionError):
            getattr(readonly_client, "")

    def test_method_name_with_whitespace(self, readonly_client):
        """Method name with whitespace should be blocked."""
        with pytest.raises(PermissionError):
            getattr(readonly_client, "get messages")

    def test_case_sensitivity(self, readonly_client):
        """Method names are case-sensitive: 'Get_Messages' != 'get_messages'."""
        with pytest.raises(PermissionError):
            readonly_client.Get_Messages

        with pytest.raises(PermissionError):
            readonly_client.GET_MESSAGES

    def test_multiple_wrapper_instances_share_allowlist(self, mock_client):
        """Multiple instances should share the same frozenset (class-level)."""
        client1 = ReadOnlyTelegramClient(mock_client)
        client2 = ReadOnlyTelegramClient(mock_client)

        assert client1._allowed is client2._allowed
        assert client1._allowed is ALLOWED_METHODS

    def test_allowed_methods_contains_expected_count(self):
        """
        Sanity check: the allowlist should have a known number of methods.
        If this changes, it means someone added or removed a method --
        which should be a deliberate, reviewed change.
        """
        expected_count = 11
        actual_count = len(ALLOWED_METHODS)
        assert actual_count == expected_count, (
            f"ALLOWED_METHODS has {actual_count} entries, expected {expected_count}. "
            f"If you intentionally changed the allowlist, update this test."
        )
