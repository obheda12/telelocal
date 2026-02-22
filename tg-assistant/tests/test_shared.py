"""
Unit tests for shared modules: secrets, db, audit.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.secrets import (
    decrypt_session_file,
    encrypt_session_file,
    generate_encryption_key,
    get_secret,
)
from shared.audit import AuditLogger
from shared.db import health_check


# ---------------------------------------------------------------------------
# secrets: encrypt / decrypt roundtrip
# ---------------------------------------------------------------------------


class TestSessionEncryption:
    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        """Encrypting then decrypting should return the original bytes."""
        key = generate_encryption_key()
        session_file = tmp_path / "test.session"
        original_data = b"telethon-session-data-here-1234567890"
        session_file.write_bytes(original_data)

        encrypt_session_file(session_file, key)

        # The file on disk should now be different from original
        assert session_file.read_bytes() != original_data

        # Decrypt should recover the original
        decrypted = decrypt_session_file(session_file, key)
        assert decrypted == original_data

    def test_encrypt_sets_restrictive_permissions(self, tmp_path):
        """After encryption the file permissions should be 0o600."""
        key = generate_encryption_key()
        session_file = tmp_path / "test.session"
        session_file.write_bytes(b"test data")

        encrypt_session_file(session_file, key)

        mode = session_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_decrypt_wrong_key_fails(self, tmp_path):
        """Decrypting with the wrong key should raise InvalidToken."""
        from cryptography.fernet import InvalidToken

        key1 = generate_encryption_key()
        key2 = generate_encryption_key()

        session_file = tmp_path / "test.session"
        session_file.write_bytes(b"secret session data")

        encrypt_session_file(session_file, key1)

        with pytest.raises(InvalidToken):
            decrypt_session_file(session_file, key2)

    def test_generate_key_is_valid_fernet_key(self):
        """Generated key should be a valid Fernet key string."""
        from cryptography.fernet import Fernet

        key = generate_encryption_key()
        assert isinstance(key, str)
        # Should not raise
        Fernet(key.encode())


# ---------------------------------------------------------------------------
# secrets: get_secret env var fallback
# ---------------------------------------------------------------------------


class TestGetSecret:
    def test_credentials_directory_first(self, tmp_path, monkeypatch):
        """$CREDENTIALS_DIRECTORY should be checked before keychain and env."""
        cred_file = tmp_path / "my-secret"
        cred_file.write_text("from-credstore")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
        # Also set env var — should NOT be used (credstore takes priority)
        monkeypatch.setenv("TG_ASSISTANT_MY_SECRET", "from-env")
        result = get_secret("my-secret")
        assert result == "from-credstore"

    def test_credentials_directory_missing_file_falls_through(self, tmp_path, monkeypatch):
        """If credential file doesn't exist, should fall through to next source."""
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
        monkeypatch.setenv("TG_ASSISTANT_ALLOW_ENV_SECRETS", "1")
        monkeypatch.setenv("TG_ASSISTANT_BOT_TOKEN", "from-env")
        result = get_secret("bot_token")
        assert result == "from-env"

    def test_credentials_directory_strips_whitespace(self, tmp_path, monkeypatch):
        """Credential file values should be stripped of leading/trailing whitespace."""
        cred_file = tmp_path / "api-key"
        cred_file.write_text("  sk-secret-123  \n")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
        result = get_secret("api-key")
        assert result == "sk-secret-123"

    def test_env_var_fallback(self, monkeypatch):
        """When secret-tool is not available, should fall back to env var."""
        monkeypatch.setenv("TG_ASSISTANT_ALLOW_ENV_SECRETS", "1")
        monkeypatch.setenv("TG_ASSISTANT_BOT_TOKEN", "test-token-123")
        # secret-tool won't be found in test environment
        result = get_secret("bot_token")
        assert result == "test-token-123"

    def test_env_var_fallback_with_hyphens(self, monkeypatch):
        """Hyphens in key names should be converted to underscores."""
        monkeypatch.setenv("TG_ASSISTANT_ALLOW_ENV_SECRETS", "1")
        monkeypatch.setenv("TG_ASSISTANT_SOME_API_KEY", "some-key-abc")
        result = get_secret("some-api-key")
        assert result == "some-key-abc"

    def test_missing_secret_raises(self):
        """Should raise RuntimeError when secret is nowhere to be found."""
        with pytest.raises(RuntimeError, match="not found"):
            get_secret("nonexistent_key_that_does_not_exist")

    def test_env_var_ignored_when_fallback_disabled(self, monkeypatch):
        """Env secrets should be rejected unless explicitly enabled."""
        monkeypatch.delenv("TG_ASSISTANT_ALLOW_ENV_SECRETS", raising=False)
        monkeypatch.setenv("TG_ASSISTANT_BOT_TOKEN", "test-token-123")
        with pytest.raises(RuntimeError, match="ALLOW_ENV_SECRETS"):
            get_secret("bot_token")


# ---------------------------------------------------------------------------
# audit: file write succeeds when DB fails
# ---------------------------------------------------------------------------


class TestAuditLogger:
    @pytest.mark.asyncio
    async def test_file_write_succeeds_when_db_fails(self, tmp_path):
        """Audit log should write to file even if DB insert fails."""
        log_file = tmp_path / "audit.log"

        # Mock pool that fails on acquire
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(side_effect=Exception("DB down"))
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        audit = AuditLogger(mock_pool, log_path=log_file)
        await audit.log("syncer", "test_action", {"key": "value"}, success=True)
        await audit.close()

        # File should have been written
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1

        event = json.loads(lines[0])
        assert event["service"] == "syncer"
        assert event["action"] == "test_action"
        assert event["details"] == {"key": "value"}
        assert event["success"] is True
        assert "timestamp" in event

    @pytest.mark.asyncio
    async def test_log_writes_to_both_file_and_db(self, tmp_path):
        """Audit log should write to both file and DB when both succeed."""
        log_file = tmp_path / "audit.log"

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        audit = AuditLogger(mock_pool, log_path=log_file)
        await audit.log("querybot", "query", {"q": "test"}, success=True)
        await audit.close()

        # File should have been written
        assert log_file.exists()

        # DB execute should have been called
        mock_conn.executemany.assert_called_once()
        call_args = mock_conn.executemany.call_args
        assert "INSERT INTO audit_log" in call_args[0][0]


# ---------------------------------------------------------------------------
# db: health check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Health check should return True when SELECT 1 succeeds."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await health_check(mock_pool)
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Health check should return False on database error."""
        mock_pool = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(
            side_effect=Exception("Connection refused")
        )
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        result = await health_check(mock_pool)
        assert result is False
