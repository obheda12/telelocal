"""
Unit tests for syncer modules: sync_once, embeddings factory, progress tracking,
and chat exclusion filtering.
"""

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mock telethon before any import that depends on it
if "telethon" not in sys.modules:
    sys.modules["telethon"] = MagicMock()

from syncer.embeddings import (
    EmbeddingProvider,
    LocalEmbeddings,
    create_embedding_provider,
)
from syncer.progress import ChatProgress, PassProgress, _format_duration


# ---------------------------------------------------------------------------
# Embeddings factory
# ---------------------------------------------------------------------------


class TestCreateEmbeddingProvider:
    def test_local_provider(self):
        """Should create LocalEmbeddings when provider is 'local'."""
        config = {"provider": "local", "local_model": "all-MiniLM-L6-v2"}
        provider = create_embedding_provider(config)
        assert isinstance(provider, LocalEmbeddings)
        assert provider.dimension == 384

    def test_default_provider_is_local(self):
        """When no provider is specified, default to local."""
        config = {}
        provider = create_embedding_provider(config)
        assert isinstance(provider, LocalEmbeddings)


class TestLocalEmbeddings:
    def test_dimension(self):
        """LocalEmbeddings should report 384 dimensions."""
        provider = LocalEmbeddings()
        assert provider.dimension == 384

    @pytest.mark.asyncio
    async def test_batch_generate_empty(self):
        """Batch generate with empty list should return empty list."""
        provider = LocalEmbeddings()
        # Mock _load_model so we don't actually load a heavy model
        provider._model = MagicMock()
        result = await provider.batch_generate([])
        assert result == []


# ---------------------------------------------------------------------------
# ONNX embeddings
# ---------------------------------------------------------------------------


class TestLocalEmbeddingsOnnx:
    def test_backend_parameter_stored(self):
        """Backend parameter should be stored on the instance."""
        provider = LocalEmbeddings(backend="onnx")
        assert provider._backend == "onnx"

    def test_default_backend_is_torch(self):
        """Default backend should be torch."""
        provider = LocalEmbeddings()
        assert provider._backend == "torch"

    def test_factory_passes_backend_config(self):
        """create_embedding_provider should pass backend from config."""
        config = {"backend": "onnx", "local_model": "all-MiniLM-L6-v2"}
        provider = create_embedding_provider(config)
        assert isinstance(provider, LocalEmbeddings)
        assert provider._backend == "onnx"

    def test_factory_default_backend_torch(self):
        """Factory should default to torch when backend not in config."""
        config = {"local_model": "all-MiniLM-L6-v2"}
        provider = create_embedding_provider(config)
        assert provider._backend == "torch"

    def test_onnx_fallback_to_torch(self):
        """When ONNX loading fails, should fall back to PyTorch."""
        provider = LocalEmbeddings(backend="onnx")

        call_count = 0

        def fake_constructor(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if kwargs.get("backend") == "onnx":
                raise ImportError("onnxruntime not installed")
            return MagicMock()

        mock_st = MagicMock(side_effect=fake_constructor)

        with patch.dict("sys.modules", {"sentence_transformers": MagicMock(SentenceTransformer=mock_st)}):
            provider._load_model()

        # Should have tried ONNX attempts (2) and then fallen back to torch (1)
        assert call_count == 3
        assert provider._model is not None

    def test_onnx_load_attempts_order(self):
        """ONNX load should try ARM64-quantized first, then generic."""
        provider = LocalEmbeddings(backend="onnx")
        attempts = provider._onnx_load_attempts()
        assert len(attempts) == 2
        assert attempts[0]["label"] == "onnx-arm64-qint8"
        assert attempts[1]["label"] == "onnx"


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------


class TestFormatDuration:
    def test_seconds_only(self):
        assert _format_duration(45) == "45s"

    def test_zero(self):
        assert _format_duration(0) == "0s"

    def test_negative(self):
        assert _format_duration(-5) == "0s"

    def test_minutes_and_seconds(self):
        assert _format_duration(150) == "2m 30s"

    def test_exact_minutes(self):
        assert _format_duration(120) == "2m"

    def test_hours_and_minutes(self):
        assert _format_duration(4500) == "1h 15m"

    def test_exact_hours(self):
        assert _format_duration(3600) == "1h"

    def test_large_value(self):
        assert _format_duration(7260) == "2h 1m"


class TestChatProgress:
    def test_initial_state(self):
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        assert cp.processed == 0
        assert cp.stored == 0
        assert cp.chat_index == 1
        assert cp.total_chats == 10

    def test_update(self):
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        cp.update(100, 95)
        assert cp.processed == 100
        assert cp.stored == 95

        cp.update(200, 180)
        assert cp.processed == 300
        assert cp.stored == 275

    def test_rate(self):
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        # Simulate elapsed time by backdating start
        cp._start = time.monotonic() - 10.0  # 10 seconds ago
        cp.update(500, 500)
        rate = cp.rate
        # 500 messages / ~10 seconds = ~50 msg/s
        assert 40.0 < rate < 60.0

    def test_rate_zero_time(self):
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        # At t=0, rate should be 0.0
        assert cp.rate == 0.0

    def test_eta_seconds(self):
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        cp._start = time.monotonic() - 10.0
        cp.update(500, 500)
        eta = cp.eta_seconds
        # 500 remaining / 50 msg/s = ~10s
        assert eta is not None
        assert 5.0 < eta < 20.0

    def test_eta_no_estimate(self):
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=0)
        cp._start = time.monotonic() - 10.0
        cp.update(500, 500)
        assert cp.eta_seconds is None

    def test_log_batch(self):
        """log_batch should not raise."""
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        cp._start = time.monotonic() - 5.0
        cp.update(100, 95)
        cp.log_batch()  # Should not raise

    def test_log_complete(self):
        """log_complete should not raise."""
        cp = ChatProgress(1, 10, "Test Chat", estimated_total=1000)
        cp._start = time.monotonic() - 5.0
        cp.update(1000, 950)
        cp.log_complete()  # Should not raise


class TestPassProgress:
    def test_initial_state(self):
        pp = PassProgress(estimated_total=10000, total_chats=10)
        assert pp.processed == 0
        assert pp.stored == 0
        assert pp.chats_completed == 0

    def test_update_from_chat(self):
        pp = PassProgress(estimated_total=10000, total_chats=10)

        cp1 = ChatProgress(1, 10, "Chat A", estimated_total=5000)
        cp1.update(3000, 2800)

        cp2 = ChatProgress(2, 10, "Chat B", estimated_total=5000)
        cp2.update(2000, 1900)

        pp.update_from_chat(cp1)
        assert pp.processed == 3000
        assert pp.stored == 2800
        assert pp.chats_completed == 1

        pp.update_from_chat(cp2)
        assert pp.processed == 5000
        assert pp.stored == 4700
        assert pp.chats_completed == 2

    def test_eta(self):
        pp = PassProgress(estimated_total=10000, total_chats=10)
        pp._start = time.monotonic() - 10.0
        pp.processed = 5000  # directly set for simplicity
        eta = pp.eta_seconds
        # 5000 remaining / 500 msg/s = ~10s
        assert eta is not None
        assert 5.0 < eta < 20.0

    def test_log_pass_progress(self):
        """log_pass_progress should not raise."""
        pp = PassProgress(estimated_total=10000, total_chats=10)
        pp._start = time.monotonic() - 5.0
        pp.processed = 2500
        pp.chats_completed = 3
        pp.log_pass_progress()  # Should not raise


# ---------------------------------------------------------------------------
# sync_once
# ---------------------------------------------------------------------------


class TestSyncOnce:
    async def _iter_messages(self, messages):
        for m in messages:
            yield m

    @pytest.mark.asyncio
    async def test_sync_once_basic(self):
        """sync_once should iterate dialogs, fetch messages, and store them."""
        from syncer.main import sync_once

        # Mock dialog
        mock_dialog = MagicMock()
        mock_dialog.id = 12345
        mock_dialog.title = "Test Chat"
        mock_dialog.is_group = False
        mock_dialog.is_channel = False
        mock_dialog.date = datetime.now(timezone.utc)

        # Mock message
        mock_msg = MagicMock()
        mock_msg.id = 100
        mock_msg.text = "Hello world"
        mock_msg.message = "Hello world"
        mock_msg.date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        mock_sender = MagicMock()
        mock_sender.id = 999
        mock_sender.first_name = "Alice"
        mock_sender.last_name = "Smith"
        mock_msg.sender = mock_sender
        mock_msg.to_dict.return_value = {"id": 100}

        # Mock TotalList for pre-scan
        mock_total_list = MagicMock()
        mock_total_list.total = 100

        # Mock client
        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[mock_dialog])
        mock_client.get_messages = AsyncMock(return_value=mock_total_list)
        mock_client.iter_messages = MagicMock(return_value=self._iter_messages([mock_msg]))

        # Mock store
        mock_store = AsyncMock()
        mock_store.get_last_synced_id.return_value = None
        mock_store.store_messages_batch.return_value = 1

        # Mock embedder (local = 384 dim, so no vectors stored)
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        # Mock audit
        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0, "max_history_days": 0}}

        with patch("syncer.main.rate_limit_delay", new_callable=AsyncMock):
            count = await sync_once(
                mock_client, mock_store, mock_embedder, mock_audit, config
            )

        assert count == 1
        mock_store.store_messages_batch.assert_called_once()
        mock_store.update_chat_metadata.assert_called_once()
        # Verify pre-scan was called
        mock_client.get_messages.assert_called_once_with(mock_dialog, limit=0)

    @pytest.mark.asyncio
    async def test_sync_once_no_messages(self):
        """sync_once should handle dialogs with no new messages."""
        from syncer.main import sync_once

        mock_dialog = MagicMock()
        mock_dialog.id = 12345
        mock_dialog.title = "Empty Chat"
        mock_dialog.date = datetime.now(timezone.utc)

        # Mock TotalList for pre-scan
        mock_total_list = MagicMock()
        mock_total_list.total = 50

        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[mock_dialog])
        mock_client.get_messages = AsyncMock(return_value=mock_total_list)
        mock_client.iter_messages = MagicMock(return_value=self._iter_messages([]))

        mock_store = AsyncMock()
        mock_store.get_last_synced_id.return_value = 50

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0}}

        with patch("syncer.main.rate_limit_delay", new_callable=AsyncMock):
            count = await sync_once(
                mock_client, mock_store, mock_embedder, mock_audit, config
            )

        assert count == 0
        mock_store.store_messages_batch.assert_not_called()

    @pytest.mark.asyncio
    async def test_sync_once_no_dialogs(self):
        """sync_once should handle empty dialog list gracefully."""
        from syncer.main import sync_once

        mock_client = AsyncMock()
        mock_client.get_dialogs.return_value = []

        mock_store = AsyncMock()
        mock_embedder = MagicMock()
        mock_embedder.dimension = 384
        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0}}

        count = await sync_once(
            mock_client, mock_store, mock_embedder, mock_audit, config
        )

        assert count == 0

    @pytest.mark.asyncio
    async def test_sync_once_prescan_failure_graceful(self):
        """Pre-scan failure for a chat should not stop sync."""
        from syncer.main import sync_once

        mock_dialog = MagicMock()
        mock_dialog.id = 12345
        mock_dialog.title = "Test Chat"
        mock_dialog.is_group = False
        mock_dialog.is_channel = False
        mock_dialog.date = datetime.now(timezone.utc)

        mock_msg = MagicMock()
        mock_msg.id = 100
        mock_msg.text = "Hello"
        mock_msg.message = "Hello"
        mock_msg.date = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        mock_msg.sender = None
        mock_msg.to_dict.return_value = {}

        # Pre-scan raises but sync should still work
        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[mock_dialog])
        mock_client.get_messages = AsyncMock(side_effect=Exception("API error"))
        mock_client.iter_messages = MagicMock(return_value=self._iter_messages([mock_msg]))

        mock_store = AsyncMock()
        mock_store.get_last_synced_id.return_value = None
        mock_store.store_messages_batch.return_value = 1

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0, "max_history_days": 0}}

        with patch("syncer.main.rate_limit_delay", new_callable=AsyncMock):
            count = await sync_once(
                mock_client, mock_store, mock_embedder, mock_audit, config
            )

        assert count == 1

    @pytest.mark.asyncio
    async def test_sync_once_filters_inactive_dialogs(self):
        """sync_once should skip dialogs with no activity within max_history_days."""
        from syncer.main import sync_once

        # Recent dialog — should be synced
        recent_dialog = MagicMock()
        recent_dialog.id = 111
        recent_dialog.title = "Active Chat"
        recent_dialog.is_group = False
        recent_dialog.is_channel = False
        recent_dialog.date = datetime.now(timezone.utc) - timedelta(days=5)

        # Old dialog — should be filtered out
        old_dialog = MagicMock()
        old_dialog.id = 222
        old_dialog.title = "Dead Chat"
        old_dialog.is_group = False
        old_dialog.is_channel = False
        old_dialog.date = datetime.now(timezone.utc) - timedelta(days=365)

        # Mock message for the recent dialog (date must be within max_history_days)
        mock_msg = MagicMock()
        mock_msg.id = 100
        mock_msg.text = "Hello"
        mock_msg.message = "Hello"
        mock_msg.date = datetime.now(timezone.utc) - timedelta(days=1)
        mock_msg.sender = None
        mock_msg.to_dict.return_value = {}

        mock_total_list = MagicMock()
        mock_total_list.total = 50

        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[recent_dialog, old_dialog])
        mock_client.get_messages = AsyncMock(return_value=mock_total_list)
        mock_client.iter_messages = MagicMock(return_value=self._iter_messages([mock_msg]))

        mock_store = AsyncMock()
        mock_store.get_last_synced_id.return_value = None
        mock_store.store_messages_batch.return_value = 1

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0, "max_history_days": 30}}

        with patch("syncer.main.rate_limit_delay", new_callable=AsyncMock):
            count = await sync_once(
                mock_client, mock_store, mock_embedder, mock_audit, config
            )

        assert count == 1
        # Only the recent dialog should be pre-scanned
        mock_client.get_messages.assert_called_once_with(recent_dialog, limit=0)
        # iter_messages should only be called for the recent dialog
        mock_client.iter_messages.assert_called_once()
        # update_chat_metadata should only be called for the recent dialog
        mock_store.update_chat_metadata.assert_called_once_with(
            chat_id=111, title="Active Chat", chat_type="user",
        )

    @pytest.mark.asyncio
    async def test_sync_once_includes_dialog_without_date(self):
        """Dialogs without a .date attribute should be included (conservative)."""
        from syncer.main import sync_once

        # Dialog with no date attribute — should still be synced
        no_date_dialog = MagicMock(spec=[])  # spec=[] means no attributes by default
        no_date_dialog.id = 333
        no_date_dialog.title = "Mystery Chat"
        no_date_dialog.is_group = False
        no_date_dialog.is_channel = False
        # Explicitly do NOT set .date

        mock_total_list = MagicMock()
        mock_total_list.total = 10

        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[no_date_dialog])
        mock_client.get_messages = AsyncMock(return_value=mock_total_list)
        mock_client.iter_messages = MagicMock(return_value=self._iter_messages([]))

        mock_store = AsyncMock()
        mock_store.get_last_synced_id.return_value = 50

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0, "max_history_days": 30}}

        with patch("syncer.main.rate_limit_delay", new_callable=AsyncMock):
            count = await sync_once(
                mock_client, mock_store, mock_embedder, mock_audit, config
            )

        # Should have processed this dialog (0 messages, but it wasn't filtered)
        assert count == 0
        mock_client.get_messages.assert_called_once_with(no_date_dialog, limit=0)

    @pytest.mark.asyncio
    async def test_sync_once_excludes_manually_excluded_chats(self):
        """sync_once should skip chats listed in excluded_chats.json."""
        from syncer.main import sync_once

        # Two active dialogs
        included_dialog = MagicMock()
        included_dialog.id = 111
        included_dialog.title = "Work Chat"
        included_dialog.is_group = True
        included_dialog.is_channel = False
        included_dialog.date = datetime.now(timezone.utc)

        excluded_dialog = MagicMock()
        excluded_dialog.id = 222
        excluded_dialog.title = "Personal Chat"
        excluded_dialog.is_group = False
        excluded_dialog.is_channel = False
        excluded_dialog.date = datetime.now(timezone.utc)

        mock_msg = MagicMock()
        mock_msg.id = 100
        mock_msg.text = "Hello"
        mock_msg.message = "Hello"
        mock_msg.date = datetime.now(timezone.utc) - timedelta(days=1)
        mock_msg.sender = None
        mock_msg.to_dict.return_value = {}

        mock_total_list = MagicMock()
        mock_total_list.total = 50

        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[included_dialog, excluded_dialog])
        mock_client.get_messages = AsyncMock(return_value=mock_total_list)
        mock_client.iter_messages = MagicMock(return_value=self._iter_messages([mock_msg]))

        mock_store = AsyncMock()
        mock_store.get_last_synced_id.return_value = None
        mock_store.store_messages_batch.return_value = 1

        mock_embedder = MagicMock()
        mock_embedder.dimension = 384

        mock_audit = AsyncMock()

        config = {"syncer": {"batch_size": 100, "rate_limit_seconds": 0, "max_history_days": 0}}

        with (
            patch("syncer.main.rate_limit_delay", new_callable=AsyncMock),
            patch("syncer.main.load_excluded_ids", return_value={222}),
        ):
            count = await sync_once(
                mock_client, mock_store, mock_embedder, mock_audit, config
            )

        assert count == 1
        # Only the included dialog should be pre-scanned and synced
        mock_client.get_messages.assert_called_once_with(included_dialog, limit=0)
        mock_client.iter_messages.assert_called_once()
        mock_store.update_chat_metadata.assert_called_once_with(
            chat_id=111, title="Work Chat", chat_type="group",
        )


# ---------------------------------------------------------------------------
# Chat exclusion file helpers
# ---------------------------------------------------------------------------


class TestLoadExcludedIds:
    def test_missing_file_returns_empty_set(self, tmp_path):
        """load_excluded_ids should return empty set when file doesn't exist."""
        from syncer.manage_chats import load_excluded_ids

        config = {}
        with patch("syncer.manage_chats.get_excluded_chats_path", return_value=tmp_path / "nope.json"):
            result = load_excluded_ids(config)

        assert result == set()

    def test_valid_file_returns_ids(self, tmp_path):
        """load_excluded_ids should parse chat IDs from valid JSON."""
        from syncer.manage_chats import load_excluded_ids

        json_path = tmp_path / "excluded_chats.json"
        json_path.write_text(json.dumps({
            "excluded": {"111": "Chat A", "222": "Chat B"}
        }))

        config = {}
        with patch("syncer.manage_chats.get_excluded_chats_path", return_value=json_path):
            result = load_excluded_ids(config)

        assert result == {111, 222}

    def test_invalid_json_returns_empty_set(self, tmp_path):
        """load_excluded_ids should return empty set for malformed JSON."""
        from syncer.manage_chats import load_excluded_ids

        json_path = tmp_path / "excluded_chats.json"
        json_path.write_text("not valid json {{{")

        config = {}
        with patch("syncer.manage_chats.get_excluded_chats_path", return_value=json_path):
            result = load_excluded_ids(config)

        assert result == set()

    def test_empty_excluded_returns_empty_set(self, tmp_path):
        """load_excluded_ids should return empty set when excluded dict is empty."""
        from syncer.manage_chats import load_excluded_ids

        json_path = tmp_path / "excluded_chats.json"
        json_path.write_text(json.dumps({"excluded": {}}))

        config = {}
        with patch("syncer.manage_chats.get_excluded_chats_path", return_value=json_path):
            result = load_excluded_ids(config)

        assert result == set()


class TestSaveExcludedChats:
    def test_save_and_reload(self, tmp_path):
        """save_excluded_chats should write JSON that load_excluded_ids can read."""
        from syncer.manage_chats import load_excluded_ids, save_excluded_chats

        json_path = tmp_path / "excluded_chats.json"
        config = {}
        excluded = {111: "Chat A", 222: "Chat B"}

        with patch("syncer.manage_chats.get_excluded_chats_path", return_value=json_path):
            save_excluded_chats(config, excluded)
            result = load_excluded_ids(config)

        assert result == {111, 222}

        # Verify file content is human-readable
        data = json.loads(json_path.read_text())
        assert "111" in data["excluded"]
        assert data["excluded"]["111"] == "Chat A"
