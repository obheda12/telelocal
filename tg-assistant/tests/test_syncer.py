"""
Unit tests for syncer modules: sync_once, embeddings factory.
"""

import sys
from datetime import datetime, timezone
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

        # Mock client
        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[mock_dialog])
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

    @pytest.mark.asyncio
    async def test_sync_once_no_messages(self):
        """sync_once should handle dialogs with no new messages."""
        from syncer.main import sync_once

        mock_dialog = MagicMock()
        mock_dialog.id = 12345
        mock_dialog.title = "Empty Chat"

        mock_client = MagicMock()
        mock_client.get_dialogs = AsyncMock(return_value=[mock_dialog])
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
