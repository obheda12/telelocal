"""
Embedding generation for semantic search.

Provides a common interface with two backends:

1. **VoyageEmbeddings** — calls the Voyage AI API (1024-dim vectors).
   Preferred for quality; requires an API key.
2. **LocalEmbeddings** — runs ``all-MiniLM-L6-v2`` on-device (384-dim).
   No external calls; suitable as a fallback on constrained hardware.

Both backends implement the same ``EmbeddingProvider`` ABC so the rest
of the codebase is backend-agnostic.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List

logger = logging.getLogger("syncer.embeddings")


class EmbeddingProvider(ABC):
    """Abstract base class for embedding generators."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimensionality of the embedding vectors produced."""
        ...

    @abstractmethod
    async def generate_embedding(self, text: str) -> List[float]:
        """Generate a single embedding vector for *text*.

        Args:
            text: Input text (will be truncated to the model's max token
                  length internally).

        Returns:
            A list of floats with length == ``self.dimension``.
        """
        ...

    @abstractmethod
    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts in one call.

        Args:
            texts: List of input strings.

        Returns:
            A list of embedding vectors, one per input text.
        """
        ...


# ---------------------------------------------------------------------------
# Voyage AI (API-based, 1024 dimensions)
# ---------------------------------------------------------------------------


class VoyageEmbeddings(EmbeddingProvider):
    """Embedding provider using the Voyage AI API.

    Args:
        api_key: Voyage AI API key (loaded from system keychain).
        model: Model identifier (default ``"voyage-2"``).
    """

    _DIMENSION: int = 1024

    def __init__(self, api_key: str, model: str = "voyage-2") -> None:
        self._api_key = api_key
        self._model = model
        # TODO: initialise HTTP client (httpx.AsyncClient or similar)

    @property
    def dimension(self) -> int:
        return self._DIMENSION

    async def generate_embedding(self, text: str) -> List[float]:
        """Call the Voyage API for a single text.

        Returns:
            1024-dimensional float vector.
        """
        # TODO: implement
        #   - POST to https://api.voyageai.com/v1/embeddings
        #   - Include Authorization header with self._api_key
        #   - Parse response JSON -> data[0].embedding
        #   - Handle rate-limit (429) with exponential back-off
        raise NotImplementedError

    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Call the Voyage API with a batch of texts.

        The Voyage API supports batches natively (up to ~128 inputs per
        request, depending on token count).

        Returns:
            List of 1024-dimensional vectors.
        """
        # TODO: implement
        #   - Split into API-allowed batch sizes
        #   - Collect results, preserving input order
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Local (sentence-transformers, 384 dimensions)
# ---------------------------------------------------------------------------


class LocalEmbeddings(EmbeddingProvider):
    """Embedding provider using ``all-MiniLM-L6-v2`` via sentence-transformers.

    Runs entirely on-device — no network calls.  Suitable as a fallback
    when the Voyage API is unavailable or for development/testing.

    Args:
        model_name: HuggingFace model identifier.
        device: ``"cpu"`` or ``"cuda"`` (Raspberry Pi will always be CPU).
    """

    _DIMENSION: int = 384

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        device: str = "cpu",
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._model = None  # lazy-loaded
        # TODO: lazy-load the model on first call to avoid import cost at
        #       startup (sentence_transformers is heavy)

    def _load_model(self) -> None:
        """Lazy-load the sentence-transformers model."""
        # TODO: implement
        #   from sentence_transformers import SentenceTransformer
        #   self._model = SentenceTransformer(self._model_name, device=self._device)
        raise NotImplementedError

    @property
    def dimension(self) -> int:
        return self._DIMENSION

    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding locally using sentence-transformers.

        Returns:
            384-dimensional float vector.
        """
        # TODO: implement
        #   - Ensure model is loaded (_load_model)
        #   - Run self._model.encode(text) in a thread executor
        #     (sentence-transformers is synchronous)
        #   - Return list of floats
        raise NotImplementedError

    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings locally for a batch.

        Returns:
            List of 384-dimensional vectors.
        """
        # TODO: implement
        #   - self._model.encode(texts) supports batches natively
        #   - Run in thread executor
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_embedding_provider(config: dict) -> EmbeddingProvider:
    """Create the appropriate embedding provider based on configuration.

    Falls back to LocalEmbeddings if the Voyage API key is not configured.

    Args:
        config: The ``[embeddings]`` section from settings.toml.

    Returns:
        An ``EmbeddingProvider`` instance.
    """
    # TODO: implement
    #   - Check config for "voyage_api_key" or "provider" key
    #   - Return VoyageEmbeddings if API key present, else LocalEmbeddings
    #   - Log which provider was selected
    raise NotImplementedError
