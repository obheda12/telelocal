"""
Embedding generation for semantic search.

Provides local on-device embeddings using ``all-MiniLM-L6-v2`` via
sentence-transformers (384-dim vectors).  Supports ONNX Runtime backend
for 2-5x speedup on ARM64 (Raspberry Pi).

The ``EmbeddingProvider`` ABC allows swapping in a different backend later
without changing the rest of the codebase.
"""

from __future__ import annotations

import asyncio
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
        """Generate a single embedding vector for *text*."""
        ...

    @abstractmethod
    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts in one call."""
        ...


class LocalEmbeddings(EmbeddingProvider):
    """Embedding provider using ``all-MiniLM-L6-v2`` via sentence-transformers.

    Runs entirely on-device — no network calls.  Supports ONNX Runtime
    backend for faster inference on CPU/ARM64.

    Args:
        model_name: HuggingFace model identifier.
        device: ``"cpu"`` or ``"cuda"``.
        backend: ``"onnx"`` for ONNX Runtime or ``"torch"`` for PyTorch.
    """

    _DIMENSION: int = 384

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        device: str = "cpu",
        backend: str = "torch",
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._backend = backend
        self._model = None  # lazy-loaded

    def _load_model(self) -> None:
        """Lazy-load the sentence-transformers model.

        If backend is ``"onnx"``, tries ONNX Runtime first (with ARM64
        quantized model if available), falling back to PyTorch on failure.
        """
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        if self._backend == "onnx":
            # Try ARM64-quantized ONNX model first, then generic ONNX, then PyTorch
            for attempt in self._onnx_load_attempts():
                try:
                    self._model = SentenceTransformer(
                        self._model_name,
                        device=self._device,
                        backend="onnx",
                        model_kwargs=attempt.get("model_kwargs"),
                    )
                    label = attempt.get("label", "onnx")
                    logger.info(
                        "Loaded local embedding model: %s (backend=%s)",
                        self._model_name,
                        label,
                    )
                    return
                except Exception:
                    label = attempt.get("label", "onnx")
                    logger.debug(
                        "ONNX load attempt '%s' failed", label, exc_info=True
                    )

            logger.warning(
                "All ONNX load attempts failed; falling back to PyTorch"
            )

        self._model = SentenceTransformer(self._model_name, device=self._device)
        logger.info("Loaded local embedding model: %s (backend=torch)", self._model_name)

    def _onnx_load_attempts(self) -> list[dict]:
        """Return ordered list of ONNX loading strategies to try."""
        return [
            {
                "label": "onnx-arm64-qint8",
                "model_kwargs": {"file_name": "onnx/model_qint8_arm64.onnx"},
            },
            {
                "label": "onnx",
                "model_kwargs": None,
            },
        ]

    @property
    def dimension(self) -> int:
        return self._DIMENSION

    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding locally using sentence-transformers."""
        self._load_model()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._model.encode, text)
        return result.tolist()

    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings locally for a batch."""
        if not texts:
            return []
        self._load_model()
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._model.encode, texts)
        return [r.tolist() for r in results]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_embedding_provider(config: dict) -> EmbeddingProvider:
    """Create the embedding provider based on configuration.

    Args:
        config: The ``[embeddings]`` section from settings.toml.

    Returns:
        An ``EmbeddingProvider`` instance.
    """
    model = config.get("local_model", "all-MiniLM-L6-v2")
    backend = config.get("backend", "torch")
    logger.info("Using local embeddings (model=%s, backend=%s)", model, backend)
    return LocalEmbeddings(
        model_name=model,
        device="cpu",
        backend=backend,
    )
