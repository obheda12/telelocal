"""
Sync progress tracking with ETA for journalctl output.

Provides ``ChatProgress`` (per-chat) and ``PassProgress`` (overall pass)
trackers that log human-readable progress lines with message rates and
estimated time remaining.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger("syncer.progress")


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string.

    Examples: ``"45s"``, ``"2m 30s"``, ``"1h 15m"``.
    """
    if seconds < 0:
        return "0s"
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        if secs:
            return f"{minutes}m {secs}s"
        return f"{minutes}m"
    hours, mins = divmod(minutes, 60)
    if mins:
        return f"{hours}h {mins}m"
    return f"{hours}h"


class ChatProgress:
    """Tracks progress for a single chat sync.

    Args:
        chat_index: 1-based index of this chat in the dialog list.
        total_chats: Total number of chats in the pass.
        chat_title: Display name for the chat.
        estimated_total: Estimated total messages from pre-scan (may be 0).
    """

    def __init__(
        self,
        chat_index: int,
        total_chats: int,
        chat_title: str,
        estimated_total: int = 0,
    ) -> None:
        self.chat_index = chat_index
        self.total_chats = total_chats
        self.chat_title = chat_title
        self.estimated_total = estimated_total
        self.processed = 0
        self.stored = 0
        self._start = time.monotonic()

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start

    @property
    def rate(self) -> float:
        """Messages processed per second."""
        elapsed = self.elapsed_seconds
        if elapsed <= 0:
            return 0.0
        return self.processed / elapsed

    @property
    def eta_seconds(self) -> float | None:
        """Estimated seconds remaining, or None if no estimate possible."""
        if self.estimated_total <= 0 or self.rate <= 0:
            return None
        remaining = max(0, self.estimated_total - self.processed)
        return remaining / self.rate

    def update(self, batch_processed: int, batch_stored: int) -> None:
        """Update counters after a batch flush."""
        self.processed += batch_processed
        self.stored += batch_stored

    def log_batch(self) -> None:
        """Log a progress line for the current batch."""
        tag = f"[Chat {self.chat_index}/{self.total_chats}]"
        rate_str = f"{self.rate:.1f} msg/s"

        if self.estimated_total > 0:
            pct = min(100, int(self.processed / self.estimated_total * 100))
            eta = self.eta_seconds
            eta_str = f"ETA: ~{_format_duration(eta)}" if eta is not None else ""
            logger.info(
                "  %s %d/~%d messages (%d%%) | %s | %s",
                tag,
                self.processed,
                self.estimated_total,
                pct,
                rate_str,
                eta_str,
            )
        else:
            logger.info(
                "  %s %d messages | %s",
                tag,
                self.processed,
                rate_str,
            )

    def log_complete(self) -> None:
        """Log a completion line for this chat."""
        elapsed = _format_duration(self.elapsed_seconds)
        logger.info(
            '  Completed %d/%d: "%s" | %d new in %s',
            self.chat_index,
            self.total_chats,
            self.chat_title,
            self.stored,
            elapsed,
        )


class PassProgress:
    """Tracks overall progress across all chats in a sync pass.

    Args:
        estimated_total: Sum of estimated message counts across all chats.
        total_chats: Total number of chats being synced.
    """

    def __init__(self, estimated_total: int, total_chats: int) -> None:
        self.estimated_total = estimated_total
        self.total_chats = total_chats
        self.processed = 0
        self.stored = 0
        self.chats_completed = 0
        self._start = time.monotonic()

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start

    @property
    def rate(self) -> float:
        """Overall messages processed per second."""
        elapsed = self.elapsed_seconds
        if elapsed <= 0:
            return 0.0
        return self.processed / elapsed

    @property
    def eta_seconds(self) -> float | None:
        """Estimated seconds remaining for the entire pass."""
        if self.estimated_total <= 0 or self.rate <= 0:
            return None
        remaining = max(0, self.estimated_total - self.processed)
        return remaining / self.rate

    def update_from_chat(self, chat: ChatProgress) -> None:
        """Accumulate stats from a completed chat."""
        self.processed += chat.processed
        self.stored += chat.stored
        self.chats_completed += 1

    def log_pass_progress(self) -> None:
        """Log overall pass progress."""
        if self.estimated_total > 0:
            pct = min(100, int(self.processed / self.estimated_total * 100))
            eta = self.eta_seconds
            eta_str = f"ETA: ~{_format_duration(eta)}" if eta is not None else ""
            logger.info(
                "  Pass: %d/~%d messages (%d%%) | %s",
                self.processed,
                self.estimated_total,
                pct,
                eta_str,
            )
        else:
            logger.info(
                "  Pass: %d messages processed across %d/%d chats",
                self.processed,
                self.chats_completed,
                self.total_chats,
            )
