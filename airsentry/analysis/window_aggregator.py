"""Rolling event window for the AirSentry analysis pipeline.

``RollingEventWindow`` accumulates ``FrameEvent`` objects within a configurable
look-back duration.  It is the bridge between the per-packet parse pipeline
and the periodic feature-extraction layer.

Design notes
------------
- Distinct from the per-detector ``RollingWindow[T]`` in
  ``airsentry.detection.window`` — that class is generic and detector-private;
  this class is analysis-specific and holds typed ``FrameEvent`` objects.
- ``push()`` is called on every parsed event (no filtering).
- ``snapshot()`` returns all events still within the look-back window.
- Thread safety is not provided; AirSentry is currently single-threaded.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Sequence

from airsentry.models.events import FrameEvent


class RollingEventWindow:
    """
    A sliding time-window that retains ``FrameEvent`` objects.

    Parameters
    ----------
    window_seconds:
        How far back (in seconds) to retain events.  Events older than
        ``window_seconds`` relative to the most recent push are evicted.
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        self._duration = timedelta(seconds=window_seconds)
        self._buffer: deque[tuple[datetime, FrameEvent]] = deque()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def window_seconds(self) -> float:
        """Configured look-back duration in seconds."""
        return self._duration.total_seconds()

    def push(self, event: FrameEvent) -> None:
        """
        Add *event* to the window and evict expired entries.

        Parameters
        ----------
        event:
            A parsed, normalized FrameEvent (any subclass).
        """
        self._buffer.append((event.timestamp, event))
        self._evict(event.timestamp)

    def snapshot(self) -> list[FrameEvent]:
        """
        Return a list of all events currently within the look-back window.

        Does **not** mutate the internal buffer (safe to call repeatedly).
        """
        if not self._buffer:
            return []
        now = self._buffer[-1][0]
        self._evict(now)
        return [ev for _ts, ev in self._buffer]

    def clear(self) -> None:
        """Remove all buffered events."""
        self._buffer.clear()

    @property
    def event_count(self) -> int:
        """Number of events currently in the window."""
        return len(self._buffer)

    @property
    def oldest_timestamp(self) -> datetime | None:
        """Timestamp of the oldest buffered event, or None if empty."""
        return self._buffer[0][0] if self._buffer else None

    @property
    def newest_timestamp(self) -> datetime | None:
        """Timestamp of the newest buffered event, or None if empty."""
        return self._buffer[-1][0] if self._buffer else None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict(self, now: datetime) -> None:
        cutoff = now - self._duration
        while self._buffer and self._buffer[0][0] < cutoff:
            self._buffer.popleft()
