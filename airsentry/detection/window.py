"""Generic rolling time-window for the AirSentry detection engine.

The ``RollingWindow`` keeps track of timestamped items within a configurable
trailing duration.  It is the primitive used by all rule-based detectors to
measure event frequency over time.

Design notes:
- Backed by a ``collections.deque`` for O(1) appends and efficient left-eviction.
- All timestamps must be timezone-aware ``datetime`` objects (UTC preferred).
- Thread safety is intentionally *not* provided — AirSentry currently runs
  single-threaded; a lock can be added later if needed.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Generic, TypeVar

T = TypeVar("T")


class RollingWindow(Generic[T]):
    """
    A sliding time-window that retains items within a trailing duration.

    Items older than ``duration_seconds`` are automatically evicted when
    ``push()`` or any read operation is called.

    Example
    -------
    ::

        window: RollingWindow[str] = RollingWindow(duration_seconds=10.0)
        window.push("first_event", ts=datetime.now(timezone.utc))
        count = window.count(now=datetime.now(timezone.utc))
    """

    def __init__(self, duration_seconds: float) -> None:
        if duration_seconds <= 0:
            raise ValueError(f"duration_seconds must be positive, got {duration_seconds}")
        self._duration = timedelta(seconds=duration_seconds)
        # Each element: (timestamp, item)
        self._buffer: deque[tuple[datetime, T]] = deque()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def duration_seconds(self) -> float:
        """The configured window width in seconds."""
        return self._duration.total_seconds()

    def push(self, item: T, ts: datetime) -> None:
        """
        Append *item* with timestamp *ts*, then evict expired entries.

        Parameters
        ----------
        item:
            The object to store.
        ts:
            The event timestamp.  Must be timezone-aware for consistency.
        """
        self._buffer.append((ts, item))
        self._evict(ts)

    def items_in_window(self, now: datetime) -> list[T]:
        """
        Return all items whose timestamps fall within ``[now − duration, now]``.

        Evicts expired entries as a side-effect.
        """
        self._evict(now)
        return [item for _ts, item in self._buffer]

    def count(self, now: datetime) -> int:
        """Return the number of items currently in the window."""
        self._evict(now)
        return len(self._buffer)

    def clear(self) -> None:
        """Remove all items from the window."""
        self._buffer.clear()

    def oldest_timestamp(self) -> datetime | None:
        """Return the timestamp of the oldest item, or None if empty."""
        if not self._buffer:
            return None
        return self._buffer[0][0]

    def newest_timestamp(self) -> datetime | None:
        """Return the timestamp of the newest item, or None if empty."""
        if not self._buffer:
            return None
        return self._buffer[-1][0]

    def __len__(self) -> int:
        return len(self._buffer)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict(self, now: datetime) -> None:
        """Remove entries older than the window duration relative to *now*."""
        cutoff = now - self._duration
        while self._buffer and self._buffer[0][0] < cutoff:
            self._buffer.popleft()
