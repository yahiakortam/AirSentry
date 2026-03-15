"""Timestamp utilities for AirSentry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)


def from_epoch(epoch: Optional[float]) -> datetime:
    """
    Convert a Unix epoch float (as returned by Scapy's packet.time)
    to a timezone-aware UTC datetime.  Falls back to utc_now() if None.
    """
    if epoch is None:
        return utc_now()
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def format_timestamp(dt: datetime) -> str:
    """
    Return a human-readable, compact timestamp string for terminal display.
    Example: "14:32:05.123"
    """
    return dt.strftime("%H:%M:%S.%f")[:-3]  # Trim microseconds to milliseconds


def format_timestamp_iso(dt: datetime) -> str:
    """Return an ISO 8601 timestamp string for structured logging use."""
    return dt.isoformat()
