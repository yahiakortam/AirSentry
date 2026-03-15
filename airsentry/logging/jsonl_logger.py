"""Structured JSONL logging for AirSentry sessions.

Each log record is a single JSON object on its own line (JSONL / JSON Lines
format), making log files easy to stream, grep, and import into analysis
tools such as pandas, jq, or a future database backend.

Three record types are written:
  - ``"event"``   — normalized 802.11 management frame events
  - ``"alert"``   — detection alerts from the engine
  - ``"summary"`` — end-of-session statistics

Usage::

    with StructuredLogger.open() as log:
        log.log_event(event)
        log.log_alert(alert)
    # File is auto-flushed and closed on context exit

The logger is intentionally file-only and synchronous — consistent with the
no-external-infrastructure constraint for Phase 2.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Optional, Type

from airsentry.models.alerts import Alert
from airsentry.models.events import (
    BeaconEvent,
    DeauthEvent,
    DisassocEvent,
    FrameEvent,
    ProbeRequestEvent,
    ProbeResponseEvent,
)
from airsentry.utils.time import format_timestamp_iso


# ---------------------------------------------------------------------------
# Default log directory
# ---------------------------------------------------------------------------

def _default_log_dir() -> Path:
    """
    Return the platform-appropriate default log directory.

    Uses XDG_DATA_HOME on Linux, ~/Library/Application Support on macOS,
    and LOCALAPPDATA on Windows — with a fallback to ~/.local/share.
    """
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        base = Path(xdg)
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif Path("/Library").exists():
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path.home() / ".local" / "share"
    return base / "airsentry" / "sessions"


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------


class StructuredLogger:
    """
    Append-mode JSONL logger for AirSentry events and alerts.

    Parameters
    ----------
    log_path:
        Full path of the JSONL file to write.  Created (including any missing
        parent directories) if it does not exist.
    log_events:
        When True, raw parsed frame events are also logged.  Alerts are always
        logged regardless of this flag.
    """

    def __init__(self, log_path: Path, log_events: bool = False) -> None:
        self._path = log_path
        self._log_events = log_events
        self._file = None
        self._alert_count = 0
        self._event_count = 0

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "StructuredLogger":
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> "StructuredLogger":
        """Open the log file for appending."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a", encoding="utf-8", buffering=1)
        return self

    def close(self) -> None:
        """Flush and close the log file."""
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()

    @property
    def log_path(self) -> Path:
        """The path of the log file being written."""
        return self._path

    @property
    def alert_count(self) -> int:
        """Number of alert records written so far."""
        return self._alert_count

    @property
    def event_count(self) -> int:
        """Number of event records written so far."""
        return self._event_count

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_event(self, event: FrameEvent) -> None:
        """
        Write a normalized frame event to the log.

        Only written when ``log_events=True`` was passed to the constructor.
        """
        if not self._log_events:
            return
        record = _event_to_dict(event)
        self._write(record)
        self._event_count += 1

    def log_alert(self, alert: Alert) -> None:
        """Write a detection alert to the log."""
        self._write(alert.to_dict())
        self._alert_count += 1

    def log_session_summary(self, summary: dict) -> None:
        """Write a session summary record."""
        record = {
            "record_type": "summary",
            "timestamp": format_timestamp_iso(datetime.now(tz=timezone.utc)),
            **summary,
        }
        self._write(record)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def open_session(
        cls,
        log_dir: Optional[Path] = None,
        log_events: bool = False,
    ) -> "StructuredLogger":
        """
        Create and open a logger for a new session.

        The log file name is auto-generated from the current UTC date so that
        sessions on the same day share a file.

        Parameters
        ----------
        log_dir:
            Override the log directory.  Defaults to the platform-appropriate
            AirSentry data directory.
        log_events:
            If True, raw events are also written to the log.
        """
        base = log_dir or _default_log_dir()
        date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        log_path = base / f"airsentry-{date_str}.jsonl"
        instance = cls(log_path=log_path, log_events=log_events)
        instance.open()
        return instance

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write(self, record: dict) -> None:
        if self._file is None or self._file.closed:
            raise RuntimeError("StructuredLogger is not open; call open() first.")
        self._file.write(json.dumps(record, default=str) + "\n")


# ---------------------------------------------------------------------------
# Event serialisation helpers
# ---------------------------------------------------------------------------

def _event_to_dict(event: FrameEvent) -> dict:
    """Convert a FrameEvent to a JSON-serialisable dict."""
    base: dict = {
        "record_type":  "event",
        "frame_type":   event.frame_type.name,
        "timestamp":    format_timestamp_iso(event.timestamp),
        "src_mac":      event.src_mac,
        "dst_mac":      event.dst_mac,
        "bssid":        event.bssid,
        "channel":      event.channel,
        "signal_dbm":   event.signal_dbm,
    }

    if isinstance(event, BeaconEvent):
        base.update({
            "ssid":             event.ssid,
            "beacon_interval":  event.beacon_interval,
            "capability_info":  event.capability_info,
            "is_hidden":        event.is_hidden,
        })
    elif isinstance(event, ProbeRequestEvent):
        base.update({
            "ssid":        event.ssid,
            "is_directed": event.is_directed,
        })
    elif isinstance(event, ProbeResponseEvent):
        base.update({
            "ssid":            event.ssid,
            "beacon_interval": event.beacon_interval,
            "capability_info": event.capability_info,
        })
    elif isinstance(event, (DeauthEvent, DisassocEvent)):
        base.update({
            "reason_code":        event.reason_code.value,
            "reason_description": event.reason_description,
        })

    return base
