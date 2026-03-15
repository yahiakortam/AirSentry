"""Deauthentication burst detector.

Detects suspicious floods of 802.11 Deauthentication and Disassociation
frames — the hallmark of a deauth attack used to kick clients off a network.

Algorithm
---------
Per source MAC address, a rolling time window tracks recent deauth/disassoc
frames.  When the frame count within the window exceeds ``burst_threshold``,
an alert is raised.

- Severity ``HIGH`` is used when the destination is a specific client.
- Severity ``CRITICAL`` is used when the destination is the broadcast address,
  because broadcast deauths affect *all* clients simultaneously.

Confidence scales linearly with frame count: ``count / threshold``, capped at 1.0.
An alert fires at most once per source MAC per window, then re-arms only after
the count drops back below the threshold for a fresh window.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from airsentry.detection.base import Detector
from airsentry.detection.window import RollingWindow
from airsentry.models.alerts import Alert, AlertType, Severity, make_alert
from airsentry.models.events import DeauthEvent, DisassocEvent, FrameEvent
from airsentry.utils.mac import is_broadcast


class DeauthBurstDetector(Detector):
    """
    Detects deauthentication/disassociation frame bursts per source MAC.

    Parameters
    ----------
    window_seconds:
        Rolling window width.  Frames older than this are forgotten.
    burst_threshold:
        Minimum frame count within the window to trigger an alert.
    """

    _NAME = "deauth_burst"

    def __init__(
        self,
        window_seconds: float = 10.0,
        burst_threshold: int = 10,
    ) -> None:
        self._window_seconds = window_seconds
        self._threshold = burst_threshold
        # Per-source-MAC rolling window: src_mac → RollingWindow[str (dst_mac)]
        self._windows: dict[str, RollingWindow[str]] = {}
        # Track which sources already have an active alert to avoid spam
        self._alerted: set[str] = set()

    @property
    def name(self) -> str:
        return self._NAME

    def feed(self, event: FrameEvent, now: datetime) -> list[Alert]:
        if not isinstance(event, (DeauthEvent, DisassocEvent)):
            return []

        src = event.src_mac
        dst = event.dst_mac

        # Get or create the rolling window for this source
        if src not in self._windows:
            self._windows[src] = RollingWindow(duration_seconds=self._window_seconds)

        window = self._windows[src]
        window.push(dst, now)
        count = window.count(now)

        # Re-arm: if the source fell below threshold, clear the alerted flag
        if count < self._threshold and src in self._alerted:
            self._alerted.discard(src)

        # Only fire once per continuous burst episode
        if count >= self._threshold and src not in self._alerted:
            self._alerted.add(src)
            return [self._build_alert(src, dst, count, now)]

        return []

    def reset(self) -> None:
        self._windows.clear()
        self._alerted.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_alert(
        self,
        src_mac: str,
        most_recent_dst: str,
        frame_count: int,
        now: datetime,
    ) -> Alert:
        broadcast = is_broadcast(most_recent_dst)
        severity = Severity.CRITICAL if broadcast else Severity.HIGH
        target_desc = "BROADCAST (all clients)" if broadcast else most_recent_dst
        confidence = min(1.0, frame_count / self._threshold)
        window_s = int(self._window_seconds)

        description = (
            f"{frame_count} deauth/disassoc frames from {src_mac} "
            f"targeting {target_desc} within {window_s}s window"
        )
        return make_alert(
            alert_type=AlertType.DEAUTH_BURST,
            severity=severity,
            confidence=confidence,
            description=description,
            timestamp=now,
            detector_name=self._NAME,
            src_macs=[src_mac],
            bssid=src_mac,
        )
