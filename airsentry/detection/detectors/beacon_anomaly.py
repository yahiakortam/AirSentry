"""Beacon anomaly detector.

Identifies two types of unusual beacon behavior:

1. **Excessive beacon rate per BSSID** — a legitimate AP sends beacons roughly
   10 times per second (every 100 ms by default).  A much higher rate could
   indicate a replay attack, misconfiguration, or a rogue AP spamming beacons
   to maximise visibility.

2. **Unique SSID flood** — a sudden burst of many different SSIDs in a short
   window can indicate a Wi-Fi Karma attack, a probe injection tool, or a
   crowded environment (e.g., conference with many APs).  This sub-check is
   more of an environmental alert than a precise attack indicator.

Algorithm
---------
Both sub-checks use rolling time windows.  Statistics (count, rate) are
computed lazily when the window is queried.

Confidence is proportional to how far the observed value exceeds the threshold:
  - Beacon rate:  ``(observed_rate / threshold) − 1``, capped at 1.0
  - SSID count:   ``(unique_count / threshold) − 1``, capped at 1.0

To avoid alert spam, each sub-alert has an independent cooldown period equal
to the window width.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from airsentry.detection.base import Detector
from airsentry.detection.window import RollingWindow
from airsentry.models.alerts import Alert, AlertType, Severity, make_alert
from airsentry.models.events import BeaconEvent, FrameEvent


class BeaconAnomalyDetector(Detector):
    """
    Detects excessive per-BSSID beacon rates and unique SSID floods.

    Parameters
    ----------
    window_seconds:
        Rolling window width used for both sub-checks.
    rate_threshold:
        Beacons per second per BSSID that triggers a rate alert.
    unique_ssid_threshold:
        Distinct SSIDs in the window that triggers an SSID flood alert.
    """

    _NAME = "beacon_anomaly"

    def __init__(
        self,
        window_seconds: float = 30.0,
        rate_threshold: float = 50.0,
        unique_ssid_threshold: int = 20,
    ) -> None:
        self._window_seconds = window_seconds
        self._rate_threshold = rate_threshold
        self._ssid_threshold = unique_ssid_threshold

        # Per-BSSID window: bssid → RollingWindow of beacon timestamps (stored as ssid strings)
        self._per_bssid_windows: dict[str, RollingWindow[str]] = {}

        # Global window tracking SSIDs seen (for the flood check)
        self._ssid_window: RollingWindow[str] = RollingWindow(duration_seconds=window_seconds)

        # Cooldown tracking to avoid alert spam
        # key: ("rate", bssid) or ("flood",)  →  last alert timestamp
        self._last_alerted: dict[tuple, datetime] = {}
        self._cooldown = timedelta(seconds=window_seconds)

    @property
    def name(self) -> str:
        return self._NAME

    def feed(self, event: FrameEvent, now: datetime) -> list[Alert]:
        if not isinstance(event, BeaconEvent):
            return []

        bssid = event.bssid
        ssid = event.ssid.strip()

        # --------------- Per-BSSID rate check ---------------
        if bssid not in self._per_bssid_windows:
            self._per_bssid_windows[bssid] = RollingWindow(
                duration_seconds=self._window_seconds
            )
        bssid_window = self._per_bssid_windows[bssid]
        bssid_window.push(ssid, now)
        frame_count = bssid_window.count(now)
        rate = frame_count / self._window_seconds

        alerts: list[Alert] = []

        if rate >= self._rate_threshold and self._can_alert(("rate", bssid), now):
            self._mark_alerted(("rate", bssid), now)
            alerts.append(self._build_rate_alert(bssid, ssid, rate, frame_count, now))

        # --------------- Global SSID flood check ---------------
        self._ssid_window.push(ssid, now)
        unique_ssids = set(self._ssid_window.items_in_window(now))
        unique_count = len(unique_ssids)

        if unique_count >= self._ssid_threshold and self._can_alert(("flood",), now):
            self._mark_alerted(("flood",), now)
            alerts.append(self._build_ssid_flood_alert(unique_ssids, unique_count, now))

        return alerts

    def reset(self) -> None:
        self._per_bssid_windows.clear()
        self._ssid_window.clear()
        self._last_alerted.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _can_alert(self, key: tuple, now: datetime) -> bool:
        """Return True if enough time has passed since the last alert for *key*."""
        last = self._last_alerted.get(key)
        return last is None or (now - last) >= self._cooldown

    def _mark_alerted(self, key: tuple, now: datetime) -> None:
        self._last_alerted[key] = now

    def _build_rate_alert(
        self,
        bssid: str,
        ssid: str,
        rate: float,
        frame_count: int,
        now: datetime,
    ) -> Alert:
        excess = rate / self._rate_threshold - 1.0
        confidence = min(1.0, excess)
        description = (
            f"Abnormal beacon rate from BSSID {bssid} "
            f"(SSID: \"{ssid}\"): {rate:.1f} b/s "
            f"({frame_count} frames in {int(self._window_seconds)}s, "
            f"threshold: {self._rate_threshold:.0f} b/s)"
        )
        return make_alert(
            alert_type=AlertType.BEACON_ANOMALY,
            severity=Severity.LOW,
            confidence=confidence,
            description=description,
            timestamp=now,
            detector_name=self._NAME,
            src_macs=[bssid],
            ssids=[ssid] if ssid else [],
            bssid=bssid,
        )

    def _build_ssid_flood_alert(
        self,
        unique_ssids: set[str],
        unique_count: int,
        now: datetime,
    ) -> Alert:
        excess = unique_count / self._ssid_threshold - 1.0
        confidence = min(1.0, excess)
        sample = sorted(s for s in unique_ssids if s)[:5]
        sample_str = ", ".join(f'"{s}"' for s in sample)
        if unique_count > 5:
            sample_str += f", ... (+{unique_count - 5} more)"
        description = (
            f"{unique_count} unique SSIDs observed in {int(self._window_seconds)}s window "
            f"— possible beacon flood or Karma attack "
            f"(sample: {sample_str})"
        )
        return make_alert(
            alert_type=AlertType.BEACON_ANOMALY,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=description,
            timestamp=now,
            detector_name=self._NAME,
            src_macs=[],
            ssids=sorted(unique_ssids)[:20],
        )
