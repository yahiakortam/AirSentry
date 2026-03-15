"""Session-level statistics accumulator for AirSentry.

``SessionAccumulator`` tracks aggregate statistics across an entire monitoring
session (unlike the per-window ``RollingEventWindow`` which evicts old events).
It is the source of data for the end-of-session summary dashboard.

Usage::

    accumulator = SessionAccumulator()
    for event in pipeline:
        accumulator.feed(event)

    summary = accumulator.summary(
        total_packets=1234,
        alerts_raised=3,
        windows_analyzed=12,
        last_anomaly_score=0.42,
    )
    out.print_session_summary(summary)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from airsentry.models.events import (
    BeaconEvent,
    DeauthEvent,
    DisassocEvent,
    FrameEvent,
    ProbeRequestEvent,
    ProbeResponseEvent,
)


# ---------------------------------------------------------------------------
# SessionSummary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionSummary:
    """
    Aggregated statistics for a complete monitoring or replay session.

    Produced by ``SessionAccumulator.summary()`` and consumed by the console
    output layer and (optionally) the structured logger.
    """

    duration_seconds: float
    total_packets: int
    devices_detected: int
    unique_ssids: int
    unique_bssids: int
    n_beacons: int
    n_probe_requests: int
    n_probe_responses: int
    n_deauths: int
    n_total_frames: int
    alerts_raised: int
    windows_analyzed: int
    last_anomaly_score: Optional[float]
    is_model_fitted: bool

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "duration_seconds":   round(self.duration_seconds, 1),
            "total_packets":      self.total_packets,
            "devices_detected":   self.devices_detected,
            "unique_ssids":       self.unique_ssids,
            "unique_bssids":      self.unique_bssids,
            "n_beacons":          self.n_beacons,
            "n_probe_requests":   self.n_probe_requests,
            "n_probe_responses":  self.n_probe_responses,
            "n_deauths":          self.n_deauths,
            "n_total_frames":     self.n_total_frames,
            "alerts_raised":      self.alerts_raised,
            "windows_analyzed":   self.windows_analyzed,
            "last_anomaly_score": round(self.last_anomaly_score, 4) if self.last_anomaly_score is not None else None,
            "is_model_fitted":    self.is_model_fitted,
        }


# ---------------------------------------------------------------------------
# SessionAccumulator
# ---------------------------------------------------------------------------


class SessionAccumulator:
    """
    Accumulates session-wide wireless environment statistics.

    Unlike the rolling event window (which evicts aged-out events),
    ``SessionAccumulator`` tracks running totals and unique identifier sets
    from the first event to the last.  This gives the end-of-session
    summary its session-wide accuracy.

    Typical broadcast and null MAC addresses (ff:ff:ff:ff:ff:ff,
    00:00:00:00:00:00) are excluded from unique-device counts.
    """

    _EXCLUDED_MACS = frozenset({"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"})

    def __init__(self) -> None:
        self._start_time: float = time.monotonic()
        self._unique_src_macs: set[str] = set()
        self._unique_ssids: set[str] = set()
        self._unique_bssids: set[str] = set()
        self._n_beacons: int = 0
        self._n_probe_requests: int = 0
        self._n_probe_responses: int = 0
        self._n_deauths: int = 0
        self._n_total_frames: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, event: FrameEvent) -> None:
        """
        Ingest one parsed frame event and update session counters.

        This is a hot-path method; keep it fast.
        """
        self._n_total_frames += 1

        if event.src_mac and event.src_mac not in self._EXCLUDED_MACS:
            self._unique_src_macs.add(event.src_mac)

        if event.bssid and event.bssid not in self._EXCLUDED_MACS:
            self._unique_bssids.add(event.bssid)

        if isinstance(event, BeaconEvent):
            self._n_beacons += 1
            if event.ssid:
                self._unique_ssids.add(event.ssid)

        elif isinstance(event, ProbeRequestEvent):
            self._n_probe_requests += 1
            if event.ssid and event.is_directed:
                self._unique_ssids.add(event.ssid)

        elif isinstance(event, ProbeResponseEvent):
            self._n_probe_responses += 1
            if event.ssid:
                self._unique_ssids.add(event.ssid)

        elif isinstance(event, (DeauthEvent, DisassocEvent)):
            self._n_deauths += 1

    def summary(
        self,
        total_packets: int,
        alerts_raised: int,
        windows_analyzed: int = 0,
        last_anomaly_score: Optional[float] = None,
        is_model_fitted: bool = False,
    ) -> SessionSummary:
        """
        Build and return a ``SessionSummary`` from accumulated data.

        Parameters
        ----------
        total_packets:
            Raw packet count from the capture source (includes non-management
            frames, unlike ``n_total_frames`` which counts only parsed ones).
        alerts_raised:
            Total alerts produced by all detectors during the session.
        windows_analyzed:
            Number of analysis windows completed by the ``ResearchCollector``.
        last_anomaly_score:
            Anomaly score from the most recent analysis window, if any.
        is_model_fitted:
            True if the IsolationForest model was fitted (as opposed to the
            heuristic fallback).
        """
        duration = time.monotonic() - self._start_time
        return SessionSummary(
            duration_seconds=duration,
            total_packets=total_packets,
            devices_detected=len(self._unique_src_macs),
            unique_ssids=len(self._unique_ssids),
            unique_bssids=len(self._unique_bssids),
            n_beacons=self._n_beacons,
            n_probe_requests=self._n_probe_requests,
            n_probe_responses=self._n_probe_responses,
            n_deauths=self._n_deauths,
            n_total_frames=self._n_total_frames,
            alerts_raised=alerts_raised,
            windows_analyzed=windows_analyzed,
            last_anomaly_score=last_anomaly_score,
            is_model_fitted=is_model_fitted,
        )
