"""Detection engine — orchestrates all registered detectors.

The ``DetectionEngine`` is the central coordinator of the detection layer.
It receives a normalized event from the parsing pipeline, fans it out to every
registered detector, and collects the resulting alerts.

Usage::

    engine = DetectionEngine.default_engine(settings)
    for packet in capture.packets():
        event = dispatcher.dispatch(packet)
        if event is not None:
            alerts = engine.process(event)
            for alert in alerts:
                out.print_alert(alert)
"""

from __future__ import annotations

from datetime import datetime, timezone

from airsentry.detection.base import Detector
from airsentry.detection.detectors.beacon_anomaly import BeaconAnomalyDetector
from airsentry.detection.detectors.deauth_burst import DeauthBurstDetector
from airsentry.detection.detectors.rogue_ap import RogueAPDetector
from airsentry.models.alerts import Alert
from airsentry.models.events import FrameEvent


class DetectionEngine:
    """
    Fan-out coordinator that feeds events to all registered detectors.

    The engine is intentionally thin — it has no detection logic of its
    own.  All intelligence lives in the individual ``Detector`` subclasses.

    Parameters
    ----------
    detectors:
        The list of ``Detector`` instances to run.  Order does not matter.
    """

    def __init__(self, detectors: list[Detector]) -> None:
        self._detectors = list(detectors)
        self._alert_count = 0

    def process(self, event: FrameEvent) -> list[Alert]:
        """
        Feed *event* to all detectors and return any alerts they raise.

        Parameters
        ----------
        event:
            A parsed, normalized management frame event.

        Returns
        -------
        list[Alert]
            Combined list of alerts from all detectors.  Usually empty.
        """
        now = datetime.now(tz=timezone.utc)
        alerts: list[Alert] = []
        for detector in self._detectors:
            try:
                results = detector.feed(event, now)
                alerts.extend(results)
            except Exception:
                # Detectors must never crash the main pipeline.
                # Swallow all exceptions silently to stay resilient.
                pass
        self._alert_count += len(alerts)
        return alerts

    def reset(self) -> None:
        """Reset all detectors to their initial state."""
        for detector in self._detectors:
            detector.reset()
        self._alert_count = 0

    @property
    def alert_count(self) -> int:
        """Total number of alerts produced across all ``process()`` calls."""
        return self._alert_count

    @property
    def detectors(self) -> list[Detector]:
        """The registered detectors (read-only view)."""
        return list(self._detectors)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def default_engine(cls, settings: object | None = None) -> "DetectionEngine":
        """
        Build and return the default detection engine with all built-in detectors.

        Parameters
        ----------
        settings:
            An AirSentry ``Settings`` object.  If ``None``, detectors are
            constructed with their built-in defaults.

        Returns
        -------
        DetectionEngine
            Fully initialised engine ready to process events.
        """
        # Extract detector-specific settings when available
        det_cfg = getattr(settings, "detector", None)

        deauth_window  = getattr(det_cfg, "deauth_window_seconds",   10.0)
        deauth_thresh  = getattr(det_cfg, "deauth_burst_threshold",  10)
        beacon_window  = getattr(det_cfg, "beacon_window_seconds",   30.0)
        beacon_rate    = getattr(det_cfg, "beacon_rate_threshold",   50.0)
        beacon_ssid_th = getattr(det_cfg, "beacon_unique_ssid_threshold", 20)

        detectors: list[Detector] = [
            DeauthBurstDetector(
                window_seconds=deauth_window,
                burst_threshold=deauth_thresh,
            ),
            RogueAPDetector(),
            BeaconAnomalyDetector(
                window_seconds=beacon_window,
                rate_threshold=beacon_rate,
                unique_ssid_threshold=beacon_ssid_th,
            ),
        ]
        return cls(detectors)
