"""Structured alert model for AirSentry detection engine.

Alerts are the primary output of the detection layer.  They represent a
detected suspicious wireless condition and carry enough context for both
terminal display and structured logging.

Design notes:
- Alerts are frozen dataclasses, making them safe to pass across pipeline
  stages without mutation risk.
- ``AlertType`` and ``Severity`` are plain string enums so they serialise
  cleanly to JSON without custom encoders.
- The ``confidence`` field (0.0–1.0) is a *relative indicator*, not a
  calibrated probability.  Future ML phases can refine this.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AlertType(str, Enum):
    """The category of threat or anomaly an alert describes."""
    DEAUTH_BURST   = "DEAUTH_BURST"    # Deauthentication frame flood
    ROGUE_AP       = "ROGUE_AP"        # Possible evil-twin / rogue access point
    BEACON_ANOMALY = "BEACON_ANOMALY"  # Unusual beacon rate or SSID count
    ANOMALY_SCORE  = "ANOMALY_SCORE"   # ML/heuristic anomaly score threshold exceeded


class Severity(str, Enum):
    """Alert severity levels, ordered from least to most critical."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def ordinal(self) -> int:
        """Numeric ordinal for comparison (LOW=0 … CRITICAL=3)."""
        return list(Severity).index(self)

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.ordinal > other.ordinal

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.ordinal >= other.ordinal


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Alert:
    """
    A single detected wireless threat or anomaly event.

    Produced by a ``Detector`` and consumed by output and logging layers.
    The ``confidence`` field is a 0.0–1.0 indicator: higher means the
    detector is more certain about the threat.

    Fields
    ------
    id : str
        UUID4 uniquely identifying this alert within a session.
    timestamp : datetime
        When the alert was raised (UTC, timezone-aware).
    alert_type : AlertType
        The category of threat.
    severity : Severity
        How severe the alert is.
    confidence : float
        0.0–1.0 indicator of detector confidence.  Not a calibrated probability.
    description : str
        Short, human-readable explanation of why the alert fired.
    src_macs : tuple[str, ...]
        Implicated source MAC addresses (may be empty).
    ssids : tuple[str, ...]
        Implicated SSIDs (may be empty).
    bssid : str | None
        Implicated BSSID, if applicable.
    detector_name : str
        Name of the detector that produced this alert (for traceability).
    """
    id:            str
    timestamp:     datetime
    alert_type:    AlertType
    severity:      Severity
    confidence:    float
    description:   str
    src_macs:      tuple[str, ...]
    ssids:         tuple[str, ...]
    bssid:         Optional[str]
    detector_name: str

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation of this alert."""
        return {
            "record_type":   "alert",
            "id":            self.id,
            "timestamp":     self.timestamp.isoformat(),
            "alert_type":    self.alert_type.value,
            "severity":      self.severity.value,
            "confidence":    round(self.confidence, 4),
            "description":   self.description,
            "src_macs":      list(self.src_macs),
            "ssids":         list(self.ssids),
            "bssid":         self.bssid,
            "detector_name": self.detector_name,
        }


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------


def make_alert(
    *,
    alert_type: AlertType,
    severity: Severity,
    confidence: float,
    description: str,
    timestamp: datetime,
    detector_name: str,
    src_macs: Optional[list[str]] = None,
    ssids: Optional[list[str]] = None,
    bssid: Optional[str] = None,
) -> Alert:
    """Convenience factory that auto-generates the alert UUID."""
    return Alert(
        id=str(uuid.uuid4()),
        timestamp=timestamp,
        alert_type=alert_type,
        severity=severity,
        confidence=float(confidence),
        description=description,
        src_macs=tuple(src_macs or []),
        ssids=tuple(ssids or []),
        bssid=bssid,
        detector_name=detector_name,
    )
