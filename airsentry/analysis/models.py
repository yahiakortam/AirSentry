"""Scored window dataclass combining a FeatureVector with an anomaly score.

``ScoredWindow`` is the primary output type of the analysis pipeline, combining
the computed feature vector with the anomaly score from the scoring model and
an optional location label from the operator.  It is used by both the console
output layer and the research dataset exporter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ScoredWindow:
    """
    The output of one analysis cycle: features + anomaly score.

    Parameters
    ----------
    window_start:
        UTC start of the event window (oldest event timestamp).
    window_end:
        UTC end of the event window (newest event timestamp or analysis time).
    window_seconds:
        Duration of the window in seconds.
    n_beacons:
        Number of Beacon frames in the window.
    n_probe_requests:
        Number of Probe Request frames in the window.
    n_probe_responses:
        Number of Probe Response frames in the window.
    n_deauths:
        Combined count of Deauthentication + Disassociation frames.
    n_total_frames:
        Total management frames in the window.
    unique_ssids:
        Number of distinct SSIDs observed (hidden/empty excluded).
    unique_bssids:
        Number of distinct BSSIDs observed.
    unique_src_macs:
        Number of distinct source MAC addresses observed.
    ssid_duplication_count:
        Number of SSIDs advertised by more than one BSSID (evil-twin signal).
    beacon_rate:
        Beacons per second during this window.
    probe_request_rate:
        Probe requests per second during this window.
    frame_type_entropy:
        Shannon entropy of the management frame type distribution.
    anomaly_score:
        0.0–1.0 anomaly indicator (higher = more anomalous).
    is_model_fitted:
        True if the IsolationForest model was used; False if heuristic fallback.
    location:
        Operator-supplied location label (empty string if not in collect mode).
    """

    # --- window bounds ---
    window_start: datetime
    window_end: datetime
    window_seconds: float

    # --- frame counts ---
    n_beacons: int
    n_probe_requests: int
    n_probe_responses: int
    n_deauths: int
    n_total_frames: int

    # --- device / network diversity ---
    unique_ssids: int
    unique_bssids: int
    unique_src_macs: int
    ssid_duplication_count: int

    # --- rates ---
    beacon_rate: float
    probe_request_rate: float

    # --- information-theoretic ---
    frame_type_entropy: float

    # --- scoring ---
    anomaly_score: float
    is_model_fitted: bool

    # --- metadata ---
    location: str = ""

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict representation."""
        return {
            "window_start":          self.window_start.isoformat(),
            "window_end":            self.window_end.isoformat(),
            "window_seconds":        round(self.window_seconds, 2),
            "n_beacons":             self.n_beacons,
            "n_probe_requests":      self.n_probe_requests,
            "n_probe_responses":     self.n_probe_responses,
            "n_deauths":             self.n_deauths,
            "n_total_frames":        self.n_total_frames,
            "unique_ssids":          self.unique_ssids,
            "unique_bssids":         self.unique_bssids,
            "unique_src_macs":       self.unique_src_macs,
            "ssid_duplication_count": self.ssid_duplication_count,
            "beacon_rate":           round(self.beacon_rate, 4),
            "probe_request_rate":    round(self.probe_request_rate, 4),
            "frame_type_entropy":    round(self.frame_type_entropy, 4),
            "anomaly_score":         round(self.anomaly_score, 4),
            "is_model_fitted":       self.is_model_fitted,
            "location":              self.location,
        }
