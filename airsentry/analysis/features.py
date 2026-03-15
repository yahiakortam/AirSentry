"""Feature extraction for 802.11 wireless environment analysis.

The ``FeatureExtractor`` converts a snapshot of ``FrameEvent`` objects (from a
``RollingEventWindow``) into a ``FeatureVector`` — a flat set of numerical and
categorical statistics that describe the wireless environment observed during
that window.

Design
------
- Stateless: ``FeatureExtractor.extract()`` takes a list of events and returns a
  new ``FeatureVector``.  No internal state is mutated.
- Extensible: additional feature functions can be added; the method simply
  groups extraction logic into clearly named private helpers.
- Values are safe for ML pipelines: all features are real-valued or int-valued
  (no string fields on the vector itself).

``FeatureVector``
-----------------
A frozen dataclass that holds all feature values.  Provides ``to_dict()`` for
serialisation and ``to_numpy()`` for use with scikit-learn.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from airsentry.models.events import (
    BeaconEvent,
    DeauthEvent,
    DisassocEvent,
    FrameEvent,
    ProbeRequestEvent,
    ProbeResponseEvent,
)
from airsentry.models.frame_types import ManagementSubtype


# ---------------------------------------------------------------------------
# FeatureVector
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FeatureVector:
    """
    A structured feature vector computed from one rolling event window.

    All numeric fields are safe for direct use with scikit-learn estimators.

    Fields
    ------
    window_start, window_end:
        Timestamp bounds of the window.
    window_seconds:
        Actual duration spanned by the events (may be < configured window if
        fewer events are present).
    n_beacons, n_probe_requests, n_probe_responses, n_deauths:
        Per-type frame counts.
    n_total_frames:
        Sum of all management frames in the window.
    unique_ssids:
        Count of distinct non-empty SSIDs.
    unique_bssids:
        Count of distinct BSSID strings.
    unique_src_macs:
        Count of distinct source MAC addresses (all frame types).
    ssid_duplication_count:
        Number of SSIDs advertised by more than one distinct BSSID.
        A non-zero value is a common rogue-AP / evil-twin signal.
    beacon_rate, probe_request_rate:
        Frame counts normalised to per-second rates over the window duration.
    frame_type_entropy:
        Shannon entropy (nats) over the distribution of management frame types.
        Higher = more diverse traffic mix.
    """

    # Window bounds
    window_start: datetime
    window_end: datetime
    window_seconds: float

    # Frame counts
    n_beacons: int
    n_probe_requests: int
    n_probe_responses: int
    n_deauths: int
    n_total_frames: int

    # Diversity
    unique_ssids: int
    unique_bssids: int
    unique_src_macs: int
    ssid_duplication_count: int

    # Rates
    beacon_rate: float
    probe_request_rate: float

    # Information-theoretic
    frame_type_entropy: float

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict."""
        return {
            "window_start":           self.window_start.isoformat(),
            "window_end":             self.window_end.isoformat(),
            "window_seconds":         round(self.window_seconds, 2),
            "n_beacons":              self.n_beacons,
            "n_probe_requests":       self.n_probe_requests,
            "n_probe_responses":      self.n_probe_responses,
            "n_deauths":              self.n_deauths,
            "n_total_frames":         self.n_total_frames,
            "unique_ssids":           self.unique_ssids,
            "unique_bssids":          self.unique_bssids,
            "unique_src_macs":        self.unique_src_macs,
            "ssid_duplication_count": self.ssid_duplication_count,
            "beacon_rate":            round(self.beacon_rate, 4),
            "probe_request_rate":     round(self.probe_request_rate, 4),
            "frame_type_entropy":     round(self.frame_type_entropy, 4),
        }

    def to_numpy_row(self) -> list[float]:
        """
        Return feature values as a flat list of floats for ML estimators.

        Order is stable across calls; new features should be appended.
        """
        return [
            float(self.n_beacons),
            float(self.n_probe_requests),
            float(self.n_probe_responses),
            float(self.n_deauths),
            float(self.n_total_frames),
            float(self.unique_ssids),
            float(self.unique_bssids),
            float(self.unique_src_macs),
            float(self.ssid_duplication_count),
            self.beacon_rate,
            self.probe_request_rate,
            self.frame_type_entropy,
        ]


# ---------------------------------------------------------------------------
# FeatureExtractor
# ---------------------------------------------------------------------------


class FeatureExtractor:
    """
    Stateless extractor that converts a list of FrameEvents into a FeatureVector.

    Parameters
    ----------
    window_seconds:
        The nominal window duration.  Used to compute rates when the actual
        event span is 0 (avoids division-by-zero).
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window_seconds = window_seconds

    def extract(
        self,
        events: Sequence[FrameEvent],
        analysis_time: datetime | None = None,
    ) -> FeatureVector:
        """
        Build a FeatureVector from *events*.

        Parameters
        ----------
        events:
            Snapshot from ``RollingEventWindow.snapshot()``.  May be empty.
        analysis_time:
            The current wall-clock time.  Used as ``window_end`` if no events
            are present, and as context for the window bounds.

        Returns
        -------
        FeatureVector
        """
        now = analysis_time or datetime.now(tz=timezone.utc)

        if not events:
            return self._empty_vector(now)

        # --- Window bounds ---
        timestamps = [e.timestamp for e in events]
        window_start = min(timestamps)
        window_end   = max(timestamps)
        window_secs  = max(
            (window_end - window_start).total_seconds(),
            self._window_seconds,  # use nominal if actual span is tiny
        )

        # --- Frame type counts ---
        n_beacons   = sum(1 for e in events if isinstance(e, BeaconEvent))
        n_probe_req = sum(1 for e in events if isinstance(e, ProbeRequestEvent))
        n_probe_rsp = sum(1 for e in events if isinstance(e, ProbeResponseEvent))
        n_deauths   = sum(1 for e in events if isinstance(e, (DeauthEvent, DisassocEvent)))
        n_total     = len(events)

        # --- Network / device diversity ---
        ssids_by_bssid: dict[str, set[str]] = {}
        bssids: set[str] = set()
        src_macs: set[str] = set()

        for ev in events:
            src_macs.add(ev.src_mac)
            if ev.bssid and ev.bssid not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                bssids.add(ev.bssid)
            if isinstance(ev, (BeaconEvent, ProbeResponseEvent)) and ev.ssid:
                ssids_by_bssid.setdefault(ev.ssid, set()).add(ev.bssid)

        unique_ssids     = len(ssids_by_bssid)
        unique_bssids    = len(bssids)
        unique_src_macs  = len(src_macs)
        ssid_dup_count   = sum(1 for bssid_set in ssids_by_bssid.values() if len(bssid_set) > 1)

        # --- Rates ---
        rate_denom      = max(window_secs, 1.0)
        beacon_rate     = n_beacons / rate_denom
        probe_rate      = n_probe_req / rate_denom

        # --- Frame type entropy ---
        type_counts = Counter(e.frame_type.name for e in events)
        entropy     = _shannon_entropy(list(type_counts.values()), n_total)

        return FeatureVector(
            window_start          = window_start,
            window_end            = window_end,
            window_seconds        = window_secs,
            n_beacons             = n_beacons,
            n_probe_requests      = n_probe_req,
            n_probe_responses     = n_probe_rsp,
            n_deauths             = n_deauths,
            n_total_frames        = n_total,
            unique_ssids          = unique_ssids,
            unique_bssids         = unique_bssids,
            unique_src_macs       = unique_src_macs,
            ssid_duplication_count= ssid_dup_count,
            beacon_rate           = beacon_rate,
            probe_request_rate    = probe_rate,
            frame_type_entropy    = entropy,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _empty_vector(self, now: datetime) -> FeatureVector:
        """Return a zero-filled FeatureVector for an empty event list."""
        return FeatureVector(
            window_start          = now,
            window_end            = now,
            window_seconds        = self._window_seconds,
            n_beacons             = 0,
            n_probe_requests      = 0,
            n_probe_responses     = 0,
            n_deauths             = 0,
            n_total_frames        = 0,
            unique_ssids          = 0,
            unique_bssids         = 0,
            unique_src_macs       = 0,
            ssid_duplication_count= 0,
            beacon_rate           = 0.0,
            probe_request_rate    = 0.0,
            frame_type_entropy    = 0.0,
        )


# ---------------------------------------------------------------------------
# Helper: Shannon entropy
# ---------------------------------------------------------------------------


def _shannon_entropy(counts: list[int], total: int) -> float:
    """
    Compute the Shannon entropy of a distribution.

    Parameters
    ----------
    counts:
        Counts for each category.
    total:
        Sum of counts (passed explicitly to avoid recomputing).

    Returns
    -------
    float
        Entropy in nats.  Returns 0.0 if total == 0.
    """
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log(p)
    return entropy
