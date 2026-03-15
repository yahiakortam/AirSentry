"""Research collection orchestrator for AirSentry Phase 3.

``ResearchCollector`` ties together the rolling event window, feature
extractor, anomaly scorer, and dataset exporter into a single lightweight
object that the CLI commands can interact with.

The collector has a simple two-method interface:

- ``feed(event)``     — called per parsed packet (fast path)
- ``tick(now)``       — called periodically; triggers analysis if interval elapsed

When an analysis interval fires the collector:
  1. Takes a snapshot of events from the rolling window
  2. Extracts a FeatureVector
  3. Scores the vector
  4. Calls the optional export callback (dataset file)
  5. Returns a ScoredWindow for the caller to display / alert on
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Optional

from airsentry.analysis.features import FeatureExtractor
from airsentry.analysis.models import ScoredWindow
from airsentry.analysis.scoring import AnomalyScorer
from airsentry.analysis.window_aggregator import RollingEventWindow
from airsentry.models.events import FrameEvent
from airsentry.research.exporter import DatasetExporter


# ---------------------------------------------------------------------------
# ResearchCollector
# ---------------------------------------------------------------------------


class ResearchCollector:
    """
    Orchestrates event ingestion, feature extraction, scoring, and export.

    Parameters
    ----------
    window_seconds:
        Look-back duration for the rolling event window.
    interval_seconds:
        How often (in seconds) to extract features and score.
    location:
        Operator-supplied location label for dataset records.
    exporter:
        An open ``DatasetExporter`` instance.  Pass ``None`` if running in
        analysis-only mode (monitor/replay) without dataset output.
    warmup_windows:
        Number of windows to collect before fitting the IsolationForest.
    on_scored_window:
        Optional callback invoked with each ``ScoredWindow`` after scoring.
        Useful for injecting console output from the CLI layer.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        interval_seconds: float = 30.0,
        location: str = "",
        exporter: Optional[DatasetExporter] = None,
        warmup_windows: int = 30,
        on_scored_window: Optional[Callable[[ScoredWindow], None]] = None,
    ) -> None:
        self._event_window   = RollingEventWindow(window_seconds=window_seconds)
        self._extractor      = FeatureExtractor(window_seconds=window_seconds)
        self._scorer         = AnomalyScorer(warmup_windows=warmup_windows)
        self._exporter       = exporter
        self._location       = location
        self._interval       = interval_seconds
        self._on_window      = on_scored_window
        self._last_tick_time: Optional[datetime] = None
        self._windows_analyzed = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, event: FrameEvent) -> None:
        """
        Ingest one parsed frame event.

        This is the hot path — must remain fast.

        Parameters
        ----------
        event:
            Any FrameEvent subclass from the parsing pipeline.
        """
        self._event_window.push(event)

    def tick(self, now: Optional[datetime] = None) -> Optional[ScoredWindow]:
        """
        Check whether an analysis interval has elapsed and, if so, run analysis.

        Parameters
        ----------
        now:
            The current wall-clock time (UTC).  If None, uses ``datetime.now()``.

        Returns
        -------
        ScoredWindow or None
            A scored window if an interval fired; None otherwise.
        """
        now = now or datetime.now(tz=timezone.utc)

        if self._last_tick_time is None:
            self._last_tick_time = now
            return None

        elapsed = (now - self._last_tick_time).total_seconds()
        if elapsed < self._interval:
            return None

        self._last_tick_time = now
        return self._analyze(now)

    def finalize(self) -> Optional[ScoredWindow]:
        """
        Analyze whatever events are left in the window (end-of-session).

        Returns
        -------
        ScoredWindow or None
            Final window, or None if the window was empty.
        """
        now = datetime.now(tz=timezone.utc)
        events = self._event_window.snapshot()
        if not events:
            return None
        return self._analyze(now)

    @property
    def windows_analyzed(self) -> int:
        """Total number of analysis windows completed."""
        return self._windows_analyzed

    @property
    def is_model_fitted(self) -> bool:
        """True if the anomaly scorer's model has been fitted."""
        return self._scorer.is_fitted

    @property
    def scorer(self) -> AnomalyScorer:
        """Direct access to the internal AnomalyScorer."""
        return self._scorer

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _analyze(self, now: datetime) -> Optional[ScoredWindow]:
        """Run one full analysis cycle and return the ScoredWindow."""
        events = self._event_window.snapshot()
        if not events:
            return None

        fv = self._extractor.extract(events, analysis_time=now)
        score = self._scorer.score(fv)

        scored = ScoredWindow(
            window_start           = fv.window_start,
            window_end             = fv.window_end,
            window_seconds         = fv.window_seconds,
            n_beacons              = fv.n_beacons,
            n_probe_requests       = fv.n_probe_requests,
            n_probe_responses      = fv.n_probe_responses,
            n_deauths              = fv.n_deauths,
            n_total_frames         = fv.n_total_frames,
            unique_ssids           = fv.unique_ssids,
            unique_bssids          = fv.unique_bssids,
            unique_src_macs        = fv.unique_src_macs,
            ssid_duplication_count = fv.ssid_duplication_count,
            beacon_rate            = fv.beacon_rate,
            probe_request_rate     = fv.probe_request_rate,
            frame_type_entropy     = fv.frame_type_entropy,
            anomaly_score          = score,
            is_model_fitted        = self._scorer.is_fitted,
            location               = self._location,
        )

        self._windows_analyzed += 1

        if self._exporter:
            try:
                self._exporter.write(scored)
            except Exception:
                pass  # Export errors must not crash the capture pipeline

        if self._on_window:
            try:
                self._on_window(scored)
            except Exception:
                pass

        return scored
