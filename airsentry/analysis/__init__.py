"""AirSentry analysis package — feature extraction and anomaly scoring.

This package converts rolling windows of raw 802.11 management frame events
into structured feature vectors and anomaly scores.

Public API
----------
- ``RollingEventWindow`` — accumulates FrameEvents for a look-back window
- ``FeatureExtractor``  — converts a window snapshot into a FeatureVector
- ``AnomalyScorer``     — scores a FeatureVector for anomalousness (0–1)
- ``ScoredWindow``      — combined FeatureVector + anomaly score dataclass
"""

from airsentry.analysis.features import FeatureExtractor, FeatureVector
from airsentry.analysis.models import ScoredWindow
from airsentry.analysis.scoring import AnomalyScorer
from airsentry.analysis.window_aggregator import RollingEventWindow

__all__ = [
    "FeatureExtractor",
    "FeatureVector",
    "AnomalyScorer",
    "RollingEventWindow",
    "ScoredWindow",
]
