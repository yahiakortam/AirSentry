"""Anomaly scoring for 802.11 wireless environment analysis.

``AnomalyScorer`` evaluates how anomalous a given ``FeatureVector`` is relative
to previously observed windows.

Model strategy
--------------
1. **Warm-up phase** (first N windows, configurable):
   The model has no training data.  During this phase a *heuristic* score is
   returned, based on deauthentication count and SSID duplication — both
   reliable early indicators of attack traffic.  Score is normalised to 0–1.

2. **Fitted phase** (after warm-up):
   An ``IsolationForest`` is fitted on the accumulated warm-up vectors and
   is then used for all subsequent scoring.  The model is periodically
   *refitted* on the full history (capped at ``max_history`` windows) so that
   the baseline adapts as the environment changes.

Score normalisation
-------------------
``IsolationForest.decision_function()`` returns raw anomaly scores typically
in [-0.5, 0.5] where lower = more anomalous.  We map this to [0, 1] with 1
being most anomalous using a sigmoid-like clamp.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np

from airsentry.analysis.features import FeatureVector


# ---------------------------------------------------------------------------
# AnomalyScorer
# ---------------------------------------------------------------------------


class AnomalyScorer:
    """
    Lightweight anomaly scorer for wireless feature vectors.

    Parameters
    ----------
    warmup_windows:
        Minimum number of windows required before fitting the IsolationForest.
        During warm-up, a heuristic score is returned.
    max_history:
        Maximum number of feature vectors retained for incremental refitting.
        Older vectors are dropped when this limit is reached.
    refit_every:
        Refit the model every N windows after the initial fit.
    n_estimators:
        Number of trees in the IsolationForest.
    contamination:
        Expected proportion of anomalies in the training data.
    """

    def __init__(
        self,
        warmup_windows: int   = 30,
        max_history: int      = 500,
        refit_every: int      = 20,
        n_estimators: int     = 100,
        contamination: float  = 0.05,
    ) -> None:
        self._warmup_windows = max(warmup_windows, 5)
        self._max_history    = max_history
        self._refit_every    = refit_every
        self._n_estimators   = n_estimators
        self._contamination  = contamination

        self._history: list[list[float]] = []  # feature rows
        self._model: object | None = None       # IsolationForest after fit
        self._windows_scored: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_fitted(self) -> bool:
        """True if the IsolationForest model has been fitted at least once."""
        return self._model is not None

    @property
    def windows_scored(self) -> int:
        """Total number of windows scored so far."""
        return self._windows_scored

    def score(self, fv: FeatureVector) -> float:
        """
        Score *fv* and return an anomaly indicator in [0.0, 1.0].

        1.0 = maximally anomalous; 0.0 = normal.

        Internally accumulates the vector for model training and triggers a
        model refit when appropriate.

        Parameters
        ----------
        fv:
            Feature vector from one analysis window.

        Returns
        -------
        float
            Anomaly score in [0.0, 1.0].
        """
        row = fv.to_numpy_row()
        self._history.append(row)

        # Trim history to cap memory usage
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        self._windows_scored += 1

        # Decide whether to (re)fit model
        n = len(self._history)
        should_fit = (
            n >= self._warmup_windows
            and (
                self._model is None
                or self._windows_scored % self._refit_every == 0
            )
        )
        if should_fit:
            self._fit()

        # Score
        if self._model is None:
            return self._heuristic_score(fv)
        return self._model_score(row)

    def score_raw(self, n_deauths: int, n_beacons: int) -> float:
        """
        Return a fast heuristic score without accumulating history.

        Intended for unit-testing or very early pipeline stages.
        """
        return _heuristic(n_deauths, n_beacons)

    def reset(self) -> None:
        """Clear all history and the fitted model."""
        self._history.clear()
        self._model = None
        self._windows_scored = 0

    # ------------------------------------------------------------------
    # Internal: model fitting
    # ------------------------------------------------------------------

    def _fit(self) -> None:
        """Fit (or refit) the IsolationForest on accumulated history."""
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest

            X = np.array(self._history, dtype=float)
            model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=42,
                n_jobs=1,
            )
            model.fit(X)
            self._model = model
        except Exception:
            # If sklearn is not available or fitting fails, keep using heuristic
            self._model = None

    def _model_score(self, row: list[float]) -> float:
        """Return a 0–1 score from the fitted IsolationForest."""
        try:
            import numpy as np

            X = np.array([row], dtype=float)
            raw = float(self._model.decision_function(X)[0])  # type: ignore[union-attr]
            # decision_function: lower = more anomalous.
            # Typical range ≈ [-0.5, 0.5]; map to [0, 1] inversely.
            # score = sigmoid(-raw * 8) clipped to [0, 1]
            score = 1.0 / (1.0 + math.exp(raw * 8))
            return max(0.0, min(1.0, score))
        except Exception:
            return 0.5  # safe fallback

    def _heuristic_score(self, fv: FeatureVector) -> float:
        """Return a heuristic 0–1 anomaly score when the model is not yet fitted."""
        return _heuristic(fv.n_deauths, fv.n_beacons, fv.ssid_duplication_count)


# ---------------------------------------------------------------------------
# Pure heuristic (also used by score_raw)
# ---------------------------------------------------------------------------


def _heuristic(
    n_deauths: int,
    n_beacons: int,
    ssid_dup: int = 0,
) -> float:
    """
    Rule-based anomaly score for the warm-up phase.

    Weights deauthentication frames and SSID duplication heavily as early
    attack indicators. Returns a value in [0.0, 1.0].
    """
    # Each component normalised to [0,1], then combined with weights.
    # deauth: 30+ deauths → score 1.0; 0 deauths → 0.0
    deauth_score = min(n_deauths / 30.0, 1.0)
    # ssid_dup: 3+ collisions → score 1.0
    dup_score    = min(ssid_dup / 3.0, 1.0)
    # beacon_spike: 500+ beacons in window → score 1.0
    beacon_score = min(n_beacons / 500.0, 1.0)

    # Weighted combination
    combined = 0.55 * deauth_score + 0.30 * dup_score + 0.15 * beacon_score
    return round(max(0.0, min(1.0, combined)), 4)
