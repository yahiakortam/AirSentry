"""Abstract base class for AirSentry rule-based detectors.

Every detector in AirSentry implements this interface.  The detection engine
calls ``feed()`` for each normalized event and collects the resulting alerts.

To add a new detector:
  1. Subclass ``Detector``.
  2. Implement ``name`` and ``feed()``.
  3. Register it in ``DetectionEngine.default_engine()``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from airsentry.models.alerts import Alert
from airsentry.models.events import FrameEvent


class Detector(ABC):
    """
    Abstract base for all AirSentry rule-based detectors.

    Each detector is stateful: it accumulates context across many ``feed()``
    calls and only emits an alert when a threshold or pattern is met.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this detector (used in alert metadata and logs)."""
        ...

    @abstractmethod
    def feed(self, event: FrameEvent, now: datetime) -> list[Alert]:
        """
        Process a single normalized frame event.

        Parameters
        ----------
        event:
            A parsed 802.11 management frame event from the pipeline.
        now:
            The "current" time to use for window calculations.  Passing this
            in (rather than calling ``datetime.now()`` internally) keeps
            detectors deterministic and easy to test.

        Returns
        -------
        list[Alert]
            Zero or more alerts produced by this event.  Most events produce
            an empty list; an alert is only returned when a threshold is crossed.
        """
        ...

    def reset(self) -> None:
        """
        Reset internal state.

        Optional — detectors can override this if they support mid-session
        resets.  The default implementation is a no-op.
        """
