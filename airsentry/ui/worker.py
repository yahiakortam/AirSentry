"""Background QThread workers for AirSentry packet capture pipelines.

Two workers share the same pipeline stages (dispatch → detect → analyze →
accumulate) but differ only in their capture source:

- ``ReplayWorker``  — reads from a PCAP file via ``PcapCapture``
- ``MonitorWorker`` — reads from a live interface via Scapy's AsyncSniffer

Both emit Qt signals that the UI connects to for thread-safe updates.
Signals are delivered to the main thread by Qt's queued-connection mechanism.

Stopping
--------
``ReplayWorker.stop()`` — sets a flag; the loop checks it after each packet.
``MonitorWorker.stop()`` — sets the flag *and* calls ``AsyncSniffer.stop()``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QThread, Signal

from airsentry.analysis.session import SessionAccumulator, SessionSummary
from airsentry.config.settings import load_settings
from airsentry.detection.engine import DetectionEngine
from airsentry.models.alerts import Alert
from airsentry.models.events import FrameEvent
from airsentry.parsing.dispatcher import FrameDispatcher
from airsentry.research.collector import ResearchCollector


# ---------------------------------------------------------------------------
# Shared pipeline builder
# ---------------------------------------------------------------------------


def _build_pipeline(settings):
    """Create the standard per-session pipeline objects."""
    dispatcher = FrameDispatcher()
    engine = DetectionEngine.default_engine(settings)
    session = SessionAccumulator()
    collector = ResearchCollector(
        window_seconds=settings.analysis.window_seconds,
        interval_seconds=settings.analysis.interval_seconds,
        warmup_windows=settings.analysis.warmup_windows,
    )
    return dispatcher, engine, session, collector


# ---------------------------------------------------------------------------
# ReplayWorker
# ---------------------------------------------------------------------------


class ReplayWorker(QThread):
    """
    Replays a PCAP file through the full AirSentry pipeline in a background thread.

    Signals
    -------
    event_parsed(FrameEvent)
        Emitted for every successfully parsed management frame.
    alert_raised(Alert)
        Emitted when a detector fires.
    window_scored(object)
        Emitted when an analysis window completes (carries a ScoredWindow).
    progress_updated(int, int)
        Emitted periodically with (packets_processed, total_packets).
    finished(SessionSummary)
        Emitted once when the replay finishes or is stopped.
    error(str)
        Emitted if an unrecoverable error occurs.
    """

    event_parsed    = Signal(object)   # FrameEvent
    alert_raised    = Signal(object)   # Alert
    window_scored   = Signal(object)   # ScoredWindow
    progress_updated = Signal(int, int) # (processed, total)
    finished        = Signal(object)   # SessionSummary
    error           = Signal(str)

    def __init__(
        self,
        file_path: Path,
        rate_pps: Optional[int],
        settings=None,
    ) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._rate_pps  = rate_pps
        self._settings  = settings or load_settings()
        self._stop_requested = False

    def stop(self) -> None:
        """Request graceful stop; the loop will exit after the current packet."""
        self._stop_requested = True

    def run(self) -> None:
        from airsentry.capture.pcap import PcapCapture
        from airsentry.capture.base import CaptureError

        try:
            capture = PcapCapture(
                file_path=self._file_path,
                rate_limit_pps=self._rate_pps,
            )
            total = capture.packet_count()
        except Exception as exc:
            self.error.emit(str(exc))
            return

        dispatcher, engine, session, collector = _build_pipeline(self._settings)

        processed = 0
        all_alerts: list[Alert] = []
        last_scored = None

        try:
            for packet in capture.packets():
                if self._stop_requested:
                    break

                processed += 1
                event = dispatcher.dispatch(packet)

                if event is not None:
                    session.feed(event)
                    self.event_parsed.emit(event)

                    for alert in engine.process(event):
                        all_alerts.append(alert)
                        self.alert_raised.emit(alert)

                    collector.feed(event)
                    scored = collector.tick(event.timestamp)
                    if scored is not None:
                        last_scored = scored
                        self.window_scored.emit(scored)

                if processed % 50 == 0:
                    self.progress_updated.emit(processed, total)

        except Exception as exc:
            self.error.emit(str(exc))
            return

        # Final analysis window
        final = collector.finalize()
        if final is not None and final is not last_scored:
            last_scored = final
            self.window_scored.emit(final)

        self.progress_updated.emit(processed, total)

        summary = session.summary(
            total_packets=processed,
            alerts_raised=len(all_alerts),
            windows_analyzed=collector.windows_analyzed,
            last_anomaly_score=last_scored.anomaly_score if last_scored else None,
            is_model_fitted=last_scored.is_model_fitted if last_scored else False,
        )
        self.finished.emit(summary)


# ---------------------------------------------------------------------------
# MonitorWorker
# ---------------------------------------------------------------------------


class MonitorWorker(QThread):
    """
    Captures live 802.11 traffic and routes it through the AirSentry pipeline.

    Uses Scapy's ``AsyncSniffer`` (which runs in its own thread) so that
    ``stop()`` can terminate the sniff at any time without being blocked
    inside the generator.

    Signals — identical to ``ReplayWorker``.
    """

    event_parsed    = Signal(object)
    alert_raised    = Signal(object)
    window_scored   = Signal(object)
    progress_updated = Signal(int, int)
    finished        = Signal(object)
    error           = Signal(str)

    def __init__(
        self,
        interface: str,
        settings=None,
    ) -> None:
        super().__init__()
        self._interface = interface
        self._settings  = settings or load_settings()
        self._stop_requested = False
        self._sniffer = None  # AsyncSniffer, set in run()

    def stop(self) -> None:
        """Stop live capture; safe to call from any thread."""
        self._stop_requested = True
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def run(self) -> None:
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError:
            self.error.emit("Scapy AsyncSniffer is not available.")
            return

        dispatcher, engine, session, collector = _build_pipeline(self._settings)

        processed = 0
        all_alerts: list[Alert] = []
        last_scored = None

        def _handle(pkt) -> None:
            nonlocal processed, last_scored

            if self._stop_requested:
                return

            processed += 1
            event = dispatcher.dispatch(pkt)

            if event is None:
                return

            session.feed(event)
            self.event_parsed.emit(event)

            for alert in engine.process(event):
                all_alerts.append(alert)
                self.alert_raised.emit(alert)

            collector.feed(event)
            scored = collector.tick(event.timestamp)
            if scored is not None:
                last_scored = scored
                self.window_scored.emit(scored)

            if processed % 50 == 0:
                self.progress_updated.emit(processed, 0)

        try:
            self._sniffer = AsyncSniffer(
                iface=self._interface,
                prn=_handle,
                filter=self._settings.capture.bpf_filter or "type mgt",
                store=False,
                monitor=True,
            )
            self._sniffer.start()
        except Exception as exc:
            self.error.emit(
                f"Failed to start capture on {self._interface!r}: {exc}\n\n"
                "Ensure the interface is in monitor mode and AirSentry is "
                "running with sufficient privileges."
            )
            return

        # Spin until stop is requested; the sniffer callback runs in its own thread
        while not self._stop_requested:
            self.msleep(150)

        # Ensure sniffer is stopped
        try:
            self._sniffer.stop()
        except Exception:
            pass

        # Final analysis window
        final = collector.finalize()
        if final is not None and final is not last_scored:
            last_scored = final
            self.window_scored.emit(final)

        summary = session.summary(
            total_packets=processed,
            alerts_raised=len(all_alerts),
            windows_analyzed=collector.windows_analyzed,
            last_anomaly_score=last_scored.anomaly_score if last_scored else None,
            is_model_fitted=last_scored.is_model_fitted if last_scored else False,
        )
        self.finished.emit(summary)
