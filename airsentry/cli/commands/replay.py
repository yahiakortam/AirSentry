"""Replay subcommand — offline PCAP file analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from airsentry.capture.base import CaptureError
from airsentry.capture.pcap import PcapCapture
from airsentry.config.settings import load_settings
from airsentry.detection.engine import DetectionEngine
from airsentry.logging.jsonl_logger import StructuredLogger
from airsentry.output import console as out
from airsentry.parsing.dispatcher import FrameDispatcher
from airsentry.research.collector import ResearchCollector

app = typer.Typer()


@app.command()
def replay(
    file: Path = typer.Option(
        ...,
        "--file", "-f",
        help="Path to the PCAP or PCAPng file to replay.",
        show_default=False,
        exists=False,    # We validate manually to give a better error message
    ),
    rate: Optional[int] = typer.Option(
        None,
        "--rate", "-r",
        help=(
            "Maximum replay rate in packets per second. "
            "When not set, AirSentry simulates the original inter-packet timing."
        ),
        min=1,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Print detailed field-level output for each event.",
    ),
    filter_types: Optional[str] = typer.Option(
        None,
        "--filter",
        help=(
            "Comma-separated list of frame types to display "
            "(beacon, probe_req, probe_resp, deauth, disassoc). "
            "Shows all if not specified."
        ),
    ),
    fast: bool = typer.Option(
        False,
        "--fast",
        help="Replay as fast as possible, ignoring all timing.",
    ),
    detect: bool = typer.Option(
        True,
        "--detect/--no-detect",
        help="Enable or disable the rule-based detection engine.",
    ),
    log_file: Optional[Path] = typer.Option(
        None,
        "--log-file",
        help=(
            "Override the JSONL log file path.  "
            "By default AirSentry writes to ~/.local/share/airsentry/sessions/."
        ),
    ),
    analyze: bool = typer.Option(
        True,
        "--analyze/--no-analyze",
        help="Enable or disable real-time anomaly scoring and environment analysis.",
    ),
) -> None:
    """
    Replay a PCAP file and display parsed 802.11 management frames.

    Replays at original inter-packet timing by default.  Use --fast to
    process as quickly as possible, or --rate to cap the speed.

    \\b
    Example:
        airsentry replay --file capture.pcap
        airsentry replay --file capture.pcap --fast --verbose
        airsentry replay --file capture.pcap --rate 50
        airsentry replay --file capture.pcap --fast --no-detect
    """
    settings = load_settings()
    allowed_types = _parse_filter(filter_types)

    effective_rate: Optional[int] = None
    if fast:
        # Signal PcapCapture to disable all timing by using very high rate
        effective_rate = 0
    elif rate is not None:
        effective_rate = rate

    try:
        capture = PcapCapture(
            file_path=file,
            rate_limit_pps=effective_rate,
        )
    except CaptureError as exc:
        out.print_error(str(exc))
        raise typer.Exit(code=1)

    dispatcher = FrameDispatcher()
    engine = DetectionEngine.default_engine(settings) if detect else None

    # Phase 3: Analysis Collector
    collector: Optional[ResearchCollector] = None
    if analyze:
        collector = ResearchCollector(
            window_seconds=settings.analysis.window_seconds,
            interval_seconds=settings.analysis.interval_seconds,
            warmup_windows=settings.analysis.warmup_windows,
        )

    total_packets = 0
    all_alerts = []

    out.print_session_header(capture.source_description)
    if fast:
        out.print_info("Replaying at maximum speed.")
    elif rate:
        out.print_info(f"Replaying at up to {rate} packets/second.")
    else:
        out.print_info("Replaying with original inter-packet timing.")

    if detect:
        out.print_info("Detection engine active — rule-based threat detectors running.")
    else:
        out.print_info("Detection engine disabled (--no-detect).")

    # Resolve log path
    log_dir = Path(settings.logging.log_dir) if settings.logging.log_dir else None
    effective_log_path = log_file

    logger: Optional[StructuredLogger] = None
    if settings.logging.enabled:
        try:
            if effective_log_path:
                logger = StructuredLogger(
                    log_path=effective_log_path,
                    log_events=settings.logging.log_events,
                )
                logger.open()
            else:
                logger = StructuredLogger.open_session(
                    log_dir=log_dir,
                    log_events=settings.logging.log_events,
                )
            out.print_info(f"Logging session to: {logger.log_path}")
        except OSError as exc:
            out.print_warning(f"Could not open log file: {exc}  (logging disabled)")
            logger = None

    out.console.print()

    try:
        for packet in capture.packets():
            total_packets += 1
            event = dispatcher.dispatch(packet)
            if event is None:
                continue
            if allowed_types and event.frame_type.name.lower() not in allowed_types:
                continue

            out.print_event(event, verbose=verbose)

            if logger:
                logger.log_event(event)

            if collector:
                collector.feed(event)
                scored = collector.tick(event.timestamp)
                if scored:
                    out.print_window_stats(scored)
                    if scored.anomaly_score >= settings.analysis.anomaly_threshold:
                        # Create a synthetic alert for the anomaly
                        from airsentry.models.alerts import AlertType, Severity, make_alert
                        anomaly_alert = make_alert(
                            alert_type=AlertType.ANOMALY_SCORE,
                            severity=Severity.HIGH,
                            confidence=scored.anomaly_score,
                            description=f"Unusual wireless behavior detected (score: {scored.anomaly_score:.2f})",
                            timestamp=event.timestamp,
                            detector_name="AnomalyScorer",
                        )
                        out.print_alert(anomaly_alert)
                        all_alerts.append(anomaly_alert)
                        if logger:
                            logger.log_alert(anomaly_alert)

            if engine:
                alerts = engine.process(event)
                for alert in alerts:
                    out.print_alert(alert)
                    all_alerts.append(alert)
                    if logger:
                        logger.log_alert(alert)

    except CaptureError as exc:
        out.print_error(str(exc))
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        out.print_warning("Replay interrupted by user.")

    out.console.print()
    out.print_session_footer(dispatcher.stats, total_packets)

    if all_alerts:
        out.console.rule("[dim]Detection Alerts[/dim]", style="dim red")
        out.print_alert_summary(all_alerts)

    if logger:
        try:
            logger.log_session_summary({
                "total_packets":   total_packets,
                "parsed_frames":   sum(dispatcher.stats.values()),
                "alerts_raised":   len(all_alerts),
                "frame_breakdown": dispatcher.stats,
            })
        finally:
            logger.close()
        out.print_info(f"Session log saved: {logger.log_path}")


def _parse_filter(filter_str: Optional[str]) -> set[str]:
    _alias_map = {
        "beacon":     "beacon",
        "probe_req":  "probe_request",
        "probereq":   "probe_request",
        "probe_resp": "probe_response",
        "proberesp":  "probe_response",
        "deauth":     "deauthentication",
        "disassoc":   "disassociation",
    }
    if not filter_str:
        return set()
    result = set()
    for part in filter_str.lower().split(","):
        part = part.strip()
        result.add(_alias_map.get(part, part))
    return result
