"""Demo subcommand — showcase AirSentry using a PCAP capture file.

The demo command is designed for quick demonstrations and first-time users.
It replays a PCAP file with detection and anomaly scoring enabled, using
moderate timing, and prints a clear annotated session summary at the end.

Unlike 'replay', demo mode:
  - Always enables detection and analysis (cannot be disabled)
  - Uses a moderate, human-readable replay rate (200 pps) by default
  - Shows an explanatory banner before playback begins
  - Runs a final analysis cycle on any remaining buffered events
  - Produces a prominent session summary at the end
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from airsentry.analysis.session import SessionAccumulator
from airsentry.capture.base import CaptureError
from airsentry.capture.pcap import PcapCapture
from airsentry.config.settings import load_settings
from airsentry.detection.engine import DetectionEngine
from airsentry.output import console as out
from airsentry.parsing.dispatcher import FrameDispatcher
from airsentry.research.collector import ResearchCollector

app = typer.Typer()


@app.command()
def demo(
    file: Path = typer.Option(
        ...,
        "--file", "-f",
        help="Path to the PCAP or PCAPng file to replay in demo mode.",
        show_default=False,
    ),
    rate: int = typer.Option(
        200,
        "--rate", "-r",
        help="Replay rate in packets per second (default: 200).",
        min=1,
        max=10000,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Print detailed field-level output for each event.",
    ),
) -> None:
    """
    Run AirSentry in demo mode using a PCAP file.

    Replays the capture file with detection and anomaly scoring always
    enabled.  Designed to give first-time users a clear walkthrough of
    what AirSentry does in a single command.

    \\b
    Example:
        airsentry demo --file examples/sample_capture.pcap
        airsentry demo --file capture.pcap --rate 500
        airsentry demo --file capture.pcap --verbose
    """
    if not file.exists():
        out.print_error(f"PCAP file not found: {file}")
        raise typer.Exit(code=1)

    settings = load_settings()

    # --- Demo intro banner ---
    out.console.rule("[bold cyan]AirSentry Demo Mode[/bold cyan]", style="cyan")
    out.console.print()
    out.console.print(
        "  This demo replays a Wi-Fi capture file and shows AirSentry's core features:\n"
        "  • [bold]Frame parsing[/bold]     — 802.11 management frames decoded in real time\n"
        "  • [bold]Threat detection[/bold]  — deauth floods, rogue APs, beacon anomalies\n"
        "  • [bold]Anomaly scoring[/bold]   — heuristic + IsolationForest model\n"
        "  • [bold]Session summary[/bold]   — environment stats at the end\n"
    )
    out.console.print(f"  [dim]Source:[/dim]  {file}")
    out.console.print(f"  [dim]Rate:[/dim]    {rate} packets/second")
    out.console.print()
    out.console.rule(style="dim cyan")
    out.console.print()

    try:
        capture = PcapCapture(file_path=file, rate_limit_pps=rate)
    except CaptureError as exc:
        out.print_error(str(exc))
        raise typer.Exit(code=1)

    dispatcher = FrameDispatcher()
    engine = DetectionEngine.default_engine(settings)
    session = SessionAccumulator()
    collector = ResearchCollector(
        window_seconds=settings.analysis.window_seconds,
        interval_seconds=settings.analysis.interval_seconds,
        warmup_windows=settings.analysis.warmup_windows,
    )

    total_packets = 0
    all_alerts = []
    last_scored = None

    try:
        for packet in capture.packets():
            total_packets += 1
            event = dispatcher.dispatch(packet)
            if event is None:
                continue

            session.feed(event)
            out.print_event(event, verbose=verbose)

            collector.feed(event)
            scored = collector.tick(event.timestamp)
            if scored:
                last_scored = scored
                out.print_window_stats(scored)
                if scored.anomaly_score >= settings.analysis.anomaly_threshold:
                    from airsentry.models.alerts import AlertType, Severity, make_alert
                    anomaly_alert = make_alert(
                        alert_type=AlertType.ANOMALY_SCORE,
                        severity=Severity.HIGH,
                        confidence=scored.anomaly_score,
                        description=(
                            f"Unusual wireless behavior detected "
                            f"(score: {scored.anomaly_score:.2f})"
                        ),
                        timestamp=event.timestamp,
                        detector_name="AnomalyScorer",
                    )
                    out.print_alert(anomaly_alert)
                    all_alerts.append(anomaly_alert)

            alerts = engine.process(event)
            for alert in alerts:
                out.print_alert(alert)
                all_alerts.append(alert)

    except CaptureError as exc:
        out.print_error(str(exc))
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        out.print_warning("Demo interrupted by user.")

    # Final analysis cycle for any remaining buffered events
    final = collector.finalize()
    if final and final is not last_scored:
        last_scored = final
        out.print_window_stats(final)

    out.console.print()
    out.print_session_footer(dispatcher.stats, total_packets)

    if all_alerts:
        out.console.rule("[dim]Detection Alerts[/dim]", style="dim red")
        out.print_alert_summary(all_alerts)

    summary = session.summary(
        total_packets=total_packets,
        alerts_raised=len(all_alerts),
        windows_analyzed=collector.windows_analyzed,
        last_anomaly_score=last_scored.anomaly_score if last_scored else None,
        is_model_fitted=last_scored.is_model_fitted if last_scored else False,
    )
    out.print_session_summary(summary)

    out.console.rule("[bold cyan]Demo Complete[/bold cyan]", style="cyan")
    out.console.print(
        "\n  To monitor live traffic:  [bold]sudo airsentry monitor --interface wlan0mon[/bold]\n"
        "  To replay your own PCAP:  [bold]airsentry replay --file capture.pcap[/bold]\n"
        "  To collect research data: [bold]sudo airsentry collect --interface wlan0mon --location myplace --duration 600[/bold]\n"
    )
