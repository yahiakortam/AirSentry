"""Collect subcommand — research data collection for wireless environments."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer

from airsentry.capture.base import CaptureError
from airsentry.capture.live import StreamingLiveCapture
from airsentry.config.settings import load_settings
from airsentry.output import console as out
from airsentry.parsing.dispatcher import FrameDispatcher
from airsentry.research.collector import ResearchCollector
from airsentry.research.exporter import DatasetExporter

app = typer.Typer()


@app.command()
def collect(
    interface: str = typer.Option(
        ...,
        "--interface", "-i",
        help="Name of the monitor-mode Wi-Fi interface (e.g., wlan0mon).",
        show_default=False,
    ),
    location: str = typer.Option(
        ...,
        "--location", "-l",
        help="Label for the current collection location (e.g., 'coffee_shop_1').",
        show_default=False,
    ),
    duration: int = typer.Option(
        ...,
        "--duration", "-d",
        help="Duration of the collection session in seconds.",
        min=10,
    ),
    interval: float = typer.Option(
        30.0,
        "--interval",
        help="Analysis interval in seconds (how often to extract features).",
        min=5.0,
    ),
    window: float = typer.Option(
        60.0,
        "--window",
        help="Rolling look-back window width in seconds.",
        min=10.0,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for the research dataset. Auto-generated if not set.",
    ),
    fmt: str = typer.Option(
        "jsonl",
        "--format",
        help="Dataset output format (jsonl or csv).",
    ),
) -> None:
    """
    Collect wireless environment statistics for research analysis.

    This mode monitors wireless activity for a fixed duration, computes
    rolling features, and exports an anonymized, structured dataset.

    Requires root privileges and a wireless interface in monitor mode.
    """
    settings = load_settings()
    fmt = fmt.lower()
    if fmt not in ("jsonl", "csv"):
        out.print_error(f"Invalid format: {fmt}. Must be 'jsonl' or 'csv'.")
        raise typer.Exit(code=1)

    try:
        capture = StreamingLiveCapture(
            interface=interface,
            bpf_filter=settings.capture.bpf_filter,
            snap_length=settings.capture.snap_length,
        )
    except CaptureError as exc:
        out.print_error(str(exc))
        raise typer.Exit(code=1)

    # Prepare exporter
    exporter: Optional[DatasetExporter] = None
    try:
        if output:
            exporter = DatasetExporter(path=output, fmt=fmt) # type: ignore[arg-type]
            exporter.open()
        else:
            exporter = DatasetExporter.open_session(
                output_dir=Path(settings.research.default_output_dir) if settings.research.default_output_dir else None,
                fmt=fmt, # type: ignore[arg-type]
                location=location,
            )
    except Exception as exc:
        out.print_error(f"Could not open research dataset file: {exc}")
        raise typer.Exit(code=1)

    collector = ResearchCollector(
        window_seconds=window,
        interval_seconds=interval,
        location=location,
        exporter=exporter,
        warmup_windows=settings.analysis.warmup_windows,
    )

    dispatcher = FrameDispatcher()
    total_packets = 0
    start_time = time.time()
    next_tick = start_time + interval

    out.print_session_header(f"Research Collection: {location}")
    out.print_info(f"Capturing for {duration} seconds...")
    out.print_info(f"Analysis interval: {interval}s | Rolling window: {window}s")
    out.print_info(f"Dataset path: {exporter.output_path}")
    out.console.print()

    try:
        for packet in capture.packets():
            total_packets += 1
            event = dispatcher.dispatch(packet)
            now = datetime.now(tz=timezone.utc)
            
            if event:
                collector.feed(event)
            
            # Periodic analysis tick
            scored = collector.tick(now)
            if scored:
                out.print_window_stats(scored)
                if scored.anomaly_score >= settings.analysis.anomaly_threshold:
                    out.print_info(f"[bold yellow]ANOMALY DETECTED:[/] Score {scored.anomaly_score:.2f}")

            # Duration check
            if time.time() - start_time >= duration:
                break

    except CaptureError as exc:
        out.print_error(str(exc))
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        out.print_info("Collection interrupted by user.")
    finally:
        # Final analysis cycle
        final_window = collector.finalize()
        if final_window:
            out.print_window_stats(final_window)
        
        if exporter:
            exporter.close()
        
        out.console.print()
        out.print_session_footer(dispatcher.stats, total_packets)
        out.print_info(f"Collection complete. {collector.windows_analyzed} windows analyzed.")
        out.print_info(f"Dataset saved: {exporter.output_path}")
