"""Rich-based terminal output for AirSentry events and alerts.

Design philosophy:
- Each frame type has a distinct color/style so events are visually scannable
- All rendering logic lives here; models and parsers have no output knowledge
- A single ``print_event()`` entrypoint makes it trivial to swap backends later
  (e.g., JSON output, file logging) without touching the rest of the codebase
- ``print_alert()`` renders detection alerts in a consistent, high-visibility style
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from airsentry.analysis.models import ScoredWindow
    from airsentry.analysis.session import SessionSummary

from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich import box

from airsentry.models.alerts import Alert, AlertType, Severity
from airsentry.models.events import (
    BeaconEvent,
    DeauthEvent,
    DisassocEvent,
    FrameEvent,
    ProbeRequestEvent,
    ProbeResponseEvent,
)
from airsentry.models.frame_types import ManagementSubtype
from airsentry.utils.mac import is_broadcast
from airsentry.utils.time import format_timestamp

# ---------------------------------------------------------------------------
# Shared console instance — use stderr=False so output is capturable
# ---------------------------------------------------------------------------

console = Console(highlight=False)

# ---------------------------------------------------------------------------
# Per-frame-type style configuration
# ---------------------------------------------------------------------------

_STYLES: dict[ManagementSubtype, tuple[str, str]] = {
    # (label, color)
    ManagementSubtype.BEACON:           ("BEACON   ", "bright_blue"),
    ManagementSubtype.PROBE_REQUEST:    ("PROBE REQ", "green"),
    ManagementSubtype.PROBE_RESPONSE:   ("PROBE RSP", "cyan"),
    ManagementSubtype.DEAUTHENTICATION: ("DEAUTH   ", "bold red"),
    ManagementSubtype.DISASSOCIATION:   ("DISASSOC ", "red"),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def print_event(event: FrameEvent, verbose: bool = False) -> None:
    """
    Print a single parsed frame event to the terminal.

    The compact one-line format is always shown.  When ``verbose=True``,
    additional detail lines are printed beneath it.
    """
    label, color = _STYLES.get(
        event.frame_type,
        (event.frame_type.name[:9].ljust(9), "white")
    )

    timestamp_str = format_timestamp(event.timestamp)

    line = Text()
    line.append(f"{timestamp_str}  ", style="dim")
    line.append(f"[{label}]", style=f"bold {color}")
    line.append("  ")

    # Frame-type-specific main line content
    if isinstance(event, BeaconEvent):
        _append_beacon(line, event, color)
    elif isinstance(event, ProbeRequestEvent):
        _append_probe_req(line, event, color)
    elif isinstance(event, ProbeResponseEvent):
        _append_probe_resp(line, event, color)
    elif isinstance(event, (DeauthEvent, DisassocEvent)):
        _append_deauth_or_disassoc(line, event, color)
    else:
        line.append(f"{event.src_mac} → {event.dst_mac}", style="white")

    if event.signal_dbm is not None:
        line.append(f"  {_signal_badge(event.signal_dbm)}", style=_signal_style(event.signal_dbm))

    console.print(line)

    if verbose:
        _print_verbose_detail(event)


def print_session_header(source_description: str) -> None:
    """Print a professional session start banner."""
    console.rule(
        f"[bold cyan]AirSentry[/bold cyan]  [dim]{source_description}[/dim]",
        style="dim cyan",
    )


def print_session_footer(stats: dict[str, int], total_packets: int) -> None:
    """Print a summary table at the end of a capture/replay session."""
    console.rule("[dim]Session Summary[/dim]", style="dim")

    if not stats:
        console.print("[dim]  No supported management frames were parsed.[/dim]")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        padding=(0, 2),
    )
    table.add_column("Frame Type", style="white")
    table.add_column("Count", style="bold white", justify="right")

    for frame_type, count in sorted(stats.items(), key=lambda x: -x[1]):
        table.add_row(frame_type.replace("_", " ").title(), str(count))

    table.add_section()
    table.add_row("[bold]Total Packets Processed[/bold]", f"[bold]{total_packets}[/bold]")

    console.print(table)


def print_error(message: str) -> None:
    """Print a formatted error message."""
    console.print(f"[bold red]ERROR[/bold red]  {message}")


def print_warning(message: str) -> None:
    """Print a formatted warning message."""
    console.print(f"[bold yellow]WARN[/bold yellow]   {message}")


def print_info(message: str) -> None:
    """Print a formatted informational message."""
    console.print(f"[bold cyan]INFO[/bold cyan]   {message}")


# ---------------------------------------------------------------------------
# Alert rendering
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[Severity, tuple[str, str]] = {
    # (label_color, icon)
    Severity.LOW:      ("yellow",          "⚠ "),
    Severity.MEDIUM:   ("bold yellow",     "⚠ "),
    Severity.HIGH:     ("bold red",        "🚨"),
    Severity.CRITICAL: ("bold red blink",  "🔴"),
}

_ALERT_TYPE_LABELS: dict[AlertType, str] = {
    AlertType.ROGUE_AP:       "ROGUE AP      ",
    AlertType.BEACON_ANOMALY: "BEACON ANOMALY",
    AlertType.DEAUTH_BURST:   "DEAUTH BURST  ",
    AlertType.ANOMALY_SCORE:  "ANOMALY       ",
}


def print_alert(alert: Alert) -> None:
    """
    Print a single detection alert to the terminal.

    Output is clearly visually distinct from normal event lines:
    a separator rule precedes the alert, followed by the alert detail
    and a short description.
    """
    from airsentry.utils.time import format_timestamp

    style, icon = _SEVERITY_STYLES.get(alert.severity, ("white", "! "))
    label = _ALERT_TYPE_LABELS.get(alert.alert_type, alert.alert_type.value.ljust(14))
    ts = format_timestamp(alert.timestamp)
    confidence_pct = int(alert.confidence * 100)

    # Top line: timestamp, type label, severity, confidence
    line = Text()
    line.append(f"{ts}  ", style="dim")
    line.append(f"{icon} [{label}]", style=f"bold {style}")
    line.append("  ", style="")
    line.append(alert.severity.value, style=f"bold {style}")
    line.append(f"  confidence: {confidence_pct}%", style="dim")

    console.rule(style=style)
    console.print(line)

    # Description line
    console.print(f"   [dim]{alert.description}[/dim]")
    console.rule(style=style)
    console.print()


def print_alert_summary(alerts: list[Alert]) -> None:
    """Print a summary table of all alerts raised during the session."""
    if not alerts:
        console.print("[dim]  No alerts were raised this session.[/dim]")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        padding=(0, 2),
    )
    table.add_column("Time",        style="dim")
    table.add_column("Alert Type",  style="bold white")
    table.add_column("Severity",    style="white")
    table.add_column("Confidence",  style="dim", justify="right")
    table.add_column("Description", style="dim")

    from airsentry.utils.time import format_timestamp

    for al in alerts:
        style, _ = _SEVERITY_STYLES.get(al.severity, ("white", ""))
        label = _ALERT_TYPE_LABELS.get(al.alert_type, al.alert_type.value)
        sev_text = Text(al.severity.value, style=f"bold {style}")
        conf_text = f"{int(al.confidence * 100)}%"
        # Truncate long descriptions for the summary table
        desc = al.description if len(al.description) <= 80 else al.description[:77] + "..."
        table.add_row(
            format_timestamp(al.timestamp),
            label.strip(),
            sev_text,
            conf_text,
            desc,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Per-type line formatters
# ---------------------------------------------------------------------------

def _append_beacon(line: Text, event: BeaconEvent, color: str) -> None:
    ssid_display = f'"{event.ssid}"' if event.ssid else "[dim](hidden)[/dim]"
    line.append(f"SSID: ", style="dim")
    line.append(f"{event.ssid if event.ssid else '(hidden)'}", style=f"bold {color}")
    line.append(f"  BSSID: ", style="dim")
    line.append(event.bssid, style="white")
    if event.channel:
        line.append(f"  ch{event.channel}", style="dim")


def _append_probe_req(line: Text, event: ProbeRequestEvent, color: str) -> None:
    line.append(f"SRC: ", style="dim")
    line.append(event.src_mac, style="white")
    if event.is_directed:
        line.append(f"  →  SSID: ", style="dim")
        line.append(f'"{event.ssid}"', style=f"bold {color}")
    else:
        line.append(f"  →  ", style="dim")
        line.append("[broadcast scan]", style="dim green")


def _append_probe_resp(line: Text, event: ProbeResponseEvent, color: str) -> None:
    line.append(f"SSID: ", style="dim")
    line.append(f'"{event.ssid}"', style=f"bold {color}")
    line.append(f"  →  DST: ", style="dim")
    line.append(event.dst_mac, style="white")
    if event.channel:
        line.append(f"  ch{event.channel}", style="dim")


def _append_deauth_or_disassoc(
    line: Text, event: DeauthEvent | DisassocEvent, color: str
) -> None:
    broadcast_dst = is_broadcast(event.dst_mac)
    line.append(f"SRC: ", style="dim")
    line.append(event.src_mac, style="white")
    line.append(f"  →  ", style="dim")
    if broadcast_dst:
        line.append("BROADCAST", style=f"bold {color}")
    else:
        line.append(event.dst_mac, style=f"bold {color}")
    line.append(f"  reason: ", style="dim")
    line.append(f"{event.reason_code.value} ({event.reason_description})", style=color)


# ---------------------------------------------------------------------------
# Verbose detail block
# ---------------------------------------------------------------------------

def _print_verbose_detail(event: FrameEvent) -> None:
    details: list[tuple[str, str]] = [
        ("src_mac", event.src_mac),
        ("dst_mac", event.dst_mac),
        ("bssid", event.bssid),
        ("channel", str(event.channel) if event.channel is not None else "—"),
        ("signal_dbm", str(event.signal_dbm) if event.signal_dbm is not None else "—"),
    ]

    if isinstance(event, (BeaconEvent, ProbeResponseEvent)):
        details += [
            ("beacon_interval", str(event.beacon_interval) if event.beacon_interval else "—"),
            ("capability_info", hex(event.capability_info) if event.capability_info else "—"),
        ]
    if isinstance(event, BeaconEvent):
        details.append(("is_hidden", str(event.is_hidden)))
    if isinstance(event, ProbeRequestEvent):
        details.append(("is_directed", str(event.is_directed)))
    if isinstance(event, (DeauthEvent, DisassocEvent)):
        details += [
            ("reason_code", str(event.reason_code.value)),
            ("reason", event.reason_description),
        ]

    for key, value in details:
        console.print(f"   [dim]{key + ':':<20}[/dim] {value}")
    console.print()


def print_session_summary(summary: "SessionSummary") -> None:
    """
    Print a rich wireless session summary dashboard.

    Displays session-wide accumulated statistics — unique devices, SSID/BSSID
    counts, frame breakdowns, alert count, and the final anomaly score.
    Called once at the end of a monitoring or replay session.
    """
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.table import Table
    from rich import box
    from airsentry.analysis.session import SessionSummary  # noqa: F401 (type hint)

    console.rule("[bold cyan]Wireless Session Summary[/bold cyan]", style="cyan")

    left = Table(box=None, show_header=False, padding=(0, 2))
    left.add_column(style="dim", no_wrap=True)
    left.add_column(style="bold white", no_wrap=True)
    left.add_row("Devices detected",        str(summary.devices_detected))
    left.add_row("Unique SSIDs",            str(summary.unique_ssids))
    left.add_row("Unique BSSIDs",           str(summary.unique_bssids))

    right = Table(box=None, show_header=False, padding=(0, 2))
    right.add_column(style="dim", no_wrap=True)
    right.add_column(style="bold white", no_wrap=True)
    right.add_row("Beacon frames",          str(summary.n_beacons))
    right.add_row("Probe requests",         str(summary.n_probe_requests))
    right.add_row("Deauth / Disassoc",      str(summary.n_deauths))
    right.add_row("Total frames parsed",    str(summary.n_total_frames))

    console.print(Columns([left, right], padding=(0, 4)))
    console.print()

    meta = Table(box=None, show_header=False, padding=(0, 2))
    meta.add_column(style="dim", no_wrap=True)
    meta.add_column(style="bold white", no_wrap=True)
    meta.add_row("Alerts raised",           str(summary.alerts_raised))
    meta.add_row("Analysis windows",        str(summary.windows_analyzed))

    if summary.last_anomaly_score is not None:
        score = summary.last_anomaly_score
        score_color = "red" if score > 0.6 else "yellow" if score > 0.4 else "green"
        model_label = "IsolationForest" if summary.is_model_fitted else "heuristic"
        meta.add_row(
            "Last anomaly score",
            f"[bold {score_color}]{score:.2f}[/bold {score_color}]  [dim]({model_label})[/dim]",
        )

    mins, secs = divmod(int(summary.duration_seconds), 60)
    duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"
    meta.add_row("Session duration",        duration_str)

    console.print(meta)
    console.print()


def print_window_stats(window: "ScoredWindow") -> None:
    """Print a summary box of wireless environment statistics for a window."""
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    table = Table.grid(expand=True)
    table.add_column(justify="left", style="cyan")
    table.add_column(justify="left", style="white", min_width=8)
    table.add_column(justify="left", style="cyan")
    table.add_column(justify="left", style="white", min_width=8)
    table.add_column(justify="left", style="cyan")
    table.add_column(justify="left", style="white", min_width=8)

    # Row 1
    table.add_row(
        " Devices: ", f"{window.unique_src_macs}",
        " Unique SSIDs: ", f"{window.unique_ssids}",
        " Beacon rate: ", f"{window.beacon_rate:.1f}/s"
    )
    # Row 2
    table.add_row(
        " Probes:  ", f"{window.n_probe_requests}",
        " Deauths:      ", f"{window.n_deauths}",
        " Entropy:     ", f"{window.frame_type_entropy:.2f}"
    )

    score_color = "red" if window.anomaly_score > 0.6 else "yellow" if window.anomaly_score > 0.4 else "green"
    model_info = "IsolationForest" if window.is_model_fitted else "Heuristic"
    
    # Text line for anomaly score
    score_line = f" [bold white]Anomaly score:[/] [bold {score_color}]{window.anomaly_score:.2f}[/] [dim][{model_info}][/]"
    
    panel = Panel(
        table,
        title="[bold blue]Window Statistics[/]",
        subtitle=score_line,
        border_style="dim blue",
        padding=(0, 1)
    )
    console.print()
    console.print(panel)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _signal_badge(dbm: int) -> str:
    """Return a compact signal strength label (e.g. '-72 dBm')."""
    return f"{dbm} dBm"


def _signal_style(dbm: int) -> str:
    """Return a Rich style string based on signal strength."""
    if dbm >= -60:
        return "bold green"
    elif dbm >= -75:
        return "yellow"
    else:
        return "dim red"
