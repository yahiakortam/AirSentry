"""AirSentry CLI — main application entrypoint."""

from __future__ import annotations

import typer

from airsentry import __version__
from airsentry.cli.commands.collect import collect
from airsentry.cli.commands.dataset import dataset_app
from airsentry.cli.commands.demo import demo
from airsentry.cli.commands.monitor import monitor
from airsentry.cli.commands.replay import replay
from airsentry.cli.commands.visualize import visualize

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="airsentry",
    help=(
        "[bold cyan]AirSentry[/bold cyan] — Passive Wi-Fi security monitoring and research platform.\n\n"
        "Observe nearby 802.11 management frames in real-time, replay captured PCAP files,\n"
        "collect wireless research datasets, and visualize wireless environments."
    ),
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"AirSentry {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print AirSentry version and exit.",
    ),
) -> None:
    """AirSentry passive Wi-Fi monitoring platform."""


# ---------------------------------------------------------------------------
# Register subcommands
# ---------------------------------------------------------------------------

app.command(name="monitor",   help="Monitor a live Wi-Fi interface in real-time.")(monitor)
app.command(name="replay",    help="Replay and analyze a PCAP capture file.")(replay)
app.command(name="collect",   help="Collect wireless environment statistics for research.")(collect)
app.command(name="demo",      help="Showcase AirSentry features using a PCAP file.")(demo)
app.command(name="visualize", help="Generate charts from a research dataset.")(visualize)
app.add_typer(dataset_app,    name="dataset", help="Manage and analyze wireless research datasets.")
