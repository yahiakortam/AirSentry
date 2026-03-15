"""Dataset subcommands — manage and analyze AirSentry research datasets."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer

from airsentry.output import console as out

dataset_app = typer.Typer(
    name="dataset",
    help="Manage and analyze AirSentry wireless research datasets.",
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------


@dataset_app.command("merge")
def merge_cmd(
    files: List[Path] = typer.Option(
        ...,
        "--file", "-f",
        help="Dataset file to include (repeat for multiple files).",
    ),
    output: Path = typer.Option(
        ...,
        "--output", "-o",
        help="Output file path for the merged dataset.",
    ),
    fmt: str = typer.Option(
        "csv",
        "--format",
        help="Output format: csv or jsonl.",
    ),
) -> None:
    """
    Merge multiple dataset files into a single sorted dataset.

    Records are merged and sorted by window_start timestamp.
    Accepts any mix of .csv and .jsonl files.

    \\b
    Example:
        airsentry dataset merge --file session_a.csv --file session_b.csv --output merged.csv
        airsentry dataset merge -f a.jsonl -f b.jsonl --output merged.jsonl --format jsonl
    """
    from airsentry.dataset.toolkit import merge_datasets, save_records

    fmt = fmt.lower()
    if fmt not in ("csv", "jsonl"):
        out.print_error(f"Invalid format: {fmt!r}. Must be 'csv' or 'jsonl'.")
        raise typer.Exit(code=1)

    for f in files:
        if not f.exists():
            out.print_error(f"File not found: {f}")
            raise typer.Exit(code=1)

    out.print_info(f"Merging {len(files)} dataset file(s)...")
    try:
        records = merge_datasets(list(files))
    except Exception as exc:
        out.print_error(f"Merge failed: {exc}")
        raise typer.Exit(code=1)

    try:
        save_records(records, output, fmt=fmt)  # type: ignore[arg-type]
    except Exception as exc:
        out.print_error(f"Could not write output: {exc}")
        raise typer.Exit(code=1)

    out.print_info(f"Merged {len(records)} windows → {output}")


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------


@dataset_app.command("summarize")
def summarize_cmd(
    file: Path = typer.Option(
        ...,
        "--file", "-f",
        help="Dataset file to summarize (.csv or .jsonl).",
        show_default=False,
    ),
    location: Optional[str] = typer.Option(
        None,
        "--location", "-l",
        help="Filter by location label before summarizing.",
    ),
) -> None:
    """
    Print aggregate statistics for a research dataset.

    Displays per-dataset averages, maximums, and counts for all key
    wireless environment features.

    \\b
    Example:
        airsentry dataset summarize --file dataset.csv
        airsentry dataset summarize --file dataset.csv --location cafe_downtown
    """
    from rich.table import Table
    from rich import box

    from airsentry.dataset.toolkit import load_records, filter_by_location, summarize_dataset

    if not file.exists():
        out.print_error(f"File not found: {file}")
        raise typer.Exit(code=1)

    try:
        records = load_records(file)
    except Exception as exc:
        out.print_error(f"Failed to load dataset: {exc}")
        raise typer.Exit(code=1)

    if not records:
        out.print_error("Dataset is empty.")
        raise typer.Exit(code=1)

    if location:
        records = filter_by_location(records, location)
        if not records:
            out.print_warning(f"No records found for location: {location!r}")
            raise typer.Exit(code=0)

    stats = summarize_dataset(records)

    out.console.rule("[bold cyan]Dataset Summary[/bold cyan]", style="cyan")

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        padding=(0, 3),
    )
    table.add_column("Metric",  style="dim")
    table.add_column("Value",   style="bold white", justify="right")

    if location:
        table.add_row("Location filter",    location)

    def _fmt(v) -> str:
        if isinstance(v, float):
            return f"{v:.4f}"
        if isinstance(v, list):
            return ", ".join(v) if v else "(none)"
        return str(v)

    label_map = {
        "total_windows":          "Total windows",
        "locations":              "Locations",
        "avg_anomaly_score":      "Avg anomaly score",
        "max_anomaly_score":      "Max anomaly score",
        "min_anomaly_score":      "Min anomaly score",
        "stdev_anomaly_score":    "Std dev anomaly score",
        "avg_n_beacons":          "Avg beacons / window",
        "avg_n_probe_requests":   "Avg probe requests / window",
        "avg_n_deauths":          "Avg deauths / window",
        "avg_unique_src_macs":    "Avg devices / window",
        "avg_unique_ssids":       "Avg unique SSIDs / window",
        "avg_unique_bssids":      "Avg unique BSSIDs / window",
        "avg_beacon_rate":        "Avg beacon rate (beacons/s)",
        "max_beacon_rate":        "Max beacon rate (beacons/s)",
        "avg_frame_type_entropy": "Avg frame entropy",
        "avg_ssid_duplication":   "Avg SSID duplication count",
    }

    for key, label in label_map.items():
        if key in stats:
            table.add_row(label, _fmt(stats[key]))

    out.console.print(table)


# ---------------------------------------------------------------------------
# filter
# ---------------------------------------------------------------------------


@dataset_app.command("filter")
def filter_cmd(
    file: Path = typer.Option(
        ...,
        "--file", "-f",
        help="Dataset file to filter (.csv or .jsonl).",
        show_default=False,
    ),
    location: str = typer.Option(
        ...,
        "--location", "-l",
        help="Location label to keep (exact match).",
        show_default=False,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path. Defaults to <name>-filtered.<ext> next to the source.",
    ),
    fmt: Optional[str] = typer.Option(
        None,
        "--format",
        help="Output format: csv or jsonl. Defaults to same as input.",
    ),
) -> None:
    """
    Filter a dataset by location label.

    Keeps only records whose 'location' field matches the given label.

    \\b
    Example:
        airsentry dataset filter --file dataset.csv --location cafe_downtown
        airsentry dataset filter --file dataset.csv -l cafe_downtown --output cafe.csv
    """
    from airsentry.dataset.toolkit import load_records, filter_by_location, save_records

    if not file.exists():
        out.print_error(f"File not found: {file}")
        raise typer.Exit(code=1)

    # Resolve output path and format
    out_fmt = (fmt or file.suffix.lstrip(".")).lower()
    if out_fmt not in ("csv", "jsonl"):
        out_fmt = "csv"

    if output is None:
        stem = file.stem + "-filtered"
        output = file.parent / f"{stem}.{out_fmt}"

    try:
        records = load_records(file)
    except Exception as exc:
        out.print_error(f"Failed to load dataset: {exc}")
        raise typer.Exit(code=1)

    filtered = filter_by_location(records, location)

    if not filtered:
        out.print_warning(f"No records match location: {location!r}")
        raise typer.Exit(code=0)

    try:
        save_records(filtered, output, fmt=out_fmt)  # type: ignore[arg-type]
    except Exception as exc:
        out.print_error(f"Could not write output: {exc}")
        raise typer.Exit(code=1)

    out.print_info(
        f"Filtered {len(filtered)} / {len(records)} records "
        f"(location={location!r}) → {output}"
    )


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------


@dataset_app.command("clean")
def clean_cmd(
    file: Path = typer.Option(
        ...,
        "--file", "-f",
        help="Dataset file to clean (.csv or .jsonl).",
        show_default=False,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output path. Defaults to <name>-clean.<ext> next to the source.",
    ),
    fmt: Optional[str] = typer.Option(
        None,
        "--format",
        help="Output format: csv or jsonl. Defaults to same as input.",
    ),
) -> None:
    """
    Remove invalid or incomplete records from a dataset.

    Records are dropped if they are missing required fields, have an
    anomaly score outside [0, 1], or contain unparseable numeric values.

    \\b
    Example:
        airsentry dataset clean --file dataset.csv
        airsentry dataset clean --file dataset.csv --output cleaned.csv
    """
    from airsentry.dataset.toolkit import load_records, clean_dataset, save_records

    if not file.exists():
        out.print_error(f"File not found: {file}")
        raise typer.Exit(code=1)

    out_fmt = (fmt or file.suffix.lstrip(".")).lower()
    if out_fmt not in ("csv", "jsonl"):
        out_fmt = "csv"

    if output is None:
        stem = file.stem + "-clean"
        output = file.parent / f"{stem}.{out_fmt}"

    try:
        records = load_records(file)
    except Exception as exc:
        out.print_error(f"Failed to load dataset: {exc}")
        raise typer.Exit(code=1)

    cleaned = clean_dataset(records)
    removed = len(records) - len(cleaned)

    try:
        save_records(cleaned, output, fmt=out_fmt)  # type: ignore[arg-type]
    except Exception as exc:
        out.print_error(f"Could not write output: {exc}")
        raise typer.Exit(code=1)

    out.print_info(
        f"Cleaned dataset: {len(cleaned)} records kept, "
        f"{removed} removed → {output}"
    )
