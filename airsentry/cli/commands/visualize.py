"""Visualize subcommand — generate charts from AirSentry research datasets."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from airsentry.output import console as out

app = typer.Typer()


@app.command()
def visualize(
    file: Path = typer.Option(
        ...,
        "--file", "-f",
        help="Path to the AirSentry dataset file (.csv or .jsonl).",
        show_default=False,
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir", "-o",
        help="Directory to save generated charts. Defaults to ./charts/ next to the dataset.",
    ),
    fmt: str = typer.Option(
        "png",
        "--format",
        help="Image format for charts: png, svg, or pdf.",
    ),
) -> None:
    """
    Generate visualization charts from an AirSentry research dataset.

    Reads a CSV or JSONL dataset file collected by 'airsentry collect' and
    produces a set of charts covering anomaly scores, frame distributions,
    device activity, and beacon rates.

    \\b
    Example:
        airsentry visualize --file dataset.csv
        airsentry visualize --file dataset.jsonl --output-dir ./analysis --format svg
    """
    if not file.exists():
        out.print_error(f"File not found: {file}")
        raise typer.Exit(code=1)

    if file.suffix.lower() not in (".csv", ".jsonl"):
        out.print_error(f"Unsupported file format: {file.suffix!r}. Expected .csv or .jsonl")
        raise typer.Exit(code=1)

    if fmt not in ("png", "svg", "pdf"):
        out.print_error(f"Invalid format: {fmt!r}. Choose from: png, svg, pdf")
        raise typer.Exit(code=1)

    # Resolve output directory
    charts_dir = output_dir or file.parent / "charts"

    # Check matplotlib availability before loading data
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        out.print_error(
            "matplotlib is not installed. Install it with:\n"
            "        pip install matplotlib\n"
            "  or:   pip install \"airsentry[viz]\""
        )
        raise typer.Exit(code=1)

    # Load dataset
    from airsentry.visualization.charts import load_dataset, DatasetVisualizer

    out.print_info(f"Loading dataset: {file}")
    try:
        records = load_dataset(file)
    except Exception as exc:
        out.print_error(f"Failed to load dataset: {exc}")
        raise typer.Exit(code=1)

    if not records:
        out.print_error("Dataset is empty — no records to visualize.")
        raise typer.Exit(code=1)

    out.print_info(f"Loaded {len(records)} windows from dataset.")
    out.print_info(f"Generating charts → {charts_dir}/")
    out.console.print()

    viz = DatasetVisualizer(records)
    written = viz.generate_all(output_dir=charts_dir, fmt=fmt)

    if not written:
        out.print_warning("No charts could be generated. Dataset may be too small or missing required fields.")
        raise typer.Exit(code=1)

    out.console.rule("[bold cyan]Charts Generated[/bold cyan]", style="cyan")
    for path in written:
        out.console.print(f"  [green]✓[/green]  {path}")
    out.console.print()
    out.print_info(f"{len(written)} chart(s) saved to: {charts_dir}")
