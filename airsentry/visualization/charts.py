"""Visualization tools for AirSentry wireless research datasets.

``DatasetVisualizer`` generates matplotlib charts from AirSentry CSV or JSONL
research datasets.  Matplotlib is an optional dependency; a clear error is
raised if it is not installed.

Usage::

    from airsentry.visualization.charts import load_dataset, DatasetVisualizer
    from pathlib import Path

    records = load_dataset(Path("dataset.csv"))
    viz = DatasetVisualizer(records)
    paths = viz.generate_all(output_dir=Path("charts"))

Install the optional dependency::

    pip install matplotlib
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Dataset loader
# ---------------------------------------------------------------------------


def load_dataset(path: Path) -> list[dict[str, Any]]:
    """
    Load a CSV or JSONL dataset file and return a list of record dicts.

    Parameters
    ----------
    path:
        Path to a ``.csv`` or ``.jsonl`` file produced by AirSentry.

    Returns
    -------
    list[dict]
        List of records with numeric fields already coerced to float/int.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file extension is not ``.csv`` or ``.jsonl``.
    """
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    suffix = path.suffix.lower()
    if suffix not in (".csv", ".jsonl"):
        raise ValueError(f"Unsupported file format: {suffix!r}. Expected .csv or .jsonl")

    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        if suffix == ".csv":
            for row in csv.DictReader(f):
                records.append(_coerce_row(dict(row)))
        else:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

    return records


def _coerce_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert CSV string values to numeric types where applicable."""
    numeric_keys = {
        "window_seconds", "n_beacons", "n_probe_requests", "n_probe_responses",
        "n_deauths", "n_total_frames", "unique_ssids", "unique_bssids",
        "unique_src_macs", "ssid_duplication_count", "beacon_rate",
        "probe_request_rate", "frame_type_entropy", "anomaly_score",
    }
    for key in numeric_keys:
        if key in row and row[key] != "":
            try:
                row[key] = float(row[key])
            except (ValueError, TypeError):
                pass
    if "is_model_fitted" in row:
        row["is_model_fitted"] = str(row["is_model_fitted"]).lower() == "true"
    return row


# ---------------------------------------------------------------------------
# DatasetVisualizer
# ---------------------------------------------------------------------------


class DatasetVisualizer:
    """
    Generates matplotlib charts from AirSentry research dataset records.

    Parameters
    ----------
    records:
        Dataset records loaded by ``load_dataset()``.

    Raises
    ------
    ImportError
        On first chart generation if matplotlib is not installed.
    """

    _PALETTE = {
        "blue":   "#4c8cbf",
        "green":  "#5abf8c",
        "amber":  "#bf9f4c",
        "red":    "#bf5555",
        "purple": "#8c6dbf",
    }

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    # ------------------------------------------------------------------
    # Batch generation
    # ------------------------------------------------------------------

    def generate_all(self, output_dir: Path, fmt: str = "png") -> list[Path]:
        """
        Generate all available charts and save them to *output_dir*.

        Parameters
        ----------
        output_dir:
            Directory where chart files are written (created if needed).
        fmt:
            Image format: ``"png"`` (default), ``"svg"``, or ``"pdf"``.

        Returns
        -------
        list[Path]
            Paths of successfully written chart files.
        """
        _require_matplotlib()
        output_dir.mkdir(parents=True, exist_ok=True)

        generators = [
            ("anomaly_timeline",    self.plot_anomaly_timeline),
            ("frame_distribution",  self.plot_frame_distribution),
            ("device_activity",     self.plot_device_activity),
            ("beacon_rate",         self.plot_beacon_rate),
        ]

        written: list[Path] = []
        for name, fn in generators:
            out_path = output_dir / f"{name}.{fmt}"
            try:
                fn(out_path)
                written.append(out_path)
            except _InsufficientDataError:
                pass  # skip quietly if this chart needs more data
            except Exception:
                pass  # never crash the batch run

        return written

    # ------------------------------------------------------------------
    # Individual chart methods
    # ------------------------------------------------------------------

    def plot_anomaly_timeline(self, output_path: Path) -> None:
        """
        Line chart: anomaly score over time.

        Includes a dashed reference line at the default alert threshold (0.65).
        """
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from datetime import datetime

        times, scores = [], []
        for r in self._records:
            try:
                ts = _parse_ts(str(r.get("window_end", "")))
                score = float(r["anomaly_score"])
                times.append(ts)
                scores.append(score)
            except (KeyError, ValueError, TypeError):
                continue

        if len(times) < 2:
            raise _InsufficientDataError("anomaly_timeline needs at least 2 windows")

        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(times, scores, color=self._PALETTE["blue"], linewidth=1.8,
                marker="o", markersize=4, zorder=3)
        ax.fill_between(times, scores, alpha=0.12, color=self._PALETTE["blue"])
        ax.axhline(0.65, color=self._PALETTE["red"], linewidth=1.1,
                   linestyle="--", label="Alert threshold (0.65)", zorder=2)
        ax.set_ylim(0, 1.05)
        ax.set_xlabel("Time (UTC)", labelpad=6)
        ax.set_ylabel("Anomaly Score")
        ax.set_title("Anomaly Score Timeline", fontweight="bold", pad=10)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        fig.autofmt_xdate()
        ax.legend(fontsize=9)
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.set_axisbelow(True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close(fig)

    def plot_frame_distribution(self, output_path: Path) -> None:
        """
        Bar chart: total frame counts by type across the dataset.
        """
        import matplotlib.pyplot as plt

        keys   = ["n_beacons", "n_probe_requests", "n_probe_responses", "n_deauths"]
        labels = ["Beacon", "Probe Request", "Probe Response", "Deauth / Disassoc"]
        colors = [self._PALETTE["blue"], self._PALETTE["green"],
                  self._PALETTE["purple"], self._PALETTE["red"]]

        totals: list[float] = []
        for k in keys:
            vals = [float(r[k]) for r in self._records if k in r]
            totals.append(sum(vals))

        if sum(totals) == 0:
            raise _InsufficientDataError("frame_distribution: no frame data")

        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(labels, totals, color=colors, width=0.55,
                      edgecolor="white", linewidth=0.6)

        peak = max(totals)
        for bar, val in zip(bars, totals):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + peak * 0.012,
                f"{int(val):,}",
                ha="center", va="bottom", fontsize=10,
            )

        ax.set_ylabel("Total Frames")
        ax.set_title("Frame Type Distribution", fontweight="bold", pad=10)
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.set_axisbelow(True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close(fig)

    def plot_device_activity(self, output_path: Path) -> None:
        """
        Line chart: unique device count and SSID count per analysis window.
        """
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from datetime import datetime

        times, devices, ssids = [], [], []
        for r in self._records:
            try:
                ts = _parse_ts(str(r.get("window_end", "")))
                times.append(ts)
                devices.append(int(float(r["unique_src_macs"])))
                ssids.append(int(float(r.get("unique_ssids", 0))))
            except (KeyError, ValueError, TypeError):
                continue

        if len(times) < 2:
            raise _InsufficientDataError("device_activity needs at least 2 windows")

        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(times, devices, label="Devices (unique src MACs)",
                color=self._PALETTE["blue"], linewidth=1.8, marker="o", markersize=3)
        ax.plot(times, ssids, label="Unique SSIDs",
                color=self._PALETTE["green"], linewidth=1.8, marker="s", markersize=3)
        ax.set_xlabel("Time (UTC)", labelpad=6)
        ax.set_ylabel("Count (per window)")
        ax.set_title("Device & SSID Activity Over Time", fontweight="bold", pad=10)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        fig.autofmt_xdate()
        ax.legend()
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.set_axisbelow(True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close(fig)

    def plot_beacon_rate(self, output_path: Path) -> None:
        """
        Line chart: beacon frames per second over time.
        """
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates

        times, rates = [], []
        for r in self._records:
            try:
                ts = _parse_ts(str(r.get("window_end", "")))
                times.append(ts)
                rates.append(float(r["beacon_rate"]))
            except (KeyError, ValueError, TypeError):
                continue

        if len(times) < 2:
            raise _InsufficientDataError("beacon_rate needs at least 2 windows")

        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(times, rates, color=self._PALETTE["amber"], linewidth=1.8,
                marker="o", markersize=3)
        ax.fill_between(times, rates, alpha=0.12, color=self._PALETTE["amber"])
        ax.set_xlabel("Time (UTC)", labelpad=6)
        ax.set_ylabel("Beacons / second")
        ax.set_title("Beacon Rate Over Time", fontweight="bold", pad=10)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        fig.autofmt_xdate()
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.set_axisbelow(True)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close(fig)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _InsufficientDataError(Exception):
    """Raised internally when a chart cannot be drawn due to sparse data."""


def _parse_ts(ts_str: str):
    """Parse an ISO-8601 timestamp string, handling common Z-suffix variants."""
    from datetime import datetime
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def _require_matplotlib() -> None:
    """Raise a friendly ImportError if matplotlib is not installed."""
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        raise ImportError(
            "matplotlib is required for visualization. "
            "Install it with:  pip install matplotlib\n"
            "Or install the optional extras:  pip install airsentry[viz]"
        ) from None
