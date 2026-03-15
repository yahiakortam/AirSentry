"""Dataset management toolkit for AirSentry wireless research data.

Provides pure-stdlib functions for loading, merging, filtering, cleaning,
summarizing, and saving AirSentry research datasets (CSV and JSONL formats).
No external dependencies beyond the Python standard library.

Usage::

    from airsentry.dataset.toolkit import load_records, merge_datasets, summarize_dataset
    from pathlib import Path

    records = load_records(Path("session_a.csv"))
    stats   = summarize_dataset(records)
    print(stats)
"""

from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path
from typing import Any, Literal


# ---------------------------------------------------------------------------
# Column schema (must match ScoredWindow.to_dict() keys)
# ---------------------------------------------------------------------------

_CSV_FIELDNAMES: list[str] = [
    "window_start",
    "window_end",
    "window_seconds",
    "location",
    "n_beacons",
    "n_probe_requests",
    "n_probe_responses",
    "n_deauths",
    "n_total_frames",
    "unique_ssids",
    "unique_bssids",
    "unique_src_macs",
    "ssid_duplication_count",
    "beacon_rate",
    "probe_request_rate",
    "frame_type_entropy",
    "anomaly_score",
    "is_model_fitted",
]

_NUMERIC_KEYS: frozenset[str] = frozenset({
    "window_seconds",
    "n_beacons",
    "n_probe_requests",
    "n_probe_responses",
    "n_deauths",
    "n_total_frames",
    "unique_ssids",
    "unique_bssids",
    "unique_src_macs",
    "ssid_duplication_count",
    "beacon_rate",
    "probe_request_rate",
    "frame_type_entropy",
    "anomaly_score",
})


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def load_records(path: Path) -> list[dict[str, Any]]:
    """
    Load an AirSentry research dataset from a CSV or JSONL file.

    Parameters
    ----------
    path:
        Path to the ``.csv`` or ``.jsonl`` dataset file.

    Returns
    -------
    list[dict]
        List of records with numeric fields coerced to float.

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
        raise ValueError(f"Unsupported format: {suffix!r}. Expected .csv or .jsonl")

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


def save_records(
    records: list[dict[str, Any]],
    path: Path,
    fmt: Literal["csv", "jsonl"] = "jsonl",
) -> None:
    """
    Write dataset records to a CSV or JSONL file.

    Parameters
    ----------
    records:
        List of record dicts (as returned by ``load_records``).
    path:
        Output file path.  Parent directories are created if needed.
    fmt:
        Output format: ``"csv"`` or ``"jsonl"``.
    """
    if fmt not in ("csv", "jsonl"):
        raise ValueError(f"fmt must be 'csv' or 'jsonl', got {fmt!r}")

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        if fmt == "csv":
            writer = csv.DictWriter(
                f,
                fieldnames=_CSV_FIELDNAMES,
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(records)
        else:
            for record in records:
                f.write(json.dumps(record, default=str) + "\n")


# ---------------------------------------------------------------------------
# Dataset operations
# ---------------------------------------------------------------------------


def merge_datasets(paths: list[Path]) -> list[dict[str, Any]]:
    """
    Merge multiple dataset files into a single sorted list.

    Records from all files are combined and sorted by ``window_start``
    in ascending order.  Duplicate records are preserved (not deduplicated).

    Parameters
    ----------
    paths:
        Paths of dataset files to merge.  Must all be ``.csv`` or ``.jsonl``.

    Returns
    -------
    list[dict]
        Merged, sorted record list.
    """
    merged: list[dict[str, Any]] = []
    for p in paths:
        merged.extend(load_records(p))
    merged.sort(key=lambda r: str(r.get("window_start", "")))
    return merged


def filter_by_location(
    records: list[dict[str, Any]],
    location: str,
) -> list[dict[str, Any]]:
    """
    Return only records whose ``location`` field matches *location* exactly.

    Parameters
    ----------
    records:
        Input record list.
    location:
        Location label to filter on (e.g., ``"cafe_downtown"``).

    Returns
    -------
    list[dict]
        Filtered record list.
    """
    return [r for r in records if r.get("location", "") == location]


def clean_dataset(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove incomplete or invalid records from a dataset.

    A record is removed if:
    - It is missing any of the required keys (``window_start``,
      ``window_end``, ``anomaly_score``, ``n_total_frames``).
    - Its ``anomaly_score`` is outside the valid range ``[0.0, 1.0]``.
    - Its numeric fields cannot be parsed as floats.

    Parameters
    ----------
    records:
        Input record list (may contain mixed-quality records).

    Returns
    -------
    list[dict]
        Cleaned record list with invalid entries removed.
    """
    required_keys = {"window_start", "window_end", "anomaly_score", "n_total_frames"}
    cleaned: list[dict[str, Any]] = []

    for r in records:
        if not required_keys.issubset(r.keys()):
            continue
        try:
            score = float(r["anomaly_score"])
            if not (0.0 <= score <= 1.0):
                continue
            float(r["n_total_frames"])
        except (ValueError, TypeError):
            continue
        cleaned.append(r)

    return cleaned


def summarize_dataset(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute aggregate summary statistics over a dataset.

    Parameters
    ----------
    records:
        Input record list.

    Returns
    -------
    dict
        Summary statistics dict, or an empty dict if *records* is empty.
    """
    if not records:
        return {}

    locations = sorted({str(r.get("location", "")) for r in records if r.get("location")})

    def _vals(key: str) -> list[float]:
        return [float(r[key]) for r in records if key in r and r[key] != ""]

    def _avg(key: str) -> float:
        v = _vals(key)
        return round(statistics.mean(v), 4) if v else 0.0

    def _max(key: str) -> float:
        v = _vals(key)
        return round(max(v), 4) if v else 0.0

    def _min(key: str) -> float:
        v = _vals(key)
        return round(min(v), 4) if v else 0.0

    def _stdev(key: str) -> float:
        v = _vals(key)
        return round(statistics.pstdev(v), 4) if len(v) > 1 else 0.0

    return {
        "total_windows":            len(records),
        "locations":                locations,
        "avg_anomaly_score":        _avg("anomaly_score"),
        "max_anomaly_score":        _max("anomaly_score"),
        "min_anomaly_score":        _min("anomaly_score"),
        "stdev_anomaly_score":      _stdev("anomaly_score"),
        "avg_n_beacons":            _avg("n_beacons"),
        "avg_n_probe_requests":     _avg("n_probe_requests"),
        "avg_n_deauths":            _avg("n_deauths"),
        "avg_unique_src_macs":      _avg("unique_src_macs"),
        "avg_unique_ssids":         _avg("unique_ssids"),
        "avg_unique_bssids":        _avg("unique_bssids"),
        "avg_beacon_rate":          _avg("beacon_rate"),
        "max_beacon_rate":          _max("beacon_rate"),
        "avg_frame_type_entropy":   _avg("frame_type_entropy"),
        "avg_ssid_duplication":     _avg("ssid_duplication_count"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert CSV string values to numeric types where applicable."""
    for key in _NUMERIC_KEYS:
        if key in row and row[key] != "":
            try:
                row[key] = float(row[key])
            except (ValueError, TypeError):
                pass
    if "is_model_fitted" in row:
        row["is_model_fitted"] = str(row["is_model_fitted"]).lower() == "true"
    return row
