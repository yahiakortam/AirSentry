"""Structured dataset exporter for AirSentry research collection mode.

``DatasetExporter`` writes ``ScoredWindow`` records to disk in either CSV or
JSONL format.  Privacy filtering (MAC anonymization) is applied by the
``ResearchCollector`` before records reach this class; the exporter itself
only handles serialisation and file I/O.

Formats
-------
csv:
    A standard comma-separated values file with a header row on the first
    write.  Compatible with pandas, Excel, R, etc.

jsonl:
    One JSON object per line (JSON Lines format).  Easy to stream and import
    into analysis tools.

Usage
-----
::

    with DatasetExporter.open(path=Path("output.csv"), fmt="csv") as exp:
        exp.write(scored_window)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import TracebackType
from typing import IO, Literal, Optional, Type

from airsentry.analysis.models import ScoredWindow


# ---------------------------------------------------------------------------
# DatasetExporter
# ---------------------------------------------------------------------------


class DatasetExporter:
    """
    Append-mode writer for research dataset files.

    Parameters
    ----------
    path:
        Output file path.  Created (with parent dirs) if it does not exist.
    fmt:
        ``"csv"`` or ``"jsonl"``.
    """

    # Stable CSV column order (must match ScoredWindow.to_dict() keys)
    _CSV_FIELDNAMES = [
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

    def __init__(
        self,
        path: Path,
        fmt: Literal["csv", "jsonl"] = "jsonl",
    ) -> None:
        if fmt not in ("csv", "jsonl"):
            raise ValueError(f"fmt must be 'csv' or 'jsonl', got {fmt!r}")
        self._path   = path
        self._fmt    = fmt
        self._file: Optional[IO[str]] = None
        self._csv_writer: Optional[csv.DictWriter] = None
        self._records_written = 0

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "DatasetExporter":
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> "DatasetExporter":
        """Open the output file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if self._path.exists() else "w"
        self._file = open(self._path, mode, encoding="utf-8", newline="")
        if self._fmt == "csv":
            write_header = mode == "w"
            self._csv_writer = csv.DictWriter(
                self._file,
                fieldnames=self._CSV_FIELDNAMES,
                extrasaction="ignore",
                lineterminator="\n",
            )
            if write_header:
                self._csv_writer.writeheader()
        return self

    def close(self) -> None:
        """Flush and close the output file."""
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, window: ScoredWindow) -> None:
        """
        Write one ``ScoredWindow`` record to the output file.

        Parameters
        ----------
        window:
            A privacy-filtered scored window.
        """
        if self._file is None or self._file.closed:
            raise RuntimeError("DatasetExporter is not open; call open() first.")
        record = window.to_dict()
        if self._fmt == "csv":
            assert self._csv_writer is not None
            self._csv_writer.writerow(record)
        else:  # jsonl
            self._file.write(json.dumps(record, default=str) + "\n")
        self._records_written += 1

    @property
    def records_written(self) -> int:
        """Number of records written so far."""
        return self._records_written

    @property
    def output_path(self) -> Path:
        """The resolved output file path."""
        return self._path

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def open_session(
        cls,
        output_dir: Optional[Path] = None,
        fmt: Literal["csv", "jsonl"] = "jsonl",
        location: str = "",
        timestamp_str: str = "",
    ) -> "DatasetExporter":
        """
        Create and open a new dataset exporter with an auto-generated filename.

        Parameters
        ----------
        output_dir:
            Directory to write the file.  Defaults to the platform data dir.
        fmt:
            ``"csv"`` or ``"jsonl"``.
        location:
            Location label (sanitised and included in filename).
        timestamp_str:
            ISO-like timestamp string for the filename (optional).
        """
        from datetime import datetime, timezone

        base = output_dir or _default_research_dir()
        date_str  = timestamp_str or datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
        loc_slug  = "".join(c if c.isalnum() else "_" for c in location)[:24] if location else "session"
        filename  = f"airsentry-research-{loc_slug}-{date_str}.{fmt}"
        path = base / filename
        instance = cls(path=path, fmt=fmt)
        instance.open()
        return instance


# ---------------------------------------------------------------------------
# Default output directory
# ---------------------------------------------------------------------------


def _default_research_dir() -> Path:
    """Return the platform-appropriate default research data directory."""
    import os

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        base = Path(xdg)
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif Path("/Library").exists():
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path.home() / ".local" / "share"
    return base / "airsentry" / "research"
