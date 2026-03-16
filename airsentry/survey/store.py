"""Persistent JSON store for Wi-Fi survey scan records.

Each scan is saved as a ``ScanRecord`` to a JSON file in the AirSentry
data directory.  Records can be loaded, listed, and deleted.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from airsentry.survey.scorer import SurveyResult


@dataclass
class ScanRecord:
    """One saved survey scan."""

    location_name: str
    timestamp: str  # ISO 8601
    latitude: Optional[float]
    longitude: Optional[float]
    result: SurveyResult

    def to_dict(self) -> dict:
        d = {
            "location_name": self.location_name,
            "timestamp": self.timestamp,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }
        d.update(asdict(self.result))
        return d

    @classmethod
    def from_dict(cls, d: dict) -> ScanRecord:
        result = SurveyResult(
            total_networks=d.get("total_networks", 0),
            open_count=d.get("open_count", 0),
            wep_count=d.get("wep_count", 0),
            wpa_count=d.get("wpa_count", 0),
            wpa2_count=d.get("wpa2_count", 0),
            wpa3_count=d.get("wpa3_count", 0),
            hidden_count=d.get("hidden_count", 0),
            duplicate_ssid_count=d.get("duplicate_ssid_count", 0),
            risk_score=d.get("risk_score", 0),
        )
        return cls(
            location_name=d["location_name"],
            timestamp=d["timestamp"],
            latitude=d.get("latitude"),
            longitude=d.get("longitude"),
            result=result,
        )


class SurveyStore:
    """Simple JSON-file backed store for scan records."""

    def __init__(self, path: Optional[Path] = None) -> None:
        if path is None:
            path = Path.home() / ".airsentry" / "surveys.json"
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, record: ScanRecord) -> None:
        records = self.load_all()
        records.append(record)
        self._write(records)

    def load_all(self) -> list[ScanRecord]:
        if not self._path.exists():
            return []
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return [ScanRecord.from_dict(d) for d in data]
        except (json.JSONDecodeError, KeyError):
            return []

    def delete(self, index: int) -> bool:
        records = self.load_all()
        if 0 <= index < len(records):
            records.pop(index)
            self._write(records)
            return True
        return False

    def clear(self) -> None:
        self._write([])

    @property
    def path(self) -> Path:
        return self._path

    def _write(self, records: list[ScanRecord]) -> None:
        data = [r.to_dict() for r in records]
        self._path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
