"""Summary view — session statistics dashboard displayed after each session."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QLabel,
    QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from airsentry.analysis.session import SessionSummary
from airsentry.ui.style import TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY


class StatCard(QFrame):

    def __init__(
        self,
        value: str,
        label: str,
        color: str = TEXT_PRIMARY,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("stat_card")
        self.setMinimumHeight(100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(6)
        lay.setAlignment(Qt.AlignCenter)

        self._val_label = QLabel(value)
        self._val_label.setObjectName("stat_value")
        self._val_label.setStyleSheet(
            f"color: {color}; font-size: 28px; font-weight: 700;"
        )
        self._val_label.setAlignment(Qt.AlignCenter)

        self._key_label = QLabel(label)
        self._key_label.setObjectName("stat_label")
        self._key_label.setAlignment(Qt.AlignCenter)

        lay.addWidget(self._val_label)
        lay.addWidget(self._key_label)

    def update(self, value: str, color: str = TEXT_PRIMARY) -> None:  # type: ignore[override]
        self._val_label.setText(value)
        self._val_label.setStyleSheet(
            f"color: {color}; font-size: 28px; font-weight: 700;"
        )


class SummaryView(QWidget):

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def populate(self, summary: SessionSummary) -> None:
        self._card_devices.update(str(summary.devices_detected))
        self._card_ssids.update(str(summary.unique_ssids))
        self._card_bssids.update(str(summary.unique_bssids))
        self._card_beacons.update(f"{summary.n_beacons:,}")
        self._card_probes.update(f"{summary.n_probe_requests:,}")
        self._card_deauths.update(
            str(summary.n_deauths),
            color="#f87171" if summary.n_deauths > 0 else TEXT_PRIMARY,
        )
        self._card_frames.update(f"{summary.n_total_frames:,}")
        self._card_alerts.update(
            str(summary.alerts_raised),
            color="#f87171" if summary.alerts_raised > 0 else TEXT_PRIMARY,
        )
        self._card_windows.update(str(summary.windows_analyzed))

        if summary.last_anomaly_score is not None:
            s = summary.last_anomaly_score
            sc = "#f87171" if s > 0.6 else "#facc15" if s > 0.4 else "#4ade80"
            model_note = "IsolationForest" if summary.is_model_fitted else "Heuristic"
            self._card_score.update(f"{s:.2f}", color=sc)
            self._model_label.setText(f"Scoring model: {model_note}")
        else:
            self._card_score.update("--")
            self._model_label.setText("")

        mins, secs = divmod(int(summary.duration_seconds), 60)
        dur = f"{mins}m {secs}s" if mins else f"{secs}s"
        self._card_duration.update(dur)
        self._card_packets.update(f"{summary.total_packets:,}")

        self._no_data_label.setVisible(False)
        self._grid_container.setVisible(True)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)

        title = QLabel("Session Summary")
        title.setObjectName("view_title")
        root.addWidget(title)

        self._model_label = QLabel("")
        self._model_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 12px;"
        )
        root.addWidget(self._model_label)

        self._no_data_label = QLabel(
            "Run a monitoring or replay session to see statistics here."
        )
        self._no_data_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 13px;"
        )
        self._no_data_label.setAlignment(Qt.AlignCenter)
        root.addWidget(self._no_data_label, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        self._grid_container = QWidget()
        self._grid_container.setVisible(False)
        grid = QGridLayout(self._grid_container)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)

        self._card_devices  = StatCard("--", "Devices Detected")
        self._card_ssids    = StatCard("--", "Unique SSIDs")
        self._card_bssids   = StatCard("--", "Unique BSSIDs")
        grid.addWidget(self._card_devices, 0, 0)
        grid.addWidget(self._card_ssids,   0, 1)
        grid.addWidget(self._card_bssids,  0, 2)

        self._card_beacons  = StatCard("--", "Beacon Frames")
        self._card_probes   = StatCard("--", "Probe Requests")
        self._card_deauths  = StatCard("--", "Deauth / Disassoc")
        grid.addWidget(self._card_beacons, 1, 0)
        grid.addWidget(self._card_probes,  1, 1)
        grid.addWidget(self._card_deauths, 1, 2)

        self._card_alerts   = StatCard("--", "Alerts Raised")
        self._card_windows  = StatCard("--", "Analysis Windows")
        self._card_score    = StatCard("--", "Last Anomaly Score")
        grid.addWidget(self._card_alerts,  2, 0)
        grid.addWidget(self._card_windows, 2, 1)
        grid.addWidget(self._card_score,   2, 2)

        self._card_frames   = StatCard("--", "Total Frames Parsed")
        self._card_packets  = StatCard("--", "Total Packets Seen")
        self._card_duration = StatCard("--", "Session Duration")
        grid.addWidget(self._card_frames,   3, 0)
        grid.addWidget(self._card_packets,  3, 1)
        grid.addWidget(self._card_duration, 3, 2)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        grid.addWidget(spacer, 4, 0, 1, 3)

        scroll.setWidget(self._grid_container)
        root.addWidget(scroll, 1)
