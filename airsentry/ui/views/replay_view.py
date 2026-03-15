"""Replay view — PCAP file replay panel."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel,
    QProgressBar, QPushButton, QSizePolicy,
    QSlider, QVBoxLayout, QWidget,
)

from airsentry.ui.style import ACCENT, TEXT_DIM, TEXT_PRIMARY
from airsentry.ui.views._event_feed import EventFeedWidget


class ReplayView(QWidget):
    """
    PCAP replay panel.

    Lets the user browse for a PCAP file, adjust replay rate,
    and start / stop replay with a live event feed and progress bar.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._selected_path: Optional[Path] = None
        self._build_ui()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def selected_file(self) -> Optional[Path]:
        return self._selected_path

    @property
    def replay_rate(self) -> Optional[int]:
        """Packets per second, or None to use original timing."""
        v = self._rate_slider.value()
        return v if v > 0 else None

    def on_session_started(self) -> None:
        self.event_feed.clear_feed()
        self._progress.setValue(0)
        self._progress.setFormat("Starting…")
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._browse_btn.setEnabled(False)
        self._status_label.setText("● REPLAYING")
        self._status_label.setStyleSheet("color: #38bdf8; font-weight: 600;")

    def on_session_stopped(self) -> None:
        self._start_btn.setEnabled(self._selected_path is not None)
        self._stop_btn.setEnabled(False)
        self._browse_btn.setEnabled(True)
        self._status_label.setText("● IDLE")
        self._status_label.setStyleSheet(f"color: {TEXT_DIM}; font-weight: 600;")

    def update_progress(self, processed: int, total: int) -> None:
        if total > 0:
            pct = int(processed / total * 100)
            self._progress.setValue(pct)
            self._progress.setFormat(f"{processed:,} / {total:,} packets  ({pct}%)")
        else:
            self._progress.setFormat(f"{processed:,} packets processed")

    def update_window_stats(self, window) -> None:
        score = window.anomaly_score
        color = "#ff5f57" if score > 0.6 else "#ffd93d" if score > 0.4 else "#4dffb4"
        self._score_label.setText(f"Score: <b style='color:{color}'>{score:.2f}</b>")
        self._devices_label.setText(f"Devices: {window.unique_src_macs}")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Title ────────────────────────────────────────────────────
        title_row = QHBoxLayout()
        title = QLabel("PCAP Replay")
        title.setObjectName("view_title")
        self._status_label = QLabel("● IDLE")
        self._status_label.setStyleSheet(f"color: {TEXT_DIM}; font-weight: 600;")
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(self._status_label)
        root.addLayout(title_row)

        # ── File picker ──────────────────────────────────────────────
        ctrl_frame = QFrame()
        ctrl_frame.setObjectName("stat_card")
        ctrl_lay = QVBoxLayout(ctrl_frame)
        ctrl_lay.setContentsMargins(16, 14, 16, 14)
        ctrl_lay.setSpacing(12)

        file_row = QHBoxLayout()
        file_row.setSpacing(8)
        file_lbl = QLabel("FILE")
        file_lbl.setObjectName("section_title")
        file_lbl.setFixedWidth(36)

        self._file_edit = QLabel("No file selected")
        self._file_edit.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 12px; font-style: italic;"
        )
        self._file_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._browse_btn = QPushButton("Browse…")
        self._browse_btn.setFixedWidth(90)
        self._browse_btn.setCursor(Qt.PointingHandCursor)
        self._browse_btn.clicked.connect(self._on_browse)

        file_row.addWidget(file_lbl)
        file_row.addWidget(self._file_edit, 1)
        file_row.addWidget(self._browse_btn)
        ctrl_lay.addLayout(file_row)

        # Rate slider
        rate_row = QHBoxLayout()
        rate_row.setSpacing(12)
        rate_lbl = QLabel("RATE")
        rate_lbl.setObjectName("section_title")
        rate_lbl.setFixedWidth(36)

        self._rate_slider = QSlider(Qt.Horizontal)
        self._rate_slider.setMinimum(0)
        self._rate_slider.setMaximum(2000)
        self._rate_slider.setValue(200)
        self._rate_slider.setTickInterval(200)
        self._rate_slider.valueChanged.connect(self._on_rate_changed)

        self._rate_val_label = QLabel("200 pps")
        self._rate_val_label.setStyleSheet(f"color: {ACCENT}; font-weight: 600; min-width: 60px;")
        self._rate_val_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        rate_row.addWidget(rate_lbl)
        rate_row.addWidget(self._rate_slider, 1)
        rate_row.addWidget(self._rate_val_label)
        ctrl_lay.addLayout(rate_row)

        # Start / Stop
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self._start_btn = QPushButton("▶  Start Replay")
        self._start_btn.setObjectName("start_btn")
        self._start_btn.setMinimumHeight(36)
        self._start_btn.setEnabled(False)
        self._start_btn.setCursor(Qt.PointingHandCursor)

        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setObjectName("stop_btn")
        self._stop_btn.setMinimumHeight(36)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setCursor(Qt.PointingHandCursor)

        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        ctrl_lay.addLayout(btn_row)
        root.addWidget(ctrl_frame)

        # ── Event feed ───────────────────────────────────────────────
        root.addWidget(self._small_label("LIVE EVENT FEED"))
        self.event_feed = EventFeedWidget()
        self.event_feed.setMinimumHeight(240)
        root.addWidget(self.event_feed, 1)

        # ── Footer: progress + live stats ────────────────────────────
        footer = QHBoxLayout()
        footer.setSpacing(16)

        progress_col = QVBoxLayout()
        progress_col.addWidget(self._small_label("PROGRESS"))
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFormat("No replay in progress")
        self._progress.setFixedHeight(16)
        progress_col.addWidget(self._progress)
        footer.addLayout(progress_col, 2)

        self._devices_label = QLabel("Devices: —")
        self._devices_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
        self._score_label = QLabel("Score: —")
        self._score_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 12px;")
        footer.addWidget(self._devices_label)
        footer.addWidget(self._score_label)

        root.addLayout(footer)

    # ------------------------------------------------------------------
    # Slots / helpers
    # ------------------------------------------------------------------

    def _on_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP file",
            "",
            "PCAP files (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if path:
            self._selected_path = Path(path)
            self._file_edit.setText(str(self._selected_path))
            self._file_edit.setStyleSheet(
                f"color: {TEXT_PRIMARY}; font-size: 12px; font-style: normal;"
            )
            self._start_btn.setEnabled(True)

    def _on_rate_changed(self, value: int) -> None:
        if value == 0:
            self._rate_val_label.setText("Original timing")
        else:
            self._rate_val_label.setText(f"{value} pps")

    @staticmethod
    def _small_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("section_title")
        return lbl
