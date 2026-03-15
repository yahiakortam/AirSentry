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

from airsentry.ui.style import ACCENT, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY
from airsentry.ui.views._event_feed import EventFeedWidget


def _find_demo_pcap() -> Optional[Path]:
    candidates = [
        Path("examples/sample_capture.pcap"),
        Path(__file__).parents[4] / "examples" / "sample_capture.pcap",
    ]
    for p in candidates:
        if p.exists():
            return p.resolve()
    return None


class ReplayView(QWidget):

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
        v = self._rate_slider.value()
        return v if v > 0 else None

    def on_session_started(self) -> None:
        self.event_feed.clear_feed()
        self._progress.setValue(0)
        self._progress_text.setText("Starting...")
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._browse_btn.setEnabled(False)
        self._status_label.setText("REPLAYING")
        self._status_label.setStyleSheet(
            f"color: {ACCENT}; font-weight: 600; font-size: 12px;"
        )

    def on_session_stopped(self) -> None:
        self._start_btn.setEnabled(self._selected_path is not None)
        self._stop_btn.setEnabled(False)
        self._browse_btn.setEnabled(True)
        self._status_label.setText("IDLE")
        self._status_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-weight: 600; font-size: 12px;"
        )

    def update_progress(self, processed: int, total: int) -> None:
        if total > 0:
            pct = int(processed / total * 100)
            self._progress.setValue(pct)
            self._progress_text.setText(
                f"{processed:,} / {total:,} packets ({pct}%)"
            )
        else:
            self._progress_text.setText(f"{processed:,} packets processed")

    def update_window_stats(self, window) -> None:
        score = window.anomaly_score
        sc = "#f87171" if score > 0.6 else "#facc15" if score > 0.4 else "#4ade80"
        self._score_label.setText(f"{score:.2f}")
        self._score_label.setStyleSheet(
            f"color: {sc}; font-size: 14px; font-weight: 700;"
        )
        self._devices_label.setText(str(window.unique_src_macs))

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        # Title
        title_row = QHBoxLayout()
        title = QLabel("PCAP Replay")
        title.setObjectName("view_title")
        self._status_label = QLabel("IDLE")
        self._status_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-weight: 600; font-size: 12px;"
        )
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(self._status_label)
        root.addLayout(title_row)

        # Demo banner
        demo_path = _find_demo_pcap()
        if demo_path:
            banner = QFrame()
            banner.setObjectName("notice_info")
            b_lay = QHBoxLayout(banner)
            b_lay.setContentsMargins(16, 12, 16, 12)
            b_lay.setSpacing(12)
            b_txt = QLabel(
                "<span style='color:#38bdf8; font-weight:600;'>Demo PCAP available</span>"
                "<span style='color:#64748b; font-size:12px;'>"
                "  &mdash; Load it to see frame parsing, threat detection, and anomaly scoring.</span>"
            )
            b_txt.setStyleSheet("background: transparent; border: none;")
            b_txt.setWordWrap(True)
            b_btn = QPushButton("Load Demo")
            b_btn.setObjectName("start_btn")
            b_btn.setFixedWidth(100)
            b_btn.setCursor(Qt.PointingHandCursor)
            b_btn.clicked.connect(lambda: self._load_file(demo_path))
            b_lay.addWidget(b_txt, 1)
            b_lay.addWidget(b_btn)
            root.addWidget(banner)

        # Controls card
        ctrl_frame = QFrame()
        ctrl_frame.setObjectName("stat_card")
        ctrl_lay = QVBoxLayout(ctrl_frame)
        ctrl_lay.setContentsMargins(18, 16, 18, 16)
        ctrl_lay.setSpacing(14)

        # File row
        file_row = QHBoxLayout()
        file_row.setSpacing(10)
        file_lbl = self._section_label("FILE")
        file_lbl.setFixedWidth(36)

        self._file_edit = QLabel("No file selected")
        self._file_edit.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; font-style: italic;"
        )
        self._file_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._browse_btn = QPushButton("Browse")
        self._browse_btn.setFixedWidth(80)
        self._browse_btn.setCursor(Qt.PointingHandCursor)
        self._browse_btn.clicked.connect(self._on_browse)

        file_row.addWidget(file_lbl)
        file_row.addWidget(self._file_edit, 1)
        file_row.addWidget(self._browse_btn)
        ctrl_lay.addLayout(file_row)

        # Rate row
        rate_row = QHBoxLayout()
        rate_row.setSpacing(12)
        rate_lbl = self._section_label("RATE")
        rate_lbl.setFixedWidth(36)

        self._rate_slider = QSlider(Qt.Horizontal)
        self._rate_slider.setMinimum(0)
        self._rate_slider.setMaximum(2000)
        self._rate_slider.setValue(200)
        self._rate_slider.valueChanged.connect(self._on_rate_changed)

        self._rate_val_label = QLabel("200 pps")
        self._rate_val_label.setStyleSheet(
            f"color: {ACCENT}; font-weight: 600; min-width: 90px;"
        )
        self._rate_val_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        rate_row.addWidget(rate_lbl)
        rate_row.addWidget(self._rate_slider, 1)
        rate_row.addWidget(self._rate_val_label)
        ctrl_lay.addLayout(rate_row)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self._start_btn = QPushButton("Start Replay")
        self._start_btn.setObjectName("start_btn")
        self._start_btn.setMinimumHeight(38)
        self._start_btn.setMinimumWidth(140)
        self._start_btn.setEnabled(False)
        self._start_btn.setCursor(Qt.PointingHandCursor)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setObjectName("stop_btn")
        self._stop_btn.setMinimumHeight(38)
        self._stop_btn.setMinimumWidth(80)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setCursor(Qt.PointingHandCursor)

        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        ctrl_lay.addLayout(btn_row)
        root.addWidget(ctrl_frame)

        # Event feed
        root.addWidget(self._section_label("EVENT FEED"))
        self.event_feed = EventFeedWidget()
        self.event_feed.setMinimumHeight(220)
        root.addWidget(self.event_feed, 1)

        # Footer: progress + live stats
        footer = QFrame()
        footer.setObjectName("stat_card")
        f_lay = QHBoxLayout(footer)
        f_lay.setContentsMargins(18, 12, 18, 12)
        f_lay.setSpacing(20)

        progress_col = QVBoxLayout()
        progress_col.setSpacing(6)
        progress_col.addWidget(self._section_label("PROGRESS"))
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFormat("No replay in progress")
        self._progress.setFixedHeight(8)
        self._progress.setTextVisible(False)
        progress_col.addWidget(self._progress)

        self._progress_text = QLabel("No replay in progress")
        self._progress_text.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 11px;"
        )
        progress_col.addWidget(self._progress_text)
        f_lay.addLayout(progress_col, 2)

        # Mini stats
        stats_col = QHBoxLayout()
        stats_col.setSpacing(20)

        dev_col = QVBoxLayout()
        dev_col.setSpacing(2)
        dev_col.setAlignment(Qt.AlignCenter)
        self._devices_label = QLabel("--")
        self._devices_label.setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;"
        )
        self._devices_label.setAlignment(Qt.AlignCenter)
        dev_key = QLabel("Devices")
        dev_key.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: 500;"
        )
        dev_key.setAlignment(Qt.AlignCenter)
        dev_col.addWidget(self._devices_label)
        dev_col.addWidget(dev_key)

        score_col = QVBoxLayout()
        score_col.setSpacing(2)
        score_col.setAlignment(Qt.AlignCenter)
        self._score_label = QLabel("--")
        self._score_label.setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;"
        )
        self._score_label.setAlignment(Qt.AlignCenter)
        score_key = QLabel("Score")
        score_key.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: 500;"
        )
        score_key.setAlignment(Qt.AlignCenter)
        score_col.addWidget(self._score_label)
        score_col.addWidget(score_key)

        stats_col.addLayout(dev_col)
        stats_col.addLayout(score_col)
        f_lay.addLayout(stats_col)

        root.addWidget(footer)

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
            self._load_file(Path(path))

    def _load_file(self, path: Path) -> None:
        self._selected_path = path
        self._file_edit.setText(str(path))
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
    def _section_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("section_title")
        return lbl
