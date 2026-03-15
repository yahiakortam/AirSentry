"""Monitor view — live wireless interface capture panel."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QFrame, QGroupBox, QHBoxLayout,
    QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from airsentry.ui.style import ACCENT, BG_SURFACE, BORDER, TEXT_DIM, TEXT_PRIMARY
from airsentry.ui.views._event_feed import EventFeedWidget


def _get_interfaces() -> list[str]:
    """Return a filtered list of network interfaces from scapy."""
    try:
        from scapy.arch import get_if_list
        all_ifaces = get_if_list()
        # Filter out loopback and virtual tunnel interfaces for clarity
        skip = {"lo", "lo0"}
        skip_prefixes = ("gif", "stf", "utun", "llw", "awdl", "XHC", "anpi")
        return [
            i for i in all_ifaces
            if i not in skip and not any(i.startswith(p) for p in skip_prefixes)
        ]
    except Exception:
        return ["en0", "wlan0mon"]


class MonitorView(QWidget):
    """
    Live monitoring panel.

    Provides interface / channel selection, start / stop controls,
    a live event feed, and a window-statistics bar updated each time
    the anomaly scorer produces a new ScoredWindow.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()

    # ------------------------------------------------------------------
    # Public API (called by MainWindow)
    # ------------------------------------------------------------------

    def on_session_started(self) -> None:
        """Called when a new monitoring session begins."""
        self.event_feed.clear_feed()
        self._update_stats_bar(None)
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._iface_combo.setEnabled(False)
        self._chan_combo.setEnabled(False)
        self._status_label.setText("● MONITORING")
        self._status_label.setStyleSheet(f"color: #4dffb4; font-weight: 600;")

    def on_session_stopped(self) -> None:
        """Called when a session ends or is stopped."""
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._chan_combo.setEnabled(True)
        self._status_label.setText("● IDLE")
        self._status_label.setStyleSheet(f"color: {TEXT_DIM}; font-weight: 600;")

    def update_window_stats(self, window) -> None:
        """Refresh the stats bar from a ScoredWindow."""
        self._update_stats_bar(window)

    @property
    def selected_interface(self) -> str:
        return self._iface_combo.currentText()

    @property
    def selected_channel(self) -> Optional[int]:
        text = self._chan_combo.currentText()
        return int(text) if text != "Auto" else None

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Title ────────────────────────────────────────────────────
        title_row = QHBoxLayout()
        title = QLabel("Live Monitor")
        title.setObjectName("view_title")
        self._status_label = QLabel("● IDLE")
        self._status_label.setStyleSheet(f"color: {TEXT_DIM}; font-weight: 600;")
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(self._status_label)
        root.addLayout(title_row)

        # ── Controls ─────────────────────────────────────────────────
        ctrl_frame = QFrame()
        ctrl_frame.setObjectName("stat_card")
        ctrl_lay = QVBoxLayout(ctrl_frame)
        ctrl_lay.setContentsMargins(16, 14, 16, 14)
        ctrl_lay.setSpacing(12)

        # Interface + channel row
        row1 = QHBoxLayout()
        row1.setSpacing(12)

        iface_col = QVBoxLayout()
        iface_col.setSpacing(4)
        iface_col.addWidget(self._small_label("INTERFACE"))
        self._iface_combo = QComboBox()
        self._iface_combo.addItems(_get_interfaces())
        self._iface_combo.setMinimumWidth(160)
        iface_col.addWidget(self._iface_combo)

        chan_col = QVBoxLayout()
        chan_col.setSpacing(4)
        chan_col.addWidget(self._small_label("CHANNEL"))
        self._chan_combo = QComboBox()
        self._chan_combo.addItem("Auto")
        for ch in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161]:
            self._chan_combo.addItem(str(ch))
        chan_col.addWidget(self._chan_combo)

        row1.addLayout(iface_col)
        row1.addLayout(chan_col)
        row1.addStretch()

        # Start / Stop row
        row2 = QHBoxLayout()
        row2.setSpacing(10)
        self._start_btn = QPushButton("▶  Start Monitoring")
        self._start_btn.setObjectName("start_btn")
        self._start_btn.setMinimumHeight(36)
        self._start_btn.setCursor(Qt.PointingHandCursor)

        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setObjectName("stop_btn")
        self._stop_btn.setMinimumHeight(36)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setCursor(Qt.PointingHandCursor)

        row2.addWidget(self._start_btn)
        row2.addWidget(self._stop_btn)
        row2.addStretch()

        ctrl_lay.addLayout(row1)
        ctrl_lay.addLayout(row2)
        root.addWidget(ctrl_frame)

        # ── Event feed ───────────────────────────────────────────────
        feed_label = self._small_label("LIVE EVENT FEED")
        root.addWidget(feed_label)

        self.event_feed = EventFeedWidget()
        self.event_feed.setMinimumHeight(280)
        root.addWidget(self.event_feed, 1)

        # ── Window stats bar ─────────────────────────────────────────
        self._stats_bar = self._build_stats_bar()
        root.addWidget(self._stats_bar)

    def _build_stats_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("stat_card")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 10, 16, 10)
        lay.setSpacing(0)

        self._ws_devices = self._stat_pair("—", "Devices")
        self._ws_ssids   = self._stat_pair("—", "SSIDs")
        self._ws_deauths = self._stat_pair("—", "Deauths")
        self._ws_rate    = self._stat_pair("—", "Beacon/s")
        self._ws_score   = self._stat_pair("—", "Score")

        for w in [self._ws_devices, self._ws_ssids, self._ws_deauths,
                  self._ws_rate, self._ws_score]:
            lay.addWidget(w, 1)

        return bar

    def _update_stats_bar(self, window) -> None:
        if window is None:
            for w in [self._ws_devices, self._ws_ssids, self._ws_deauths,
                      self._ws_rate, self._ws_score]:
                self._set_stat_val(w, "—", TEXT_PRIMARY)
            return

        self._set_stat_val(self._ws_devices, str(window.unique_src_macs), TEXT_PRIMARY)
        self._set_stat_val(self._ws_ssids,   str(window.unique_ssids),    TEXT_PRIMARY)
        self._set_stat_val(self._ws_deauths, str(window.n_deauths),
                           "#ff5f57" if window.n_deauths > 0 else TEXT_PRIMARY)
        self._set_stat_val(self._ws_rate,    f"{window.beacon_rate:.1f}", TEXT_PRIMARY)

        score = window.anomaly_score
        score_color = "#ff5f57" if score > 0.6 else "#ffd93d" if score > 0.4 else "#4dffb4"
        self._set_stat_val(self._ws_score, f"{score:.2f}", score_color)

    @staticmethod
    def _stat_pair(value: str, label: str) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(1)
        lay.setAlignment(Qt.AlignCenter)
        val = QLabel(value)
        val.setObjectName("stat_value_sm")
        val.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        val.setAlignment(Qt.AlignCenter)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px;")
        lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(val)
        lay.addWidget(lbl)
        return w

    @staticmethod
    def _set_stat_val(widget: QWidget, text: str, color: str) -> None:
        label = widget.findChild(QLabel, "stat_value_sm")
        if label:
            label.setText(text)
            label.setStyleSheet(f"color: {color}; font-size: 15px; font-weight: 700;")

    @staticmethod
    def _small_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("section_title")
        return lbl
