"""Monitor view — live wireless interface capture panel."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout,
    QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from airsentry.ui.style import ACCENT, TEXT_DIM, TEXT_PRIMARY
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

    # Warn the user if no events arrive within this many milliseconds.
    _NO_PACKET_WARN_MS = 8_000

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._events_received = 0
        self._no_packet_timer = QTimer(self)
        self._no_packet_timer.setSingleShot(True)
        self._no_packet_timer.timeout.connect(self._on_no_packets_timeout)
        self._build_ui()

    # ------------------------------------------------------------------
    # Public API (called by MainWindow)
    # ------------------------------------------------------------------

    def on_session_started(self) -> None:
        """Called when a new monitoring session begins."""
        self._events_received = 0
        self.event_feed.clear_feed()
        self._update_stats_bar(None)
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._iface_combo.setEnabled(False)
        self._chan_combo.setEnabled(False)
        self._status_label.setText("● MONITORING")
        self._status_label.setStyleSheet("color: #4dffb4; font-weight: 600;")
        self._no_packet_timer.start(self._NO_PACKET_WARN_MS)

    def on_session_stopped(self) -> None:
        """Called when a session ends or is stopped."""
        self._no_packet_timer.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._chan_combo.setEnabled(True)
        self._status_label.setText("● IDLE")
        self._status_label.setStyleSheet(f"color: {TEXT_DIM}; font-weight: 600;")

    def on_event_received(self) -> None:
        """Call once for each parsed event to reset the no-packet timer."""
        self._events_received += 1
        if self._events_received == 1:
            self._no_packet_timer.stop()

    def update_window_stats(self, window) -> None:
        """Refresh the stats bar from a ScoredWindow."""
        self._update_stats_bar(window)

    def _on_no_packets_timeout(self) -> None:
        """Insert a warning into the feed when no frames arrive quickly enough."""
        if self._events_received > 0:
            return
        iface = self._iface_combo.currentText()
        warning_html = (
            f'<span style="color:#ff9f43;font-weight:600;">'
            f'⚠  No 802.11 management frames received on <b>{iface}</b>.</span>'
            f'<br>'
            f'<span style="color:#6b7a99;">'
            f'Live monitoring requires:</span>'
            f'<br>'
            f'<span style="color:#6b7a99;">'
            f'&nbsp;&nbsp;① The interface must be in <b style="color:#dde3f0">monitor mode</b> '
            f'(e.g. <code>sudo airmon-ng start {iface}</code>)</span>'
            f'<br>'
            f'<span style="color:#6b7a99;">'
            f'&nbsp;&nbsp;② AirSentry must run with <b style="color:#dde3f0">root / sudo</b> '
            f'for raw packet capture</span>'
            f'<br>'
            f'<span style="color:#6b7a99;">'
            f'&nbsp;&nbsp;③ On macOS, try a dedicated Wi-Fi adapter in monitor mode</span>'
            f'<br><br>'
            f'<span style="color:#38bdf8;">'
            f'💡  Use the <b>Replay</b> view to load a PCAP file and see the full pipeline.</span>'
        )
        # Inject directly (not via the batched add_event path)
        from PySide6.QtGui import QTextCursor
        cursor = QTextCursor(self.event_feed.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertHtml(warning_html)
        cursor.insertBlock()
        sb = self.event_feed.verticalScrollBar()
        sb.setValue(sb.maximum())

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

        # ── Requirements notice ────────────────────────────────────────
        notice = QFrame()
        notice.setStyleSheet(
            "QFrame { background-color: #1a1a08; border: 1px solid #3a3a00; border-radius: 6px; }"
        )
        notice_lay = QHBoxLayout(notice)
        notice_lay.setContentsMargins(14, 10, 14, 10)
        notice_lay.setSpacing(10)
        icon = QLabel("⚡")
        icon.setStyleSheet("font-size: 16px; border: none; background: transparent;")
        notice_txt = QLabel(
            "<b style='color:#ffd93d'>Live monitoring requires a monitor-mode interface + root/sudo.</b>"
            "<br><span style='color:#8a8060; font-size:12px;'>"
            "No hardware? Use <b style='color:#38bdf8'>Replay</b> to load a PCAP file "
            "and see the full detection pipeline in action.</span>"
        )
        notice_txt.setStyleSheet("border: none; background: transparent;")
        notice_txt.setWordWrap(True)
        notice_lay.addWidget(icon, 0, Qt.AlignTop)
        notice_lay.addWidget(notice_txt, 1)
        root.addWidget(notice)

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
