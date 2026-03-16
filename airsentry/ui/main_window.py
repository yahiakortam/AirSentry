"""AirSentry main window — assembles sidebar, content stack, and alerts panel."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMainWindow,
    QMessageBox, QPushButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

from airsentry import __version__
from airsentry.ui.style import (
    ACCENT, BG_DEEP, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)
from airsentry.ui.views.alerts_panel import AlertsPanel
from airsentry.ui.views.monitor_view import MonitorView
from airsentry.ui.views.replay_view import ReplayView
from airsentry.ui.views.settings_view import SettingsView
from airsentry.ui.views.summary_view import SummaryView
from airsentry.ui.views.survey_view import SurveyView
from airsentry.ui.views.visualize_view import VisualizeView
from airsentry.ui.worker import MonitorWorker, ReplayWorker


IDX_MONITOR   = 0
IDX_REPLAY    = 1
IDX_SURVEY    = 2
IDX_SUMMARY   = 3
IDX_VISUALIZE = 4
IDX_SETTINGS  = 5


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"AirSentry {__version__}")
        self.setMinimumSize(1200, 720)
        self.resize(1400, 840)

        self._worker: Optional[MonitorWorker | ReplayWorker] = None

        self._build_ui()
        self._connect_view_buttons()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QVBoxLayout(central)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        main_lay.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_content_stack(), 1)
        body.addWidget(self._build_alerts_panel())

        main_lay.addLayout(body, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("header_bar")
        bar.setFixedHeight(48)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(22, 0, 22, 0)
        lay.setSpacing(10)

        brand = QLabel("AirSentry")
        brand.setObjectName("brand_label")

        ver = QLabel(f"v{__version__}")
        ver.setObjectName("brand_version")

        lay.addWidget(brand)
        lay.addWidget(ver)
        lay.addStretch()

        self._status_badge = QLabel("IDLE")
        self._status_badge.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; font-weight: 600; "
            f"letter-spacing: 1px;"
        )
        self._status_dot = QLabel()
        self._status_dot.setFixedSize(8, 8)
        self._status_dot.setStyleSheet(
            f"background-color: {TEXT_MUTED}; border-radius: 4px;"
        )

        lay.addWidget(self._status_dot)
        lay.addWidget(self._status_badge)

        return bar

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(190)

        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(0, 20, 0, 16)
        lay.setSpacing(0)

        nav_items = [
            ("Monitor",   IDX_MONITOR),
            ("Replay",    IDX_REPLAY),
            ("Survey",    IDX_SURVEY),
            ("Summary",   IDX_SUMMARY),
            ("Visualize", IDX_VISUALIZE),
            ("Settings",  IDX_SETTINGS),
        ]

        self._nav_buttons: list[QPushButton] = []

        for label, idx in nav_items:
            btn = QPushButton(f"   {label}")
            btn.setObjectName("nav_btn")
            btn.setFixedHeight(42)
            btn.setProperty("active", "false")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, i=idx: self._switch_view(i))
            self._nav_buttons.append(btn)
            lay.addWidget(btn)

        lay.addStretch()

        ver_lbl = QLabel(f"v{__version__}")
        ver_lbl.setObjectName("brand_version")
        ver_lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(ver_lbl)

        return sidebar

    def _build_content_stack(self) -> QStackedWidget:
        self._stack = QStackedWidget()

        self._monitor_view   = MonitorView()
        self._replay_view    = ReplayView()
        self._survey_view    = SurveyView()
        self._summary_view   = SummaryView()
        self._visualize_view = VisualizeView()
        self._settings_view  = SettingsView()

        self._stack.addWidget(self._monitor_view)
        self._stack.addWidget(self._replay_view)
        self._stack.addWidget(self._survey_view)
        self._stack.addWidget(self._summary_view)
        self._stack.addWidget(self._visualize_view)
        self._stack.addWidget(self._settings_view)

        return self._stack

    def _build_alerts_panel(self) -> AlertsPanel:
        self._alerts_panel = AlertsPanel()
        return self._alerts_panel

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _connect_view_buttons(self) -> None:
        self._switch_view(IDX_MONITOR)

        self._monitor_view._start_btn.clicked.connect(self._start_monitoring)
        self._monitor_view._stop_btn.clicked.connect(self._stop_session)

        self._replay_view._start_btn.clicked.connect(self._start_replay)
        self._replay_view._stop_btn.clicked.connect(self._stop_session)

    def _switch_view(self, idx: int) -> None:
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_buttons):
            btn.setProperty("active", "true" if i == idx else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    # ------------------------------------------------------------------
    # Worker lifecycle
    # ------------------------------------------------------------------

    def _start_monitoring(self) -> None:
        if self._worker and self._worker.isRunning():
            return

        interface = self._monitor_view.selected_interface
        if not interface:
            QMessageBox.warning(self, "No Interface", "Select a network interface first.")
            return

        self._alerts_panel.reset()
        self._monitor_view.on_session_started()
        self._set_status("MONITORING", "#4ade80")

        from airsentry.config.settings import load_settings
        settings = load_settings()

        self._worker = MonitorWorker(interface=interface, settings=settings)
        self._connect_worker(self._worker)
        self._worker.start()

    def _start_replay(self) -> None:
        if self._worker and self._worker.isRunning():
            return

        file_path = self._replay_view.selected_file
        if not file_path:
            QMessageBox.warning(self, "No File", "Select a PCAP file first.")
            return

        self._alerts_panel.reset()
        self._replay_view.on_session_started()
        self._set_status("REPLAYING", ACCENT)

        from airsentry.config.settings import load_settings
        settings = load_settings()

        self._worker = ReplayWorker(
            file_path=file_path,
            rate_pps=self._replay_view.replay_rate,
            settings=settings,
        )
        self._connect_worker(self._worker)
        self._worker.start()

    def _stop_session(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        self._set_status("IDLE", TEXT_MUTED)

    def _connect_worker(self, worker: MonitorWorker | ReplayWorker) -> None:
        is_monitor = isinstance(worker, MonitorWorker)

        if is_monitor:
            worker.event_parsed.connect(self._monitor_view.event_feed.add_event)
            worker.event_parsed.connect(lambda _ev: self._monitor_view.on_event_received())
            worker.window_scored.connect(self._monitor_view.update_window_stats)
        else:
            worker.event_parsed.connect(self._replay_view.event_feed.add_event)
            worker.window_scored.connect(self._replay_view.update_window_stats)
            worker.progress_updated.connect(self._replay_view.update_progress)

        worker.alert_raised.connect(self._alerts_panel.add_alert)

        worker.window_scored.connect(
            lambda w: self._alerts_panel.update_quick_stats(
                devices=w.unique_src_macs,
                score=w.anomaly_score,
            )
        )

        worker.finished.connect(self._on_session_finished)
        worker.error.connect(self._on_worker_error)

    def _on_session_finished(self, summary) -> None:
        self._set_status("IDLE", TEXT_MUTED)

        if isinstance(self._worker, MonitorWorker):
            self._monitor_view.on_session_stopped()
        else:
            self._replay_view.on_session_stopped()

        self._summary_view.populate(summary)
        self._switch_view(IDX_SUMMARY)

    def _on_worker_error(self, message: str) -> None:
        self._set_status("ERROR", "#f87171")
        if isinstance(self._worker, MonitorWorker):
            self._monitor_view.on_session_stopped()
        elif isinstance(self._worker, ReplayWorker):
            self._replay_view.on_session_stopped()
        QMessageBox.critical(self, "AirSentry Error", message)

    # ------------------------------------------------------------------
    # Status badge
    # ------------------------------------------------------------------

    def _set_status(self, text: str, color: str) -> None:
        self._status_badge.setText(text)
        self._status_badge.setStyleSheet(
            f"color: {color}; font-size: 12px; font-weight: 600; "
            f"letter-spacing: 1px;"
        )
        self._status_dot.setStyleSheet(
            f"background-color: {color}; border-radius: 4px;"
        )

    # ------------------------------------------------------------------
    # Close event
    # ------------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(3000)
        super().closeEvent(event)
