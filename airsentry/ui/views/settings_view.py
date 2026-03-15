"""Settings view — display and edit AirSentry configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDoubleSpinBox, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QLabel, QMessageBox,
    QPushButton, QScrollArea, QSizePolicy,
    QSpinBox, QVBoxLayout, QWidget,
)

from airsentry.config.settings import load_settings
from airsentry.ui.style import TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY


class SettingsView(QWidget):

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._settings = load_settings()
        self._build_ui()
        self._load_values()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        title = QLabel("Settings")
        title.setObjectName("view_title")
        root.addWidget(title)

        subtitle = QLabel(
            "Changes are saved to airsentry.toml in the current directory "
            "and take effect on the next session."
        )
        subtitle.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        body = QWidget()
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(0, 0, 16, 0)
        body_lay.setSpacing(18)

        body_lay.addWidget(self._build_detection_group())
        body_lay.addWidget(self._build_analysis_group())
        body_lay.addWidget(self._build_logging_group())
        body_lay.addStretch()

        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("start_btn")
        save_btn.setMinimumHeight(38)
        save_btn.setMinimumWidth(130)
        save_btn.clicked.connect(self._on_save)

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setMinimumHeight(38)
        reset_btn.clicked.connect(self._on_reset)

        btn_row.addWidget(save_btn)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

    def _build_detection_group(self) -> QGroupBox:
        grp = QGroupBox("Detection Engine")
        lay = QGridLayout(grp)
        lay.setContentsMargins(18, 20, 18, 18)
        lay.setVerticalSpacing(12)
        lay.setHorizontalSpacing(16)

        self._deauth_window   = self._spin_double(1.0, 120.0, 1.0)
        self._deauth_thresh   = self._spin_int(1, 200)
        self._beacon_window   = self._spin_double(1.0, 300.0, 1.0)
        self._beacon_rate_th  = self._spin_double(1.0, 500.0, 1.0)
        self._beacon_ssid_th  = self._spin_int(1, 200)

        row = 0
        for label, widget, tip in [
            ("Deauth window (s)",           self._deauth_window,  "Rolling window width for deauth burst detection"),
            ("Deauth burst threshold",      self._deauth_thresh,  "Frame count to trigger a deauth burst alert"),
            ("Beacon window (s)",           self._beacon_window,  "Rolling window width for beacon anomaly detection"),
            ("Beacon rate threshold (/s)",  self._beacon_rate_th, "Beacons/s per BSSID to trigger an alert"),
            ("Beacon unique SSID threshold",self._beacon_ssid_th, "Unique SSIDs in window to trigger alert"),
        ]:
            self._add_row(lay, row, label, widget, tip)
            row += 1

        return grp

    def _build_analysis_group(self) -> QGroupBox:
        grp = QGroupBox("Anomaly Analysis")
        lay = QGridLayout(grp)
        lay.setContentsMargins(18, 20, 18, 18)
        lay.setVerticalSpacing(12)
        lay.setHorizontalSpacing(16)

        self._window_seconds   = self._spin_double(10.0, 600.0, 5.0)
        self._interval_seconds = self._spin_double(5.0, 300.0, 5.0)
        self._anomaly_thresh   = self._spin_double(0.0, 1.0, 0.05)
        self._warmup_windows   = self._spin_int(5, 200)

        row = 0
        for label, widget, tip in [
            ("Window size (s)",      self._window_seconds,   "Rolling look-back window for feature extraction"),
            ("Analysis interval (s)",self._interval_seconds, "How often to extract features and score"),
            ("Anomaly threshold",    self._anomaly_thresh,   "Score above which an ANOMALY_SCORE alert fires"),
            ("Warm-up windows",      self._warmup_windows,   "Windows collected before fitting IsolationForest"),
        ]:
            self._add_row(lay, row, label, widget, tip)
            row += 1

        return grp

    def _build_logging_group(self) -> QGroupBox:
        grp = QGroupBox("Logging")
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(18, 20, 18, 18)
        lay.setSpacing(10)

        self._log_enabled = QCheckBox("Enable structured JSONL session logging")
        self._log_events  = QCheckBox("Also log raw frame events (verbose)")
        lay.addWidget(self._log_enabled)
        lay.addWidget(self._log_events)

        return grp

    def _load_values(self) -> None:
        s = self._settings
        self._deauth_window.setValue(s.detector.deauth_window_seconds)
        self._deauth_thresh.setValue(s.detector.deauth_burst_threshold)
        self._beacon_window.setValue(s.detector.beacon_window_seconds)
        self._beacon_rate_th.setValue(s.detector.beacon_rate_threshold)
        self._beacon_ssid_th.setValue(s.detector.beacon_unique_ssid_threshold)
        self._window_seconds.setValue(s.analysis.window_seconds)
        self._interval_seconds.setValue(s.analysis.interval_seconds)
        self._anomaly_thresh.setValue(s.analysis.anomaly_threshold)
        self._warmup_windows.setValue(s.analysis.warmup_windows)
        self._log_enabled.setChecked(s.logging.enabled)
        self._log_events.setChecked(s.logging.log_events)

    def _on_save(self) -> None:
        toml_path = Path("airsentry.toml")
        content = f"""# AirSentry configuration

[detector]
deauth_window_seconds          = {self._deauth_window.value()}
deauth_burst_threshold         = {self._deauth_thresh.value()}
beacon_window_seconds          = {self._beacon_window.value()}
beacon_rate_threshold          = {self._beacon_rate_th.value()}
beacon_unique_ssid_threshold   = {self._beacon_ssid_th.value()}

[analysis]
window_seconds    = {self._window_seconds.value()}
interval_seconds  = {self._interval_seconds.value()}
anomaly_threshold = {self._anomaly_thresh.value()}
warmup_windows    = {self._warmup_windows.value()}

[logging]
enabled    = {"true" if self._log_enabled.isChecked() else "false"}
log_events = {"true" if self._log_events.isChecked() else "false"}
"""
        try:
            toml_path.write_text(content, encoding="utf-8")
            QMessageBox.information(
                self, "Saved",
                f"Settings saved to:\n{toml_path.resolve()}\n\n"
                "Changes take effect on next session."
            )
        except OSError as exc:
            QMessageBox.critical(self, "Save Error", str(exc))

    def _on_reset(self) -> None:
        from airsentry.config.settings import Settings
        self._settings = Settings()
        self._load_values()

    @staticmethod
    def _spin_double(min_: float, max_: float, step: float = 0.1) -> QDoubleSpinBox:
        sb = QDoubleSpinBox()
        sb.setRange(min_, max_)
        sb.setSingleStep(step)
        sb.setDecimals(2)
        sb.setFixedWidth(120)
        return sb

    @staticmethod
    def _spin_int(min_: int, max_: int) -> QSpinBox:
        sb = QSpinBox()
        sb.setRange(min_, max_)
        sb.setFixedWidth(120)
        return sb

    @staticmethod
    def _add_row(
        lay: QGridLayout,
        row: int,
        label: str,
        widget: QWidget,
        tooltip: str = "",
    ) -> None:
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 13px;")
        if tooltip:
            lbl.setToolTip(tooltip)
            widget.setToolTip(tooltip)
        lay.addWidget(lbl,    row, 0, Qt.AlignLeft | Qt.AlignVCenter)
        lay.addWidget(widget, row, 1, Qt.AlignLeft)
        lay.setColumnStretch(2, 1)
