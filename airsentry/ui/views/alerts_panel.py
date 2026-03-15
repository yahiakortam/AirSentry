"""Right-side alerts panel — always-visible live alert feed and quick stats."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from airsentry.models.alerts import Alert, Severity
from airsentry.ui.style import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_LOW, COLOR_MEDIUM,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)


_SEV_COLOR = {
    Severity.LOW:      COLOR_LOW,
    Severity.MEDIUM:   COLOR_MEDIUM,
    Severity.HIGH:     COLOR_HIGH,
    Severity.CRITICAL: COLOR_CRITICAL,
}

_SEV_LABEL = {
    Severity.LOW:      "LOW",
    Severity.MEDIUM:   "MED",
    Severity.HIGH:     "HIGH",
    Severity.CRITICAL: "CRIT",
}


class AlertCard(QFrame):

    def __init__(self, alert: Alert, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        sev = alert.severity
        color = _SEV_COLOR.get(sev, COLOR_HIGH)

        self.setObjectName("alert_card")
        self.setStyleSheet(
            f"QFrame#alert_card {{ border-left-color: {color}; }}"
        )
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(8)

        badge = QLabel(_SEV_LABEL.get(sev, sev.value))
        badge.setStyleSheet(
            f"color: {color}; font-size: 9px; font-weight: 700; "
            f"padding: 2px 6px; border: 1px solid {color}; border-radius: 3px; "
            f"letter-spacing: 0.5px;"
        )
        badge.setFixedHeight(18)

        type_label = QLabel(alert.alert_type.value.replace("_", " "))
        type_label.setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-weight: 600; font-size: 12px;"
        )

        ts_label = QLabel(alert.timestamp.strftime("%H:%M:%S"))
        ts_label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")

        top.addWidget(badge)
        top.addWidget(type_label)
        top.addStretch()
        top.addWidget(ts_label)

        desc = alert.description
        if len(desc) > 72:
            desc = desc[:69] + "..."
        desc_label = QLabel(desc)
        desc_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        desc_label.setWordWrap(True)

        layout.addLayout(top)
        layout.addWidget(desc_label)


class AlertsPanel(QWidget):

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("alerts_panel")
        self.setFixedWidth(260)

        self._alert_count = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        header.setFixedHeight(48)
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(16, 14, 12, 8)

        title = QLabel("ALERTS")
        title.setObjectName("alerts_title")

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setObjectName("icon_btn")
        self._clear_btn.setFixedHeight(22)
        self._clear_btn.setCursor(Qt.PointingHandCursor)
        self._clear_btn.clicked.connect(self.clear_alerts)

        h_lay.addWidget(title)
        h_lay.addStretch()
        h_lay.addWidget(self._clear_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)

        # Scroll area
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setFrameShape(QFrame.NoFrame)

        self._cards_widget = QWidget()
        self._cards_widget.setStyleSheet("background: transparent;")
        self._cards_layout = QVBoxLayout(self._cards_widget)
        self._cards_layout.setContentsMargins(10, 10, 10, 10)
        self._cards_layout.setSpacing(8)
        self._cards_layout.addStretch()

        self._scroll.setWidget(self._cards_widget)

        # Quick stats footer
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)

        footer = QWidget()
        footer.setFixedHeight(100)
        footer.setStyleSheet("background: transparent;")
        f_lay = QVBoxLayout(footer)
        f_lay.setContentsMargins(16, 10, 16, 14)
        f_lay.setSpacing(8)

        qs_title = QLabel("STATS")
        qs_title.setObjectName("section_title")
        f_lay.addWidget(qs_title)

        grid = QHBoxLayout()
        grid.setSpacing(6)

        self._stat_devices = self._make_stat("--", "Devices")
        self._stat_alerts  = self._make_stat("0", "Alerts")
        self._stat_score   = self._make_stat("--", "Score")

        grid.addWidget(self._stat_devices)
        grid.addWidget(self._stat_alerts)
        grid.addWidget(self._stat_score)
        f_lay.addLayout(grid)

        root.addWidget(header)
        root.addWidget(sep)
        root.addWidget(self._scroll, 1)
        root.addWidget(sep2)
        root.addWidget(footer)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_alert(self, alert: Alert) -> None:
        card = AlertCard(alert)
        self._cards_layout.insertWidget(
            self._cards_layout.count() - 1, card
        )
        self._alert_count += 1
        self._stat_alerts.findChild(QLabel, "val").setText(str(self._alert_count))
        self._scroll.verticalScrollBar().setValue(0)

    def update_quick_stats(
        self,
        devices: Optional[int] = None,
        score: Optional[float] = None,
    ) -> None:
        if devices is not None:
            self._stat_devices.findChild(QLabel, "val").setText(str(devices))
        if score is not None:
            color = "#f87171" if score > 0.6 else "#facc15" if score > 0.4 else "#4ade80"
            label = self._stat_score.findChild(QLabel, "val")
            label.setText(f"{score:.2f}")
            label.setStyleSheet(
                f"color: {color}; font-size: 18px; font-weight: 700;"
            )

    def clear_alerts(self) -> None:
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._alert_count = 0
        self._stat_alerts.findChild(QLabel, "val").setText("0")

    def reset(self) -> None:
        self.clear_alerts()
        self._stat_devices.findChild(QLabel, "val").setText("--")
        self._stat_score.findChild(QLabel, "val").setText("--")
        self._stat_score.findChild(QLabel, "val").setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-size: 18px; font-weight: 700;"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_stat(self, value: str, label: str) -> QWidget:
        w = QFrame()
        w.setStyleSheet("QFrame { background: transparent; }")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        lay.setAlignment(Qt.AlignCenter)

        val_lbl = QLabel(value)
        val_lbl.setObjectName("val")
        val_lbl.setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-size: 18px; font-weight: 700;"
        )
        val_lbl.setAlignment(Qt.AlignCenter)

        key_lbl = QLabel(label)
        key_lbl.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: 500;"
        )
        key_lbl.setAlignment(Qt.AlignCenter)

        lay.addWidget(val_lbl)
        lay.addWidget(key_lbl)
        return w
