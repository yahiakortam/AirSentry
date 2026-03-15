"""Right-side alerts panel — always-visible live alert feed and quick stats."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from airsentry.models.alerts import Alert, Severity
from airsentry.ui.style import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_LOW, COLOR_MEDIUM,
    TEXT_DIM, TEXT_PRIMARY, ACCENT,
)


# ---------------------------------------------------------------------------
# Severity colours mapping
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# AlertCard
# ---------------------------------------------------------------------------


class AlertCard(QFrame):
    """A compact card representing one alert in the side panel."""

    def __init__(self, alert: Alert, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        sev = alert.severity
        color = _SEV_COLOR.get(sev, COLOR_HIGH)

        self.setObjectName("alert_card")
        self.setProperty("class", f"alert_card_{sev.value.lower()}")
        self.setStyleSheet(
            f"QFrame#alert_card {{ border-left-color: {color}; }}"
        )
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(3)

        # Top row: badge + type label
        top = QHBoxLayout()
        top.setSpacing(6)

        badge = QLabel(_SEV_LABEL.get(sev, sev.value))
        badge.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: 700; "
            f"padding: 1px 5px; border: 1px solid {color}; border-radius: 3px;"
        )
        badge.setFixedHeight(18)

        type_label = QLabel(alert.alert_type.value.replace("_", " "))
        type_label.setStyleSheet(f"color: {TEXT_PRIMARY}; font-weight: 600; font-size: 12px;")

        ts_str = alert.timestamp.strftime("%H:%M:%S")
        ts_label = QLabel(ts_str)
        ts_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")

        top.addWidget(badge)
        top.addWidget(type_label)
        top.addStretch()
        top.addWidget(ts_label)

        # Description (truncated)
        desc = alert.description
        if len(desc) > 72:
            desc = desc[:69] + "…"
        desc_label = QLabel(desc)
        desc_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        desc_label.setWordWrap(True)

        layout.addLayout(top)
        layout.addWidget(desc_label)


# ---------------------------------------------------------------------------
# AlertsPanel
# ---------------------------------------------------------------------------


class AlertsPanel(QWidget):
    """
    Right-side panel that shows live alerts and quick session statistics.
    Always visible regardless of which main view is active.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("alerts_panel")
        self.setFixedWidth(270)

        self._alert_count = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──────────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        header.setFixedHeight(46)
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(14, 10, 10, 6)

        title = QLabel("LIVE ALERTS")
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

        # ── Scroll area for alert cards ──────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setFrameShape(QFrame.NoFrame)

        self._cards_widget = QWidget()
        self._cards_widget.setStyleSheet("background: transparent;")
        self._cards_layout = QVBoxLayout(self._cards_widget)
        self._cards_layout.setContentsMargins(10, 8, 10, 8)
        self._cards_layout.setSpacing(6)
        self._cards_layout.addStretch()

        self._scroll.setWidget(self._cards_widget)

        # ── Quick stats footer ───────────────────────────────────────
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)

        footer = QWidget()
        footer.setFixedHeight(110)
        footer.setStyleSheet("background: transparent;")
        f_lay = QVBoxLayout(footer)
        f_lay.setContentsMargins(14, 10, 14, 12)
        f_lay.setSpacing(6)

        qs_title = QLabel("QUICK STATS")
        qs_title.setObjectName("section_title")
        f_lay.addWidget(qs_title)

        grid = QHBoxLayout()
        grid.setSpacing(8)

        self._stat_devices = self._make_quick_stat("—", "Devices")
        self._stat_alerts  = self._make_quick_stat("0", "Alerts")
        self._stat_score   = self._make_quick_stat("—", "Score")

        grid.addWidget(self._stat_devices)
        grid.addWidget(self._stat_alerts)
        grid.addWidget(self._stat_score)
        f_lay.addLayout(grid)

        # Assemble
        root.addWidget(header)
        root.addWidget(sep)
        root.addWidget(self._scroll, 1)
        root.addWidget(sep2)
        root.addWidget(footer)

    # ------------------------------------------------------------------
    # Public API (called from MainWindow via signals)
    # ------------------------------------------------------------------

    def add_alert(self, alert: Alert) -> None:
        """Prepend an AlertCard to the top of the panel."""
        card = AlertCard(alert)
        # Insert before the trailing stretch (index = count - 1)
        self._cards_layout.insertWidget(
            self._cards_layout.count() - 1, card
        )
        self._alert_count += 1
        self._stat_alerts.findChild(QLabel, "val").setText(str(self._alert_count))
        # Auto-scroll to top so newest alerts are visible
        self._scroll.verticalScrollBar().setValue(0)

    def update_quick_stats(
        self,
        devices: Optional[int] = None,
        score: Optional[float] = None,
    ) -> None:
        """Update the quick-stats footer with fresh values."""
        if devices is not None:
            self._stat_devices.findChild(QLabel, "val").setText(str(devices))
        if score is not None:
            color = "#ff5f57" if score > 0.6 else "#ffd93d" if score > 0.4 else "#4dffb4"
            label = self._stat_score.findChild(QLabel, "val")
            label.setText(f"{score:.2f}")
            label.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: 700;")

    def clear_alerts(self) -> None:
        """Remove all alert cards."""
        while self._cards_layout.count() > 1:  # keep the stretch
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._alert_count = 0
        self._stat_alerts.findChild(QLabel, "val").setText("0")

    def reset(self) -> None:
        """Reset panel to initial state (call before a new session)."""
        self.clear_alerts()
        self._stat_devices.findChild(QLabel, "val").setText("—")
        self._stat_score.findChild(QLabel, "val").setText("—")
        self._stat_score.findChild(QLabel, "val").setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-size: 18px; font-weight: 700;"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_quick_stat(self, value: str, label: str) -> QWidget:
        w = QFrame()
        w.setStyleSheet("QFrame { background: transparent; }")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(1)
        lay.setAlignment(Qt.AlignCenter)

        val_lbl = QLabel(value)
        val_lbl.setObjectName("val")
        val_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 18px; font-weight: 700;")
        val_lbl.setAlignment(Qt.AlignCenter)

        key_lbl = QLabel(label)
        key_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px;")
        key_lbl.setAlignment(Qt.AlignCenter)

        lay.addWidget(val_lbl)
        lay.addWidget(key_lbl)
        return w
