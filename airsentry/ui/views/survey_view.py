"""Survey view — Wi-Fi environment scan, risk scoring, and map generation."""

from __future__ import annotations

import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDoubleSpinBox, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton,
    QScrollArea, QSizePolicy, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from airsentry.ui.style import (
    ACCENT, BG_SURFACE, BORDER, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

class _ScanWorker(QThread):
    finished = Signal(list)   # list[NetworkInfo]
    error    = Signal(str)

    def run(self) -> None:
        try:
            from airsentry.survey.scanner import scan_networks
            networks = scan_networks()
            self.finished.emit(networks)
        except Exception as exc:
            self.error.emit(str(exc))


class _LocationWorker(QThread):
    """Fetch GPS coordinates using macOS CoreLocation."""
    location_found = Signal(float, float)  # lat, lon
    error = Signal(str)

    def run(self) -> None:
        try:
            import platform
            if platform.system() != "Darwin":
                self.error.emit("Auto-detect is only supported on macOS.")
                return

            import CoreLocation
            import objc
            import time

            manager = CoreLocation.CLLocationManager.alloc().init()
            manager.requestWhenInUseAuthorization()

            status = CoreLocation.CLLocationManager.authorizationStatus()
            if status == 2:  # denied
                self.error.emit(
                    "Location Services denied for this app.\n\n"
                    "Enable in: System Settings → Privacy & Security → Location Services → Python"
                )
                return

            manager.startUpdatingLocation()

            # Poll for up to 10 seconds
            for _ in range(40):
                time.sleep(0.25)
                loc = manager.location()
                if loc is not None:
                    coord = loc.coordinate()
                    lat = coord.latitude
                    lon = coord.longitude
                    if lat != 0.0 or lon != 0.0:
                        manager.stopUpdatingLocation()
                        self.location_found.emit(lat, lon)
                        return

            manager.stopUpdatingLocation()
            self.error.emit(
                "Could not determine location.\n\n"
                "Make sure Location Services is enabled for Python in:\n"
                "System Settings → Privacy & Security → Location Services"
            )
        except ImportError:
            self.error.emit(
                "pyobjc-framework-CoreLocation is required.\n\n"
                "Install with: pip install pyobjc-framework-CoreLocation"
            )
        except Exception as exc:
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# SurveyView
# ---------------------------------------------------------------------------

class SurveyView(QWidget):

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._last_networks: list = []
        self._last_result = None
        self._worker: Optional[_ScanWorker] = None
        self._loc_worker: Optional[_LocationWorker] = None

        from airsentry.survey.store import SurveyStore
        self._store = SurveyStore()

        self._build_ui()
        self._refresh_history()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        # Title
        title = QLabel("Wi-Fi Survey")
        title.setObjectName("view_title")
        root.addWidget(title)

        subtitle = QLabel(
            "Scan nearby Wi-Fi networks, compute a security risk score, "
            "and build a map across multiple locations."
        )
        subtitle.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        # --- Scan controls card ---
        ctrl = QFrame()
        ctrl.setObjectName("stat_card")
        ctrl_lay = QVBoxLayout(ctrl)
        ctrl_lay.setContentsMargins(18, 16, 18, 16)
        ctrl_lay.setSpacing(14)

        # Location row
        loc_row = QHBoxLayout()
        loc_row.setSpacing(12)
        loc_label = self._section_label("LOCATION")
        loc_label.setFixedWidth(70)
        self._location_edit = QLineEdit()
        self._location_edit.setPlaceholderText("e.g. Downtown Cafe, Airport Terminal 2...")
        loc_row.addWidget(loc_label)
        loc_row.addWidget(self._location_edit, 1)
        ctrl_lay.addLayout(loc_row)

        # Coordinates row
        coord_row = QHBoxLayout()
        coord_row.setSpacing(12)
        coord_label = self._section_label("COORDS")
        coord_label.setFixedWidth(70)

        self._lat_spin = QDoubleSpinBox()
        self._lat_spin.setRange(-90.0, 90.0)
        self._lat_spin.setDecimals(6)
        self._lat_spin.setValue(0.0)
        self._lat_spin.setPrefix("Lat ")
        self._lat_spin.setFixedWidth(150)

        self._lon_spin = QDoubleSpinBox()
        self._lon_spin.setRange(-180.0, 180.0)
        self._lon_spin.setDecimals(6)
        self._lon_spin.setValue(0.0)
        self._lon_spin.setPrefix("Lon ")
        self._lon_spin.setFixedWidth(150)

        self._autodetect_btn = QPushButton("Auto-detect")
        self._autodetect_btn.setMinimumHeight(30)
        self._autodetect_btn.setCursor(Qt.PointingHandCursor)
        self._autodetect_btn.clicked.connect(self._on_autodetect_location)

        self._coord_status = QLabel("")
        self._coord_status.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")

        coord_row.addWidget(coord_label)
        coord_row.addWidget(self._lat_spin)
        coord_row.addWidget(self._lon_spin)
        coord_row.addWidget(self._autodetect_btn)
        coord_row.addWidget(self._coord_status)
        coord_row.addStretch()
        ctrl_lay.addLayout(coord_row)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self._scan_btn = QPushButton("Scan Networks")
        self._scan_btn.setObjectName("start_btn")
        self._scan_btn.setMinimumHeight(38)
        self._scan_btn.setMinimumWidth(140)
        self._scan_btn.setCursor(Qt.PointingHandCursor)
        self._scan_btn.clicked.connect(self._on_scan)

        self._save_btn = QPushButton("Save Result")
        self._save_btn.setMinimumHeight(38)
        self._save_btn.setEnabled(False)
        self._save_btn.setCursor(Qt.PointingHandCursor)
        self._save_btn.clicked.connect(self._on_save)

        self._map_btn = QPushButton("Generate Map")
        self._map_btn.setMinimumHeight(38)
        self._map_btn.setCursor(Qt.PointingHandCursor)
        self._map_btn.clicked.connect(self._on_generate_map)

        btn_row.addWidget(self._scan_btn)
        btn_row.addWidget(self._save_btn)
        btn_row.addWidget(self._map_btn)
        btn_row.addStretch()
        ctrl_lay.addLayout(btn_row)

        root.addWidget(ctrl)

        # Location services notice (hidden by default, shown after scan if needed)
        self._loc_notice = QFrame()
        self._loc_notice.setObjectName("notice_warn")
        self._loc_notice.setVisible(False)
        notice_lay = QHBoxLayout(self._loc_notice)
        notice_lay.setContentsMargins(14, 10, 14, 10)
        notice_lbl = QLabel(
            "SSIDs are hidden by macOS privacy settings. "
            "To reveal network names, enable Location Services for Terminal: "
            "System Settings → Privacy & Security → Location Services → Terminal"
        )
        notice_lbl.setWordWrap(True)
        notice_lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        notice_lay.addWidget(notice_lbl)
        root.addWidget(self._loc_notice)

        # --- Results area (two columns) ---
        results_lay = QHBoxLayout()
        results_lay.setSpacing(14)

        # Left: risk summary card
        self._summary_card = self._build_summary_card()
        results_lay.addWidget(self._summary_card)

        # Right: network table
        table_col = QVBoxLayout()
        table_col.setSpacing(6)

        table_header = QHBoxLayout()
        table_header.addWidget(self._section_label("DETECTED NETWORKS"))
        table_header.addStretch()
        self._show_ssid_toggle = QCheckBox("Show SSIDs")
        self._show_ssid_toggle.setChecked(False)
        self._show_ssid_toggle.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        self._show_ssid_toggle.toggled.connect(self._refresh_table)
        table_header.addWidget(self._show_ssid_toggle)
        table_col.addLayout(table_header)

        self._net_table = QTableWidget()
        self._net_table.setColumnCount(5)
        self._net_table.setHorizontalHeaderLabels(
            ["SSID", "BSSID", "Signal", "Channel", "Security"]
        )
        self._net_table.horizontalHeader().setStretchLastSection(True)
        self._net_table.verticalHeader().setVisible(False)
        self._net_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._net_table.setSelectionMode(QTableWidget.NoSelection)
        self._net_table.setStyleSheet(
            f"QTableWidget {{ background-color: {BG_SURFACE}; "
            f"border: 1px solid {BORDER}; border-radius: 8px; gridline-color: {BORDER}; }}"
            f"QHeaderView::section {{ background-color: {BG_SURFACE}; "
            f"color: {TEXT_MUTED}; font-size: 10px; font-weight: 700; "
            f"letter-spacing: 1px; border: none; padding: 6px 8px; "
            f"border-bottom: 1px solid {BORDER}; }}"
        )
        table_col.addWidget(self._net_table, 1)
        results_lay.addLayout(table_col, 2)

        root.addLayout(results_lay, 1)

        # --- History row ---
        root.addWidget(self._section_label("SCAN HISTORY"))

        self._history_table = QTableWidget()
        self._history_table.setColumnCount(5)
        self._history_table.setHorizontalHeaderLabels(
            ["Location", "Date", "Networks", "Open", "Risk Score"]
        )
        self._history_table.horizontalHeader().setStretchLastSection(True)
        self._history_table.verticalHeader().setVisible(False)
        self._history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._history_table.setSelectionMode(QTableWidget.SingleSelection)
        self._history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._history_table.setMaximumHeight(160)
        self._history_table.setStyleSheet(
            f"QTableWidget {{ background-color: {BG_SURFACE}; "
            f"border: 1px solid {BORDER}; border-radius: 8px; gridline-color: {BORDER}; }}"
            f"QHeaderView::section {{ background-color: {BG_SURFACE}; "
            f"color: {TEXT_MUTED}; font-size: 10px; font-weight: 700; "
            f"letter-spacing: 1px; border: none; padding: 6px 8px; "
            f"border-bottom: 1px solid {BORDER}; }}"
            f"QTableWidget::item:selected {{ background-color: #1a3f5c; }}"
        )
        root.addWidget(self._history_table)

    def _build_summary_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("stat_card")
        card.setFixedWidth(240)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)

        lay.addWidget(self._section_label("RISK ANALYSIS"))

        self._score_label = QLabel("--")
        self._score_label.setStyleSheet(
            f"color: {TEXT_PRIMARY}; font-size: 42px; font-weight: 700;"
        )
        self._score_label.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._score_label)

        self._risk_label = QLabel("")
        self._risk_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; font-weight: 600;"
        )
        self._risk_label.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._risk_label)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        lay.addWidget(sep)

        self._stat_rows: dict[str, QLabel] = {}
        for key, label in [
            ("total",  "Networks"),
            ("open",   "Open"),
            ("wpa2",   "WPA2"),
            ("wpa3",   "WPA3"),
            ("dups",   "Dup SSIDs"),
            ("hidden", "Hidden"),
        ]:
            row = QHBoxLayout()
            k = QLabel(label)
            k.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
            v = QLabel("--")
            v.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 600;")
            v.setAlignment(Qt.AlignRight)
            row.addWidget(k)
            row.addStretch()
            row.addWidget(v)
            lay.addLayout(row)
            self._stat_rows[key] = v

        lay.addStretch()
        return card

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_autodetect_location(self) -> None:
        self._autodetect_btn.setEnabled(False)
        self._autodetect_btn.setText("Detecting...")
        self._coord_status.setText("")

        self._loc_worker = _LocationWorker()
        self._loc_worker.location_found.connect(self._on_location_found)
        self._loc_worker.error.connect(self._on_location_error)
        self._loc_worker.start()

    def _on_location_found(self, lat: float, lon: float) -> None:
        self._autodetect_btn.setEnabled(True)
        self._autodetect_btn.setText("Auto-detect")
        self._lat_spin.setValue(lat)
        self._lon_spin.setValue(lon)
        self._coord_status.setText("Location detected")
        self._coord_status.setStyleSheet(f"color: #4ade80; font-size: 11px;")

    def _on_location_error(self, msg: str) -> None:
        self._autodetect_btn.setEnabled(True)
        self._autodetect_btn.setText("Auto-detect")
        self._coord_status.setText("Failed")
        self._coord_status.setStyleSheet(f"color: #f87171; font-size: 11px;")
        QMessageBox.warning(self, "Location Error", msg)

    def _on_scan(self) -> None:
        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scanning...")
        self._save_btn.setEnabled(False)

        self._worker = _ScanWorker()
        self._worker.finished.connect(self._on_scan_done)
        self._worker.error.connect(self._on_scan_error)
        self._worker.start()

    def _on_scan_done(self, networks: list) -> None:
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("Scan Networks")

        self._last_networks = networks

        from airsentry.survey.scanner import ssids_available
        self._loc_notice.setVisible(not ssids_available)
        if not ssids_available:
            self._show_ssid_toggle.setChecked(False)
            self._show_ssid_toggle.setEnabled(False)
            self._show_ssid_toggle.setToolTip(
                "SSIDs are hidden by macOS.\n"
                "Grant Location Services to Terminal/Python:\n"
                "System Settings → Privacy & Security → Location Services"
            )
        else:
            self._show_ssid_toggle.setEnabled(True)
            self._show_ssid_toggle.setToolTip("")

        from airsentry.survey.scorer import score_environment
        result = score_environment(networks)
        self._last_result = result

        # Update summary card
        score = result.risk_score
        if score <= 30:
            sc = "#4ade80"
        elif score <= 60:
            sc = "#facc15"
        else:
            sc = "#f87171"

        self._score_label.setText(f"{score}")
        self._score_label.setStyleSheet(
            f"color: {sc}; font-size: 42px; font-weight: 700;"
        )
        self._risk_label.setText(f"{result.risk_label} Risk")
        self._risk_label.setStyleSheet(
            f"color: {sc}; font-size: 13px; font-weight: 600; letter-spacing: 1px;"
        )

        self._stat_rows["total"].setText(str(result.total_networks))
        self._stat_rows["open"].setText(str(result.open_count))
        open_color = "#f87171" if result.open_count > 0 else TEXT_PRIMARY
        self._stat_rows["open"].setStyleSheet(
            f"color: {open_color}; font-size: 12px; font-weight: 600;"
        )
        self._stat_rows["wpa2"].setText(str(result.wpa2_count))
        self._stat_rows["wpa3"].setText(str(result.wpa3_count))
        self._stat_rows["dups"].setText(str(result.duplicate_ssid_count))
        dup_color = "#fb923c" if result.duplicate_ssid_count > 0 else TEXT_PRIMARY
        self._stat_rows["dups"].setStyleSheet(
            f"color: {dup_color}; font-size: 12px; font-weight: 600;"
        )
        self._stat_rows["hidden"].setText(str(result.hidden_count))

        self._refresh_table()
        self._save_btn.setEnabled(True)

    def _refresh_table(self) -> None:
        networks = self._last_networks
        show_ssid = self._show_ssid_toggle.isChecked()

        self._net_table.setRowCount(len(networks))
        for i, net in enumerate(networks):
            if show_ssid:
                ssid_text = net.ssid
            elif net.is_hidden:
                ssid_text = "(hidden)"
            else:
                ssid_text = f"Network {i + 1}"

            self._net_table.setItem(i, 0, QTableWidgetItem(ssid_text))
            self._net_table.setItem(i, 1, QTableWidgetItem(net.bssid if net.bssid else "--"))
            self._net_table.setItem(i, 2, QTableWidgetItem(f"{net.signal_dbm} dBm"))
            self._net_table.setItem(
                i, 3,
                QTableWidgetItem(str(net.channel) if net.channel else "--"),
            )

            sec_item = QTableWidgetItem(net.security.value)
            if net.security.value == "Open":
                sec_item.setForeground(Qt.red)
            elif net.security.value == "WPA3":
                sec_item.setForeground(Qt.green)
            self._net_table.setItem(i, 4, sec_item)

        self._net_table.resizeColumnsToContents()

    def _on_scan_error(self, msg: str) -> None:
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("Scan Networks")
        QMessageBox.critical(self, "Scan Error", msg)

    def _on_save(self) -> None:
        if self._last_result is None:
            return

        location = self._location_edit.text().strip()
        if not location:
            QMessageBox.warning(
                self, "Missing Location",
                "Enter a location name before saving.",
            )
            return

        lat = self._lat_spin.value() if self._lat_spin.value() != 0.0 else None
        lon = self._lon_spin.value() if self._lon_spin.value() != 0.0 else None

        # Allow saving with 0,0 if both are explicitly set
        if self._lat_spin.value() == 0.0 and self._lon_spin.value() == 0.0:
            lat = None
            lon = None

        from airsentry.survey.store import ScanRecord

        record = ScanRecord(
            location_name=location,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            latitude=lat,
            longitude=lon,
            result=self._last_result,
        )
        self._store.save(record)
        self._refresh_history()
        self._save_btn.setEnabled(False)

        QMessageBox.information(
            self, "Saved",
            f"Scan saved for \"{location}\".\n"
            f"Risk score: {self._last_result.risk_score}/100",
        )

    def _on_generate_map(self) -> None:
        records = self._store.load_all()
        geo_records = [r for r in records if r.latitude and r.longitude]

        if not geo_records:
            QMessageBox.information(
                self, "No Map Data",
                "Save at least one scan with coordinates to generate a map.\n\n"
                "Enter latitude/longitude in the Coords fields before saving.",
            )
            return

        try:
            from airsentry.survey.mapper import generate_map
            path = generate_map(records)
            webbrowser.open(f"file://{path}")
        except ImportError:
            QMessageBox.critical(
                self, "Missing Dependency",
                "folium is required for map generation.\n\n"
                "Install it with:  pip install folium",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Map Error", str(exc))

    def _refresh_history(self) -> None:
        records = self._store.load_all()
        self._history_table.setRowCount(len(records))
        for i, rec in enumerate(records):
            self._history_table.setItem(i, 0, QTableWidgetItem(rec.location_name))
            self._history_table.setItem(i, 1, QTableWidgetItem(rec.timestamp[:19]))
            self._history_table.setItem(
                i, 2, QTableWidgetItem(str(rec.result.total_networks))
            )
            self._history_table.setItem(
                i, 3, QTableWidgetItem(str(rec.result.open_count))
            )

            score_item = QTableWidgetItem(f"{rec.result.risk_score}/100")
            score = rec.result.risk_score
            if score <= 30:
                score_item.setForeground(Qt.green)
            elif score <= 60:
                score_item.setForeground(Qt.yellow)
            else:
                score_item.setForeground(Qt.red)
            self._history_table.setItem(i, 4, score_item)

        self._history_table.resizeColumnsToContents()

    @staticmethod
    def _section_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("section_title")
        return lbl
