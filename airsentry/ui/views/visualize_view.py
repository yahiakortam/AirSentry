"""Visualize view — generate and display charts from AirSentry research datasets."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QScrollArea,
    QSizePolicy, QTabWidget, QVBoxLayout, QWidget,
)

from airsentry.ui.style import TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY


class _ChartWorker(QThread):

    charts_ready = Signal(list)
    error        = Signal(str)

    def __init__(self, file_path: Path, output_dir: Path) -> None:
        super().__init__()
        self._file_path  = file_path
        self._output_dir = output_dir

    def run(self) -> None:
        try:
            from airsentry.visualization.charts import load_dataset, DatasetVisualizer
            records = load_dataset(self._file_path)
            viz = DatasetVisualizer(records)
            paths = viz.generate_all(self._output_dir, fmt="png")
            self.charts_ready.emit(paths)
        except ImportError:
            self.error.emit(
                "matplotlib is not installed.\n\n"
                "Install it with:\n    pip install matplotlib\n"
                "or:  pip install \"airsentry[viz]\""
            )
        except Exception as exc:
            self.error.emit(str(exc))


class VisualizeView(QWidget):

    _CHART_TITLES = {
        "anomaly_timeline":   "Anomaly Timeline",
        "frame_distribution": "Frame Distribution",
        "device_activity":    "Device Activity",
        "beacon_rate":        "Beacon Rate",
    }

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._selected_path: Optional[Path] = None
        self._tmp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._worker: Optional[_ChartWorker] = None
        self._build_ui()

    def closeEvent(self, event) -> None:  # noqa: N802
        if self._tmp_dir:
            try:
                self._tmp_dir.cleanup()
            except Exception:
                pass
        super().closeEvent(event)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        title = QLabel("Visualize Dataset")
        title.setObjectName("view_title")
        root.addWidget(title)

        # Controls
        ctrl = QFrame()
        ctrl.setObjectName("stat_card")
        ctrl_lay = QHBoxLayout(ctrl)
        ctrl_lay.setContentsMargins(18, 14, 18, 14)
        ctrl_lay.setSpacing(12)

        file_lbl = QLabel("DATASET")
        file_lbl.setObjectName("section_title")
        file_lbl.setFixedWidth(60)

        self._file_label = QLabel("No file selected")
        self._file_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; font-style: italic;"
        )
        self._file_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._browse_btn = QPushButton("Browse")
        self._browse_btn.setFixedWidth(80)
        self._browse_btn.setCursor(Qt.PointingHandCursor)
        self._browse_btn.clicked.connect(self._on_browse)

        self._generate_btn = QPushButton("Generate Charts")
        self._generate_btn.setObjectName("start_btn")
        self._generate_btn.setMinimumWidth(140)
        self._generate_btn.setEnabled(False)
        self._generate_btn.setCursor(Qt.PointingHandCursor)
        self._generate_btn.clicked.connect(self._on_generate)

        ctrl_lay.addWidget(file_lbl)
        ctrl_lay.addWidget(self._file_label, 1)
        ctrl_lay.addWidget(self._browse_btn)
        ctrl_lay.addWidget(self._generate_btn)

        root.addWidget(ctrl)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 12px;"
        )
        root.addWidget(self._status_label)

        self._tab_widget = QTabWidget()
        self._tab_widget.setVisible(False)
        root.addWidget(self._tab_widget, 1)

        self._placeholder = QLabel(
            "Select a research dataset and click Generate Charts.\n\n"
            "Requires: pip install matplotlib"
        )
        self._placeholder.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 13px;"
        )
        self._placeholder.setAlignment(Qt.AlignCenter)
        root.addWidget(self._placeholder, 1)

    def _on_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open AirSentry Dataset",
            "",
            "Dataset files (*.csv *.jsonl);;All files (*)",
        )
        if path:
            self._selected_path = Path(path)
            self._file_label.setText(str(self._selected_path))
            self._file_label.setStyleSheet(
                f"color: {TEXT_PRIMARY}; font-size: 12px; font-style: normal;"
            )
            self._generate_btn.setEnabled(True)

    def _on_generate(self) -> None:
        if self._selected_path is None:
            return

        self._generate_btn.setEnabled(False)
        self._generate_btn.setText("Generating...")
        self._status_label.setText("Generating charts, please wait...")
        self._tab_widget.setVisible(False)
        self._placeholder.setVisible(False)

        if self._tmp_dir:
            try:
                self._tmp_dir.cleanup()
            except Exception:
                pass
        self._tmp_dir = tempfile.TemporaryDirectory(prefix="airsentry_charts_")
        output_dir = Path(self._tmp_dir.name)

        self._worker = _ChartWorker(self._selected_path, output_dir)
        self._worker.charts_ready.connect(self._on_charts_ready)
        self._worker.error.connect(self._on_chart_error)
        self._worker.start()

    def _on_charts_ready(self, paths: list) -> None:
        self._generate_btn.setEnabled(True)
        self._generate_btn.setText("Generate Charts")
        self._status_label.setText(
            f"{len(paths)} chart(s) generated from {self._selected_path.name}"
        )

        self._tab_widget.clear()

        for path in paths:
            path = Path(path)
            tab_title = self._CHART_TITLES.get(
                path.stem, path.stem.replace("_", " ").title()
            )

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setAlignment(Qt.AlignCenter)

            img_label = QLabel()
            img_label.setAlignment(Qt.AlignCenter)
            pixmap = QPixmap(str(path))
            if not pixmap.isNull():
                img_label.setPixmap(
                    pixmap.scaled(
                        900, 500,
                        Qt.KeepAspectRatio,
                        Qt.SmoothTransformation,
                    )
                )
            else:
                img_label.setText(f"Could not load: {path.name}")

            scroll.setWidget(img_label)
            self._tab_widget.addTab(scroll, tab_title)

        self._tab_widget.setVisible(len(paths) > 0)
        self._placeholder.setVisible(len(paths) == 0)

        if not paths:
            self._status_label.setText(
                "No charts were generated. The dataset may be too small."
            )

    def _on_chart_error(self, msg: str) -> None:
        self._generate_btn.setEnabled(True)
        self._generate_btn.setText("Generate Charts")
        self._status_label.setText("Chart generation failed.")
        self._placeholder.setVisible(True)
        QMessageBox.critical(self, "Chart Error", msg)
