"""AirSentry desktop application entry point."""

from __future__ import annotations

import sys


def run() -> None:
    """
    Create the QApplication, apply the dark theme, and show the main window.
    """
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("AirSentry")
    app.setOrganizationName("AirSentry")

    from airsentry.ui.style import apply_theme
    from airsentry.ui.main_window import MainWindow

    apply_theme(app)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
