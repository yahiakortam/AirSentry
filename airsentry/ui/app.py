"""AirSentry desktop application entry point."""

from __future__ import annotations

import sys


def run() -> None:
    """
    Create the QApplication, apply the dark theme, and show the main window.

    Intended to be called from ``__main__.py`` and the ``airsentry-ui``
    console script entry point.
    """
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt

    # Must be created before any other Qt objects
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("AirSentry")
    app.setOrganizationName("AirSentry")
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    from airsentry.ui.style import apply_theme
    from airsentry.ui.main_window import MainWindow

    apply_theme(app)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
