"""Dark theme stylesheet and palette for the AirSentry desktop application."""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


# ---------------------------------------------------------------------------
# Color palette constants (used by both QSS and code that paints directly)
# ---------------------------------------------------------------------------

BG_DEEP    = "#0b0b16"   # deepest background (sidebar, event feed)
BG_PANEL   = "#10111f"   # card / panel background
BG_SURFACE = "#161728"   # slightly lighter surface
BORDER     = "#1e2340"   # subtle border

ACCENT     = "#38bdf8"   # primary accent (sky blue — matches CLI cyan)
ACCENT_DIM = "#1e4a6a"

TEXT_PRIMARY = "#dde3f0"
TEXT_DIM     = "#6b7a99"
TEXT_MUTED   = "#454e6a"

# Frame-type colours (must match CLI for visual continuity)
COLOR_BEACON  = "#4a9eff"
COLOR_PROBE_Q = "#50d890"
COLOR_PROBE_R = "#47d4d4"
COLOR_DEAUTH  = "#ff5f57"
COLOR_DISASSOC = "#ff9f43"

# Alert severity colours
COLOR_LOW      = "#ffd93d"
COLOR_MEDIUM   = "#ff9f43"
COLOR_HIGH     = "#ff5f57"
COLOR_CRITICAL = "#ff3377"

# Status colours
COLOR_OK      = "#4dffb4"
COLOR_WARN    = "#ffd93d"
COLOR_DANGER  = "#ff5f57"


# ---------------------------------------------------------------------------
# QSS stylesheet
# ---------------------------------------------------------------------------

QSS = f"""
/* ── Global ─────────────────────────────────────────────────────── */
QMainWindow, QDialog, QWidget {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 13px;
}}

/* ── Sidebar ─────────────────────────────────────────────────────── */
QWidget#sidebar {{
    background-color: {BG_DEEP};
    border-right: 1px solid {BORDER};
}}
QLabel#brand_label {{
    color: {ACCENT};
    font-size: 16px;
    font-weight: 700;
    padding: 4px 0;
}}
QLabel#brand_version {{
    color: {TEXT_MUTED};
    font-size: 11px;
}}
QPushButton#nav_btn {{
    background-color: transparent;
    color: {TEXT_DIM};
    text-align: left;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    padding: 11px 18px;
    font-size: 13px;
}}
QPushButton#nav_btn:hover {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
}}
QPushButton#nav_btn[active="true"] {{
    background-color: {BG_SURFACE};
    color: {ACCENT};
    border-left: 3px solid {ACCENT};
    font-weight: 600;
}}

/* ── Header bar ──────────────────────────────────────────────────── */
QWidget#header_bar {{
    background-color: {BG_DEEP};
    border-bottom: 1px solid {BORDER};
}}

/* ── Alerts panel ────────────────────────────────────────────────── */
QWidget#alerts_panel {{
    background-color: {BG_DEEP};
    border-left: 1px solid {BORDER};
}}
QLabel#alerts_title {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}}

/* ── Section titles ──────────────────────────────────────────────── */
QLabel#section_title {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}}
QLabel#view_title {{
    color: {TEXT_PRIMARY};
    font-size: 17px;
    font-weight: 700;
}}

/* ── Stat cards ──────────────────────────────────────────────────── */
QFrame#stat_card {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QLabel#stat_value {{
    color: {TEXT_PRIMARY};
    font-size: 26px;
    font-weight: 700;
}}
QLabel#stat_label {{
    color: {TEXT_DIM};
    font-size: 11px;
}}

/* ── Alert cards ─────────────────────────────────────────────────── */
QFrame#alert_card {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-left: 3px solid {COLOR_HIGH};
    border-radius: 4px;
}}
QFrame#alert_card_low    {{ border-left-color: {COLOR_LOW}; }}
QFrame#alert_card_medium {{ border-left-color: {COLOR_MEDIUM}; }}
QFrame#alert_card_high   {{ border-left-color: {COLOR_HIGH}; }}
QFrame#alert_card_critical {{ border-left-color: {COLOR_CRITICAL}; }}

/* ── Buttons ─────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 5px;
    padding: 6px 16px;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: #1a2038;
    border-color: {ACCENT_DIM};
    color: #ffffff;
}}
QPushButton:pressed {{
    background-color: #101525;
}}
QPushButton:disabled {{
    background-color: {BG_PANEL};
    color: {TEXT_MUTED};
    border-color: {TEXT_MUTED};
}}
QPushButton#start_btn {{
    background-color: #0d4d32;
    color: {COLOR_OK};
    border: 1px solid #0f6642;
    font-weight: 600;
}}
QPushButton#start_btn:hover {{
    background-color: #0f6642;
    color: #ffffff;
}}
QPushButton#start_btn:disabled {{
    background-color: #0a2e1e;
    color: #2a5040;
    border-color: #0a2e1e;
}}
QPushButton#stop_btn {{
    background-color: #4d1515;
    color: {COLOR_DANGER};
    border: 1px solid #6a1f1f;
    font-weight: 600;
}}
QPushButton#stop_btn:hover {{
    background-color: #6a1f1f;
    color: #ffffff;
}}
QPushButton#stop_btn:disabled {{
    background-color: #1a0a0a;
    color: #3a1515;
    border-color: #1a0a0a;
}}
QPushButton#icon_btn {{
    background-color: transparent;
    border: none;
    color: {TEXT_DIM};
    padding: 4px;
}}
QPushButton#icon_btn:hover {{
    color: {TEXT_PRIMARY};
}}

/* ── Text / event feed ───────────────────────────────────────────── */
QTextEdit, QPlainTextEdit {{
    background-color: {BG_DEEP};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 4px;
    font-family: "SF Mono", "Cascadia Code", Consolas, "Courier New", monospace;
    font-size: 12px;
    selection-background-color: {ACCENT_DIM};
}}

/* ── Combos / dropdowns ──────────────────────────────────────────── */
QComboBox {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 5px;
    padding: 5px 10px;
    min-height: 26px;
}}
QComboBox:hover {{ border-color: {ACCENT_DIM}; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox::down-arrow {{ image: none; width: 0; }}
QComboBox QAbstractItemView {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT_DIM};
    outline: none;
}}

/* ── Line edits ──────────────────────────────────────────────────── */
QLineEdit {{
    background-color: {BG_DEEP};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 5px;
    padding: 5px 10px;
    min-height: 26px;
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QLineEdit:read-only {{
    color: {TEXT_DIM};
    background-color: {BG_PANEL};
}}

/* ── Sliders ─────────────────────────────────────────────────────── */
QSlider::groove:horizontal {{
    background-color: {BG_SURFACE};
    height: 4px;
    border-radius: 2px;
    border: 1px solid {BORDER};
}}
QSlider::handle:horizontal {{
    background-color: {ACCENT};
    width: 16px;
    height: 16px;
    margin: -7px 0;
    border-radius: 8px;
}}
QSlider::sub-page:horizontal {{
    background-color: {ACCENT};
    border-radius: 2px;
}}

/* ── Spin boxes ──────────────────────────────────────────────────── */
QSpinBox, QDoubleSpinBox {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 5px;
    padding: 4px 8px;
}}

/* ── Scroll bars ─────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {BG_PANEL};
    width: 7px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: #2a3050;
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: #3a4070; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {BG_PANEL};
    height: 7px;
}}
QScrollBar::handle:horizontal {{
    background: #2a3050;
    border-radius: 3px;
    min-width: 24px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Tab widgets ─────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 4px;
    background: {BG_PANEL};
}}
QTabBar::tab {{
    background: {BG_SURFACE};
    color: {TEXT_DIM};
    padding: 6px 18px;
    border: 1px solid {BORDER};
    border-bottom: none;
    border-radius: 4px 4px 0 0;
}}
QTabBar::tab:selected {{
    background: {BG_PANEL};
    color: {ACCENT};
    border-bottom: 2px solid {ACCENT};
}}
QTabBar::tab:hover {{ color: {TEXT_PRIMARY}; }}

/* ── Progress bar ────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 4px;
    text-align: center;
    color: {TEXT_DIM};
    font-size: 11px;
    height: 14px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 3px;
}}

/* ── Scroll area ─────────────────────────────────────────────────── */
QScrollArea {{
    border: none;
    background: transparent;
}}
QScrollArea > QWidget > QWidget {{
    background: transparent;
}}

/* ── Separators ──────────────────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {BORDER};
}}

/* ── Checkboxes ──────────────────────────────────────────────────── */
QCheckBox {{
    color: {TEXT_PRIMARY};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {BORDER};
    border-radius: 3px;
    background: {BG_SURFACE};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT};
}}

/* ── Tool tips ───────────────────────────────────────────────────── */
QToolTip {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


def apply_theme(app: QApplication) -> None:
    """Apply the dark Fusion theme to the QApplication."""
    from PySide6.QtWidgets import QStyleFactory

    app.setStyle(QStyleFactory.create("Fusion"))

    palette = QPalette()
    c = QColor

    palette.setColor(QPalette.ColorRole.Window,          c(BG_PANEL))
    palette.setColor(QPalette.ColorRole.WindowText,      c(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.Base,            c(BG_DEEP))
    palette.setColor(QPalette.ColorRole.AlternateBase,   c(BG_SURFACE))
    palette.setColor(QPalette.ColorRole.ToolTipBase,     c(BG_SURFACE))
    palette.setColor(QPalette.ColorRole.ToolTipText,     c(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.Text,            c(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.Button,          c(BG_SURFACE))
    palette.setColor(QPalette.ColorRole.ButtonText,      c(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.BrightText,      c("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link,            c(ACCENT))
    palette.setColor(QPalette.ColorRole.Highlight,       c(ACCENT_DIM))
    palette.setColor(QPalette.ColorRole.HighlightedText, c("#ffffff"))

    # Disabled state
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, c(TEXT_MUTED))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       c(TEXT_MUTED))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, c(TEXT_MUTED))

    app.setPalette(palette)
    app.setStyleSheet(QSS)
