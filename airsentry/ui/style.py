"""Dark theme stylesheet and palette for the AirSentry desktop application."""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

BG_DEEP    = "#0a0e17"
BG_PANEL   = "#0f1320"
BG_SURFACE = "#171c2e"
BG_HOVER   = "#1c2238"
BORDER     = "#232a42"
BORDER_LT  = "#2c3555"

ACCENT     = "#38bdf8"
ACCENT_DIM = "#1a3f5c"
ACCENT_BG  = "#0d1e30"

TEXT_PRIMARY   = "#e2e8f0"
TEXT_SECONDARY = "#94a3b8"
TEXT_MUTED     = "#475569"

COLOR_BEACON   = "#60a5fa"
COLOR_PROBE_Q  = "#34d399"
COLOR_PROBE_R  = "#2dd4bf"
COLOR_DEAUTH   = "#f87171"
COLOR_DISASSOC = "#fb923c"

COLOR_LOW      = "#facc15"
COLOR_MEDIUM   = "#fb923c"
COLOR_HIGH     = "#f87171"
COLOR_CRITICAL = "#f43f5e"

COLOR_OK     = "#4ade80"
COLOR_WARN   = "#facc15"
COLOR_DANGER = "#f87171"

FONT_FAMILY = '"Helvetica Neue", Helvetica, Arial, sans-serif'
FONT_MONO   = 'Menlo, "Cascadia Code", Consolas, monospace'


# ---------------------------------------------------------------------------
# QSS stylesheet
# ---------------------------------------------------------------------------

QSS = f"""
/* ── Global ─────────────────────────────────────────────────────── */
QMainWindow, QDialog, QWidget {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: 13px;
}}

/* ── Sidebar ─────────────────────────────────────────────────────── */
QWidget#sidebar {{
    background-color: {BG_DEEP};
    border-right: 1px solid {BORDER};
}}
QLabel#brand_label {{
    color: {ACCENT};
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}
QLabel#brand_version {{
    color: {TEXT_MUTED};
    font-size: 10px;
}}
QPushButton#nav_btn {{
    background-color: transparent;
    color: {TEXT_SECONDARY};
    text-align: left;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 500;
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
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}

/* ── Section titles ──────────────────────────────────────────────── */
QLabel#section_title {{
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
}}
QLabel#view_title {{
    color: {TEXT_PRIMARY};
    font-size: 18px;
    font-weight: 700;
}}

/* ── Stat cards ──────────────────────────────────────────────────── */
QFrame#stat_card {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}
QLabel#stat_value {{
    color: {TEXT_PRIMARY};
    font-size: 28px;
    font-weight: 700;
}}
QLabel#stat_label {{
    color: {TEXT_SECONDARY};
    font-size: 11px;
    font-weight: 500;
}}

/* ── Alert cards ─────────────────────────────────────────────────── */
QFrame#alert_card {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-left: 3px solid {COLOR_HIGH};
    border-radius: 6px;
}}

/* ── Buttons ─────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 18px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {BG_HOVER};
    border-color: {BORDER_LT};
}}
QPushButton:pressed {{
    background-color: {BG_PANEL};
}}
QPushButton:disabled {{
    background-color: {BG_PANEL};
    color: {TEXT_MUTED};
    border-color: {BORDER};
}}
QPushButton#start_btn {{
    background-color: #0c3d2a;
    color: {COLOR_OK};
    border: 1px solid #145c3e;
    font-weight: 600;
}}
QPushButton#start_btn:hover {{
    background-color: #145c3e;
    color: #ffffff;
}}
QPushButton#start_btn:disabled {{
    background-color: #081f16;
    color: #1e4030;
    border-color: #0e2e20;
}}
QPushButton#stop_btn {{
    background-color: #3d1515;
    color: {COLOR_DANGER};
    border: 1px solid #5c2020;
    font-weight: 600;
}}
QPushButton#stop_btn:hover {{
    background-color: #5c2020;
    color: #ffffff;
}}
QPushButton#stop_btn:disabled {{
    background-color: #1a0a0a;
    color: #301515;
    border-color: #1a0a0a;
}}
QPushButton#icon_btn {{
    background-color: transparent;
    border: none;
    color: {TEXT_MUTED};
    padding: 4px 8px;
    font-size: 12px;
}}
QPushButton#icon_btn:hover {{
    color: {TEXT_SECONDARY};
}}

/* ── Text / event feed ───────────────────────────────────────────── */
QTextEdit, QPlainTextEdit {{
    background-color: {BG_DEEP};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 8px;
    font-family: {FONT_MONO};
    font-size: 12px;
    padding: 6px;
    selection-background-color: {ACCENT_DIM};
}}

/* ── Combos / dropdowns ──────────────────────────────────────────── */
QComboBox {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 12px;
    min-height: 28px;
    font-size: 13px;
}}
QComboBox:hover {{ border-color: {BORDER_LT}; }}
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
    border-radius: 6px;
    padding: 6px 12px;
    min-height: 28px;
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}

/* ── Sliders ─────────────────────────────────────────────────────── */
QSlider::groove:horizontal {{
    background-color: {BORDER};
    height: 4px;
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background-color: {ACCENT};
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
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
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 13px;
}}

/* ── Scroll bars ─────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {BORDER_LT}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 6px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 3px;
    min-width: 30px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Tab widgets ─────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    background: {BG_PANEL};
}}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_SECONDARY};
    padding: 8px 20px;
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {ACCENT};
    border-bottom: 2px solid {ACCENT};
}}
QTabBar::tab:hover {{ color: {TEXT_PRIMARY}; }}

/* ── Progress bar ────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {BORDER};
    border: none;
    border-radius: 4px;
    text-align: center;
    color: {TEXT_MUTED};
    font-size: 11px;
    height: 8px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 4px;
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
    max-height: 1px;
}}

/* ── Checkboxes ──────────────────────────────────────────────────── */
QCheckBox {{
    color: {TEXT_PRIMARY};
    spacing: 8px;
    font-size: 13px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {BORDER_LT};
    border-radius: 4px;
    background: {BG_SURFACE};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT};
}}

/* ── Group boxes ─────────────────────────────────────────────────── */
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding-top: 14px;
    margin-top: 8px;
    font-weight: 600;
    font-size: 12px;
    color: {TEXT_SECONDARY};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}}

/* ── Tool tips ───────────────────────────────────────────────────── */
QToolTip {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
}}

/* ── Notice banners ──────────────────────────────────────────────── */
QFrame#notice_warn {{
    background-color: #18170e;
    border: 1px solid #2e2b10;
    border-radius: 8px;
}}
QFrame#notice_info {{
    background-color: #0c1820;
    border: 1px solid #142838;
    border-radius: 8px;
}}
"""


def apply_theme(app: QApplication) -> None:
    """Apply the dark Fusion theme to the QApplication."""
    from PySide6.QtWidgets import QStyleFactory

    app.setStyle(QStyleFactory.create("Fusion"))

    font = QFont("Helvetica Neue", 13)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)

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

    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, c(TEXT_MUTED))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       c(TEXT_MUTED))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, c(TEXT_MUTED))

    app.setPalette(palette)
    app.setStyleSheet(QSS)
