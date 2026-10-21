"""Visual identity: a radiology lightbox. Pale film-viewer background (light) or a dim
reading room (dark), deep slate-blue chrome, and one cyan "scan" accent. Severity
colours are reserved for findings.

The colour dicts below are updated in place by set_theme(), so code that imported
them always sees the current theme.
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette

LIGHT = dict(
    text="#17324A", muted="#5B7083", body="#2A4459", page="#EEF3F6", card="#FFFFFF",
    line="#D5DFE6", alt="#F6F9FB", head="#F3F7F9", grid="#EDF2F5", select="#D6EEF5",
    code="#EEF3F6", banner="#E6F5F9", drop="#9FB4C4", drop_hover="#E6F5F9",
    header="#17324A", header_line="#3D5B75", header_input="#23445F", header_text="#E3EDF4",
    scan="#1D8FB0", scan_dark="#16748F", glow="#9ED8E6", grade_panel="#17324A",
    chart_bar="#C9D9E3", log_bg="#17324A",
)
DARK = dict(
    text="#E3EDF4", muted="#9DB2C2", body="#C9D7E2", page="#0F1E2B", card="#16293A",
    line="#2C4255", alt="#1A2F42", head="#1B3044", grid="#1F3447", select="#1F4A5C",
    code="#22384C", banner="#163646", drop="#3D5B75", drop_hover="#163646",
    header="#0B1824", header_line="#2C4255", header_input="#1A2F42", header_text="#E3EDF4",
    scan="#3BA9C9", scan_dark="#2E95B4", glow="#9ED8E6", grade_panel="#0B1824",
    chart_bar="#2C4A60", log_bg="#0B1824",
)
SEVERITY_LIGHT = {
    "critical": ("Critical", "#9F1D1D", "#FDE8E8"),
    "high": ("High", "#B4470F", "#FDEEDC"),
    "medium": ("Medium", "#8A6100", "#FDF4D6"),
    "low": ("Low", "#1F5D8C", "#E3EFF8"),
    "good": ("Good", "#1E6B43", "#E1F3E8"),
}
SEVERITY_DARK = {
    "critical": ("Critical", "#F59A9A", "#3A1C1F"),
    "high": ("High", "#F5AF7B", "#3A2718"),
    "medium": ("Medium", "#F2D06B", "#3A3218"),
    "low": ("Low", "#8EC3F0", "#1B2E42"),
    "good": ("Good", "#7FE0A8", "#173527"),
}
CATEGORY_LIGHT = {"authorized": "#1E6B43", "partial": "#8A6100", "service_failing": "#B4470F",
                  "unknown": "#9F1D1D", "forwarded": "#5B7083", "ignored": "#8A9AA8"}
CATEGORY_DARK = {"authorized": "#7FE0A8", "partial": "#F2D06B", "service_failing": "#F5AF7B",
                 "unknown": "#F59A9A", "forwarded": "#9DB2C2", "ignored": "#6E8496"}
GRADE_LIGHT = {"A": "#1E6B43", "B": "#3C7A2E", "C": "#8A6100", "D": "#B4470F", "F": "#9F1D1D"}
GRADE_DARK = {"A": "#7FE0A8", "B": "#A9DD8A", "C": "#F2D06B", "D": "#F5AF7B", "F": "#F59A9A"}

T: dict = dict(LIGHT)
SEVERITY: dict = dict(SEVERITY_LIGHT)
CATEGORY_COLORS: dict = dict(CATEGORY_LIGHT)
GRADE_COLORS: dict = dict(GRADE_LIGHT)
CURRENT = {"dark": False}

# Backwards-compatible names used by older code (light values).
INK, MUTED = LIGHT["text"], LIGHT["muted"]


def is_dark() -> bool:
    return CURRENT["dark"]


def resolve(mode: str) -> bool:
    """mode: 'system', 'light' or 'dark' -> True when dark should be used."""
    if mode == "dark":
        return True
    if mode == "light":
        return False
    try:
        return QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except AttributeError:  # Qt older than 6.5
        return False


def set_theme(dark: bool) -> None:
    CURRENT["dark"] = dark
    for target, src in ((T, DARK if dark else LIGHT),
                        (SEVERITY, SEVERITY_DARK if dark else SEVERITY_LIGHT),
                        (CATEGORY_COLORS, CATEGORY_DARK if dark else CATEGORY_LIGHT),
                        (GRADE_COLORS, GRADE_DARK if dark else GRADE_LIGHT)):
        target.clear()
        target.update(src)


def palette() -> QPalette:
    """Pin the palette so the OS theme can't make text unreadable."""
    p = QPalette()
    roles = {
        QPalette.Window: T["page"], QPalette.WindowText: T["text"], QPalette.Base: T["card"],
        QPalette.AlternateBase: T["alt"], QPalette.Text: T["text"], QPalette.Button: T["card"],
        QPalette.ButtonText: T["text"], QPalette.Highlight: T["scan"],
        QPalette.HighlightedText: "#FFFFFF", QPalette.ToolTipBase: T["header"],
        QPalette.ToolTipText: "#FFFFFF", QPalette.PlaceholderText: T["muted"],
        QPalette.Link: T["scan"] if CURRENT["dark"] else T["scan_dark"],
        QPalette.BrightText: "#FFFFFF",
    }
    for role, color in roles.items():
        p.setColor(role, QColor(color))
    p.setColor(QPalette.Disabled, QPalette.Text, QColor(T["muted"]))
    p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(T["muted"]))
    return p


def light_palette() -> QPalette:  # kept for the Release Manager
    set_theme(False)
    return palette()


def stylesheet() -> str:
    t = T
    return f"""
* {{ font-family: "Segoe UI Variable Text", "Segoe UI", "Helvetica Neue", Arial, sans-serif; font-size: 10pt; }}
QMainWindow, #Page, QDialog {{ background: {t['page']}; color: {t['text']}; }}
QToolTip {{ background: {t['header']}; color: white; border: none; padding: 6px; }}
QMenuBar {{ background: {t['page']}; color: {t['text']}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {t['select']}; color: {t['text']}; }}
QMenu {{ background: {t['card']}; color: {t['text']}; border: 1px solid {t['line']}; }}
QLabel {{ color: {t['text']}; }}

#Header {{ background: {t['header']}; }}
#Header QLabel {{ background: transparent; }}
#AppTitle {{ color: #FFFFFF; font-size: 19pt; font-weight: 700; }}
#AppTagline {{ color: {t['glow']}; font-size: 10pt; }}
#Header QPushButton, #Header QToolButton {{ background: transparent; color: {t['header_text']}; border: 1px solid {t['header_line']}; border-radius: 5px; padding: 6px 14px; }}
#Header QPushButton:hover, #Header QToolButton:hover {{ border-color: {t['glow']}; color: #FFFFFF; }}
#Header QToolButton::menu-indicator {{ image: none; }}
#Header QPushButton#Primary {{ background: {t['scan']}; border: 1px solid {t['scan']}; color: white; font-weight: 600; }}
#Header QPushButton#Primary:hover {{ background: {t['scan_dark']}; }}
#Header QPushButton#Alert {{ background: #B4470F; border-color: #B4470F; color: white; font-weight: 600; }}
#Header QComboBox {{ background: {t['header_input']}; color: white; border: 1px solid {t['header_line']}; border-radius: 5px; padding: 5px 10px; min-width: 140px; }}
#Header QComboBox QAbstractItemView {{ background: {t['card']}; color: {t['text']}; selection-background-color: {t['scan']}; }}

QPushButton {{ background: {t['card']}; color: {t['text']}; border: 1px solid {t['line']}; border-radius: 5px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {t['scan']}; }}
QPushButton:focus {{ border: 2px solid {t['scan']}; }}
QPushButton:disabled {{ color: {t['muted']}; }}
QPushButton#Primary {{ background: {t['scan']}; color: white; border: none; font-weight: 600; padding: 9px 20px; }}
QPushButton#Primary:hover {{ background: {t['scan_dark']}; }}
QPushButton#Link {{ background: transparent; border: none; color: {t['scan'] if CURRENT['dark'] else t['scan_dark']}; padding: 2px; text-decoration: underline; }}
QPushButton#Small {{ padding: 3px 10px; font-size: 9pt; }}

#DropZone {{ background: {t['card']}; border: 2px dashed {t['drop']}; border-radius: 18px; }}
#DropZone[dragging="true"] {{ border-color: {t['scan']}; background: {t['drop_hover']}; }}
#DropTitle {{ font-size: 17pt; font-weight: 600; }}
#DropHint {{ color: {t['muted']}; font-size: 10.5pt; }}

#GradePanel {{ background: {t['grade_panel']}; border-radius: 10px; }}
#GradePanel QLabel {{ background: transparent; color: #E3EDF4; }}
#GradeLetter {{ font-size: 44pt; font-weight: 700; }}
#GradeLabel {{ font-size: 13pt; font-weight: 600; color: white; }}
#GradeSub {{ color: {t['glow']}; }}

#StatCard {{ background: {t['card']}; border: 1px solid {t['line']}; border-radius: 8px; }}
#StatTitle {{ color: {t['muted']}; font-size: 9pt; }}
#StatValue {{ font-size: 17pt; font-weight: 700; }}
#StatSub {{ color: {t['muted']}; font-size: 9pt; }}

#FindingCard {{ background: {t['card']}; border: 1px solid {t['line']}; border-radius: 8px; }}
#FindingTitle {{ font-size: 12.5pt; font-weight: 600; }}
#FindingBody {{ color: {t['body']}; font-size: 10.5pt; }}
#FindingMeta, #Muted {{ color: {t['muted']}; font-size: 9pt; }}
#SectionTitle {{ font-size: 11pt; font-weight: 600; color: {t['muted']}; }}

QTabWidget::pane {{ border: 1px solid {t['line']}; background: {t['card']}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {t['muted']}; padding: 8px 16px; border: none; border-bottom: 3px solid transparent; font-weight: 600; }}
QTabBar::tab:selected {{ color: {t['text']}; border-bottom: 3px solid {t['scan']}; }}
QTabBar::tab:hover {{ color: {t['text']}; }}

QScrollArea {{ background: transparent; border: none; }}
#FindingsHost, #TabHost {{ background: {t['card']}; }}
QTableWidget {{ background: {t['card']}; color: {t['text']}; border: none; gridline-color: {t['grid']}; selection-background-color: {t['select']}; selection-color: {t['text']}; alternate-background-color: {t['alt']}; }}
QHeaderView::section {{ background: {t['head']}; color: {t['muted']}; border: none; border-bottom: 1px solid {t['line']}; padding: 7px 6px; font-weight: 600; }}
QTableCornerButton::section {{ background: {t['head']}; border: none; }}
QTextBrowser {{ background: {t['alt']}; border: none; border-top: 1px solid {t['line']}; padding: 10px; color: {t['text']}; }}
QLineEdit, QComboBox, QPlainTextEdit, QSpinBox {{ background: {t['card']}; border: 1px solid {t['line']}; border-radius: 5px; padding: 5px 8px; color: {t['text']}; }}
QComboBox QAbstractItemView {{ background: {t['card']}; color: {t['text']}; selection-background-color: {t['select']}; selection-color: {t['text']}; }}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QSpinBox:focus {{ border-color: {t['scan']}; }}
QGroupBox {{ color: {t['text']}; border: 1px solid {t['line']}; border-radius: 6px; margin-top: 10px; padding-top: 8px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; }}
QCheckBox, QRadioButton {{ color: {t['text']}; }}
#Banner {{ background: {t['banner']}; border: 1px solid {t['glow']}; border-radius: 5px; }}
#Banner QLabel {{ background: transparent; }}
QStatusBar {{ background: {t['card']}; color: {t['muted']}; border-top: 1px solid {t['line']}; }}
QProgressBar {{ border: 1px solid {t['line']}; border-radius: 4px; background: {t['card']}; text-align: center; height: 14px; color: {t['text']}; }}
QProgressBar::chunk {{ background: {t['scan']}; border-radius: 3px; }}
QSplitter::handle {{ background: {t['page']}; }}
"""


# Backwards compatibility for the Release Manager, which imports STYLESHEET.
STYLESHEET = stylesheet()


def apply(app, mode: str = "system") -> bool:
    """Apply the theme to the whole application. Returns True when dark."""
    dark = resolve(mode)
    set_theme(dark)
    app.setPalette(palette())
    app.setStyleSheet(stylesheet())
    return dark
