"""Visual identity: a radiology lightbox. Pale film-viewer background, deep slate-blue
chrome, and one cyan "scan" accent. Severity colours are reserved for findings."""
from PySide6.QtGui import QColor, QPalette

INK = "#17324A"        # deep slate blue: header, primary text
MUTED = "#5B7083"
LIGHTBOX = "#EEF3F6"   # page background
FILM = "#FFFFFF"       # cards and tables
LINE = "#D5DFE6"
SCAN = "#1D8FB0"       # the single accent
SCAN_DARK = "#16748F"
SCAN_GLOW = "#9ED8E6"

SEVERITY = {  # label, foreground, background
    "critical": ("Critical", "#9F1D1D", "#FDE8E8"),
    "high": ("High", "#B4470F", "#FDEEDC"),
    "medium": ("Medium", "#8A6100", "#FDF4D6"),
    "low": ("Low", "#1F5D8C", "#E3EFF8"),
    "good": ("Good", "#1E6B43", "#E1F3E8"),
}

CATEGORY_COLORS = {
    "authorized": "#1E6B43",
    "partial": "#8A6100",
    "service_failing": "#B4470F",
    "unknown": "#9F1D1D",
    "forwarded": "#5B7083",
}

GRADE_COLORS = {"A": "#1E6B43", "B": "#3C7A2E", "C": "#8A6100", "D": "#B4470F", "F": "#9F1D1D"}


def light_palette() -> QPalette:
    """Pin a light palette so Windows dark mode can't make text unreadable."""
    p = QPalette()
    roles = {
        QPalette.Window: LIGHTBOX, QPalette.WindowText: INK, QPalette.Base: FILM,
        QPalette.AlternateBase: "#F6F9FB", QPalette.Text: INK, QPalette.Button: FILM,
        QPalette.ButtonText: INK, QPalette.Highlight: SCAN, QPalette.HighlightedText: "#FFFFFF",
        QPalette.ToolTipBase: INK, QPalette.ToolTipText: "#FFFFFF",
        QPalette.PlaceholderText: MUTED, QPalette.Link: SCAN_DARK,
    }
    for role, color in roles.items():
        p.setColor(role, QColor(color))
    return p


STYLESHEET = f"""
* {{ font-family: "Segoe UI Variable Text", "Segoe UI", "Helvetica Neue", Arial, sans-serif; font-size: 10pt; }}
QMainWindow, #Page {{ background: {LIGHTBOX}; }}
QToolTip {{ background: {INK}; color: white; border: none; padding: 6px; }}

#Header {{ background: {INK}; }}
#Header QLabel {{ background: transparent; }}
#AppTitle {{ color: #FFFFFF; font-size: 19pt; font-weight: 700; }}
#AppTagline {{ color: {SCAN_GLOW}; font-size: 10pt; }}
#Header QPushButton {{ background: transparent; color: #E3EDF4; border: 1px solid #3D5B75; border-radius: 5px; padding: 6px 14px; }}
#Header QPushButton:hover {{ border-color: {SCAN_GLOW}; color: #FFFFFF; }}
#Header QPushButton#Primary {{ background: {SCAN}; border: 1px solid {SCAN}; color: white; font-weight: 600; }}
#Header QPushButton#Primary:hover {{ background: {SCAN_DARK}; }}
#Header QComboBox {{ background: #23445F; color: white; border: 1px solid #3D5B75; border-radius: 5px; padding: 5px 10px; min-width: 170px; }}
#Header QComboBox QAbstractItemView {{ background: white; color: {INK}; selection-background-color: {SCAN}; }}

QPushButton {{ background: {FILM}; color: {INK}; border: 1px solid {LINE}; border-radius: 5px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {SCAN}; }}
QPushButton:focus {{ border: 2px solid {SCAN}; }}
QPushButton#Primary {{ background: {SCAN}; color: white; border: none; font-weight: 600; padding: 9px 20px; }}
QPushButton#Primary:hover {{ background: {SCAN_DARK}; }}
QPushButton#Link {{ background: transparent; border: none; color: {SCAN_DARK}; padding: 2px; text-decoration: underline; }}

#DropZone {{ background: {FILM}; border: 2px dashed #9FB4C4; border-radius: 18px; }}
#DropZone[dragging="true"] {{ border-color: {SCAN}; background: #E6F5F9; }}
#DropTitle {{ font-size: 17pt; font-weight: 600; color: {INK}; }}
#DropHint {{ color: {MUTED}; font-size: 10.5pt; }}

#GradePanel {{ background: {INK}; border-radius: 10px; }}
#GradePanel QLabel {{ background: transparent; color: #E3EDF4; }}
#GradeLetter {{ font-size: 44pt; font-weight: 700; }}
#GradeLabel {{ font-size: 13pt; font-weight: 600; color: white; }}
#GradeSub {{ color: {SCAN_GLOW}; }}

#StatCard {{ background: {FILM}; border: 1px solid {LINE}; border-radius: 8px; }}
#StatTitle {{ color: {MUTED}; font-size: 9pt; }}
#StatValue {{ color: {INK}; font-size: 17pt; font-weight: 700; }}
#StatSub {{ color: {MUTED}; font-size: 9pt; }}

#FindingCard {{ background: {FILM}; border: 1px solid {LINE}; border-radius: 8px; }}
#FindingTitle {{ font-size: 12.5pt; font-weight: 600; color: {INK}; }}
#FindingBody {{ color: #2A4459; font-size: 10.5pt; }}
#FindingMeta {{ color: {MUTED}; font-size: 9pt; }}

QTabWidget::pane {{ border: 1px solid {LINE}; background: {FILM}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 8px 18px; border: none; border-bottom: 3px solid transparent; font-weight: 600; }}
QTabBar::tab:selected {{ color: {INK}; border-bottom: 3px solid {SCAN}; }}
QTabBar::tab:hover {{ color: {INK}; }}

QScrollArea {{ background: transparent; border: none; }}
#FindingsHost {{ background: {FILM}; }}
QTableWidget {{ background: {FILM}; border: none; gridline-color: #EDF2F5; selection-background-color: #D6EEF5; selection-color: {INK}; alternate-background-color: #F6F9FB; }}
QHeaderView::section {{ background: #F3F7F9; color: {MUTED}; border: none; border-bottom: 1px solid {LINE}; padding: 7px 6px; font-weight: 600; }}
QTextBrowser {{ background: #F6F9FB; border: none; border-top: 1px solid {LINE}; padding: 10px; color: {INK}; }}
QLineEdit, QComboBox, QPlainTextEdit {{ background: {FILM}; border: 1px solid {LINE}; border-radius: 5px; padding: 5px 8px; color: {INK}; }}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{ border-color: {SCAN}; }}
#Banner {{ background: #E6F5F9; border: 1px solid {SCAN_GLOW}; border-radius: 5px; }}
#Banner QLabel {{ background: transparent; }}
QStatusBar {{ background: {FILM}; color: {MUTED}; border-top: 1px solid {LINE}; }}
QProgressBar {{ border: 1px solid {LINE}; border-radius: 4px; background: {FILM}; text-align: center; height: 14px; }}
QProgressBar::chunk {{ background: {SCAN}; border-radius: 3px; }}
"""
