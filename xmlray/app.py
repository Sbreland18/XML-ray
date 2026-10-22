"""Application entry point."""
import sys

from PySide6.QtCore import QSettings, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from . import logs
from .__version__ import __version__
from .config import APP_NAME, ORG_NAME, asset
from .ui import style
from .ui.main_window import MainWindow

_windows: list = []


def open_window(start_hidden: bool = False, files=None) -> MainWindow:
    """Open the main window for the active organization. Switching organization closes the
    current window and calls this again."""
    window = MainWindow(start_hidden=start_hidden)
    window.reopen.connect(lambda: QTimer.singleShot(0, open_window))
    _windows[:] = [window]
    if files:
        window.load(files)
    return window


def main() -> None:
    if sys.platform == "win32":
        # Give XML-ray its own taskbar identity (and icon) instead of python.exe's.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{ORG_NAME}.{APP_NAME}")
        except Exception:  # noqa: BLE001
            pass

    logs.setup()
    QApplication.setApplicationName(APP_NAME)
    QApplication.setOrganizationName(ORG_NAME)
    QApplication.setApplicationVersion(__version__)
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)      # the window may hide to the tray
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(asset("icon.ico") if sys.platform == "win32" else asset("icon.png")))
    settings = QSettings(ORG_NAME, APP_NAME)
    style.apply(app, settings.value("appearance/theme", "system"))

    minimized = "--minimized" in sys.argv
    hide = minimized and settings.value("tray/enabled", False, type=bool)
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    window = open_window(start_hidden=hide, files=files)
    if minimized and not hide:
        window.showMinimized()
    sys.exit(app.exec())
