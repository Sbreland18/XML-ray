"""Application entry point."""
import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from .__version__ import __version__
from .config import APP_NAME, ORG_NAME, asset
from .ui.main_window import MainWindow
from .ui.style import STYLESHEET, light_palette


def main() -> None:
    if sys.platform == "win32":
        # Give XML-ray its own taskbar identity (and icon) instead of python.exe's.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{ORG_NAME}.{APP_NAME}")
        except Exception:  # noqa: BLE001
            pass

    QApplication.setApplicationName(APP_NAME)
    QApplication.setOrganizationName(ORG_NAME)
    QApplication.setApplicationVersion(__version__)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setPalette(light_palette())
    app.setStyleSheet(STYLESHEET)
    app.setWindowIcon(QIcon(asset("icon.ico") if sys.platform == "win32" else asset("icon.png")))

    window = MainWindow()
    window.show()
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    if files:  # e.g. files dropped onto the XML-ray shortcut
        window.load(files)
    sys.exit(app.exec())
