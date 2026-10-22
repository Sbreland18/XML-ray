"""Error log and diagnostics, so users can send useful details when something goes wrong."""
from __future__ import annotations

import logging
import logging.handlers
import platform
import sys
import threading
import traceback
import zipfile
from datetime import datetime
from pathlib import Path

from .__version__ import __version__
from .storage import default_path

log = logging.getLogger("xmlray")
_handlers = {"crash": None}


def log_dir() -> Path:
    d = default_path().parent / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def setup() -> None:
    handler = logging.handlers.RotatingFileHandler(log_dir() / "xmlray.log", maxBytes=1_000_000,
                                                   backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)
    log.info("XML-ray %s starting on %s, Python %s", __version__, platform.platform(),
             platform.python_version())

    def excepthook(etype, value, tb):
        text = "".join(traceback.format_exception(etype, value, tb))
        log.error("Unexpected error:\n%s", text)
        if _handlers["crash"]:
            try:
                _handlers["crash"](text)
            except Exception:  # noqa: BLE001
                pass

    sys.excepthook = excepthook
    threading.excepthook = lambda args: log.error(
        "Error in background thread:\n%s",
        "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))


def on_crash(callback) -> None:
    """callback(details_text) is called (on the GUI thread) for unexpected errors."""
    _handlers["crash"] = callback


def about_text(extra: dict | None = None) -> str:
    lines = [f"XML-ray {__version__}", f"Windows/OS: {platform.platform()}",
             f"Python: {platform.python_version()}", f"Frozen: {getattr(sys, 'frozen', False)}",
             f"Created: {datetime.now():%Y-%m-%d %H:%M}"]
    try:
        import PySide6
        lines.append(f"PySide6: {PySide6.__version__}")
    except ImportError:
        pass
    for k, v in (extra or {}).items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


def diagnostics_zip(path: str, extra: dict | None = None, settings: dict | None = None) -> str:
    """Zip the logs, system details and (non-secret) settings. Returns the path."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("about.txt", about_text(extra))
        if settings:
            safe = {k: v for k, v in settings.items()
                    if not any(w in k.lower() for w in ("password", "token", "secret"))}
            z.writestr("settings.txt", "\n".join(f"{k} = {v}" for k, v in sorted(safe.items())))
        for f in sorted(log_dir().glob("xmlray.log*")):
            z.write(f, f"logs/{f.name}")
    return path
