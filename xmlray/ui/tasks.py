"""Run work in the background without freezing the window."""
from PySide6.QtCore import QThread, Signal


class Task(QThread):
    """Run fn(*args, **kwargs) in the background. Emits done(result, error_text)."""
    done = Signal(object, str)
    progress = Signal(int, int)

    def __init__(self, fn, *args, with_progress: bool = False, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        if with_progress:
            self.kwargs["progress"] = self.progress.emit

    def run(self):
        import logging
        try:
            self.done.emit(self.fn(*self.args, **self.kwargs), "")
        except Exception as exc:  # noqa: BLE001
            log = logging.getLogger("xmlray")
            if isinstance(exc, _expected()):
                log.warning("%s: %s", getattr(self.fn, "__name__", "task"), exc)
            else:
                log.exception("Background task failed: %s", self.fn)
            self.done.emit(None, str(exc) or exc.__class__.__name__)


def _expected() -> tuple:
    """Errors that are normal situations (offline, wrong password), not bugs."""
    from ..dnscheck import DnsError
    from ..mailimport import MailboxError
    from ..mailsend import SendError
    from ..updater import UpdateError
    return (DnsError, MailboxError, SendError, UpdateError, OSError)


_running: list = []


def start(task: Task, callback) -> Task:
    """Start *task* and call callback(result, error) on the GUI thread when it finishes."""
    _running.append(task)
    task.done.connect(callback)
    task.finished.connect(lambda: _running.remove(task) if task in _running else None)
    task.start()
    return task
