"""The XML-ray main window."""
from __future__ import annotations

import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import QFileSystemWatcher, QSettings, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QColor, QDesktopServices, QGuiApplication, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QProgressBar,
    QProgressDialog, QPushButton, QScrollArea, QSplitter, QStackedWidget, QSystemTrayIcon,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from .. import alerts as alerts_mod
from .. import dnscheck, mailimport, rdap, updater
from ..__version__ import __version__
from ..analyzer import SEVERITY_ORDER, Analysis, SourceSummary, analyze, daily_series
from ..config import APP_NAME, GITHUB_URL, ORG_NAME, TAGLINE, asset
from ..export import html_summary, print_html, senders_csv
from ..parser import LoadResult, dedupe, load_all, load_bytes
from ..senders import reverse_lookup
from ..storage import Storage
from ..tlsrpt import FAILURE_TYPES, analyze_tls, dedupe_tls, label_for
from . import style
from .charts import TrendChart
from .dialogs import (AlertsDialog, GlossaryDialog, RecordBuilderDialog, SettingsDialog,
                      UpdateDialog, mailbox_config)
from .style import CATEGORY_COLORS, GRADE_COLORS, SEVERITY, T
from .widgets import DropZone, FindingCard, GradePanel, NumericItem, StatCard

FILE_FILTER = "DMARC and TLS reports (*.xml *.gz *.gzip *.zip *.eml *.json);;All files (*)"
MAX_RDNS = 2000
MAX_RDAP = 300
STATUS_RANK = {"service_failing": 0, "unknown": 1, "partial": 2, "forwarded": 3,
               "authorized": 4, "ignored": 5}
PERIODS = [("Latest 7 days", 7), ("Latest 30 days", 30), ("Latest 90 days", 90),
           ("Latest 12 months", 365), ("All time", 0)]
RECORD_STATUS = {"ok": ("Good", "good"), "warn": ("Check", "medium"), "bad": ("Problem", "high"),
                 "missing": ("Missing", "high"), "info": ("Info", "low")}


class Task(QThread):
    """Run a function in the background. done(result, error_text)."""
    done = Signal(object, str)
    progress = Signal(int, int)

    def __init__(self, fn, *args, with_progress: bool = False, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        if with_progress:
            self.kwargs["progress"] = self.progress.emit

    def run(self):
        try:
            self.done.emit(self.fn(*self.args, **self.kwargs), "")
        except Exception as exc:  # noqa: BLE001
            self.done.emit(None, str(exc) or exc.__class__.__name__)


# ---------------------------------------------------------- background jobs

def _load_history(storage: Storage) -> LoadResult:
    result = LoadResult()
    for _kind, raw, source in storage.iter_raw():
        load_bytes(raw, source or "saved report", result)
    result.dmarc, result.tls = dedupe(result.dmarc), dedupe_tls(result.tls)
    return result


def _reverse_all(ips: list[str], progress=None) -> dict[str, str]:
    out = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(reverse_lookup, ip): ip for ip in ips}
        for i, fut in enumerate(as_completed(futures), 1):
            out[futures[fut]] = fut.result() or ""
            if progress:
                progress(i, len(ips))
    return out


def _rdap_all(ips: list[str], storage: Storage, progress=None) -> dict[str, dict]:
    out = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(rdap.lookup, ip): ip for ip in ips}
        for i, fut in enumerate(as_completed(futures), 1):
            info = fut.result()
            if info:
                out[futures[fut]] = info
            if progress:
                progress(i, len(ips))
    storage.rdap_put(out)
    return out


def _dns_all(jobs: list[tuple[str, str | None, set]]) -> dict:
    resolver = dnscheck.DohResolver()
    return {d: dnscheck.check_domain(d, resolver, p, sels) for d, p, sels in jobs}


def _download(info, progress=None, cancelled=None):
    return updater.download_installer(info, progress, cancelled)


# ================================================================== window

class MainWindow(QMainWindow):
    SENDER_COLUMNS = ["Status", "Sender", "IP address", "Network owner", "Messages", "Passed",
                      "SPF aligned", "DKIM aligned", "What happened", "Last seen",
                      "What this means"]
    REPORT_COLUMNS = ["Type", "Reported by", "Domain", "From", "To", "Messages", "Passed",
                      "Policy", "File"]

    def __init__(self, start_hidden: bool = False):
        super().__init__()
        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.storage = Storage()
        self.reports: list = []
        self.tls_reports: list = []
        self.hostnames: dict[str, str] = {}
        self.owners: dict[str, dict] = self.storage.rdap_get()
        self.labels = self.storage.labels()
        self.acks = self.storage.acks()
        self.dns_results: dict = {}
        self.analysis: Analysis | None = None
        self.tls_analysis = None
        self.findings: list = []
        self.ip_filter: set[str] | None = None
        self.sample_mode = False
        self._threads: list[QThread] = []
        self._busy_count = 0
        self._sender_sorted = False
        self._really_quit = False
        self._tray_hint_shown = False
        self._rdap_done: set[str] = set()
        self._mail_running = self._folder_running = False

        self.setWindowTitle(f"{APP_NAME}: {TAGLINE}")
        self.resize(1280, 840)
        self.setMinimumSize(980, 640)
        self.setAcceptDrops(True)

        root = QWidget(objectName="Page")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_empty_page())
        self.stack.addWidget(self._build_loading_page())
        self.stack.addWidget(self._build_dashboard())
        outer.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self._build_menus()
        self.busy = QProgressBar()
        self.busy.setMaximumWidth(160)
        self.busy.setVisible(False)
        self.statusBar().addPermanentWidget(self.busy)
        self.statusBar().showMessage(f"Version {__version__}")
        self._build_tray()

        self.mail_timer = QTimer(self)
        self.mail_timer.timeout.connect(lambda: self.check_mailbox(manual=False))
        self.folder_timer = QTimer(self)
        self.folder_timer.timeout.connect(self.scan_watched_folder)
        self.folder_debounce = QTimer(self, singleShot=True, interval=3000)
        self.folder_debounce.timeout.connect(self.scan_watched_folder)
        self.watcher = QFileSystemWatcher(self)
        self.watcher.directoryChanged.connect(lambda _p: self.folder_debounce.start())
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(self._system_theme_changed)
        except AttributeError:
            pass

        self.stack.setCurrentIndex(1)
        self._update_header()
        self._load_history()
        self._apply_automation()
        if self._setting("updates/check_on_startup", True, bool):
            QTimer.singleShot(4000, lambda: self.check_updates(silent=True))
        if not start_hidden:
            self.show()

    def _setting(self, key, default, typ=str):
        return self.settings.value(key, default, type=typ)

    # ----------------------------------------------------------------- layout

    def _build_header(self) -> QWidget:
        header = QFrame(objectName="Header")
        lay = QHBoxLayout(header)
        lay.setContentsMargins(20, 12, 20, 12)
        lay.setSpacing(10)
        logo = QLabel()
        pm = QPixmap(asset("icon.png"))
        if not pm.isNull():
            logo.setPixmap(pm.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        lay.addWidget(logo)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(QLabel(APP_NAME, objectName="AppTitle"))
        titles.addWidget(QLabel(TAGLINE, objectName="AppTagline"))
        lay.addLayout(titles)
        lay.addStretch(1)

        self.domain_combo = QComboBox()
        self.domain_combo.setToolTip("Choose which domain to look at")
        self.domain_combo.currentIndexChanged.connect(lambda _: self.refresh())
        lay.addWidget(self.domain_combo)
        self.period_combo = QComboBox()
        self.period_combo.setToolTip("Which reports to include, counted back from the newest one")
        for label, days in PERIODS:
            self.period_combo.addItem(label, days)
        self.period_combo.setCurrentIndex(
            max(self.period_combo.findData(self._setting("view/period", 30, int)), 0))
        self.period_combo.currentIndexChanged.connect(self._period_changed)
        lay.addWidget(self.period_combo)

        self.add_btn = QPushButton("Add reports", objectName="Primary")
        self.add_btn.setCursor(Qt.PointingHandCursor)
        add_menu = QMenu(self)
        add_menu.addAction("Choose files…", self.open_files)
        add_menu.addAction("Choose a folder…", self.open_folder)
        add_menu.addAction("Check my mailbox now", lambda: self.check_mailbox(manual=True))
        self.add_btn.setMenu(add_menu)
        lay.addWidget(self.add_btn)

        self.export_btn = QPushButton("Export")
        self.export_btn.setCursor(Qt.PointingHandCursor)
        exp = QMenu(self)
        exp.addAction("Summary as a web page…", self.export_html)
        exp.addAction("Summary as a PDF…", self.export_pdf)
        exp.addAction("Senders as a spreadsheet (CSV)…", self.export_csv)
        self.export_btn.setMenu(exp)
        lay.addWidget(self.export_btn)

        self.alert_btn = QPushButton("Alerts")
        self.alert_btn.setCursor(Qt.PointingHandCursor)
        self.alert_btn.clicked.connect(self.show_alerts)
        lay.addWidget(self.alert_btn)
        return header

    def _build_empty_page(self) -> QWidget:
        page = QWidget(objectName="Page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(40, 40, 40, 40)
        lay.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.drop_zone = DropZone(asset("icon.png"))
        self.drop_zone.open_files.connect(self.open_files)
        self.drop_zone.open_folder.connect(self.open_folder)
        self.drop_zone.open_settings.connect(lambda: self.show_settings(tab=1))
        self.drop_zone.load_sample.connect(self.load_sample)
        self.drop_zone.learn_more.connect(self.show_glossary)
        row.addWidget(self.drop_zone, 3)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(2)
        return page

    def _build_loading_page(self) -> QWidget:
        page = QWidget(objectName="Page")
        lay = QVBoxLayout(page)
        lab = QLabel("Opening your saved reports…", objectName="SectionTitle")
        lab.setAlignment(Qt.AlignCenter)
        lay.addWidget(lab)
        return page

    def _build_dashboard(self) -> QWidget:
        page = QWidget(objectName="Page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(20, 16, 20, 12)
        lay.setSpacing(12)

        self.sample_banner = QFrame(objectName="Banner")
        sb = QHBoxLayout(self.sample_banner)
        sb.setContentsMargins(12, 6, 6, 6)
        sb.addWidget(QLabel("You're looking at sample reports for example.com. They aren't "
                            "saved. Add your own reports to replace them."), 1)
        rm = QPushButton("Remove sample reports")
        rm.clicked.connect(self.clear_sample)
        sb.addWidget(rm)
        self.sample_banner.setVisible(False)
        lay.addWidget(self.sample_banner)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.grade = GradePanel()
        stats.addWidget(self.grade, 3)
        self.card_messages = StatCard("Messages checked")
        self.card_passed = StatCard("Passed DMARC")
        self.card_failed = StatCard("Failed DMARC")
        self.card_policy = StatCard("Your policy")
        self.card_period = StatCard("Report period")
        for c in (self.card_messages, self.card_passed, self.card_failed, self.card_policy,
                  self.card_period):
            stats.addWidget(c, 2)
        lay.addLayout(stats)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(), "Action plan")
        self.tabs.addTab(self._build_senders_tab(), "Senders")
        self.tabs.addTab(self._build_trends_tab(), "Trends")
        self.tabs.addTab(self._build_dns_tab(), "DNS check")
        self.tabs.addTab(self._build_tls_tab(), "TLS")
        self.tabs.addTab(self._build_reports_tab(), "Reports")
        lay.addWidget(self.tabs, 1)
        return page

    def _scroll_host(self) -> tuple[QScrollArea, QVBoxLayout]:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        host = QWidget(objectName="FindingsHost")
        layout = QVBoxLayout(host)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        scroll.setWidget(host)
        return scroll, layout

    def _build_findings_tab(self) -> QWidget:
        scroll, self.findings_layout = self._scroll_host()
        return scroll

    def _build_senders_tab(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 0)
        lay.setSpacing(8)
        bar = QHBoxLayout()
        self.sender_filter = QComboBox()
        for label, key in (("All senders", "all"), ("Failing only", "failing"),
                           ("Passing only", "passing"), ("Unknown or suspicious", "unknown"),
                           ("Ignored", "ignored")):
            self.sender_filter.addItem(label, key)
        self.sender_filter.currentIndexChanged.connect(lambda _: self.fill_senders())
        self.sender_search = QLineEdit()
        self.sender_search.setPlaceholderText("Search by name, IP address, owner or domain")
        self.sender_search.setClearButtonEnabled(True)
        self.sender_search.textChanged.connect(lambda _: self.fill_senders())
        bar.addWidget(self.sender_filter)
        bar.addWidget(self.sender_search, 1)
        lay.addLayout(bar)

        self.banner = QFrame(objectName="Banner")
        b = QHBoxLayout(self.banner)
        b.setContentsMargins(12, 6, 6, 6)
        self.banner_label = QLabel()
        b.addWidget(self.banner_label, 1)
        show_all = QPushButton("Show all senders")
        show_all.clicked.connect(self.clear_ip_filter)
        b.addWidget(show_all)
        self.banner.setVisible(False)
        lay.addWidget(self.banner)

        split = QSplitter(Qt.Vertical)
        self.sender_table = self._make_table(self.SENDER_COLUMNS)
        self.sender_table.itemSelectionChanged.connect(self.show_sender_detail)
        split.addWidget(self.sender_table)
        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(0)
        actions = QHBoxLayout()
        actions.setContentsMargins(0, 6, 0, 6)
        self.btn_name = QPushButton("Name this sender…")
        self.btn_mine = QPushButton("This is one of mine")
        self.btn_ignore = QPushButton("Ignore this sender")
        self.btn_reset = QPushButton("Clear my label")
        self.btn_trend = QPushButton("Show its trend")
        self.btn_name.clicked.connect(self.name_sender)
        self.btn_mine.clicked.connect(lambda: self.set_sender_status("mine"))
        self.btn_ignore.clicked.connect(lambda: self.set_sender_status("ignore"))
        self.btn_reset.clicked.connect(self.reset_sender)
        self.btn_trend.clicked.connect(self.trend_for_selected)
        self.btn_mine.setToolTip("Tell XML-ray this server belongs to you, such as a copier, "
                                 "website or billing system. It stops being treated as possible "
                                 "spoofing, and you get steps to make it pass.")
        self.btn_ignore.setToolTip("Leave this sender out of the action plan and alerts.")
        for btn in (self.btn_name, self.btn_mine, self.btn_ignore, self.btn_reset):
            actions.addWidget(btn)
        actions.addStretch(1)
        actions.addWidget(self.btn_trend)
        dl.addLayout(actions)
        self.sender_detail = QTextBrowser()
        self.sender_detail.setOpenExternalLinks(True)
        dl.addWidget(self.sender_detail, 1)
        split.addWidget(detail)
        split.setSizes([460, 260])
        lay.addWidget(split, 1)
        self._sender_buttons(False)
        return w

    def _build_trends_tab(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 12)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Show"))
        self.trend_combo = QComboBox()
        self.trend_combo.setMinimumWidth(320)
        self.trend_combo.currentIndexChanged.connect(lambda _: self.fill_trends())
        bar.addWidget(self.trend_combo)
        bar.addStretch(1)
        lay.addLayout(bar)
        self.trend_summary = QLabel()
        self.trend_summary.setWordWrap(True)
        self.trend_summary.setObjectName("FindingBody")
        lay.addWidget(self.trend_summary)
        self.chart = TrendChart()
        lay.addWidget(self.chart, 1)
        return w

    def _build_dns_tab(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 12)
        bar = QHBoxLayout()
        self.dns_label = QLabel("Your domain's records haven't been checked yet.")
        self.dns_label.setWordWrap(True)
        bar.addWidget(self.dns_label, 1)
        self.dns_btn = QPushButton("Check DNS now")
        self.dns_btn.clicked.connect(lambda: self.check_dns(force=True))
        bar.addWidget(self.dns_btn)
        builder = QPushButton("DMARC record builder")
        builder.clicked.connect(lambda: self.open_record_builder(""))
        bar.addWidget(builder)
        lay.addLayout(bar)
        lay.addWidget(QLabel("Problems found here also appear in the action plan.",
                             objectName="Muted"))
        self.dns_table = self._make_table(["Domain", "Record", "Status", "Name", "Value", "Notes"])
        self.dns_table.setWordWrap(True)
        lay.addWidget(self.dns_table, 1)
        return w

    def _build_tls_tab(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 12, 16, 12)
        self.tls_intro = QLabel()
        self.tls_intro.setWordWrap(True)
        self.tls_intro.setObjectName("FindingBody")
        self.tls_intro.setTextFormat(Qt.RichText)
        lay.addWidget(self.tls_intro)
        row = QHBoxLayout()
        self.tls_total = StatCard("Connections reported")
        self.tls_ok = StatCard("Encrypted successfully")
        self.tls_fail = StatCard("Failed")
        for c in (self.tls_total, self.tls_ok, self.tls_fail):
            row.addWidget(c)
        lay.addLayout(row)
        self.tls_table = self._make_table(["Problem", "Attempts", "What it means"])
        self.tls_table.setWordWrap(True)
        lay.addWidget(self.tls_table, 1)
        return w

    def _build_reports_tab(self) -> QWidget:
        self.report_table = self._make_table(self.REPORT_COLUMNS)
        return self.report_table

    def _make_table(self, columns: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(columns))
        t.setHorizontalHeaderLabels(columns)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.SingleSelection)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setWordWrap(False)
        h = t.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setStretchLastSection(True)
        return t

    def _build_menus(self) -> None:
        mb = self.menuBar()
        f = mb.addMenu("&File")
        self._action(f, "Open reports…", self.open_files, QKeySequence.Open)
        self._action(f, "Open a folder…", self.open_folder, "Ctrl+Shift+O")
        self._action(f, "Check my mailbox now", lambda: self.check_mailbox(manual=True), "F5")
        f.addSeparator()
        self._action(f, "Export summary (web page)…", self.export_html, "Ctrl+E")
        self._action(f, "Export summary (PDF)…", self.export_pdf, "Ctrl+P")
        self._action(f, "Export senders (CSV)…", self.export_csv)
        f.addSeparator()
        self._action(f, "Delete all saved reports…", self.delete_history)
        self._action(f, "Exit", self.quit_app, QKeySequence.Quit)

        t = mb.addMenu("&Tools")
        self._action(t, "DMARC record builder…", lambda: self.open_record_builder(""), "Ctrl+B")
        self._action(t, "Check DNS now", lambda: self.check_dns(force=True))
        self._action(t, "Alerts…", self.show_alerts)
        t.addSeparator()
        self._action(t, "Settings…", self.show_settings, "Ctrl+,")

        h = mb.addMenu("&Help")
        self._action(h, "DMARC basics", self.show_glossary, QKeySequence.HelpContents)
        self._action(h, "Check for updates", lambda: self.check_updates(silent=False))
        self._action(h, "XML-ray on GitHub", lambda: QDesktopServices.openUrl(QUrl(GITHUB_URL)))
        h.addSeparator()
        self._action(h, f"About {APP_NAME}", self.show_about)

    def _action(self, menu, text, slot, shortcut=None) -> QAction:
        act = QAction(text, self)
        if shortcut:
            act.setShortcut(QKeySequence(shortcut))
        act.triggered.connect(slot)
        menu.addAction(act)
        return act

    def _build_tray(self) -> None:
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(QIcon(asset("icon.png")), self)
        self.tray.setToolTip(f"{APP_NAME}: {TAGLINE}")
        menu = QMenu()
        menu.addAction("Open XML-ray", self.bring_to_front)
        menu.addAction("Check my mailbox now", lambda: self.check_mailbox(manual=True))
        menu.addSeparator()
        menu.addAction("Quit XML-ray", self.quit_app)
        self.tray.setContextMenu(menu)
        self._tray_menu = menu
        self.tray.activated.connect(
            lambda reason: self.bring_to_front() if reason in (
                QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.messageClicked.connect(self.show_alerts)

    def _update_tray_visibility(self) -> None:
        if self.tray:
            self.tray.setVisible(self._setting("tray/enabled", False, bool)
                                 or self._setting("alerts/notify", True, bool))

    def _update_header(self) -> None:
        has = bool(self.reports or self.tls_reports)
        for w in (self.domain_combo, self.period_combo, self.export_btn):
            w.setVisible(has)
        unread = self.storage.unread_alerts()
        self.alert_btn.setText(f"Alerts ({unread})" if unread else "Alerts")
        self.alert_btn.setObjectName("Alert" if unread else "")
        self.alert_btn.style().unpolish(self.alert_btn)
        self.alert_btn.style().polish(self.alert_btn)

    def _show_page(self) -> None:
        self.stack.setCurrentIndex(2 if (self.reports or self.tls_reports) else 0)
        self.sample_banner.setVisible(self.sample_mode)
        self._update_header()

    # ------------------------------------------------------------ automation

    def _apply_automation(self) -> None:
        """(Re)start timers and watchers from the current settings."""
        self._update_tray_visibility()
        self.mail_timer.stop()
        if self._setting("mail/enabled", False, bool):
            self.mail_timer.start(max(5, self._setting("mail/interval_min", 60, int)) * 60_000)
            QTimer.singleShot(6000, lambda: self.check_mailbox(manual=False))
        for p in self.watcher.directories():
            self.watcher.removePath(p)
        self.folder_timer.stop()
        path = self._setting("folder/path", "")
        if self._setting("folder/enabled", False, bool) and path and Path(path).is_dir():
            self.watcher.addPath(path)
            self.folder_timer.start(10 * 60_000)
            QTimer.singleShot(2500, self.scan_watched_folder)

    # ---------------------------------------------------------------- loading

    def _load_history(self) -> None:
        days = self._setting("history/retention_days", 0, int)
        if days:
            self.storage.delete_older_than(days)
        self._run(Task(_load_history, self.storage), self._history_loaded,
                  "Opening saved reports…")

    def _history_loaded(self, result: LoadResult | None, err: str) -> None:
        if err:
            QMessageBox.warning(self, "Couldn't open saved reports", err)
            result = LoadResult()
        self.reports, self.tls_reports = result.dmarc, result.tls
        self._after_change(lookups=True)

    def _last_dir(self) -> str:
        return self.settings.value("paths/last_dir", str(Path.home()))

    def open_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Open DMARC or TLS reports",
                                                self._last_dir(), FILE_FILTER)
        if files:
            self.settings.setValue("paths/last_dir", str(Path(files[0]).parent))
            self.load(files)

    def open_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Open a folder of reports",
                                                  self._last_dir())
        if folder:
            self.settings.setValue("paths/last_dir", folder)
            self.load([folder])

    def load(self, paths) -> None:
        self._run(Task(load_all, list(paths)),
                  lambda r, e: self._ingest(r, e, "files", announce=True), "Reading reports…")

    def load_sample(self) -> None:
        def done(result, err):
            if result:
                self.sample_mode = True
                self.reports, self.tls_reports = result.dmarc, result.tls
                self.period_combo.setCurrentIndex(self.period_combo.findData(0))
                self.hostnames.update({"209.85.220.41": "mail-sor-f41.google.com",
                                       "167.89.12.34": "o1.ptr1234.sendgrid.net",
                                       "198.51.100.23": "web01.example.com",
                                       "40.107.22.91": "mail-db8eur05.outbound.protection.outlook.com"})
                self._after_change(lookups=False)
                self.dns_label.setText("Sample data uses example.com, so the live DNS check is "
                                       "turned off while samples are shown.")
        self._run(Task(load_all, [asset("sample_reports.zip")]), done, "Opening samples…")

    def clear_sample(self) -> None:
        self.sample_mode = False
        self.reports, self.tls_reports, self.dns_results = [], [], {}
        self._after_change(lookups=False)

    def _ingest(self, result: LoadResult | None, err: str, origin: str,
                announce: bool = False) -> None:
        """Add newly read reports: save them, raise alerts, refresh the screen."""
        if err or result is None:
            if announce:
                QMessageBox.warning(self, "Couldn't read reports", err)
            return
        if self.sample_mode:
            self.clear_sample()
        new_d, new_t = self.storage.add_reports(result.dmarc, result.tls)
        history = list(self.reports)
        self.reports = dedupe(self.reports + new_d)
        self.tls_reports = dedupe_tls(self.tls_reports + new_t)

        if new_d and self._setting("alerts/enabled", True, bool):
            found = alerts_mod.find_alerts(history, new_d, self.hostnames, self.labels)
            if found:
                self.storage.add_alerts(found)
                if self.tray and self.tray.isVisible() and self._setting("alerts/notify", True, bool):
                    first = found[0]
                    more = f" (and {len(found) - 1} more)" if len(found) > 1 else ""
                    self.tray.showMessage(f"XML-ray: {first.title}", first.body + more,
                                          QSystemTrayIcon.Warning, 15000)

        if announce:
            if result.errors:
                box = QMessageBox(self)
                box.setIcon(QMessageBox.Warning)
                box.setWindowTitle("Some files were skipped")
                box.setText(f"{len(result.errors)} file{'s' if len(result.errors) != 1 else ''} "
                            "couldn't be read as DMARC or TLS reports. Everything else was loaded.")
                box.setDetailedText("\n".join(result.errors[:200]))
                box.exec()
            elif not result.dmarc and not result.tls:
                QMessageBox.information(self, "No reports found",
                                        "No report files were found there. XML-ray looks for "
                                        ".xml, .gz, .zip, .json and .eml files.")
        n_new = len(new_d) + len(new_t)
        n_dup = len(result.dmarc) + len(result.tls) - n_new
        where = {"files": "", "mailbox": " from your mailbox", "folder": " from your watched folder"}[origin]
        msg = f"Added {n_new} new report{'s' if n_new != 1 else ''}{where}."
        if n_dup:
            msg += f" {n_dup} {'was' if n_dup == 1 else 'were'} already saved."
        self.statusBar().showMessage(msg, 10000)
        if n_new or announce:
            self._after_change(lookups=True)
        self._update_header()

    def _after_change(self, lookups: bool) -> None:
        self._rebuild_domains()
        self._show_page()
        self.refresh()
        if lookups and not self.sample_mode:
            self._lookup_hostnames()
            self.check_dns(force=False)

    def _rebuild_domains(self) -> None:
        current = self.domain_combo.currentData()
        domains = sorted({r.policy.domain for r in self.reports}
                         | {d for t in self.tls_reports for d in t.domains})
        self.domain_combo.blockSignals(True)
        self.domain_combo.clear()
        if len(domains) != 1:
            self.domain_combo.addItem("All domains", None)
        for d in domains:
            self.domain_combo.addItem(d, d)
        self.domain_combo.setCurrentIndex(max(self.domain_combo.findData(current), 0))
        self.domain_combo.blockSignals(False)

    def delete_history(self) -> None:
        n = self.storage.report_count()
        if QMessageBox.question(
                self, "Delete all saved reports",
                f"Delete all {n:,} saved reports from XML-ray? Your original report files and "
                "emails aren't touched, and your sender names and settings are kept.") \
                != QMessageBox.Yes:
            return
        self.storage.delete_all_reports()
        self.sample_mode = False
        self.reports, self.tls_reports, self.dns_results = [], [], {}
        self.ip_filter = None
        self._after_change(lookups=False)

    # ---------------------------------------------------------------- lookups

    def _lookup_hostnames(self) -> None:
        if self._setting("lookup/rdns", True, bool):
            ips = sorted({rec.source_ip for r in self.reports for rec in r.records}
                         - set(self.hostnames))[:MAX_RDNS]
            if ips:
                task = Task(_reverse_all, ips, with_progress=True)
                task.progress.connect(lambda i, n: self.statusBar().showMessage(
                    f"Looking up server names… {i} of {n}"))
                self._run(task, self._hostnames_ready)
                return
        self._lookup_owners()

    def _hostnames_ready(self, results, err) -> None:
        if results:
            self.hostnames.update(results)
            self.statusBar().showMessage("Server names updated.", 4000)
            self.refresh()
        self._lookup_owners()

    def _lookup_owners(self) -> None:
        if not self._setting("lookup/rdap", True, bool) or not self.analysis:
            return
        order = sorted(self.analysis.sources,
                       key=lambda s: (s.category == "authorized", -s.messages))
        ips = [s.ip for s in order if s.ip not in self.owners and s.ip not in self._rdap_done]
        ips = ips[:MAX_RDAP]
        if not ips:
            return
        self._rdap_done.update(ips)
        task = Task(_rdap_all, ips, self.storage, with_progress=True)
        task.progress.connect(lambda i, n: self.statusBar().showMessage(
            f"Looking up who owns the sending servers… {i} of {n}"))
        self._run(task, self._owners_ready)

    def _owners_ready(self, results, err) -> None:
        if results:
            self.owners.update(results)
            self.statusBar().showMessage("Network owners updated.", 4000)
            self.fill_senders()

    def check_dns(self, force: bool) -> None:
        if self.sample_mode:
            return
        if not force and not self._setting("lookup/dns", True, bool):
            self.dns_label.setText("Automatic DNS checks are off (Tools > Settings). Click "
                                   "Check DNS now to run one.")
            return
        domains = sorted({r.policy.domain for r in self.reports})
        now = datetime.now(timezone.utc)
        jobs = []
        for d in domains:
            prev = self.dns_results.get(d)
            if not force and prev and now - prev.checked_at < timedelta(hours=6):
                continue
            latest = max((r for r in self.reports if r.policy.domain == d), key=lambda r: r.end)
            jobs.append((d, latest.policy.p, dnscheck.selectors_from_reports(self.reports, d)))
        if not jobs:
            return
        self.dns_btn.setEnabled(False)
        self.dns_label.setText(f"Checking DNS for {', '.join(j[0] for j in jobs)}…")
        self._run(Task(_dns_all, jobs), self._dns_ready)

    def _dns_ready(self, results, err) -> None:
        self.dns_btn.setEnabled(True)
        if err:
            self.dns_label.setText(f"The DNS check couldn't run: {err}")
            return
        self.dns_results.update(results or {})
        self.refresh()

    # ---------------------------------------------------------------- display

    def _since(self) -> datetime | None:
        days = self.period_combo.currentData() or 0
        ends = [r.end for r in self.reports] + [t.end for t in self.tls_reports]
        if not days or not ends:
            return None
        return max(ends) - timedelta(days=days)

    def _period_changed(self) -> None:
        self.settings.setValue("view/period", self.period_combo.currentData())
        self.refresh()

    def refresh(self) -> None:
        if not (self.reports or self.tls_reports):
            return
        domain, since = self.domain_combo.currentData(), self._since()
        self.analysis = analyze(self.reports, domain, self.hostnames, self.labels, since)
        self.tls_analysis = analyze_tls(self.tls_reports, domain, since)
        dns_findings = []
        for d, res in self.dns_results.items():
            if domain is None or d == domain:
                dns_findings += res.findings
        found = self.analysis.findings + dns_findings + self.tls_analysis.findings
        if not self.reports:
            found = [f for f in found if f.key != "healthy"]
        found.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.affected))
        self.findings = found
        self.fill_stats()
        self.fill_findings()
        self.fill_senders()
        self.fill_trend_choices()
        self.fill_dns()
        self.fill_tls()
        self.fill_reports()

    def fill_stats(self) -> None:
        a = self.analysis
        self.grade.set(a.grade, a.grade_label, a.score)
        n_rep = len(a.reports)
        self.card_messages.set(f"{a.total:,}", f"In {n_rep} report{'s' if n_rep != 1 else ''} "
                               f"from {len(a.reporters)} provider{'s' if len(a.reporters) != 1 else ''}")
        self.card_passed.set(f"{a.pass_pct:.1f}%", f"{a.passed:,} messages",
                             GRADE_COLORS["A"] if a.pass_pct >= 98 else None)
        fail_pct = 100 - a.pass_pct if a.total else 0
        self.card_failed.set(f"{a.failed:,}", f"{fail_pct:.1f}% of all email",
                             GRADE_COLORS["F"] if a.failed else None)
        pols = list(a.policies.values())
        if len(pols) == 1:
            p = pols[0]
            words = {"none": "Monitoring only", "quarantine": "Failing mail goes to spam",
                     "reject": "Failing mail is blocked"}
            self.card_policy.set(f"p={p.p}", words.get(p.p, "") + (f", {p.pct}%" if p.pct < 100 else ""))
        elif pols:
            kinds = sorted({p.p for p in pols})
            self.card_policy.set("Mixed" if len(kinds) > 1 else f"p={kinds[0]}",
                                 f"Across {len(pols)} domains")
        else:
            self.card_policy.set("–", "No DMARC reports yet")
        if a.begin and a.end:
            days = max(1, round((a.end - a.begin).total_seconds() / 86400))
            self.card_period.set(f"{days} day{'s' if days != 1 else ''}",
                                 f"{a.begin:%b %d} to {a.end:%b %d, %Y}")
        else:
            self.card_period.set("–", "")
        active = sum(1 for f, state in self._finding_states() if state != "done"
                     and f.severity != "good")
        self.tabs.setTabText(0, f"Action plan ({active})" if active else "Action plan")
        self.tabs.setTabText(1, f"Senders ({len(a.sources)})")
        dns_problems = sum(1 for d in self.dns_results.values() for f in d.findings
                           if f.severity in ("critical", "high", "medium"))
        self.tabs.setTabText(3, f"DNS check ({dns_problems})" if dns_problems else "DNS check")
        tls_n = len(self.tls_analysis.reports) if self.tls_analysis else 0
        self.tabs.setTabText(4, f"TLS ({tls_n})" if tls_n else "TLS")
        self.tabs.setTabText(5, f"Reports ({n_rep + tls_n})")

    # ----------------------------------------------------- findings / done

    def _evidence_time(self, f) -> datetime | None:
        if f.source == "dns":
            res = next((r for r in self.dns_results.values() if f in r.findings), None)
            return res.checked_at if res else None
        if f.ips and self.analysis:
            seen = [s.last_seen for s in self.analysis.sources if s.ip in f.ips and s.last_seen]
            return max(seen) if seen else None
        if f.source == "tls" and self.tls_analysis and self.tls_analysis.reports:
            return max(r.end for r in self.tls_analysis.reports)
        return self.analysis.end if self.analysis else None

    def _finding_states(self):
        """Yield (finding, state): 'active', 'done' or 'reopened'."""
        for f in self.findings:
            ts = self.acks.get(f.key)
            if not ts:
                yield f, "active"
                continue
            evidence = self._evidence_time(f)
            grace = timedelta(days=1 if f.source == "dns" else 2)
            acked = datetime.fromtimestamp(ts, tz=timezone.utc)
            yield f, ("reopened" if evidence and evidence > acked + grace else "done")

    def fill_findings(self) -> None:
        lay = self.findings_layout
        while lay.count():
            item = lay.takeAt(0)
            widget = item.widget()
            if widget:
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()
        states = list(self._finding_states())
        active = [(f, s) for f, s in states if s != "done"]
        done = [f for f, s in states if s == "done"]
        intro = QLabel("Start at the top. Items are ordered by how much they matter.",
                       objectName="Muted")
        lay.addWidget(intro)
        for f, state in active:
            lay.addWidget(self._card(f, reopened=state == "reopened"))
        if done:
            toggle = QPushButton(f"Show {len(done)} item{'s' if len(done) != 1 else ''} "
                                 "marked as done", objectName="Link")
            toggle.setCursor(Qt.PointingHandCursor)
            box = QWidget()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(12)
            for f in done:
                bl.addWidget(self._card(f))
            box.setVisible(False)
            toggle.clicked.connect(lambda: (box.setVisible(not box.isVisible()), toggle.setText(
                ("Hide" if box.isVisible() else "Show") + toggle.text()[4:])))
            lay.addWidget(toggle, 0, Qt.AlignLeft)
            lay.addWidget(box)
        lay.addStretch(1)

    def _card(self, f, reopened: bool = False) -> FindingCard:
        card = FindingCard(f, self.acks.get(f.key), reopened)
        card.show_senders.connect(self.filter_to_ips)
        card.toggle_done.connect(self.toggle_done)
        card.open_builder.connect(self.open_record_builder)
        return card

    def toggle_done(self, key: str, done: bool) -> None:
        self.storage.set_ack(key, done)
        self.acks = self.storage.acks()
        self.fill_stats()
        self.fill_findings()

    # -------------------------------------------------------------- senders

    def filter_to_ips(self, ips: list[str], title: str) -> None:
        self.ip_filter = set(ips)
        self.banner_label.setText(f"Showing senders for: <b>{html.escape(title)}</b>")
        self.banner.setVisible(True)
        self.sender_filter.setCurrentIndex(0)
        self.fill_senders()
        self.tabs.setCurrentIndex(1)

    def clear_ip_filter(self) -> None:
        self.ip_filter = None
        self.banner.setVisible(False)
        self.fill_senders()

    def _visible_sources(self) -> list[SourceSummary]:
        mode = self.sender_filter.currentData()
        query = self.sender_search.text().strip().lower()
        out = []
        for s in self.analysis.sources:
            if self.ip_filter is not None and s.ip not in self.ip_filter:
                continue
            if mode == "failing" and (s.failed == 0 or s.category == "ignored"):
                continue
            if mode == "passing" and s.category != "authorized":
                continue
            if mode in ("unknown", "ignored") and s.category != mode:
                continue
            if query:
                owner = rdap.describe(self.owners.get(s.ip, {}))
                hay = " ".join([s.ip, s.name, s.hostname, owner, *s.header_from,
                                *s.envelope_from, *s.dkim_domains]).lower()
                if query not in hay:
                    continue
            out.append(s)
        return out

    def fill_senders(self) -> None:
        if not self.analysis:
            return
        t = self.sender_table
        selected = self._selected_ip()
        t.setSortingEnabled(False)
        rows = self._visible_sources()
        t.setRowCount(len(rows))
        for r, s in enumerate(rows):
            status = NumericItem(STATUS_RANK.get(s.category, 9), f"●  {s.category_label}")
            status.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            status.setForeground(QColor(CATEGORY_COLORS.get(s.category, T["muted"])))
            status.setData(Qt.UserRole, s.ip)
            name = QTableWidgetItem(s.name + ("  ✎" if s.nickname else ""))
            if s.hostname:
                name.setToolTip(s.hostname)
            owner = rdap.describe(self.owners.get(s.ip, {}))
            last = s.last_seen.timestamp() if s.last_seen else 0
            cells = [
                status, name, QTableWidgetItem(s.ip), QTableWidgetItem(owner),
                NumericItem(s.messages),
                NumericItem(s.pass_rate, f"{s.pass_rate*100:.0f}%"),
                NumericItem(s.spf_aligned / s.messages if s.messages else 0, f"{s.spf_aligned:,}"),
                NumericItem(s.dkim_aligned / s.messages if s.messages else 0, f"{s.dkim_aligned:,}"),
                QTableWidgetItem(s.delivered_summary),
                NumericItem(last, f"{s.last_seen:%b %d}" if s.last_seen else ""),
                QTableWidgetItem(s.meaning),
            ]
            cells[3].setToolTip(owner)
            cells[-1].setToolTip(s.meaning)
            for c, item in enumerate(cells):
                t.setItem(r, c, item)
        t.setSortingEnabled(True)
        if not self._sender_sorted:
            t.sortByColumn(0, Qt.AscendingOrder)
            self._sender_sorted = True
        t.clearSelection()
        target = 0
        for row in range(t.rowCount()):
            if t.item(row, 0).data(Qt.UserRole) == selected:
                target = row
        if rows:
            t.selectRow(target)
            self.show_sender_detail()
        else:
            self._sender_buttons(False)
            self.sender_detail.setHtml(f"<p style='color:{T['muted']}'>No senders match this "
                                       "filter.</p>")

    def _selected_ip(self) -> str | None:
        items = self.sender_table.selectedItems()
        if not items:
            return None
        return self.sender_table.item(items[0].row(), 0).data(Qt.UserRole)

    def _selected_source(self) -> SourceSummary | None:
        ip = self._selected_ip()
        if not ip or not self.analysis:
            return None
        return next((x for x in self.analysis.sources if x.ip == ip), None)

    def _sender_buttons(self, on: bool, s: SourceSummary | None = None) -> None:
        for b in (self.btn_name, self.btn_mine, self.btn_ignore, self.btn_reset, self.btn_trend):
            b.setEnabled(on)
        if s:
            self.btn_reset.setEnabled(bool(s.nickname or s.status))
            self.btn_mine.setEnabled(s.status != "mine" and s.category != "authorized")
            self.btn_ignore.setEnabled(s.status != "ignore")

    def show_sender_detail(self) -> None:
        s = self._selected_source()
        if not s:
            self._sender_buttons(False)
            return
        self._sender_buttons(True, s)
        e = html.escape

        def lst(counter, fmt):
            return "".join(f"<li>{fmt(k)}: {v:,} messages</li>" for k, v in counter.most_common(8)) \
                or "<li>None reported</li>"

        def dkim_fmt(k):
            d, sel, res = k.split("|")
            return f"<b>{e(d) or '(none)'}</b>{' selector ' + e(sel) if sel else ''}, {e(res)}"

        def spf_fmt(k):
            d, res = k.split("|")
            return f"<b>{e(d) or '(none)'}</b>, {e(res)}"

        color = CATEGORY_COLORS.get(s.category, T["muted"])
        owner = self.owners.get(s.ip, {})
        lines = [x for x in (s.hostname, e(s.ip)) if x]
        if owner:
            net = f" ({e(owner.get('range', ''))})" if owner.get("range") else ""
            lines.append(f"Network owner: {e(rdap.describe(owner))}{net}")
        if s.first_seen and s.last_seen:
            lines.append(f"First seen {s.first_seen:%b %d, %Y}, last seen {s.last_seen:%b %d, %Y}")
        self.sender_detail.setHtml(f"""
            <h3 style='margin:0'>{e(s.name)} <span style='color:{color}'>({e(s.category_label)})</span></h3>
            <p style='margin:4px 0 8px 0;color:{T['muted']}'>{'<br>'.join(lines)}<br>
            {s.messages:,} messages, {s.pass_rate*100:.0f}% passed DMARC</p>
            <p><b>What this means:</b> {e(s.meaning)}</p>
            <table cellspacing='0' cellpadding='4' width='100%'><tr valign='top'>
            <td width='33%'><b>DKIM signatures</b><ul>{lst(s.dkim_domains, dkim_fmt)}</ul></td>
            <td width='33%'><b>SPF checks</b><ul>{lst(s.spf_domains, spf_fmt)}</ul></td>
            <td width='33%'><b>Sent as (From domain)</b><ul>{lst(s.header_from, e)}</ul>
            <b>What receivers did</b><ul>{''.join(f'<li>{e(x)}</li>' for x in s.delivered_summary.split(', '))}</ul></td>
            </tr></table>""")

    def _relabel(self, ip: str, label=None, status=None) -> None:
        self.storage.set_label(ip, label, status)
        self.labels = self.storage.labels()
        self.refresh()

    def name_sender(self) -> None:
        s = self._selected_source()
        if not s:
            return
        text, ok = QInputDialog.getText(
            self, "Name this sender", f"What is the server at {s.ip}? For example: "
            "Office copier, Website contact form, Billing system.", text=s.nickname)
        if ok:
            self._relabel(s.ip, label=text)

    def set_sender_status(self, status: str) -> None:
        s = self._selected_source()
        if not s:
            return
        label = None
        if status == "mine" and not (s.nickname or s.provider):
            text, ok = QInputDialog.getText(self, "Name this sender",
                                            f"What is the server at {s.ip}? (optional)")
            if not ok:
                return
            label = text
        self._relabel(s.ip, label=label, status=status)
        self.statusBar().showMessage(
            f"{s.label} is now marked as yours." if status == "mine"
            else f"{s.label} will be left out of the action plan and alerts.", 6000)

    def reset_sender(self) -> None:
        s = self._selected_source()
        if s:
            self._relabel(s.ip, label="", status="")

    def trend_for_selected(self) -> None:
        s = self._selected_source()
        if not s:
            return
        idx = self.trend_combo.findData(s.ip)
        if idx < 0:
            self.trend_combo.addItem(f"{s.label} ({s.ip})", s.ip)
            idx = self.trend_combo.count() - 1
        self.trend_combo.setCurrentIndex(idx)
        self.tabs.setCurrentIndex(2)

    # --------------------------------------------------------------- trends

    def fill_trend_choices(self) -> None:
        current = self.trend_combo.currentData()
        self.trend_combo.blockSignals(True)
        self.trend_combo.clear()
        self.trend_combo.addItem("All email", None)
        for s in self.analysis.sources[:30]:
            if s.category != "ignored":
                self.trend_combo.addItem(f"{s.label} ({s.ip})", s.ip)
        self.trend_combo.setCurrentIndex(max(self.trend_combo.findData(current), 0))
        self.trend_combo.blockSignals(False)
        self.fill_trends()

    def fill_trends(self) -> None:
        if not self.analysis:
            return
        ip = self.trend_combo.currentData()
        series = daily_series(self.reports, self.domain_combo.currentData(),
                              {ip} if ip else None, self._since())
        self.chart.set_series(series)
        days = [(d, m, p) for d, m, p in series if m]
        if len(days) < 2:
            self.trend_summary.setText("Trends appear once you have reports from at least two "
                                       "different days. XML-ray keeps every report you add.")
            return
        half = max(1, min(7, len(days) // 2))
        first = sum(p for _d, _m, p in days[:half]) / max(sum(m for _d, m, _p in days[:half]), 1)
        last = sum(p for _d, _m, p in days[-half:]) / max(sum(m for _d, m, _p in days[-half:]), 1)
        who = "Your email" if not ip else self.trend_combo.currentText().rsplit(" (", 1)[0]
        change = (last - first) * 100
        if abs(change) < 1:
            verdict = f"held steady at about {last*100:.0f}% passing"
        elif change > 0:
            verdict = f"improved from {first*100:.0f}% to {last*100:.0f}% passing"
        else:
            verdict = f"got worse, from {first*100:.0f}% to {last*100:.0f}% passing"
        self.trend_summary.setText(
            f"{who} {verdict}, comparing the first {half} and last {half} days with reports. "
            "Hover over the chart for each day's numbers.")

    # ------------------------------------------------------------------ DNS

    def fill_dns(self) -> None:
        t = self.dns_table
        domain = self.domain_combo.currentData()
        results = [r for d, r in sorted(self.dns_results.items()) if domain is None or d == domain]
        rows = [(r.domain, v) for r in results for v in r.records]
        t.setRowCount(len(rows))
        for i, (d, v) in enumerate(rows):
            label, sev = RECORD_STATUS.get(v.status, (v.status, "low"))
            status = QTableWidgetItem(label)
            status.setForeground(QColor(SEVERITY[sev][1]))
            value = QTableWidgetItem(v.value or "(none)")
            value.setToolTip(v.value)
            for c, item in enumerate([QTableWidgetItem(d), QTableWidgetItem(v.kind), status,
                                      QTableWidgetItem(v.name), value, QTableWidgetItem(v.note)]):
                t.setItem(i, c, item)
        t.setColumnWidth(4, 360)
        t.horizontalHeader().setSectionResizeMode(4, QHeaderView.Interactive)
        if results:
            when = max(r.checked_at for r in results).astimezone()
            errors = [f"{r.domain}: {r.error}" for r in results if r.error]
            text = f"Checked live DNS at {when:%I:%M %p on %b %d}."
            if errors:
                text += " Some lookups failed: " + "; ".join(errors)
            self.dns_label.setText(text)
        elif not self.sample_mode and self.reports:
            self.dns_label.setText("Your domain's records haven't been checked yet.")

    # ------------------------------------------------------------------ TLS

    def fill_tls(self) -> None:
        ta = self.tls_analysis
        t = self.tls_table
        if not ta or not ta.reports:
            self.tls_intro.setText(
                "<b>No TLS reports yet.</b> TLS reports show whether email sent <i>to</i> you "
                "arrives encrypted. To receive them, add a TXT record at "
                "<b>_smtp._tls.yourdomain</b> with the value "
                "<code>v=TLSRPTv1; rua=mailto:you@yourdomain</code>. Providers such as Google "
                "and Microsoft then send a daily JSON report, which XML-ray reads just like "
                "DMARC reports.")
            for c in (self.tls_total, self.tls_ok, self.tls_fail):
                c.set("–")
            t.setRowCount(0)
            return
        names = {"sts": "MTA-STS", "tlsa": "DANE", "no-policy-found": "none (encryption is "
                 "offered but not required)"}
        kinds = ", ".join(sorted({names.get(k, k) for k in ta.policy_types})) or "none"
        self.tls_intro.setText(
            f"From {len(ta.reports)} TLS report{'s' if len(ta.reports) != 1 else ''}: how "
            f"often other mail servers could deliver to you over an encrypted connection. "
            f"Your published policy: {html.escape(kinds)}.")
        self.tls_total.set(f"{ta.total:,}")
        self.tls_ok.set(f"{ta.success_pct:.1f}%", f"{ta.success:,} connections",
                        GRADE_COLORS["A"] if ta.success_pct >= 99 else None)
        self.tls_fail.set(f"{ta.failure:,}", "", GRADE_COLORS["F"] if ta.failure else None)
        rows = ta.by_type.most_common()
        t.setRowCount(len(rows))
        for i, (ftype, n) in enumerate(rows):
            sev, _label, text = FAILURE_TYPES.get(ftype, ("medium", ftype, ""))
            name = QTableWidgetItem(label_for(ftype))
            name.setForeground(QColor(SEVERITY[sev][1]))
            for c, item in enumerate([name, NumericItem(n), QTableWidgetItem(text)]):
                t.setItem(i, c, item)

    # -------------------------------------------------------------- reports

    def fill_reports(self) -> None:
        t = self.report_table
        t.setSortingEnabled(False)
        reps = self.analysis.reports
        tls = self.tls_analysis.reports if self.tls_analysis else []
        t.setRowCount(len(reps) + len(tls))
        row = 0
        for rep in reps:
            total = rep.total_messages
            pct = rep.passed_messages / total if total else 0
            pol = f"p={rep.policy.p}" + (f", pct={rep.policy.pct}" if rep.policy.pct < 100 else "")
            cells = [QTableWidgetItem("DMARC"), QTableWidgetItem(rep.org_name),
                     QTableWidgetItem(rep.policy.domain),
                     QTableWidgetItem(f"{rep.begin:%Y-%m-%d %H:%M}"),
                     QTableWidgetItem(f"{rep.end:%Y-%m-%d %H:%M}"),
                     NumericItem(total), NumericItem(pct, f"{pct*100:.0f}%"),
                     QTableWidgetItem(pol), QTableWidgetItem(rep.source_file)]
            for c, item in enumerate(cells):
                t.setItem(row, c, item)
            row += 1
        for rep in tls:
            total = sum(p.success + p.failure for p in rep.policies)
            ok = sum(p.success for p in rep.policies)
            pct = ok / total if total else 0
            cells = [QTableWidgetItem("TLS"), QTableWidgetItem(rep.org_name),
                     QTableWidgetItem(", ".join(sorted(rep.domains))),
                     QTableWidgetItem(f"{rep.begin:%Y-%m-%d %H:%M}"),
                     QTableWidgetItem(f"{rep.end:%Y-%m-%d %H:%M}"),
                     NumericItem(total), NumericItem(pct, f"{pct*100:.0f}%"),
                     QTableWidgetItem(", ".join(sorted({p.policy_type for p in rep.policies}))),
                     QTableWidgetItem(rep.source_file)]
            for c, item in enumerate(cells):
                t.setItem(row, c, item)
            row += 1
        t.setSortingEnabled(True)

    # ---------------------------------------------------------------- export

    def _export_name(self, ext: str) -> str:
        name = "-".join(sorted(self.analysis.policies)) or "dmarc"
        return str(Path(self._last_dir()) / f"XML-ray summary {name}.{ext}")

    def _dns_for_view(self) -> dict:
        d = self.domain_combo.currentData()
        return {k: v for k, v in self.dns_results.items() if d is None or k == d}

    def _export_findings(self) -> list:
        return [f for f, state in self._finding_states() if state != "done"]

    def export_html(self) -> None:
        if not self.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export summary", self._export_name("html"),
                                              "Web page (*.html)")
        if path:
            Path(path).write_text(html_summary(self.analysis, self._export_findings(),
                                               self._dns_for_view(), self.tls_analysis),
                                  encoding="utf-8")
            self.statusBar().showMessage(f"Summary saved to {path}", 8000)
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_pdf(self) -> None:
        if not self.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export summary as PDF",
                                              self._export_name("pdf"), "PDF (*.pdf)")
        if not path:
            return
        from .pdf import export_pdf
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            export_pdf(print_html(self.analysis, self._export_findings(), self._dns_for_view(),
                                  self.tls_analysis), path)
        finally:
            QApplication.restoreOverrideCursor()
        self.statusBar().showMessage(f"PDF saved to {path}", 8000)
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_csv(self) -> None:
        if not self.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export senders", str(Path(self._last_dir()) / "XML-ray senders.csv"),
            "CSV file (*.csv)")
        if path:
            senders_csv(self.analysis, path,
                        {ip: rdap.describe(i) for ip, i in self.owners.items()})
            self.statusBar().showMessage(f"Senders saved to {path}", 8000)

    # ------------------------------------------------------ mailbox / folder

    def check_mailbox(self, manual: bool) -> None:
        cfg = mailbox_config(self.settings)
        if not self._setting("mail/enabled", False, bool) or not cfg.host:
            if manual:
                if QMessageBox.question(self, "Set up mailbox import",
                                        "XML-ray isn't connected to a mailbox yet. Set it up now?") \
                        == QMessageBox.Yes:
                    self.show_settings(tab=1)
            return
        password = mailimport.get_password(cfg)
        if not password:
            if manual:
                QMessageBox.warning(self, "Password needed", "Enter your mailbox password in "
                                    "Tools > Settings > Mailbox.")
            self.statusBar().showMessage("Mailbox check skipped: no saved password.", 8000)
            return
        if self._mail_running:
            return
        self._mail_running = True
        task = Task(mailimport.fetch_reports, cfg, password, self.storage, with_progress=True)
        task.progress.connect(lambda i, n: self.statusBar().showMessage(
            f"Downloading report emails… {i} of {n}"))

        def done(result, err):
            self._mail_running = False
            if err:
                self.statusBar().showMessage(f"Mailbox check failed: {err}", 15000)
                if manual:
                    QMessageBox.warning(self, "Mailbox check failed", err)
                return
            loaded, checked = result
            if not checked:
                self.statusBar().showMessage("Mailbox checked: no new report emails.", 8000)
                if manual:
                    self.bring_to_front()
                return
            self._ingest(loaded, "", "mailbox")
        self._run(task, done, "Checking your mailbox…" if manual else "")

    def scan_watched_folder(self) -> None:
        path = self._setting("folder/path", "")
        if not self._setting("folder/enabled", False, bool) or not path or self._folder_running:
            return
        self._folder_running = True

        def done(result, err):
            self._folder_running = False
            if result and (result.dmarc or result.tls):
                self._ingest(result, "", "folder")
        self._run(Task(mailimport.scan_folder, path, self.storage), done)

    # ---------------------------------------------------------------- dialogs

    def show_settings(self, tab: int = 0) -> None:
        old_theme = self._setting("appearance/theme", "system")
        dlg = SettingsDialog(self.settings, self, start_tab=tab)
        if dlg.exec():
            if self._setting("appearance/theme", "system") != old_theme:
                self.apply_theme()
            self._apply_automation()
            self.statusBar().showMessage("Settings saved.", 4000)

    def apply_theme(self) -> None:
        style.apply(QApplication.instance(), self._setting("appearance/theme", "system"))
        self.refresh()
        self.chart.update()

    def _system_theme_changed(self, *_args) -> None:
        if self._setting("appearance/theme", "system") == "system":
            self.apply_theme()

    def open_record_builder(self, domain: str = "") -> None:
        domains = sorted({r.policy.domain for r in self.reports}) if not self.sample_mode \
            else ["example.com"]
        policies = self.analysis.policies if self.analysis else {}
        RecordBuilderDialog(domains, policies, self.dns_results,
                            domain or (self.domain_combo.currentData() or ""), self).exec()

    def show_alerts(self) -> None:
        self.bring_to_front()
        AlertsDialog(self.storage, self).exec()
        self._update_header()

    def show_glossary(self) -> None:
        GlossaryDialog(self).exec()

    def show_about(self) -> None:
        QMessageBox.about(self, f"About {APP_NAME}",
                          f"<h3>{APP_NAME} {__version__}</h3><p>{TAGLINE}.</p>"
                          "<p>Reads DMARC and TLS reports on your computer and explains them "
                          "in plain English. Reports are never uploaded anywhere.</p>"
                          f"<p>Saved reports: {self.storage.report_count():,}<br>"
                          f"Stored in: {html.escape(str(self.storage.path))}</p>"
                          f"<p><a href='{GITHUB_URL}'>{GITHUB_URL}</a></p>")

    # ---------------------------------------------------------------- updates

    def check_updates(self, silent: bool) -> None:
        if not silent:
            self.statusBar().showMessage("Checking for updates…")
        self._run(Task(updater.check_for_update, __version__),
                  lambda info, err: self._update_checked(info, err, silent))

    def _update_checked(self, info, err: str, silent: bool) -> None:
        if err:
            if not silent:
                QMessageBox.warning(self, "Couldn't check for updates", err)
            return
        if info is None:
            if not silent:
                self.statusBar().showMessage("", 1)
                QMessageBox.information(self, "You're up to date",
                                        f"XML-ray {__version__} is the latest version.")
            return
        if silent and self.settings.value("updates/skipped", "") == info.version:
            return
        if silent and not self.isVisible():
            return  # don't pop up over other apps while running in the tray
        can_install = updater.can_self_install(info)
        dlg = UpdateDialog(info, __version__, can_install, self)
        dlg.exec()
        if dlg.choice == UpdateDialog.SKIP:
            self.settings.setValue("updates/skipped", info.version)
        elif dlg.choice == UpdateDialog.INSTALL:
            if can_install:
                self._download_update(info)
            else:
                QDesktopServices.openUrl(QUrl(info.html_url))

    def _download_update(self, info) -> None:
        progress = QProgressDialog(f"Downloading XML-ray {info.version}…", "Cancel", 0, 100, self)
        progress.setWindowTitle("Updating XML-ray")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setValue(0)
        state = {"cancel": False}
        task = Task(_download, info, with_progress=True, cancelled=lambda: state["cancel"])
        task.progress.connect(lambda d, t: progress.setValue(int(d * 100 / t)) if t else None)
        progress.canceled.connect(lambda: state.update(cancel=True))

        def finished(path, err):
            progress.close()
            if err:
                if err != "cancelled":
                    QMessageBox.warning(self, "Update failed", err)
                return
            QMessageBox.information(self, "Ready to install",
                                    "XML-ray will close, install the update and reopen.")
            try:
                updater.launch_installer(path)
            except OSError as exc:
                QMessageBox.warning(self, "Update failed", f"Couldn't start the installer: {exc}")
                return
            self.quit_app()
        self._run(task, finished)

    # ------------------------------------------------------------ plumbing

    def _run(self, task: Task, callback, busy_message: str = "") -> None:
        self._threads.append(task)
        if busy_message:
            self._busy_count += 1
            self.busy.setRange(0, 0)
            self.busy.setVisible(True)
            self.statusBar().showMessage(busy_message)

        def finished(result, err):
            if busy_message:
                self._busy_count -= 1
                self.busy.setVisible(self._busy_count > 0)
                if self.statusBar().currentMessage() == busy_message:
                    self.statusBar().clearMessage()
            callback(result, err)
        task.done.connect(finished)
        task.finished.connect(lambda: self._threads.remove(task) if task in self._threads else None)
        task.start()

    def bring_to_front(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_app(self) -> None:
        self._really_quit = True
        self.close()
        QApplication.quit()

    # ------------------------------------------------------------- drag & drop

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.drop_zone.set_dragging(True)

    def dragLeaveEvent(self, event):
        self.drop_zone.set_dragging(False)

    def dropEvent(self, event):
        self.drop_zone.set_dragging(False)
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.load(paths)

    def closeEvent(self, event):
        if (not self._really_quit and self.tray and self.tray.isVisible()
                and self._setting("tray/enabled", False, bool)):
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.showMessage("XML-ray is still running",
                                      "It keeps checking for new reports. Right-click the "
                                      "tray icon to quit.", QSystemTrayIcon.Information, 6000)
            return
        for t in list(self._threads):
            if not t.wait(1500):
                t.terminate()
                t.wait(500)
        if self.tray:
            self.tray.hide()
        super().closeEvent(event)
        QApplication.quit()
