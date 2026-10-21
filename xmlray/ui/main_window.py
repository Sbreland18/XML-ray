"""The XML-ray main window."""
from __future__ import annotations

import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QColor, QDesktopServices, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar, QProgressDialog, QPushButton,
    QScrollArea, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget,
    QTextBrowser, QVBoxLayout, QWidget,
)

from .. import updater
from ..__version__ import __version__
from ..analyzer import Analysis, SourceSummary, analyze
from ..config import APP_NAME, GITHUB_URL, ORG_NAME, TAGLINE, asset
from ..export import html_summary, senders_csv
from ..parser import Report, dedupe, load_paths
from ..senders import reverse_lookup
from .dialogs import GlossaryDialog, UpdateDialog
from .style import CATEGORY_COLORS, GRADE_COLORS, MUTED
from .widgets import DropZone, FindingCard, GradePanel, NumericItem, StatCard

FILE_FILTER = "DMARC reports (*.xml *.gz *.gzip *.zip *.eml);;All files (*)"
MAX_RDNS = 2000
# Sort order for the Senders table: most urgent first.
STATUS_RANK = {"service_failing": 0, "unknown": 1, "partial": 2, "forwarded": 3, "authorized": 4}


# ------------------------------------------------------------------- workers

class LoadWorker(QThread):
    done = Signal(object, object)

    def __init__(self, paths):
        super().__init__()
        self.paths = paths

    def run(self):
        reports, errors = load_paths(self.paths)
        self.done.emit(reports, errors)


class RdnsWorker(QThread):
    progress = Signal(int, int)
    done = Signal(object)

    def __init__(self, ips):
        super().__init__()
        self.ips = ips

    def run(self):
        results: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = {pool.submit(reverse_lookup, ip): ip for ip in self.ips}
            for i, fut in enumerate(as_completed(futures), 1):
                results[futures[fut]] = fut.result() or ""
                self.progress.emit(i, len(self.ips))
        self.done.emit(results)


class UpdateCheckWorker(QThread):
    done = Signal(object, str)

    def run(self):
        try:
            self.done.emit(updater.check_for_update(__version__), "")
        except Exception as exc:  # noqa: BLE001
            self.done.emit(None, str(exc))


class DownloadWorker(QThread):
    progress = Signal(int, int)
    done = Signal(str, str)

    def __init__(self, info):
        super().__init__()
        self.info = info
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            path = updater.download_installer(self.info, self.progress.emit, lambda: self._cancel)
            self.done.emit(path, "")
        except Exception as exc:  # noqa: BLE001
            self.done.emit("", str(exc))


# --------------------------------------------------------------------- window

class MainWindow(QMainWindow):
    SENDER_COLUMNS = ["Status", "Sender", "IP address", "Messages", "Passed", "SPF aligned",
                      "DKIM aligned", "What happened", "What this means"]
    REPORT_COLUMNS = ["Reported by", "Domain", "From", "To", "Messages", "Passed", "Policy", "File"]

    def __init__(self):
        super().__init__()
        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.reports: list[Report] = []
        self.hostnames: dict[str, str] = {}
        self.analysis: Analysis | None = None
        self.ip_filter: set[str] | None = None
        self._threads: list[QThread] = []
        self._sender_sorted = False

        self.setWindowTitle(f"{APP_NAME}: {TAGLINE}")
        self.resize(1240, 820)
        self.setMinimumSize(900, 620)
        self.setAcceptDrops(True)

        root = QWidget(objectName="Page")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_empty_page())
        self.stack.addWidget(self._build_dashboard())
        outer.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self._build_menus()
        self.busy = QProgressBar()
        self.busy.setMaximumWidth(160)
        self.busy.setVisible(False)
        self.statusBar().addPermanentWidget(self.busy)
        self.statusBar().showMessage(f"Version {__version__}")
        self._show_page()

        if self.settings.value("updates/check_on_startup", True, type=bool):
            QTimer.singleShot(3000, lambda: self.check_updates(silent=True))

    # ----------------------------------------------------------------- layout

    def _build_header(self) -> QWidget:
        header = QFrame(objectName="Header")
        lay = QHBoxLayout(header)
        lay.setContentsMargins(20, 12, 20, 12)
        lay.setSpacing(12)

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

        self.add_btn = QPushButton("Add reports", objectName="Primary")
        self.add_btn.setCursor(Qt.PointingHandCursor)
        self.add_btn.clicked.connect(self.open_files)
        lay.addWidget(self.add_btn)
        self.export_btn = QPushButton("Export summary")
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.clicked.connect(self.export_html)
        lay.addWidget(self.export_btn)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.clicked.connect(self.clear)
        lay.addWidget(self.clear_btn)
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
        self.drop_zone.load_sample.connect(lambda: self.load([asset("sample_report.xml")]))
        self.drop_zone.learn_more.connect(self.show_glossary)
        row.addWidget(self.drop_zone, 3)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(2)
        return page

    def _build_dashboard(self) -> QWidget:
        page = QWidget(objectName="Page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(20, 16, 20, 12)
        lay.setSpacing(14)

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
        self.tabs.setDocumentMode(False)
        self.tabs.addTab(self._build_findings_tab(), "Action plan")
        self.tabs.addTab(self._build_senders_tab(), "Senders")
        self.tabs.addTab(self._build_reports_tab(), "Reports")
        lay.addWidget(self.tabs, 1)
        return page

    def _build_findings_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        host = QWidget(objectName="FindingsHost")
        self.findings_layout = QVBoxLayout(host)
        self.findings_layout.setContentsMargins(18, 16, 18, 16)
        self.findings_layout.setSpacing(12)
        scroll.setWidget(host)
        return scroll

    def _build_senders_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 0)
        lay.setSpacing(8)

        bar = QHBoxLayout()
        self.sender_filter = QComboBox()
        for label, key in (("All senders", "all"), ("Failing only", "failing"),
                           ("Passing only", "passing"), ("Unknown or suspicious", "unknown")):
            self.sender_filter.addItem(label, key)
        self.sender_filter.currentIndexChanged.connect(lambda _: self.fill_senders())
        self.sender_search = QLineEdit()
        self.sender_search.setPlaceholderText("Search by name, IP address or domain")
        self.sender_search.setClearButtonEnabled(True)
        self.sender_search.textChanged.connect(lambda _: self.fill_senders())
        bar.addWidget(self.sender_filter)
        bar.addWidget(self.sender_search, 1)
        export_csv = QPushButton("Export CSV")
        export_csv.clicked.connect(self.export_csv)
        bar.addWidget(export_csv)
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
        self.sender_detail = QTextBrowser()
        self.sender_detail.setHtml(f"<p style='color:{MUTED}'>Select a sender to see the "
                                   "details behind its result.</p>")
        split.addWidget(self.sender_detail)
        split.setSizes([480, 220])
        lay.addWidget(split, 1)
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
        f.addSeparator()
        self._action(f, "Export summary (HTML)…", self.export_html, "Ctrl+E")
        self._action(f, "Export senders (CSV)…", self.export_csv)
        f.addSeparator()
        self._action(f, "Clear all reports", self.clear)
        self._action(f, "Exit", self.close, QKeySequence.Quit)

        s = mb.addMenu("&Settings")
        self.rdns_action = QAction("Look up server names (reverse DNS)", self, checkable=True)
        self.rdns_action.setChecked(self.settings.value("lookup/rdns", True, type=bool))
        self.rdns_action.toggled.connect(lambda v: self.settings.setValue("lookup/rdns", v))
        s.addAction(self.rdns_action)
        self.startup_update_action = QAction("Check for updates when XML-ray starts", self,
                                             checkable=True)
        self.startup_update_action.setChecked(
            self.settings.value("updates/check_on_startup", True, type=bool))
        self.startup_update_action.toggled.connect(
            lambda v: self.settings.setValue("updates/check_on_startup", v))
        s.addAction(self.startup_update_action)

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

    def _show_page(self) -> None:
        has = bool(self.reports)
        self.stack.setCurrentIndex(1 if has else 0)
        for w in (self.domain_combo, self.export_btn, self.clear_btn):
            w.setVisible(has)

    # ---------------------------------------------------------------- loading

    def _last_dir(self) -> str:
        return self.settings.value("paths/last_dir", str(Path.home()))

    def open_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Open DMARC reports", self._last_dir(),
                                                FILE_FILTER)
        if files:
            self.settings.setValue("paths/last_dir", str(Path(files[0]).parent))
            self.load(files)

    def open_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Open a folder of DMARC reports",
                                                  self._last_dir())
        if folder:
            self.settings.setValue("paths/last_dir", folder)
            self.load([folder])

    def load(self, paths) -> None:
        self._set_busy(True, "Reading reports…")
        worker = LoadWorker(list(paths))
        worker.done.connect(self._loaded)
        self._start(worker)

    def _loaded(self, reports: list[Report], errors: list[str]) -> None:
        self._set_busy(False)
        before = len(self.reports)
        self.reports = dedupe(self.reports + reports)
        added = len(self.reports) - before

        if errors:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Some files were skipped")
            box.setText(f"{len(errors)} file{'s' if len(errors) != 1 else ''} couldn't be read "
                        "as DMARC aggregate reports. Everything else was loaded.")
            box.setDetailedText("\n".join(errors[:200]))
            box.exec()
        if not reports and not errors:
            QMessageBox.information(self, "No reports found",
                                    "No DMARC report files were found there. XML-ray looks "
                                    "for .xml, .gz, .zip and .eml files.")

        self._rebuild_domains()
        self._show_page()
        self.refresh()
        self.statusBar().showMessage(
            f"Added {added} report{'s' if added != 1 else ''}. "
            f"{len(self.reports)} loaded in total.", 8000)
        self._lookup_hostnames()

    def _lookup_hostnames(self) -> None:
        if not self.rdns_action.isChecked():
            return
        ips = sorted({rec.source_ip for r in self.reports for rec in r.records}
                     - set(self.hostnames))[:MAX_RDNS]
        if not ips:
            return
        worker = RdnsWorker(ips)
        worker.progress.connect(
            lambda i, n: self.statusBar().showMessage(f"Looking up server names… {i} of {n}"))
        worker.done.connect(self._hostnames_ready)
        self._start(worker)

    def _hostnames_ready(self, results: dict) -> None:
        self.hostnames.update(results)
        self.statusBar().showMessage("Server names updated.", 5000)
        self.refresh()

    def _rebuild_domains(self) -> None:
        current = self.domain_combo.currentData()
        domains = sorted({r.policy.domain for r in self.reports})
        self.domain_combo.blockSignals(True)
        self.domain_combo.clear()
        if len(domains) != 1:
            self.domain_combo.addItem("All domains", None)
        for d in domains:
            self.domain_combo.addItem(d, d)
        idx = self.domain_combo.findData(current)
        self.domain_combo.setCurrentIndex(max(idx, 0))
        self.domain_combo.blockSignals(False)

    def clear(self) -> None:
        if self.reports and QMessageBox.question(
                self, "Clear all reports", "Remove all loaded reports from this window? "
                "Your report files are not deleted.") != QMessageBox.Yes:
            return
        self.reports, self.analysis, self.ip_filter = [], None, None
        self._rebuild_domains()
        self._show_page()

    # ---------------------------------------------------------------- display

    def refresh(self) -> None:
        if not self.reports:
            return
        self.analysis = analyze(self.reports, self.domain_combo.currentData(), self.hostnames)
        self.fill_stats()
        self.fill_findings()
        self.fill_senders()
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
        else:
            kinds = sorted({p.p for p in pols})
            self.card_policy.set("Mixed" if len(kinds) > 1 else f"p={kinds[0]}",
                                 f"Across {len(pols)} domains")
        if a.begin and a.end:
            days = max(1, round((a.end - a.begin).total_seconds() / 86400))
            self.card_period.set(f"{days} day{'s' if days != 1 else ''}",
                                 f"{a.begin:%b %d} to {a.end:%b %d, %Y}")
        n = a.action_count
        self.tabs.setTabText(0, f"Action plan ({n})" if n else "Action plan")
        self.tabs.setTabText(1, f"Senders ({len(a.sources)})")
        self.tabs.setTabText(2, f"Reports ({n_rep})")

    def fill_findings(self) -> None:
        lay = self.findings_layout
        while lay.count():
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        intro = QLabel("Start at the top. Items are ordered by how much they matter.")
        intro.setStyleSheet(f"color:{MUTED};")
        lay.addWidget(intro)
        for f in self.analysis.findings:
            card = FindingCard(f)
            card.show_senders.connect(self.filter_to_ips)
            lay.addWidget(card)
        lay.addStretch(1)

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
            if mode == "failing" and s.failed == 0:
                continue
            if mode == "passing" and s.category != "authorized":
                continue
            if mode == "unknown" and s.category != "unknown":
                continue
            if query:
                hay = " ".join([s.ip, s.name, s.hostname, *s.header_from, *s.envelope_from,
                                *s.dkim_domains]).lower()
                if query not in hay:
                    continue
            out.append(s)
        return out

    def fill_senders(self) -> None:
        if not self.analysis:
            return
        t = self.sender_table
        t.setSortingEnabled(False)
        rows = self._visible_sources()
        t.setRowCount(len(rows))
        for r, s in enumerate(rows):
            status = NumericItem(STATUS_RANK.get(s.category, 9), f"●  {s.category_label}")
            status.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            status.setForeground(QColor(CATEGORY_COLORS.get(s.category, MUTED)))
            status.setData(Qt.UserRole, s.ip)
            name = QTableWidgetItem(s.name)
            if s.hostname and s.provider:
                name.setToolTip(s.hostname)
            cells = [
                status, name, QTableWidgetItem(s.ip), NumericItem(s.messages),
                NumericItem(s.pass_rate, f"{s.pass_rate*100:.0f}%"),
                NumericItem(s.spf_aligned / s.messages if s.messages else 0,
                            f"{s.spf_aligned:,}"),
                NumericItem(s.dkim_aligned / s.messages if s.messages else 0,
                            f"{s.dkim_aligned:,}"),
                QTableWidgetItem(s.delivered_summary), QTableWidgetItem(s.meaning),
            ]
            cells[-1].setToolTip(s.meaning)
            for c, item in enumerate(cells):
                t.setItem(r, c, item)
        t.setSortingEnabled(True)
        if not self._sender_sorted:
            t.sortByColumn(0, Qt.AscendingOrder)  # most urgent first
            self._sender_sorted = True
        t.clearSelection()
        if rows:
            t.selectRow(0)
            self.show_sender_detail()
        else:
            self.sender_detail.setHtml(f"<p style='color:{MUTED}'>No senders match this filter.</p>")

    def show_sender_detail(self) -> None:
        items = self.sender_table.selectedItems()
        if not items or not self.analysis:
            return
        ip = self.sender_table.item(items[0].row(), 0).data(Qt.UserRole)
        s = next((x for x in self.analysis.sources if x.ip == ip), None)
        if not s:
            return
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

        color = CATEGORY_COLORS.get(s.category, MUTED)
        host = f"{e(s.hostname)}<br>" if s.hostname else ""
        self.sender_detail.setHtml(f"""
            <h3 style='margin:0'>{e(s.name)} <span style='color:{color}'>({e(s.category_label)})</span></h3>
            <p style='margin:4px 0 8px 0;color:{MUTED}'>{host}{e(s.ip)}, {s.messages:,} messages,
            {s.pass_rate*100:.0f}% passed DMARC</p>
            <p><b>What this means:</b> {e(s.meaning)}</p>
            <table cellspacing='0' cellpadding='4' width='100%'><tr valign='top'>
            <td width='33%'><b>DKIM signatures</b><ul>{lst(s.dkim_domains, dkim_fmt)}</ul></td>
            <td width='33%'><b>SPF checks</b><ul>{lst(s.spf_domains, spf_fmt)}</ul></td>
            <td width='33%'><b>Sent as (From domain)</b><ul>{lst(s.header_from, e)}</ul>
            <b>What receivers did</b><ul>{''.join(f'<li>{e(x)}</li>' for x in s.delivered_summary.split(', '))}</ul></td>
            </tr></table>""")

    def fill_reports(self) -> None:
        t = self.report_table
        t.setSortingEnabled(False)
        reports = self.analysis.reports
        t.setRowCount(len(reports))
        for r, rep in enumerate(reports):
            total = rep.total_messages
            pct = rep.passed_messages / total if total else 0
            pol = f"p={rep.policy.p}" + (f", pct={rep.policy.pct}" if rep.policy.pct < 100 else "")
            cells = [
                QTableWidgetItem(rep.org_name), QTableWidgetItem(rep.policy.domain),
                QTableWidgetItem(f"{rep.begin:%Y-%m-%d %H:%M}"),
                QTableWidgetItem(f"{rep.end:%Y-%m-%d %H:%M}"),
                NumericItem(total), NumericItem(pct, f"{pct*100:.0f}%"),
                QTableWidgetItem(pol), QTableWidgetItem(rep.source_file),
            ]
            for c, item in enumerate(cells):
                t.setItem(r, c, item)
        t.setSortingEnabled(True)

    # ----------------------------------------------------------------- export

    def export_html(self) -> None:
        if not self.analysis:
            return
        name = "-".join(sorted(self.analysis.policies)) or "dmarc"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export summary", str(Path(self._last_dir()) / f"XML-ray summary {name}.html"),
            "Web page (*.html)")
        if path:
            Path(path).write_text(html_summary(self.analysis), encoding="utf-8")
            self.statusBar().showMessage(f"Summary saved to {path}", 8000)
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_csv(self) -> None:
        if not self.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export senders", str(Path(self._last_dir()) / "XML-ray senders.csv"),
            "CSV file (*.csv)")
        if path:
            senders_csv(self.analysis, path)
            self.statusBar().showMessage(f"Senders saved to {path}", 8000)

    # ---------------------------------------------------------------- updates

    def check_updates(self, silent: bool) -> None:
        if not silent:
            self.statusBar().showMessage("Checking for updates…")
        worker = UpdateCheckWorker()
        worker.done.connect(lambda info, err: self._update_checked(info, err, silent))
        self._start(worker)

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
        worker = DownloadWorker(info)
        worker.progress.connect(lambda d, t: progress.setValue(int(d * 100 / t)) if t else None)
        progress.canceled.connect(worker.cancel)

        def finished(path: str, err: str):
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
            QApplication.quit()

        worker.done.connect(finished)
        self._start(worker)

    # ------------------------------------------------------------------- misc

    def show_glossary(self) -> None:
        GlossaryDialog(self).exec()

    def show_about(self) -> None:
        QMessageBox.about(self, f"About {APP_NAME}",
                          f"<h3>{APP_NAME} {__version__}</h3><p>{TAGLINE}.</p>"
                          "<p>Reads DMARC aggregate reports on your computer and explains "
                          "them in plain English. Reports are never uploaded anywhere.</p>"
                          f"<p><a href='{GITHUB_URL}'>{GITHUB_URL}</a></p>")

    def _set_busy(self, on: bool, message: str = "") -> None:
        self.busy.setVisible(on)
        self.busy.setRange(0, 0)
        self.add_btn.setEnabled(not on)
        if message:
            self.statusBar().showMessage(message)

    def _start(self, worker: QThread) -> None:
        self._threads.append(worker)
        worker.finished.connect(lambda: self._threads.remove(worker) if worker in self._threads else None)
        worker.start()

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
        for t in list(self._threads):
            if not t.wait(1500):
                t.terminate()
                t.wait(500)
        super().closeEvent(event)
