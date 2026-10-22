"""Road to protection, Lookalikes, report drill-down, What's new and error windows."""
from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from ..config import GITHUB_URL
from .style import SEVERITY, T

ICONS = {"done": "✔", "current": "➜", "todo": "○", "optional": "☆", "optional-done": "★"}


def _table(cols: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


# ================================================================ roadmap

class RoadmapPanel(QScrollArea):
    fix_requested = Signal(object)          # a Finding

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.host = QWidget(objectName="FindingsHost")
        self.lay = QVBoxLayout(self.host)
        self.lay.setContentsMargins(18, 16, 18, 16)
        self.lay.setSpacing(8)
        self.setWidget(self.host)

    def show_roadmaps(self, roadmaps: dict[str, list]) -> None:
        while self.lay.count():
            item = self.lay.takeAt(0)
            w = item.widget()
            if w:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        intro = QLabel("The usual path from watching your email to fully protecting it. "
                       "Work down the list: ➜ marks the next step, and XML-ray tells you when "
                       "each enforcement step is safe.", objectName="Muted")
        intro.setWordWrap(True)
        self.lay.addWidget(intro)
        if not roadmaps:
            self.lay.addWidget(QLabel("Run the DNS check to build your roadmap.",
                                      objectName="Muted"))
        for domain, steps in roadmaps.items():
            head = QLabel(domain, objectName="FindingTitle")
            head.setContentsMargins(0, 10, 0, 2)
            self.lay.addWidget(head)
            done = sum(1 for s in steps if s.status == "done")
            core = sum(1 for s in steps if not s.status.startswith("optional"))
            self.lay.addWidget(QLabel(f"{done} of {core} core steps done.", objectName="Muted"))
            for s in steps:
                self.lay.addWidget(self._row(s))
        self.lay.addStretch(1)

    def _row(self, s) -> QFrame:
        card = QFrame(objectName="FindingCard")
        color = {"done": SEVERITY["good"][1], "current": T["scan"],
                 "optional-done": SEVERITY["good"][1]}.get(s.status, T["muted"])
        if s.status == "current":
            card.setStyleSheet(f"#FindingCard {{ border: 2px solid {T['scan']}; }}")
        row = QHBoxLayout(card)
        row.setContentsMargins(14, 8, 14, 8)
        icon = QLabel(ICONS.get(s.status, "○"))
        icon.setStyleSheet(f"color:{color}; font-size:15pt; font-weight:700;")
        icon.setFixedWidth(28)
        row.addWidget(icon)
        text = QVBoxLayout()
        text.setSpacing(1)
        t = QLabel(s.title)
        t.setStyleSheet("font-weight:600;" + (f"color:{T['muted']};" if s.status == "done" else ""))
        d = QLabel(s.detail, objectName="Muted")
        d.setWordWrap(True)
        text.addWidget(t)
        text.addWidget(d)
        row.addLayout(text, 1)
        enforcement = s.key in ("q25", "q100", "reject")
        if s.fix is not None and s.status not in ("done", "optional-done") and \
                (not enforcement or s.status == "current"):
            b = QPushButton("Show me how", objectName="Primary" if s.status == "current" else "")
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda: self.fix_requested.emit(s.fix))
            row.addWidget(b)
        return card


# ============================================================== lookalikes

class LookalikePanel(QWidget):
    scan_requested = Signal()
    mark = Signal(str, str)                  # domain, "mine" / "ignore" / ""

    COLS = ["Domain", "Risk", "Registered", "Registrar", "Email servers", "Website", "Status"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("TabHost")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        bar = QHBoxLayout()
        self.status = QLabel("XML-ray hasn't looked for lookalike domains yet.")
        self.status.setWordWrap(True)
        bar.addWidget(self.status, 1)
        self.scan_btn = QPushButton("Check for lookalikes now")
        self.scan_btn.clicked.connect(self.scan_requested)
        bar.addWidget(self.scan_btn)
        lay.addLayout(bar)
        lay.addWidget(QLabel("XML-ray tries a few hundred misspellings, look-alike characters "
                             "(like 0 for o) and other endings (.net, .co) and lists the ones "
                             "someone has registered. Ones with email servers can send phishing.",
                             objectName="Muted"))
        self.table = _table(self.COLS)
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.mine_btn = QPushButton("This is mine")
        self.ignore_btn = QPushButton("Ignore")
        self.reset_btn = QPushButton("Clear")
        self.copy_btn = QPushButton("Copy abuse contact")
        for b, st in ((self.mine_btn, "mine"), (self.ignore_btn, "ignore"), (self.reset_btn, "")):
            b.clicked.connect(lambda _=False, v=st: self._mark(v))
            row.addWidget(b)
        self.copy_btn.clicked.connect(self._copy_abuse)
        row.addWidget(self.copy_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.rows: list[dict] = []

    def show_results(self, rows: list[dict], marks: dict[str, str], status: str) -> None:
        self.rows = rows
        self.status.setText(status)
        t = self.table
        t.setRowCount(len(rows))
        risk_words = {"high": ("High: new, can send email", "critical"),
                      "medium": ("Medium: can send email", "medium"),
                      "low": ("Low: website only", "low"), "info": ("Registered, inactive", "low")}
        for i, r in enumerate(rows):
            word, sev = risk_words.get(r["risk"], (r["risk"], "low"))
            mark = marks.get(r["domain"], "")
            risk = QTableWidgetItem(word)
            risk.setForeground(QColor(SEVERITY[sev][1] if not mark else T["muted"]))
            cells = [QTableWidgetItem(r["domain"]), risk,
                     QTableWidgetItem((r.get("created") or "")[:10]),
                     QTableWidgetItem(r.get("registrar", "")),
                     QTableWidgetItem("Yes" if r.get("has_mx") else "No"),
                     QTableWidgetItem("Yes" if r.get("has_web") else "No"),
                     QTableWidgetItem({"mine": "Yours", "ignore": "Ignored"}.get(mark, ""))]
            for c, item in enumerate(cells):
                t.setItem(i, c, item)

    def _selected(self) -> dict | None:
        items = self.table.selectedItems()
        return self.rows[items[0].row()] if items else None

    def _mark(self, status: str):
        r = self._selected()
        if r:
            self.mark.emit(r["domain"], status)

    def _copy_abuse(self):
        r = self._selected()
        if r and r.get("abuse"):
            QGuiApplication.clipboard().setText(r["abuse"])


# =========================================================== report detail

class ReportDialog(QDialog):
    def __init__(self, report, parent=None):
        super().__init__(parent)
        tls = hasattr(report, "policies")
        self.report = report
        if hasattr(report, "auth_failure"):
            self._forensic(report)
            return
        self.setWindowTitle(f"{'TLS' if tls else 'DMARC'} report from {report.org_name}")
        self.resize(980, 640)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Reported by", QLabel(report.org_name))
        form.addRow("Report ID", QLabel(report.report_id))
        form.addRow("Period", QLabel(f"{report.begin:%Y-%m-%d %H:%M} to {report.end:%Y-%m-%d %H:%M} UTC"))
        form.addRow("File", QLabel(report.source_file or "(saved)"))
        if not tls:
            p = report.policy
            form.addRow("Policy published", QLabel(
                f"{p.domain}: p={p.p}" + (f", sp={p.sp}" if p.sp else "") + f", pct={p.pct}, "
                f"adkim={p.adkim}, aspf={p.aspf}"))
            form.addRow("Messages", QLabel(f"{report.total_messages:,} "
                                           f"({report.passed_messages:,} passed DMARC)"))
        lay.addLayout(form)
        tabs = QTabWidget()
        if tls:
            t = _table(["Policy", "Domain", "Successful", "Failed", "Failure details"])
            t.setRowCount(len(report.policies))
            for i, p in enumerate(report.policies):
                det = "; ".join(f"{f.result_type} ×{f.count}" + (f" ({f.receiving_mx})" if f.receiving_mx else "")
                                for f in p.failures)
                for c, v in enumerate([p.policy_type, p.policy_domain, f"{p.success:,}",
                                       f"{p.failure:,}", det]):
                    t.setItem(i, c, QTableWidgetItem(v))
            tabs.addTab(t, "Policies")
        else:
            t = _table(["Server", "Messages", "DMARC", "DKIM (aligned)", "SPF (aligned)",
                        "Receiver did", "From", "Envelope from", "DKIM signatures", "SPF checks",
                        "Notes"])
            t.setRowCount(len(report.records))
            good, bad = SEVERITY["good"][1], SEVERITY["critical"][1]
            for i, r in enumerate(report.records):
                vals = [r.source_ip, f"{r.count:,}", "pass" if r.dmarc_pass else "fail",
                        r.dkim_aligned, r.spf_aligned, r.disposition, r.header_from,
                        r.envelope_from,
                        ", ".join(f"{d.domain} ({d.selector}) {d.result}" for d in r.dkim_results),
                        ", ".join(f"{s.domain} {s.result}" for s in r.spf_results),
                        ", ".join(f"{t}: {c}" if c else t for t, c in r.reasons)]
                for c, v in enumerate(vals):
                    item = QTableWidgetItem(v)
                    if c == 2:
                        item.setForeground(QColor(good if r.dmarc_pass else bad))
                    t.setItem(i, c, item)
            tabs.addTab(t, f"Records ({len(report.records)})")
        raw = QPlainTextEdit(self._pretty())
        raw.setReadOnly(True)
        f = QFont("Cascadia Mono")
        f.setStyleHint(QFont.Monospace)
        raw.setFont(f)
        tabs.addTab(raw, "Original file")
        lay.addWidget(tabs, 1)
        row = QHBoxLayout()
        save = QPushButton("Save a copy…")
        save.clicked.connect(self._save)
        row.addWidget(save)
        row.addStretch(1)
        close = QPushButton("Close", objectName="Primary")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)

    def _forensic(self, r) -> None:
        self.setWindowTitle(f"DMARC failure report from {r.reporter}")
        self.resize(820, 600)
        lay = QVBoxLayout(self)
        note = QLabel("One message that failed DMARC, as the receiving server saw it. Providers "
                      "usually remove personal details before sending these.", objectName="Muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        form = QFormLayout()
        for label, val in (("Reported by", r.reporter), ("Arrived", f"{r.arrival:%Y-%m-%d %H:%M} UTC"),
                           ("Sending server", r.source_ip), ("What failed", r.auth_failure.upper()),
                           ("Domain", r.reported_domain), ("From", r.original_from),
                           ("Envelope sender", r.original_mail_from), ("Subject", r.subject),
                           ("DKIM", f"{r.dkim_domain} ({r.dkim_selector})" if r.dkim_domain else ""),
                           ("Authentication results", r.auth_results)):
            lab = QLabel(val or "(not included)")
            lab.setWordWrap(True)
            lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
            form.addRow(label, lab)
        lay.addLayout(form)
        raw = QPlainTextEdit((r.raw or b"").decode("utf-8", "replace"))
        raw.setReadOnly(True)
        lay.addWidget(raw, 1)
        close = QPushButton("Close", objectName="Primary")
        close.clicked.connect(self.accept)
        lay.addWidget(close, 0, Qt.AlignRight)

    def _pretty(self) -> str:
        raw = self.report.raw or b""
        text = raw.decode("utf-8", "replace")
        try:
            if text.lstrip().startswith("{"):
                return json.dumps(json.loads(text), indent=2)
            from defusedxml.minidom import parseString
            return parseString(raw).toprettyxml(indent="  ")
        except Exception:  # noqa: BLE001
            return text

    def _save(self):
        ext = "json" if (self.report.raw or b"").lstrip()[:1] == b"{" else "xml"
        name = f"{self.report.org_name}-{self.report.report_id}.{ext}".replace("/", "_")
        path, _ = QFileDialog.getSaveFileName(self, "Save report", str(Path.home() / name))
        if path:
            Path(path).write_bytes(self.report.raw or b"")


# ============================================================ what's new

class WhatsNewDialog(QDialog):
    def __init__(self, version: str, notes: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("What's new")
        self.resize(560, 480)
        lay = QVBoxLayout(self)
        head = QLabel(f"<span style='font-size:14pt;font-weight:600'>What's new in XML-ray "
                      f"{html.escape(version)}</span>")
        lay.addWidget(head)
        view = QTextBrowser()
        view.setOpenExternalLinks(True)
        view.setMarkdown(notes or "_This version's release notes aren't available right now._")
        lay.addWidget(view, 1)
        ok = QDialogButtonBox(QDialogButtonBox.Ok)
        ok.accepted.connect(self.accept)
        lay.addWidget(ok)


# ================================================================== errors

class ErrorDialog(QDialog):
    """Shown for unexpected errors, with ways to send the details to the developer."""
    save_diagnostics = Signal()

    def __init__(self, details: str, parent=None):
        super().__init__(parent)
        self.details = details
        self.setWindowTitle("Something went wrong")
        self.resize(620, 420)
        lay = QVBoxLayout(self)
        msg = QLabel("<b>XML-ray ran into an unexpected problem.</b> Your saved reports are "
                     "safe. You can keep working, or send the details below so it can be fixed.")
        msg.setWordWrap(True)
        lay.addWidget(msg)
        box = QPlainTextEdit(details)
        box.setReadOnly(True)
        lay.addWidget(box, 1)
        row = QHBoxLayout()
        copy = QPushButton("Copy details")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(details))
        save = QPushButton("Save diagnostics…")
        save.clicked.connect(self.save_diagnostics)
        report = QPushButton("Report on GitHub")
        report.clicked.connect(self.report)
        for b in (copy, save, report):
            row.addWidget(b)
        row.addStretch(1)
        close = QPushButton("Close", objectName="Primary")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)

    def report(self):
        last = self.details.strip().splitlines()[-1][:120] if self.details.strip() else "Error"
        body = ("**What were you doing when this happened?**\n\n\n**Details**\n```\n"
                + self.details[-3000:] + "\n```\n")
        QDesktopServices.openUrl(QUrl(f"{GITHUB_URL}/issues/new?title={quote(last)}&body={quote(body)}"))
