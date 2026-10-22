"""Setup wizard, “Add a new email service”, and organization management windows."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton,
    QRadioButton, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import dnscheck, services
from ..analyzer import Finding
from .style import SEVERITY, T
from .tasks import Task, start


def _title(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setStyleSheet("font-size:16pt; font-weight:600;")
    lab.setWordWrap(True)
    return lab


def _text(text: str, muted: bool = False) -> QLabel:
    lab = QLabel(text, objectName="Muted" if muted else "FindingBody")
    lab.setWordWrap(True)
    lab.setTextFormat(Qt.RichText)
    lab.setOpenExternalLinks(True)
    return lab


# ============================================================ first run

class SetupWizard(QDialog):
    """Walks a new user from “what's your domain?” to reports arriving."""
    show_fix = Signal(object, object)       # Finding, DnsResult
    open_settings = Signal(int)
    load_sample = Signal()
    finished_setup = Signal(str)             # domain

    def __init__(self, parent=None, org_name: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Set up XML-ray")
        self.resize(640, 520)
        self.domain = ""
        self.res = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 20)
        self.pages = QStackedWidget()
        lay.addWidget(self.pages, 1)
        self.pages.addWidget(self._welcome(org_name))
        self.pages.addWidget(self._results())
        self.pages.addWidget(self._reports())
        self.pages.addWidget(self._done())
        nav = QHBoxLayout()
        self.skip = QPushButton("Skip setup", objectName="Link")
        self.skip.clicked.connect(self.reject)
        nav.addWidget(self.skip)
        nav.addStretch(1)
        self.back = QPushButton("Back")
        self.back.clicked.connect(lambda: self.pages.setCurrentIndex(self.pages.currentIndex() - 1))
        self.next = QPushButton("Check my domain", objectName="Primary")
        self.next.clicked.connect(self._next)
        nav.addWidget(self.back)
        nav.addWidget(self.next)
        lay.addLayout(nav)
        self.pages.currentChanged.connect(self._update_nav)
        self._update_nav(0)

    # pages ----------------------------------------------------------------
    def _welcome(self, org_name: str) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(_title("Let's get XML-ray watching your email" +
                           (f" for {html.escape(org_name)}" if org_name else "")))
        v.addWidget(_text("XML-ray reads the reports that Gmail, Outlook, Yahoo and others "
                          "send about email using your domain, and tells you in plain English "
                          "what to fix. This takes about two minutes."))
        v.addSpacing(12)
        form = QFormLayout()
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("yourcompany.com")
        self.domain_edit.returnPressed.connect(self._next)
        form.addRow("Your email domain", self.domain_edit)
        v.addLayout(form)
        v.addWidget(_text("The part after the @ in your email address.", muted=True))
        v.addStretch(1)
        return w

    def _results(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.res_title = _title("Checking…")
        v.addWidget(self.res_title)
        self.res_rows = QVBoxLayout()
        v.addLayout(self.res_rows)
        self.res_action = QPushButton("Create my DMARC record", objectName="Primary")
        self.res_action.clicked.connect(self._create_dmarc)
        self.res_action.setVisible(False)
        v.addWidget(self.res_action, 0, Qt.AlignLeft)
        v.addStretch(1)
        return w

    def _reports(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(_title("How should XML-ray get your reports?"))
        self.rua_note = _text("")
        v.addWidget(self.rua_note)
        self.opt_mail = QRadioButton("Import them from a mailbox automatically (recommended)")
        self.opt_folder = QRadioButton("Watch a folder I save them into")
        self.opt_manual = QRadioButton("I'll add report files myself")
        self.opt_mail.setChecked(True)
        for rb in (self.opt_mail, self.opt_folder, self.opt_manual):
            v.addWidget(rb)
        v.addWidget(_text("Providers send one report a day, so the first ones arrive within "
                          "24 to 48 hours of DMARC being set up.", muted=True))
        v.addStretch(1)
        return w

    def _done(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(_title("You're all set"))
        self.done_text = _text("")
        v.addWidget(self.done_text)
        sample = QPushButton("Explore sample reports while you wait")
        sample.clicked.connect(lambda: (self.load_sample.emit(), self.accept()))
        v.addWidget(sample, 0, Qt.AlignLeft)
        v.addStretch(1)
        return w

    # flow -------------------------------------------------------------------
    def _update_nav(self, idx: int):
        self.back.setVisible(idx in (1, 2))
        self.skip.setVisible(idx < 3)
        self.next.setText({0: "Check my domain", 1: "Next", 2: "Next", 3: "Finish"}[idx])

    def _next(self):
        idx = self.pages.currentIndex()
        if idx == 0:
            d = self.domain_edit.text().strip().lower()
            d = d.split("@")[-1].removeprefix("https://").removeprefix("http://").strip("/ .")
            if "." not in d or " " in d:
                QMessageBox.warning(self, "Check the domain", "Enter a domain like yourcompany.com.")
                return
            self.domain = d
            self.pages.setCurrentIndex(1)
            self.next.setEnabled(False)
            self.res_title.setText(f"Checking {d}…")
            start(Task(dnscheck.check_domain, d), self._checked)
        elif idx == 1:
            self.pages.setCurrentIndex(2)
        elif idx == 2:
            choice = 1 if self.opt_mail.isChecked() else 2 if self.opt_folder.isChecked() else 0
            self.done_text.setText(
                f"XML-ray will watch <b>{html.escape(self.domain)}</b>. "
                + ("Next, enter your mailbox details in the window that opens. "
                   if choice == 1 else "Next, choose the folder in the window that opens. "
                   if choice == 2 else "Add report files any time with Add reports. ")
                + "Your action plan fills in as reports arrive.")
            self._settings_tab = choice
            self.pages.setCurrentIndex(3)
        else:
            self.finished_setup.emit(self.domain)
            self.accept()
            if getattr(self, "_settings_tab", 0):
                self.open_settings.emit(self._settings_tab)

    def _checked(self, res, err):
        self.next.setEnabled(True)
        while self.res_rows.count():
            item = self.res_rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if err or res is None or res.error:
            self.res_title.setText("Couldn't check your domain right now")
            self.res_rows.addWidget(_text(html.escape(err or (res.error if res else "")) +
                                          "<br>You can continue; XML-ray checks again later."))
            return
        self.res = res
        good, bad, mid = SEVERITY["good"][1], SEVERITY["high"][1], SEVERITY["medium"][1]

        def row(ok, title, text):
            color = good if ok is True else bad if ok is False else mid
            icon = "✔" if ok is True else "✖" if ok is False else "!"
            self.res_rows.addWidget(_text(f"<span style='color:{color};font-size:13pt'>{icon}</span>"
                                          f" <b>{title}</b>: {text}"))
        has_dmarc = bool(res.dmarc_record)
        row(has_dmarc, "DMARC", f"set up (p={res.dmarc_tags.get('p', '?')})" if has_dmarc else
            "not set up yet. Without it, no reports are sent.")
        row(bool(res.spf_record) or None, "SPF", "set up" if res.spf_record else
            "not found. You can fix this later from the action plan.")
        row(bool(res.dkim_found) or None, "DKIM", "keys found" if res.dkim_found else
            "not found among common names. XML-ray will learn your services from the reports.")
        self.res_title.setText(f"Here's where {res.domain} stands")
        self.res_action.setVisible(not has_dmarc)
        rua = res.dmarc_tags.get("rua", "")
        if rua:
            self.rua_note.setText(f"Your DMARC record sends reports to <b>{html.escape(rua)}</b>. "
                                  "Connect that mailbox, or a folder its reports are saved to.")
        else:
            self.rua_note.setText("Once your DMARC record has a report address (rua=), reports "
                                  "go to that mailbox.")

    def _create_dmarc(self):
        f = Finding("critical", f"{self.domain} has no DMARC record", "Without a DMARC record, "
                    "receivers don't check or report on email that uses your name.", [], 0, [],
                    key=f"dns:dmarc-missing:{self.domain}", source="dns")
        self.show_fix.emit(f, self.res)


# ======================================================== new service

class ServicePicker(QDialog):
    def __init__(self, domains: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add a new email service")
        self.resize(560, 560)
        lay = QVBoxLayout(self)
        lay.addWidget(_title("Which service will send email for you?"))
        lay.addWidget(_text("Set it up before it starts sending, so its email passes DMARC "
                            "from day one.", muted=True))
        form = QFormLayout()
        self.domain = QComboBox()
        self.domain.setEditable(True)
        self.domain.addItems(domains)
        form.addRow("Your domain", self.domain)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search (for example Mailchimp)")
        self.search.textChanged.connect(self._filter)
        form.addRow("Service", self.search)
        lay.addLayout(form)
        self.list = QListWidget()
        for s in services.CATALOG:
            item = QListWidgetItem(f"{s.name}    ·    {s.category}")
            item.setData(Qt.UserRole, s.name)
            self.list.addItem(item)
        self.list.itemDoubleClicked.connect(lambda _i: self.accept())
        self.list.setCurrentRow(0)
        lay.addWidget(self.list, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        go = QPushButton("Show me the steps", objectName="Primary")
        go.clicked.connect(self.accept)
        row.addWidget(cancel)
        row.addWidget(go)
        lay.addLayout(row)

    def _filter(self, text: str):
        t = text.lower()
        first = None
        for i in range(self.list.count()):
            item = self.list.item(i)
            hide = bool(t) and t not in item.text().lower() and item.data(Qt.UserRole) != "Other service"
            item.setHidden(hide)
            if not hide and first is None:
                first = i
        if first is not None:
            self.list.setCurrentRow(first)

    def choice(self):
        item = self.list.currentItem()
        return (services.by_name(item.data(Qt.UserRole)) if item else None,
                self.domain.currentText().strip().lower())


# ======================================================== organizations

class OrganizationsDialog(QDialog):
    """Add, rename, remove and switch between organizations."""

    def __init__(self, profiles, parent=None):
        super().__init__(parent)
        self.profiles = profiles
        self.switch_to = None
        self.setWindowTitle("Organizations")
        self.resize(520, 420)
        lay = QVBoxLayout(self)
        lay.addWidget(_text("Keep each organization (or client) separate: its own reports, "
                            "domains, mailbox, alerts and weekly summary. Mailboxes and "
                            "watched folders of all organizations are checked in the background."))
        self.list = QListWidget()
        lay.addWidget(self.list, 1)
        row = QHBoxLayout()
        for label, slot in (("Add…", self._add), ("Rename…", self._rename), ("Remove…", self._remove)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        go = QPushButton("Open", objectName="Primary")
        go.clicked.connect(self._open)
        row.addWidget(go)
        lay.addLayout(row)
        self.list.itemDoubleClicked.connect(lambda _i: self._open())
        self._fill()

    def _fill(self):
        self.list.clear()
        active = self.profiles.active()
        for p in self.profiles.list():
            item = QListWidgetItem(p["name"] + ("    (open now)" if p["id"] == active else ""))
            item.setData(Qt.UserRole, p["id"])
            self.list.addItem(item)

    def _selected(self):
        item = self.list.currentItem()
        return item.data(Qt.UserRole) if item else None

    def _add(self):
        name, ok = QInputDialog.getText(self, "Add an organization", "Organization name:")
        if ok and name.strip():
            self.switch_to = self.profiles.add(name.strip())
            self.accept()

    def _rename(self):
        pid = self._selected()
        if pid:
            name, ok = QInputDialog.getText(self, "Rename", "New name:", text=self.profiles.name(pid))
            if ok and name.strip():
                self.profiles.rename(pid, name.strip())
                self._fill()

    def _remove(self):
        pid = self._selected()
        if not pid:
            return
        if pid == "default":
            QMessageBox.information(self, "Can't remove", "The first organization can't be "
                                    "removed, but you can rename it.")
            return
        if pid == self.profiles.active():
            QMessageBox.information(self, "Open another first", "Open a different organization "
                                    "before removing this one.")
            return
        if QMessageBox.question(self, "Remove organization",
                                f"Remove {self.profiles.name(pid)} and all its saved reports "
                                "from XML-ray? Original report files and emails aren't touched.") \
                == QMessageBox.Yes:
            self.profiles.remove(pid)
            self._fill()

    def _open(self):
        pid = self._selected()
        if pid and pid != self.profiles.active():
            self.switch_to = pid
        self.accept()


class OverviewDialog(QDialog):
    """Every organization at a glance."""

    def __init__(self, rows: list[dict], parent=None):
        super().__init__(parent)
        self.switch_to = None
        self.setWindowTitle("All organizations")
        self.resize(900, 460)
        lay = QVBoxLayout(self)
        lay.addWidget(_text("A summary of each organization from the last time XML-ray "
                            "processed its reports. Double-click one to open it.", muted=True))
        cols = ["Organization", "Grade", "Score", "Passing", "To do", "Domains", "Latest report",
                "Updated"]
        t = QTableWidget(len(rows), len(cols))
        t.setHorizontalHeaderLabels(cols)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        t.horizontalHeader().setStretchLastSection(True)
        grade_colors = {"A": SEVERITY["good"][1], "B": SEVERITY["good"][1],
                        "C": SEVERITY["medium"][1], "D": SEVERITY["high"][1], "F": SEVERITY["critical"][1]}
        for i, r in enumerate(rows):
            s = r.get("snapshot") or {}
            vals = [r["name"], s.get("grade", "–"), str(s.get("score", "")),
                    f"{s['pass_pct']:.1f}%" if "pass_pct" in s else "", str(s.get("actions", "")),
                    ", ".join(s.get("domains", [])), (s.get("latest") or "")[:10],
                    (s.get("updated") or "never")[:16].replace("T", " ")]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setData(Qt.UserRole, r["id"])
                if c == 1 and v in grade_colors:
                    item.setForeground(QColor(grade_colors[v]))
                t.setItem(i, c, item)
        t.itemDoubleClicked.connect(lambda it: self._open(t.item(it.row(), 0).data(Qt.UserRole)))
        lay.addWidget(t, 1)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        lay.addWidget(close, 0, Qt.AlignRight)

    def _open(self, pid):
        self.switch_to = pid
        self.accept()


# =================================================== bulk sender rules

class SenderRulesPanel(QWidget):
    fix_requested = Signal(object)

    ICON = {"pass": ("✔", "good"), "fail": ("✖", "critical"), "warn": ("!", "medium"),
            "unknown": ("?", "low"), "manual": ("i", "low")}

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FindingsHost")
        from PySide6.QtWidgets import QScrollArea
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        host = QWidget(objectName="FindingsHost")
        self.lay = QVBoxLayout(host)
        self.lay.setContentsMargins(18, 16, 18, 16)
        self.lay.setSpacing(8)
        scroll.setWidget(host)
        outer.addWidget(scroll)

    def show_rules(self, per_domain: dict[str, list], postmaster: dict) -> None:
        while self.lay.count():
            item = self.lay.takeAt(0)
            w = item.widget()
            if w:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        self.lay.addWidget(_text(
            "Gmail, Yahoo and Outlook.com reject or junk mail from domains that send 5,000 or "
            "more messages a day to their users and don't meet these rules. They're good "
            "practice for every sender.", muted=True))
        for domain, reqs in per_domain.items():
            self.lay.addWidget(_title(domain))
            for r in reqs:
                self.lay.addWidget(self._row(r))
            pm = postmaster.get(domain)
            self.lay.addWidget(self._postmaster(pm))
        if not per_domain:
            self.lay.addWidget(_text("Add reports or run the DNS check to see these rules."))
        self.lay.addStretch(1)

    def _row(self, r) -> QFrame:
        card = QFrame(objectName="FindingCard")
        h = QHBoxLayout(card)
        h.setContentsMargins(14, 8, 14, 8)
        icon, sev = self.ICON.get(r.status, ("?", "low"))
        lab = QLabel(icon)
        lab.setFixedWidth(26)
        lab.setStyleSheet(f"color:{SEVERITY[sev][1]}; font-size:14pt; font-weight:700;")
        h.addWidget(lab)
        v = QVBoxLayout()
        v.setSpacing(1)
        title = QLabel(f"<b>{html.escape(r.title)}</b> "
                       f"<span style='color:{T['muted']}'>({html.escape(r.who)})</span>")
        detail = QLabel(r.detail, objectName="Muted")
        detail.setWordWrap(True)
        v.addWidget(title)
        v.addWidget(detail)
        h.addLayout(v, 1)
        if r.fix is not None and r.status in ("fail", "warn"):
            b = QPushButton("Show me how")
            b.clicked.connect(lambda: self.fix_requested.emit(r.fix))
            h.addWidget(b)
        return card

    def _postmaster(self, pm) -> QWidget:
        if not pm:
            return _text("<b>Gmail Postmaster Tools:</b> not connected. Connect it in "
                         "Tools &gt; Settings &gt; Gmail Postmaster to see Gmail's own spam "
                         "rate for your mail.", muted=True)
        if pm.get("error") and not pm.get("summary"):
            return _text(f"<b>Gmail Postmaster Tools:</b> {html.escape(pm['error'])}", muted=True)
        s = pm.get("summary") or {}

        def pct(v, digits=1):
            return "no data" if v is None else f"{v * 100:.{digits}f}%"
        when = (pm.get("fetched") or "")[:16].replace("T", " ")
        return _text(
            f"<b>Gmail Postmaster Tools</b> (7-day average, updated {html.escape(when)}): "
            f"spam rate {pct(s.get('spam_rate'), 2)}, DMARC pass {pct(s.get('dmarc'))}, "
            f"DKIM pass {pct(s.get('dkim'))}, SPF pass {pct(s.get('spf'))}, "
            f"delivery errors {pct(s.get('delivery_errors'), 2)}.")
