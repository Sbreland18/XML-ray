"""“Show me how to fix this”: the exact change, where to make it, and a way to confirm it."""
from __future__ import annotations

import html
from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from .. import fixguide
from ..dnscheck import DohResolver
from .style import SEVERITY, T
from .tasks import Task, start
from .widgets import rich

ACTION_WORDS = {"add": "Add a {t} record", "change": "Change the {t} record",
                "delete": "Delete this {t} record",
                "from_provider": "Add a {t} record using the value from the service"}


def _mono() -> QFont:
    f = QFont("Cascadia Mono")
    f.setStyleHint(QFont.Monospace)
    f.setPointSizeF(9.5)
    return f


def token_diff(old: str, new: str) -> tuple[str, str]:
    """HTML for old/new values with removed parts struck through and added parts bold."""
    sep = ";" if old.lower().startswith("v=dmarc1") or new.lower().startswith("v=dmarc1") else " "

    def toks(v):
        return [t.strip() for t in v.split(sep) if t.strip()]
    a, b = toks(old), toks(new)
    joiner = "; " if sep == ";" else " "
    bad, good = SEVERITY["critical"][1], SEVERITY["good"][1]
    old_html = joiner.join(
        html.escape(t) if t in b else
        f"<span style='color:{bad};text-decoration:line-through'>{html.escape(t)}</span>" for t in a)
    new_html = joiner.join(
        html.escape(t) if t in a else
        f"<span style='color:{good};font-weight:600'>{html.escape(t)}</span>" for t in b)
    return old_html, new_html


def _copy_row(text: str, multiline: bool = False) -> QWidget:
    w = QWidget()
    row = QHBoxLayout(w)
    row.setContentsMargins(0, 0, 0, 0)
    if multiline:
        field = QPlainTextEdit(text)
        field.setReadOnly(True)
        field.setFixedHeight(min(220, 24 + 18 * (text.count("\n") + 1)))
    else:
        field = QLineEdit(text)
        field.setReadOnly(True)
        field.setCursorPosition(0)
    field.setFont(_mono())
    row.addWidget(field, 1)
    copy = QPushButton("Copy")
    copy.clicked.connect(lambda: (QGuiApplication.clipboard().setText(text),
                                  copy.setText("Copied")))
    row.addWidget(copy, 0, Qt.AlignTop)
    return w


def _section(title: str) -> QLabel:
    lab = QLabel(title, objectName="FindingTitle")
    lab.setContentsMargins(0, 8, 0, 0)
    return lab


class FixGuideDialog(QDialog):
    fixed = Signal(str)          # domain to re-check after a successful verification

    def __init__(self, plan: fixguide.FixPlan, host: fixguide.HostGuide, parent=None):
        super().__init__(parent)
        self.plan, self.host = plan, host
        self.setWindowTitle("How to fix this")
        self.resize(820, 760)
        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget(objectName="FindingsHost")
        lay = QVBoxLayout(body)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        title = QLabel(plan.title, objectName="FindingTitle")
        title.setWordWrap(True)
        title.setStyleSheet("font-size:14pt;")
        lay.addWidget(title)
        why = QLabel(plan.why, objectName="FindingBody")
        why.setWordWrap(True)
        lay.addWidget(why)

        n = 1
        if plan.changes:
            lay.addWidget(_section(f"{n}. Make {'this change' if len(plan.changes) == 1 else 'these changes'} in your DNS"))
            n += 1
            for c in plan.changes:
                lay.addWidget(self._change_card(c))
        for f in plan.files:
            lay.addWidget(_section(f"{n}. Put this file on a website"))
            n += 1
            lay.addWidget(_copy_row(f.url))
            lay.addWidget(_copy_row(f.content, multiline=True))
            if f.note:
                lay.addWidget(QLabel(f.note, objectName="Muted"))
        if plan.changes:
            lay.addWidget(_section(f"{n}. Where to make the change"))
            n += 1
            host_row = QHBoxLayout()
            where = QLabel(f"Your DNS is hosted at <b>{html.escape(host.name)}</b>."
                           if host.name != "your DNS provider" else
                           "XML-ray couldn't tell who hosts your DNS. These general steps "
                           "work for most providers.")
            where.setWordWrap(True)
            host_row.addWidget(where, 1)
            if host.url:
                open_btn = QPushButton(f"Open {host.name.split(' (')[0]}")
                open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(host.url)))
                host_row.addWidget(open_btn)
            lay.addLayout(host_row)
            steps = "".join(f"<li style='margin-bottom:3px'>{rich(s)}</li>" for s in host.steps)
            quirks = "".join(f"<li style='margin-bottom:3px'>{rich(q)}</li>" for q in host.quirks)
            text = f"<ol style='margin-left:-18px'>{steps}</ol>"
            if quirks:
                text += f"<b>Good to know</b><ul style='margin-left:-18px'>{quirks}</ul>"
            lab = QLabel(text, objectName="FindingBody")
            lab.setWordWrap(True)
            lab.setOpenExternalLinks(True)
            lay.addWidget(lab)
        if plan.steps:
            lay.addWidget(_section(f"{n}. {'Other steps' if plan.changes else 'What to do'}"))
            n += 1
            items = "".join(f"<li style='margin-bottom:4px'>{rich(s)}</li>" for s in plan.steps)
            lab = QLabel(f"<ol style='margin-left:-18px'>{items}</ol>", objectName="FindingBody")
            lab.setWordWrap(True)
            lab.setOpenExternalLinks(True)
            lab.setTextInteractionFlags(Qt.TextBrowserInteraction)
            lay.addWidget(lab)
        for note in plan.notes:
            lab = QLabel(note, objectName="Muted")
            lab.setWordWrap(True)
            lay.addWidget(lab)

        self.result = QLabel()
        self.result.setWordWrap(True)
        self.result.setTextFormat(Qt.RichText)
        self.result.setObjectName("Banner")
        self.result.setContentsMargins(12, 10, 12, 10)
        self.result.setVisible(False)
        lay.addWidget(self.result)
        lay.addStretch(1)

        buttons = QHBoxLayout()
        send = QPushButton("Send these steps to someone")
        send.clicked.connect(self.send_steps)
        buttons.addWidget(send)
        buttons.addStretch(1)
        self.check_btn = QPushButton("Check if it worked", objectName="Primary")
        self.check_btn.clicked.connect(self.verify)
        self.check_btn.setVisible(bool(plan.changes))
        buttons.addWidget(self.check_btn)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        outer.addLayout(buttons)

    def _change_card(self, c: fixguide.RecordChange) -> QFrame:
        card = QFrame(objectName="FindingCard")
        card.setStyleSheet(f"#FindingCard {{ border-left: 6px solid {T['scan']}; }}")
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 10, 14, 12)
        head = QLabel(ACTION_WORDS.get(c.action, c.action).format(t=c.rtype))
        head.setStyleSheet("font-weight:600;")
        v.addWidget(head)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        name = fixguide.display_name(c.host, self.plan.domain, self.host)
        form.addRow("Name / host", _copy_row(name))
        if name != c.host:
            form.addRow("", QLabel(f"Full name: {c.host}", objectName="Muted"))
        form.addRow("Type", QLabel(c.rtype))
        if c.current and c.action != "delete":
            old_html, new_html = token_diff(c.current, c.proposed) if c.exact else (
                html.escape(c.current), html.escape(c.proposed))
            cur = QLabel(f"<span style='font-family:Cascadia Mono,Consolas,monospace'>{old_html}</span>")
            cur.setWordWrap(True)
            cur.setTextInteractionFlags(Qt.TextSelectableByMouse)
            form.addRow("Current value", cur)
            if c.exact:
                diff = QLabel(f"<span style='font-family:Cascadia Mono,Consolas,monospace'>{new_html}</span>")
                diff.setWordWrap(True)
                form.addRow("What changes", diff)
        if c.action == "delete":
            form.addRow("Value to delete", _copy_row(c.current))
        elif c.exact:
            form.addRow("New value", _copy_row(c.proposed))
            if len(c.proposed) > 255:
                form.addRow("Split version", _copy_row(fixguide.split_txt(c.proposed)))
                form.addRow("", QLabel("Use the split version if your DNS host says the value "
                                       "is too long.", objectName="Muted"))
        else:
            val = QLabel(html.escape(c.proposed))
            val.setWordWrap(True)
            form.addRow("Value", val)
        v.addLayout(form)
        if c.note:
            note = QLabel(c.note, objectName="Muted")
            note.setWordWrap(True)
            v.addWidget(note)
        return card

    # ------------------------------------------------------------- actions
    def verify(self):
        self.check_btn.setEnabled(False)
        self.check_btn.setText("Checking…")
        start(Task(fixguide.verify_changes, self.plan, DohResolver()), self._verified)

    def _verified(self, out, err):
        self.check_btn.setEnabled(True)
        self.check_btn.setText("Check again")
        self.result.setVisible(True)
        if err:
            self.result.setText(f"<b>Couldn't check right now.</b> {html.escape(err)}")
            return
        results, ttl = out
        good, bad = SEVERITY["good"][1], SEVERITY["high"][1]
        rows = "".join(
            f"<li><span style='color:{good if r.ok else bad}'>{'✔' if r.ok else '✖'}</span> "
            f"{html.escape(r.change.rtype)} at {html.escape(r.change.host)}: "
            f"{html.escape(r.message)}</li>" for r in results)
        if all(r.ok for r in results):
            head = "<b>It worked.</b> XML-ray is re-checking your domain now."
            self.fixed.emit(self.plan.domain)
        else:
            head = ("<b>Not finished yet.</b> If you've just made the change, give it time: "
                    f"DNS servers can keep the old value for up to {fixguide.human_ttl(ttl)}.")
        self.result.setText(f"{head}<ul style='margin-left:-18px'>{rows}</ul>")

    def send_steps(self):
        subject, body = fixguide.email_text(self.plan, self.host)
        SendStepsDialog(subject, body, self).exec()


class SendStepsDialog(QDialog):
    """Ready-to-send instructions for an IT person, web host or DNS provider."""

    def __init__(self, subject: str, body: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Send these steps to someone")
        self.resize(640, 560)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.to = QLineEdit()
        self.to.setPlaceholderText("it-support@yourcompany.com (optional)")
        self.subject = QLineEdit(subject)
        form.addRow("To", self.to)
        form.addRow("Subject", self.subject)
        lay.addLayout(form)
        self.body = QPlainTextEdit(body)
        self.body.setFont(_mono())
        lay.addWidget(self.body, 1)
        lay.addWidget(QLabel("You can edit the message before sending it.", objectName="Muted"))
        row = QHBoxLayout()
        for label, slot in (("Copy message", self.copy), ("Save as a text file…", self.save)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        mail = QPushButton("Open in my email app", objectName="Primary")
        mail.clicked.connect(self.open_mail)
        row.addWidget(mail)
        lay.addLayout(row)
        close = QDialogButtonBox(QDialogButtonBox.Close)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

    def copy(self):
        QGuiApplication.clipboard().setText(f"Subject: {self.subject.text()}\n\n"
                                            f"{self.body.toPlainText()}")

    def save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save steps", str(Path.home() / "DNS change.txt"),
                                              "Text file (*.txt)")
        if path:
            Path(path).write_text(f"Subject: {self.subject.text()}\n\n{self.body.toPlainText()}",
                                  encoding="utf-8")

    def open_mail(self):
        body = self.body.toPlainText()
        url = f"mailto:{quote(self.to.text().strip())}?subject={quote(self.subject.text())}"
        if len(body) < 1800:
            url += f"&body={quote(body)}"
        else:                      # too long for a mailto link: paste it instead
            QGuiApplication.clipboard().setText(body)
            QMessageBox.information(self, "Message copied",
                                    "The message is long, so it's been copied. Paste it into "
                                    "the email that opens.")
        QDesktopServices.openUrl(QUrl(url))
