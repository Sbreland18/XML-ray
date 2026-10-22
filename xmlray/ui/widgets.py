"""Reusable building blocks for the XML-ray window."""
from __future__ import annotations

import html
import re
from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QTableWidgetItem, QVBoxLayout,
)

from ..analyzer import Finding
from .style import SEVERITY, T, is_dark

SOURCE_LABELS = {"dns": "From the live DNS check", "tls": "From TLS reports"}


def rich(text: str) -> str:
    """Escape text; turn `code` into monospace and [label](https://url) into links."""
    escaped = html.escape(text, quote=False)
    escaped = re.sub(r"`([^`]+)`",
                     lambda m: f"<code style='background:{T['code']};padding:1px 4px;'>"
                               f"{m.group(1)}</code>", escaped)
    link = T["scan"] if is_dark() else T["scan_dark"]
    return re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
                  lambda m: f"<a style='color:{link}' href='{html.escape(m.group(2))}'>"
                            f"{m.group(1)}</a>", escaped)


class StatCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.title = QLabel(title, objectName="StatTitle")
        self.value = QLabel("–", objectName="StatValue")
        self.sub = QLabel("", objectName="StatSub")
        self.sub.setWordWrap(True)
        for w in (self.title, self.value, self.sub):
            lay.addWidget(w)
        lay.addStretch(1)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def set(self, value: str, sub: str = "", color: str | None = None) -> None:
        self.value.setText(value)
        self.sub.setText(sub)
        self.value.setStyleSheet(f"color:{color};" if color else "")


class GradePanel(QFrame):
    """The one bold element: a big letter grade on the dark 'film' panel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("GradePanel")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(20, 12, 24, 12)
        lay.setSpacing(16)
        self.letter = QLabel("–", objectName="GradeLetter")
        self.letter.setMinimumWidth(56)
        self.letter.setAlignment(Qt.AlignCenter)
        text = QVBoxLayout()
        text.setSpacing(2)
        self.label = QLabel("", objectName="GradeLabel")
        self.sub = QLabel("", objectName="GradeSub")
        text.addStretch(1)
        text.addWidget(self.label)
        text.addWidget(self.sub)
        text.addStretch(1)
        lay.addWidget(self.letter)
        lay.addLayout(text)
        self.setToolTip("The grade combines how much of your legitimate email passes DMARC "
                        "(60%) with how strongly your policy protects you (40%).")

    def set(self, grade: str, label: str, score: int) -> None:
        self.letter.setText(grade)
        color = {"A": "#7FE0A8", "B": "#A9DD8A", "C": "#F2D06B", "D": "#F5A66B",
                 "F": "#F58A8A"}.get(grade, "#E3EDF4")
        self.letter.setStyleSheet(f"color:{color};")
        self.label.setText(label)
        self.sub.setText(f"Health score {score} of 100")


class FindingCard(QFrame):
    show_senders = Signal(list, str)
    toggle_done = Signal(str, bool)
    open_builder = Signal(str)
    fix_requested = Signal(object)

    def __init__(self, finding: Finding, done_at: float | None = None,
                 reopened: bool = False, parent=None):
        super().__init__(parent)
        self.finding = finding
        label, fg, bg = SEVERITY[finding.severity]
        self.setObjectName("FindingCard")
        self.setStyleSheet(f"#FindingCard {{ border-left: 6px solid {fg}; }}")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(6)

        top = QHBoxLayout()
        pill = QLabel(label)
        pill.setStyleSheet(f"background:{bg}; color:{fg}; border-radius:9px; "
                           "padding:2px 10px; font-weight:600; font-size:9pt;")
        top.addWidget(pill)
        if finding.source in SOURCE_LABELS:
            top.addWidget(QLabel(SOURCE_LABELS[finding.source], objectName="FindingMeta"))
        top.addStretch(1)
        if finding.key and finding.severity != "good":
            done = QPushButton("Undo" if done_at and not reopened else "Mark as done",
                               objectName="Small")
            done.setCursor(Qt.PointingHandCursor)
            done.setToolTip("Hide this item. If it's still happening in reports that arrive "
                            "after today, XML-ray brings it back.")
            done.clicked.connect(lambda: self.toggle_done.emit(
                finding.key, not (done_at and not reopened)))
            top.addWidget(done)
        lay.addLayout(top)

        if reopened and done_at:
            when = datetime.fromtimestamp(done_at).strftime("%b %d")
            note = QLabel(f"You marked this done on {when}, but newer reports show it's "
                          "still happening.")
            note.setStyleSheet(f"color:{fg}; font-weight:600;")
            note.setWordWrap(True)
            lay.addWidget(note)

        title = QLabel(finding.title, objectName="FindingTitle")
        title.setWordWrap(True)
        lay.addWidget(title)

        body = QLabel(finding.summary, objectName="FindingBody")
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(body)

        if finding.steps:
            items = "".join(f"<li style='margin-bottom:4px'>{rich(s)}</li>" for s in finding.steps)
            steps = QLabel(f"<b>What to do</b><ol style='margin-top:4px; margin-left:-18px'>"
                           f"{items}</ol>", objectName="FindingBody")
            steps.setTextFormat(Qt.RichText)
            steps.setWordWrap(True)
            steps.setOpenExternalLinks(True)
            steps.setTextInteractionFlags(Qt.TextBrowserInteraction)
            lay.addWidget(steps)

        policy_domain = ""
        for prefix in ("policy-none:", "policy-ready:", "pct:", "sp:", "testing:",
                       "dns:dmarc-missing:", "dns:dmarc-invalid:", "dns:dmarc-no-rua:"):
            if finding.key.startswith(prefix):
                policy_domain = finding.key.split(":")[-1]
        if finding.severity != "good" or finding.ips or policy_domain:
            foot = QHBoxLayout()
            if finding.ips:
                n = len(finding.ips)
                foot.addWidget(QLabel(f"{finding.affected:,} messages from {n} sending "
                                      f"server{'s' if n != 1 else ''}", objectName="FindingMeta"))
            foot.addStretch(1)
            if policy_domain:
                b = QPushButton("Build my DMARC record")
                b.setCursor(Qt.PointingHandCursor)
                b.clicked.connect(lambda: self.open_builder.emit(policy_domain))
                foot.addWidget(b)
            if finding.ips:
                btn = QPushButton("Show these senders")
                btn.setCursor(Qt.PointingHandCursor)
                btn.clicked.connect(lambda: self.show_senders.emit(finding.ips, finding.title))
                foot.addWidget(btn)
            if finding.severity != "good":
                fix = QPushButton("Show me how to fix this", objectName="Primary")
                fix.setCursor(Qt.PointingHandCursor)
                fix.clicked.connect(lambda: self.fix_requested.emit(finding))
                foot.addWidget(fix)
            lay.addLayout(foot)


class DropZone(QFrame):
    open_files = Signal()
    open_folder = Signal()
    load_sample = Signal()
    learn_more = Signal()
    open_settings = Signal()

    def __init__(self, logo_path: str, parent=None):
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setMaximumWidth(720)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(48, 44, 48, 40)
        lay.setSpacing(10)
        lay.setAlignment(Qt.AlignCenter)

        logo = QLabel()
        pm = QPixmap(logo_path)
        if not pm.isNull():
            logo.setPixmap(pm.scaled(88, 88, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        lay.addWidget(logo)

        title = QLabel("Drop your DMARC reports here", objectName="DropTitle")
        title.setAlignment(Qt.AlignCenter)
        lay.addWidget(title)
        hint = QLabel("XML, .gz, .zip, .json or .eml files, or a whole folder of them. "
                      "XML-ray reads them on this computer, keeps them for next time, and "
                      "tells you in plain English what needs fixing first.",
                      objectName="DropHint")
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignCenter)
        lay.addWidget(hint)
        lay.addSpacing(10)

        row = QHBoxLayout()
        row.addStretch(1)
        b1 = QPushButton("Choose files", objectName="Primary")
        b2 = QPushButton("Choose a folder")
        b3 = QPushButton("Import from my mailbox")
        for b in (b1, b2, b3):
            b.setCursor(Qt.PointingHandCursor)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        b1.clicked.connect(self.open_files)
        b2.clicked.connect(self.open_folder)
        b3.clicked.connect(self.open_settings)

        links = QHBoxLayout()
        links.addStretch(1)
        s = QPushButton("Try sample reports", objectName="Link")
        m = QPushButton("What is a DMARC report?", objectName="Link")
        for b in (s, m):
            b.setCursor(Qt.PointingHandCursor)
            links.addWidget(b)
        links.addStretch(1)
        lay.addSpacing(6)
        lay.addLayout(links)
        s.clicked.connect(self.load_sample)
        m.clicked.connect(self.learn_more)

    def set_dragging(self, on: bool) -> None:
        self.setProperty("dragging", "true" if on else "false")
        self.style().unpolish(self)
        self.style().polish(self)


class NumericItem(QTableWidgetItem):
    """Table cell that sorts by number rather than by text."""
    KEY = Qt.UserRole + 1

    def __init__(self, value: float, text: str | None = None):
        super().__init__(text if text is not None else f"{value:,}")
        self.setData(self.KEY, value)
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other):
        a, b = self.data(self.KEY), other.data(self.KEY)
        if a is None or b is None:
            return super().__lt__(other)
        return a < b
