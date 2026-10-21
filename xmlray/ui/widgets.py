"""Reusable building blocks for the XML-ray window."""
from __future__ import annotations

import html
import re

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QTableWidgetItem, QVBoxLayout,
)

from ..analyzer import Finding
from .style import GRADE_COLORS, SEVERITY


def rich(text: str) -> str:
    """Escape text and turn `code` spans into monospace."""
    escaped = html.escape(text)
    return re.sub(r"`([^`]+)`",
                  r"<code style='background:#EEF3F6;padding:1px 4px;'>\1</code>", escaped)


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

    def __init__(self, finding: Finding, parent=None):
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
        top.addStretch(1)
        lay.addLayout(top)

        title = QLabel(finding.title, objectName="FindingTitle")
        title.setWordWrap(True)
        lay.addWidget(title)

        body = QLabel(finding.summary, objectName="FindingBody")
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(body)

        if finding.steps:
            items = "".join(f"<li style='margin-bottom:4px'>{rich(s)}</li>" for s in finding.steps)
            steps = QLabel(f"<b>What to do</b><ol style='margin-top:4px; margin-left:-18px'>{items}</ol>",
                           objectName="FindingBody")
            steps.setTextFormat(Qt.RichText)
            steps.setWordWrap(True)
            steps.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lay.addWidget(steps)

        if finding.ips:
            foot = QHBoxLayout()
            n = len(finding.ips)
            meta = QLabel(f"{finding.affected:,} messages from {n} sending server{'s' if n != 1 else ''}",
                          objectName="FindingMeta")
            foot.addWidget(meta)
            foot.addStretch(1)
            btn = QPushButton("Show these senders")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda: self.show_senders.emit(finding.ips, finding.title))
            foot.addWidget(btn)
            lay.addLayout(foot)


class DropZone(QFrame):
    open_files = Signal()
    open_folder = Signal()
    load_sample = Signal()
    learn_more = Signal()

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
        hint = QLabel("XML, .gz, .zip or .eml files, or a whole folder of them. "
                      "XML-ray reads them on this computer and tells you, in plain "
                      "English, what needs fixing first.", objectName="DropHint")
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignCenter)
        lay.addWidget(hint)
        lay.addSpacing(10)

        row = QHBoxLayout()
        row.addStretch(1)
        b1 = QPushButton("Choose files", objectName="Primary")
        b2 = QPushButton("Choose a folder")
        for b in (b1, b2):
            b.setCursor(Qt.PointingHandCursor)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        b1.clicked.connect(self.open_files)
        b2.clicked.connect(self.open_folder)

        links = QHBoxLayout()
        links.addStretch(1)
        s = QPushButton("Try a sample report", objectName="Link")
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


__all__ = ["StatCard", "GradePanel", "FindingCard", "DropZone", "NumericItem", "rich",
           "GRADE_COLORS"]
