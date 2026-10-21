"""Dialogs: DMARC basics and update prompts."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout,
)

from ..updater import ReleaseInfo

GLOSSARY_HTML = """
<h2 style='margin-top:0'>DMARC in plain English</h2>
<p>Anyone can put your domain in the “From” line of an email. <b>DMARC</b> lets receivers
like Gmail and Outlook check whether an email really came from you, and tells them what to
do when it didn't.</p>

<h3>The two checks</h3>
<p><b>SPF</b> is a list in your DNS of the servers allowed to send email for your domain.
It's like a guest list at the door.</p>
<p><b>DKIM</b> is a digital signature added to each email. Receivers verify it with a public
key in your DNS. It's like a wax seal that proves the letter wasn't tampered with.</p>

<h3>Alignment: the part that trips people up</h3>
<p>For DMARC to pass, SPF or DKIM has to pass <i>for your domain</i>, the one people see in
the From line. Many services (SendGrid, Mailchimp, and others) pass SPF and DKIM for
<i>their</i> domain by default. That's why a sender can show “SPF pass” and still fail
DMARC. The fix is the service's “domain authentication” setting.</p>

<h3>Your policy</h3>
<ul>
<li><b>p=none</b> watches only. Failing email is still delivered. Good for getting started.</li>
<li><b>p=quarantine</b> sends failing email to spam.</li>
<li><b>p=reject</b> blocks failing email entirely. This is the goal.</li>
<li><b>pct</b> applies the policy to only a percentage of failing mail, so you can roll out gradually.</li>
<li><b>sp</b> sets a separate policy for subdomains.</li>
</ul>

<h3>What are these reports?</h3>
<p>Big mailbox providers send you a daily XML file (an <b>aggregate report</b>) listing every
server that sent email using your domain, how many messages, and whether each passed. Your
DMARC record's <b>rua=</b> address decides where they're sent. XML-ray reads those files so you
don't have to.</p>

<h3>The usual path</h3>
<ol>
<li>Publish p=none and collect reports for a few weeks.</li>
<li>Fix every legitimate sender that fails, starting with XML-ray's critical and high items.</li>
<li>Move to p=quarantine with a low pct, then raise it to 100.</li>
<li>Move to p=reject.</li>
</ol>
"""


class GlossaryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("DMARC basics")
        self.resize(640, 640)
        lay = QVBoxLayout(self)
        view = QTextBrowser()
        view.setOpenExternalLinks(True)
        view.setStyleSheet("QTextBrowser { background: white; border: none; padding: 16px; font-size: 10.5pt; }")
        view.setHtml(GLOSSARY_HTML)
        lay.addWidget(view)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


class UpdateDialog(QDialog):
    INSTALL, LATER, SKIP = "install", "later", "skip"

    def __init__(self, info: ReleaseInfo, current: str, can_install: bool, parent=None):
        super().__init__(parent)
        self.choice = self.LATER
        self.setWindowTitle("Update available")
        self.resize(520, 420)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        head = QLabel(f"<span style='font-size:14pt; font-weight:600'>XML-ray {info.version} "
                      f"is available</span><br>You have version {current}.")
        head.setTextFormat(Qt.RichText)
        lay.addWidget(head)

        notes = QTextBrowser()
        notes.setOpenExternalLinks(True)
        notes.setMarkdown(info.notes or "_No release notes were provided._")
        lay.addWidget(notes, 1)

        if not can_install:
            hint = QLabel("This copy can't update itself (it isn't the installed Windows "
                          "version), so the download page will open instead.")
            hint.setWordWrap(True)
            lay.addWidget(hint)

        row = QHBoxLayout()
        skip = QPushButton("Skip this version")
        later = QPushButton("Remind me later")
        install = QPushButton("Install and restart" if can_install else "Open download page",
                              objectName="Primary")
        row.addWidget(skip)
        row.addStretch(1)
        row.addWidget(later)
        row.addWidget(install)
        lay.addLayout(row)
        install.setDefault(True)

        skip.clicked.connect(lambda: self._done(self.SKIP))
        later.clicked.connect(lambda: self._done(self.LATER))
        install.clicked.connect(lambda: self._done(self.INSTALL))

    def _done(self, choice: str) -> None:
        self.choice = choice
        self.accept()
