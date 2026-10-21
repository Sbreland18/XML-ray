"""Dialogs: DMARC basics and update prompts."""
from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractSpinBox, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QRadioButton, QSpinBox, QTabWidget, QTextBrowser, QVBoxLayout,
    QWidget,
)

from .. import mailimport, recordbuilder, winstartup
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

<h3>TLS reports</h3>
<p>Some providers also send <b>SMTP TLS reports</b> (JSON files). They show whether email sent
<i>to</i> you arrived over an encrypted connection. XML-ray reads them in the TLS tab. Turn
them on with a TXT record at <b>_smtp._tls.yourdomain</b>.</p>

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
        view.setStyleSheet("QTextBrowser { border: none; padding: 16px; font-size: 10.5pt; }")
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


# =============================================================== settings

RETENTION = [("Keep all reports", 0), ("Keep 2 years", 730), ("Keep 1 year", 365),
             ("Keep 6 months", 182)]
THEMES = [("Match Windows", "system"), ("Light", "light"), ("Dark", "dark")]


def _hint(text: str) -> QLabel:
    lab = QLabel(text, objectName="Muted")
    lab.setWordWrap(True)
    return lab


class SettingsDialog(QDialog):
    """All preferences. Reads and writes QSettings; the caller re-reads them afterwards."""

    def __init__(self, settings: QSettings, parent=None, start_tab: int = 0):
        super().__init__(parent)
        self.s = settings
        self.setWindowTitle("Settings")
        self.resize(600, 560)
        lay = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._general(), "General")
        self.tabs.addTab(self._mailbox(), "Mailbox")
        self.tabs.addTab(self._folder(), "Watched folder")
        self.tabs.addTab(self._alerts(), "Alerts")
        self.tabs.setCurrentIndex(start_tab)
        lay.addWidget(self.tabs, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _val(self, key, default, typ=str):
        return self.s.value(key, default, type=typ)

    # tabs ---------------------------------------------------------------
    def _general(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        f = QFormLayout(w)
        self.theme = QComboBox()
        for label, key in THEMES:
            self.theme.addItem(label, key)
        self.theme.setCurrentIndex(max(self.theme.findData(self._val("appearance/theme", "system")), 0))
        f.addRow("Appearance", self.theme)
        self.retention = QComboBox()
        for label, days in RETENTION:
            self.retention.addItem(label, days)
        self.retention.setCurrentIndex(
            max(self.retention.findData(self._val("history/retention_days", 0, int)), 0))
        f.addRow("Saved reports", self.retention)
        self.rdns = QCheckBox("Look up server names (reverse DNS)")
        self.rdns.setChecked(self._val("lookup/rdns", True, bool))
        self.rdap = QCheckBox("Look up who owns unknown servers, and their country (RDAP)")
        self.rdap.setChecked(self._val("lookup/rdap", True, bool))
        self.dns = QCheckBox("Check my domain's live DNS records automatically")
        self.dns.setChecked(self._val("lookup/dns", True, bool))
        self.updates = QCheckBox("Check for XML-ray updates when it starts")
        self.updates.setChecked(self._val("updates/check_on_startup", True, bool))
        for cb in (self.rdns, self.rdap, self.dns, self.updates):
            f.addRow("", cb)
        self.tray = QCheckBox("Keep running in the system tray when I close the window")
        self.tray.setChecked(self._val("tray/enabled", False, bool))
        f.addRow("Background", self.tray)
        self.startup = QCheckBox("Start XML-ray when I sign in to Windows")
        self.startup.setChecked(winstartup.is_enabled())
        self.startup.setEnabled(winstartup.supported())
        f.addRow("", self.startup)
        f.addRow("", _hint("Running in the background lets XML-ray check your mailbox and "
                           "watched folder on a schedule and alert you to problems."))
        return w

    def _mailbox(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        v = QVBoxLayout(w)
        self.mail_on = QCheckBox("Import reports from a mailbox automatically")
        self.mail_on.setChecked(self._val("mail/enabled", False, bool))
        v.addWidget(self.mail_on)
        f = QFormLayout()
        self.preset = QComboBox()
        for name in mailimport.PRESETS:
            self.preset.addItem(name)
        self.preset.setCurrentText(self._val("mail/preset", "Gmail / Google Workspace"))
        self.preset.currentTextChanged.connect(self._apply_preset)
        f.addRow("Provider", self.preset)
        self.host = QLineEdit(self._val("mail/host", "imap.gmail.com"))
        self.port = QSpinBox()
        self.port.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.port.setRange(1, 65535)
        self.port.setValue(self._val("mail/port", 993, int))
        row = QHBoxLayout()
        row.addWidget(self.host, 1)
        row.addWidget(QLabel("Port"))
        row.addWidget(self.port)
        f.addRow("IMAP server", row)
        self.user = QLineEdit(self._val("mail/username", ""))
        self.user.setPlaceholderText("dmarc-reports@yourdomain.com")
        f.addRow("User name", self.user)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Saved securely in Windows Credential Manager")
        cfg = mailbox_config(self.s)
        if cfg.username and mailimport.get_password(cfg):
            self.password.setPlaceholderText("•••••••• (saved; type to change)")
        f.addRow("Password", self.password)
        self.preset_hint = _hint("")
        f.addRow("", self.preset_hint)
        frow = QHBoxLayout()
        self.folder = QComboBox()
        self.folder.setEditable(True)
        self.folder.setCurrentText(self._val("mail/folder", "INBOX"))
        test = QPushButton("Test and list folders")
        test.clicked.connect(self._test_mailbox)
        frow.addWidget(self.folder, 1)
        frow.addWidget(test)
        f.addRow("Folder or label", frow)
        self.interval = QSpinBox()
        self.interval.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.interval.setRange(5, 1440)
        self.interval.setSuffix(" minutes")
        self.interval.setValue(self._val("mail/interval_min", 60, int))
        f.addRow("Check every", self.interval)
        self.days = QSpinBox()
        self.days.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.days.setRange(1, 365)
        self.days.setSuffix(" days")
        self.days.setValue(self._val("mail/days", 30, int))
        f.addRow("Look back", self.days)
        v.addLayout(f)
        v.addWidget(_hint("XML-ray only reads messages whose subject contains “Report”. It "
                          "never marks them read, moves or deletes them, and each message is "
                          "downloaded once. Microsoft 365 mailboxes don't allow password "
                          "sign-in over IMAP; for those, use an Outlook rule to save report "
                          "attachments to a folder and watch that folder instead."))
        v.addStretch(1)
        self._apply_preset(self.preset.currentText(), keep_host=True)
        return w

    def _folder(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        v = QVBoxLayout(w)
        self.watch_on = QCheckBox("Watch a folder and load new reports automatically")
        self.watch_on.setChecked(self._val("folder/enabled", False, bool))
        v.addWidget(self.watch_on)
        row = QHBoxLayout()
        self.watch_path = QLineEdit(self._val("folder/path", ""))
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        row.addWidget(self.watch_path, 1)
        row.addWidget(browse)
        v.addLayout(row)
        v.addWidget(_hint("New .xml, .gz, .zip, .json and .eml files dropped into this "
                          "folder (or its subfolders) are loaded within a few seconds while "
                          "XML-ray is running. Each file is read once."))
        v.addStretch(1)
        return w

    def _alerts(self) -> QWidget:
        w = QWidget(objectName="TabHost")
        v = QVBoxLayout(w)
        self.alerts_on = QCheckBox("Look for problems each time new reports arrive")
        self.alerts_on.setChecked(self._val("alerts/enabled", True, bool))
        self.notify = QCheckBox("Show a Windows notification for each alert")
        self.notify.setChecked(self._val("alerts/notify", True, bool))
        v.addWidget(self.alerts_on)
        v.addWidget(self.notify)
        v.addWidget(_hint("You'll be alerted when a server you've never seen before sends "
                          "email as you, when a service that used to pass starts failing, "
                          "or when the share of your legitimate email passing DMARC drops "
                          "by 5 points or more."))
        v.addStretch(1)
        return w

    # helpers ------------------------------------------------------------
    def _apply_preset(self, name: str, keep_host: bool = False):
        host, port, hint = mailimport.PRESETS.get(name, ("", 993, ""))
        if not keep_host and host:
            self.host.setText(host)
            self.port.setValue(port)
        self.preset_hint.setText(hint)

    def _mail_cfg(self) -> mailimport.MailboxConfig:
        return mailimport.MailboxConfig(
            host=self.host.text().strip(), username=self.user.text().strip(),
            port=self.port.value(), folder=self.folder.currentText().strip() or "INBOX",
            days=self.days.value() if hasattr(self, "days") else 30)

    def _password(self) -> str:
        return self.password.text() or mailimport.get_password(self._mail_cfg())

    def _test_mailbox(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            folders = mailimport.list_folders(self._mail_cfg(), self._password())
        except mailimport.MailboxError as exc:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Couldn't connect", str(exc))
            return
        QApplication.restoreOverrideCursor()
        current = self.folder.currentText()
        self.folder.clear()
        self.folder.addItems(folders)
        self.folder.setCurrentText(current if current in folders else "INBOX")
        QMessageBox.information(self, "Connected",
                                f"Signed in. Found {len(folders)} folders. Choose the one "
                                "your DMARC reports arrive in.")

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "Folder to watch", self.watch_path.text())
        if path:
            self.watch_path.setText(path)

    def _save(self):
        s = self.s
        s.setValue("appearance/theme", self.theme.currentData())
        s.setValue("history/retention_days", self.retention.currentData())
        s.setValue("lookup/rdns", self.rdns.isChecked())
        s.setValue("lookup/rdap", self.rdap.isChecked())
        s.setValue("lookup/dns", self.dns.isChecked())
        s.setValue("updates/check_on_startup", self.updates.isChecked())
        s.setValue("tray/enabled", self.tray.isChecked())
        if winstartup.supported():
            try:
                winstartup.set_enabled(self.startup.isChecked())
            except OSError as exc:
                QMessageBox.warning(self, "Couldn't change start-up setting", str(exc))
        cfg = self._mail_cfg()
        if self.mail_on.isChecked() and (not cfg.host or not cfg.username):
            QMessageBox.warning(self, "Mailbox details missing",
                                "Enter the IMAP server and user name, or turn off mailbox import.")
            self.tabs.setCurrentIndex(1)
            return
        if self.password.text():
            if not mailimport.set_password(cfg, self.password.text()):
                QMessageBox.warning(self, "Password not saved",
                                    "The password couldn't be saved in Windows Credential "
                                    "Manager, so automatic mailbox checks won't work.")
        s.setValue("mail/enabled", self.mail_on.isChecked())
        s.setValue("mail/preset", self.preset.currentText())
        s.setValue("mail/host", cfg.host)
        s.setValue("mail/port", cfg.port)
        s.setValue("mail/username", cfg.username)
        s.setValue("mail/folder", cfg.folder)
        s.setValue("mail/interval_min", self.interval.value())
        s.setValue("mail/days", self.days.value())
        if self.watch_on.isChecked() and not self.watch_path.text().strip():
            QMessageBox.warning(self, "Choose a folder", "Choose a folder to watch, or turn "
                                "off folder watching.")
            self.tabs.setCurrentIndex(2)
            return
        s.setValue("folder/enabled", self.watch_on.isChecked())
        s.setValue("folder/path", self.watch_path.text().strip())
        s.setValue("alerts/enabled", self.alerts_on.isChecked())
        s.setValue("alerts/notify", self.notify.isChecked())
        self.accept()


def mailbox_config(s: QSettings) -> mailimport.MailboxConfig:
    return mailimport.MailboxConfig(
        host=s.value("mail/host", ""), username=s.value("mail/username", ""),
        port=s.value("mail/port", 993, type=int), folder=s.value("mail/folder", "INBOX"),
        days=s.value("mail/days", 30, type=int))


# ========================================================= record builder

class RecordBuilderDialog(QDialog):
    def __init__(self, domains: list[str], policies: dict, dns_results: dict,
                 domain: str = "", parent=None):
        super().__init__(parent)
        self.policies, self.dns_results = policies, dns_results
        self.setWindowTitle("DMARC record builder")
        self.resize(680, 720)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        top = QFormLayout()
        self.domain = QComboBox()
        self.domain.setEditable(True)
        self.domain.addItems(domains or ["example.com"])
        if domain:
            self.domain.setCurrentText(domain)
        top.addRow("Domain", self.domain)
        lay.addLayout(top)

        self.recommend = QLabel()
        self.recommend.setWordWrap(True)
        self.recommend.setObjectName("Banner")
        self.recommend.setContentsMargins(10, 8, 10, 8)
        lay.addWidget(self.recommend)

        stage_box = QGroupBox("Policy")
        sv = QVBoxLayout(stage_box)
        self.stage_group = QButtonGroup(self)
        self.stage_buttons = {}
        for i, (key, label, _p, _pct) in enumerate(recordbuilder.STAGES):
            rb = QRadioButton(label)
            self.stage_group.addButton(rb, i)
            self.stage_buttons[key] = rb
            sv.addWidget(rb)
        lay.addWidget(stage_box)

        f = QFormLayout()
        self.rua = QLineEdit()
        self.rua.setPlaceholderText("dmarc-reports@yourdomain.com")
        f.addRow("Send reports to", self.rua)
        self.ruf = QLineEdit()
        self.ruf.setPlaceholderText("Optional. Few providers send these, and they can contain "
                                    "personal data.")
        f.addRow("Failure reports to", self.ruf)
        self.sp = QComboBox()
        for label, val in (("Same as main domain", ""), ("Monitor only (none)", "none"),
                           ("Quarantine", "quarantine"), ("Reject", "reject")):
            self.sp.addItem(label, val)
        f.addRow("Subdomains", self.sp)
        self.strict_dkim = QCheckBox("Strict DKIM alignment (adkim=s)")
        self.strict_spf = QCheckBox("Strict SPF alignment (aspf=s)")
        f.addRow("Advanced", self.strict_dkim)
        f.addRow("", self.strict_spf)
        lay.addLayout(f)

        out = QGroupBox("Add this record in your DNS")
        of = QFormLayout(out)
        self.host_out = QLineEdit()
        self.host_out.setReadOnly(True)
        self.value_out = QLineEdit()
        self.value_out.setReadOnly(True)
        for label, field in (("Name / host", self.host_out), ("Value", self.value_out)):
            row = QHBoxLayout()
            row.addWidget(field, 1)
            copy = QPushButton("Copy")
            copy.clicked.connect(lambda _=False, w=field: QGuiApplication.clipboard().setText(w.text()))
            row.addWidget(copy)
            of.addRow(label, row)
        of.addRow("Type", QLabel("TXT"))
        self.external = _hint("")
        of.addRow("", self.external)
        lay.addWidget(out)
        lay.addWidget(_hint("If a DMARC record already exists, edit it rather than adding a "
                            "second one. Many DNS hosts want only “_dmarc” as the name; they "
                            "add your domain automatically."))
        close = QDialogButtonBox(QDialogButtonBox.Close)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

        for w in (self.rua, self.ruf):
            w.textChanged.connect(self._update)
        for w in (self.sp,):
            w.currentIndexChanged.connect(self._update)
        for w in (self.strict_dkim, self.strict_spf):
            w.toggled.connect(self._update)
        self.stage_group.idToggled.connect(lambda *_: self._update())
        self.domain.currentTextChanged.connect(self._load_domain)
        self._load_domain(self.domain.currentText())

    def _load_domain(self, d: str):
        d = d.strip().lower()
        tags = self.dns_results.get(d).dmarc_tags if self.dns_results.get(d) else {}
        rua = ",".join(u.strip().removeprefix("mailto:") for u in tags.get("rua", "").split(",")
                       if u.strip())
        self.rua.setText(rua or (f"dmarc-reports@{d}" if d else ""))
        pol = self.policies.get(d)
        key, reason = recordbuilder.recommend_stage(pol, bool(pol and pol.ready_to_enforce))
        current = recordbuilder.stage_from_tags(tags) if tags else (
            recordbuilder.stage_from_tags({"p": pol.p, "pct": str(pol.pct)}) if pol else None)
        label = dict((k, lab) for k, lab, _p, _c in recordbuilder.STAGES)[key]
        self.recommend.setText(f"<b>Recommended: {label}.</b> {reason}")
        for k, rb in self.stage_buttons.items():
            rb.setText(dict((a, b) for a, b, _p, _c in recordbuilder.STAGES)[k]
                       + ("  (current)" if k == current else ""))
        self.stage_buttons[key].setChecked(True)
        self._update()

    def options(self) -> recordbuilder.RecordOptions:
        stage = recordbuilder.STAGES[max(self.stage_group.checkedId(), 0)][0]
        return recordbuilder.RecordOptions(
            domain=self.domain.currentText().strip().lower(), stage=stage, rua=self.rua.text(),
            ruf=self.ruf.text(), sp=self.sp.currentData() or "",
            strict_dkim=self.strict_dkim.isChecked(), strict_spf=self.strict_spf.isChecked())

    def _update(self):
        o = self.options()
        self.host_out.setText(f"_dmarc.{o.domain}")
        self.value_out.setText(recordbuilder.build_record(o))
        ext = recordbuilder.external_report_domains(o)
        self.external.setText(
            "Reports go to another domain, so " + " and ".join(ext) + " must publish a TXT "
            f"record at {o.domain}._report._dmarc.<that domain> with the value v=DMARC1. "
            "DMARC reporting services usually do this for you." if ext else "")


# ================================================================== alerts

class AlertsDialog(QDialog):
    def __init__(self, storage, parent=None):
        super().__init__(parent)
        self.storage = storage
        self.setWindowTitle("Alerts")
        self.resize(560, 460)
        lay = QVBoxLayout(self)
        self.list = QListWidget()
        self.list.setWordWrap(True)
        self.list.setSpacing(4)
        lay.addWidget(self.list, 1)
        alerts = storage.recent_alerts()
        if not alerts:
            self.list.addItem("No alerts yet. XML-ray checks for problems each time new "
                              "reports arrive.")
        for a in alerts:
            when = datetime.fromtimestamp(a["ts"]).strftime("%b %d, %Y at %I:%M %p")
            item = QListWidgetItem(f"{a['title']}\n{a['body']}\n{when}")
            if not a["read"]:
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            self.list.addItem(item)
        row = QHBoxLayout()
        clear = QPushButton("Clear all")
        clear.clicked.connect(self._clear)
        row.addWidget(clear)
        row.addStretch(1)
        close = QPushButton("Close", objectName="Primary")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)
        storage.mark_alerts_read()

    def _clear(self):
        self.storage.clear_alerts()
        self.list.clear()
