"""Bring reports in automatically: from an IMAP mailbox, or from a watched folder.

IMAP works with Gmail and Google Workspace (with an app password), Yahoo, iCloud,
Fastmail, Zoho and most hosting providers. Messages are opened read-only and never
marked as read, moved or deleted. Each message is only downloaded once.
"""
from __future__ import annotations

import imaplib
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .parser import SUPPORTED_SUFFIXES, LoadResult, load_bytes

KEYRING_SERVICE = "XML-ray"

PRESETS = {  # provider -> (host, port, hint)
    "Gmail / Google Workspace": ("imap.gmail.com", 993,
                                 "Use an app password (Google Account > Security > "
                                 "2-Step Verification > App passwords)."),
    "Yahoo": ("imap.mail.yahoo.com", 993, "Use an app password from Yahoo account security."),
    "iCloud": ("imap.mail.me.com", 993, "Use an app-specific password from appleid.apple.com."),
    "Fastmail": ("imap.fastmail.com", 993, "Use an app password from Fastmail settings."),
    "Zoho Mail": ("imap.zoho.com", 993, "Turn on IMAP access in Zoho Mail settings first."),
    "Other": ("", 993, "Your provider's IMAP server name is in its help pages."),
}


class MailboxError(Exception):
    pass


@dataclass
class MailboxConfig:
    host: str
    username: str
    port: int = 993
    folder: str = "INBOX"
    days: int = 30            # how far back to look

    @property
    def keyring_user(self) -> str:
        return f"imap:{self.username}@{self.host}"


def get_password(cfg: MailboxConfig) -> str:
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, cfg.keyring_user) or ""
    except Exception:  # noqa: BLE001 - keyring missing or no backend
        return ""


def set_password(cfg: MailboxConfig, password: str) -> bool:
    try:
        import keyring
        if password:
            keyring.set_password(KEYRING_SERVICE, cfg.keyring_user, password)
        else:
            keyring.delete_password(KEYRING_SERVICE, cfg.keyring_user)
        return True
    except Exception:  # noqa: BLE001
        return False


def _connect(cfg: MailboxConfig, password: str) -> imaplib.IMAP4_SSL:
    if not cfg.host or not cfg.username:
        raise MailboxError("Enter the mail server and user name first.")
    try:
        conn = imaplib.IMAP4_SSL(cfg.host, cfg.port, ssl_context=ssl.create_default_context(),
                                 timeout=30)
    except (OSError, imaplib.IMAP4.error) as exc:
        raise MailboxError(f"Couldn't connect to {cfg.host}: {exc}") from exc
    try:
        conn.login(cfg.username, password)
    except imaplib.IMAP4.error as exc:
        conn.logout()
        raise MailboxError("The mail server rejected the user name or password. Many "
                           "providers need an app password instead of your normal one.") from exc
    return conn


def list_folders(cfg: MailboxConfig, password: str) -> list[str]:
    conn = _connect(cfg, password)
    try:
        typ, data = conn.list()
        folders = []
        for line in data or []:
            text = line.decode("utf-8", "replace") if isinstance(line, bytes) else str(line)
            m = re.search(r'\) "?[^"]*"? (.+)$', text)
            if m and "\\Noselect" not in text:
                folders.append(m.group(1).strip().strip('"'))
        return folders
    finally:
        conn.logout()


def _quote(folder: str) -> str:
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def fetch_reports(cfg: MailboxConfig, password: str, storage, progress=None) -> tuple[LoadResult, int]:
    """Download report emails not seen before. Returns (reports found, messages checked)."""
    result = LoadResult()
    conn = _connect(cfg, password)
    try:
        typ, _ = conn.select(_quote(cfg.folder), readonly=True)
        if typ != "OK":
            raise MailboxError(f"Folder “{cfg.folder}” wasn't found.")
        typ, data = conn.response("UIDVALIDITY")
        validity = (data[0].decode() if data and data[0] else "0")
        since = (datetime.now() - timedelta(days=max(cfg.days, 1))).strftime("%d-%b-%Y")
        typ, data = conn.uid("SEARCH", None, "SINCE", since, "OR", "SUBJECT", "Report",
                             "SUBJECT", "Failure")
        if typ != "OK":
            raise MailboxError("The mail server couldn't search this folder.")
        uids = data[0].split() if data and data[0] else []
        prefix = f"imap|{cfg.host}|{cfg.username}|{cfg.folder}|{validity}|"
        keys = {prefix + u.decode(): u for u in uids}
        already = storage.seen(keys)
        new = [k for k in keys if k not in already]
        for i, k in enumerate(new, 1):
            typ, msg = conn.uid("FETCH", keys[k], "(BODY.PEEK[])")
            if typ == "OK" and msg and isinstance(msg[0], tuple):
                sub = load_bytes(msg[0][1], f"email {keys[k].decode()}.eml")
                result.dmarc += sub.dmarc
                result.tls += sub.tls      # emails that aren't reports are simply skipped
                result.forensic += sub.forensic
            if progress:
                progress(i, len(new))
        storage.mark_seen(new)
        return result, len(new)
    except (imaplib.IMAP4.error, OSError) as exc:
        raise MailboxError(f"Mailbox error: {exc}") from exc
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass


def scan_folder(folder: str, storage) -> LoadResult:
    """Load report files in *folder* that haven't been imported before."""
    result = LoadResult()
    root = Path(folder)
    if not root.is_dir():
        return result
    files = [f for f in root.rglob("*") if f.is_file() and f.suffix.lower() in SUPPORTED_SUFFIXES]
    keys = {}
    for f in files:
        try:
            st = f.stat()
        except OSError:
            continue
        keys[f"file|{f.resolve()}|{st.st_size}|{int(st.st_mtime)}"] = f
    already = storage.seen(keys)
    new = [k for k in keys if k not in already]
    for k in new:
        try:
            load_bytes(keys[k].read_bytes(), keys[k].name, result)
        except OSError as exc:
            result.errors.append(f"{keys[k].name}: {exc}")
    storage.mark_seen(new)
    return result
