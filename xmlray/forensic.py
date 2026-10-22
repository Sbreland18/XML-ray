"""DMARC failure (forensic, "ruf") reports: one email per failed message, in the
Abuse Reporting Format (RFC 6591 / 5965). Few providers still send them and most remove
personal details, but when they arrive they show exactly which message failed and why."""
from __future__ import annotations

import email
import email.policy
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


@dataclass
class ForensicReport:
    reporter: str
    arrival: datetime
    source_ip: str
    auth_failure: str           # dmarc, spf, dkim ...
    reported_domain: str
    original_from: str = ""
    original_mail_from: str = ""
    subject: str = ""
    dkim_domain: str = ""
    dkim_selector: str = ""
    auth_results: str = ""
    message_id: str = ""
    source_file: str = ""
    raw: bytes = field(default=b"", repr=False)

    @property
    def key(self) -> tuple[str, str]:
        return (self.reporter.lower(), self.message_id or hashlib.sha1(self.raw).hexdigest())


def _fields(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            k, v = line.split(":", 1)
            out.setdefault(k.strip().lower(), v.strip())
    return out


def looks_like_email(data: bytes) -> bool:
    head = data.lstrip()[:400].lower()
    return any(head.startswith(p) for p in (b"from:", b"received:", b"return-path:",
                                            b"mime-version:", b"delivered-to:", b"message-id:",
                                            b"date:", b"subject:", b"to:", b"x-"))


def parse_forensic(data: bytes, source: str = "") -> ForensicReport | None:
    """A ForensicReport if *data* is a DMARC failure report email, otherwise None."""
    msg = email.message_from_bytes(data, policy=email.policy.default)
    if msg.get_content_type() != "multipart/report" or \
            (msg.get_param("report-type") or "").lower() != "feedback-report":
        return None
    report, headers = {}, {}
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/feedback-report":
            payload = part.get_payload()
            text = "\n".join(str(p) for p in payload) if isinstance(payload, list) else str(payload)
            if not text.strip():
                raw = part.get_payload(decode=True) or b""
                text = raw.decode("utf-8", "replace")
            report = _fields(text)
        elif ctype in ("text/rfc822-headers", "message/rfc822-headers"):
            raw = part.get_payload(decode=True) or str(part.get_payload()).encode()
            headers = _fields(raw.decode("utf-8", "replace"))
        elif ctype == "message/rfc822" and not headers:
            inner = part.get_payload()
            inner = inner[0] if isinstance(inner, list) and inner else inner
            if hasattr(inner, "items"):
                headers = {k.lower(): str(v) for k, v in inner.items()}
    if not report:
        return None
    try:
        arrival = parsedate_to_datetime(report.get("arrival-date") or msg.get("date", ""))
        if arrival.tzinfo is None:
            arrival = arrival.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        arrival = datetime.now(timezone.utc)
    return ForensicReport(
        reporter=str(msg.get("from", "Unknown reporter")),
        arrival=arrival,
        source_ip=report.get("source-ip", ""),
        auth_failure=report.get("auth-failure", report.get("feedback-type", "")),
        reported_domain=report.get("reported-domain", "").lower(),
        original_from=headers.get("from", ""),
        original_mail_from=report.get("original-mail-from", ""),
        subject=headers.get("subject", ""),
        dkim_domain=report.get("dkim-domain", ""),
        dkim_selector=report.get("dkim-selector", ""),
        auth_results=report.get("authentication-results", headers.get("authentication-results", "")),
        message_id=str(msg.get("message-id", "")),
        source_file=source,
        raw=data,
    )


def dedupe_forensic(reports) -> list[ForensicReport]:
    seen: dict = {}
    for r in reports:
        seen.setdefault(r.key, r)
    return sorted(seen.values(), key=lambda r: r.arrival)
