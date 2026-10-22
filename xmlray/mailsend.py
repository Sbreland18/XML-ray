"""Send the weekly summary email over SMTP."""
from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

KEYRING_SERVICE = "XML-ray"
PRESETS = {
    "Gmail / Google Workspace": ("smtp.gmail.com", 587, "starttls",
                                 "Use an app password, the same kind as for mailbox import."),
    "Microsoft 365": ("smtp.office365.com", 587, "starttls",
                      "Your admin must allow “Authenticated SMTP” for this mailbox."),
    "Other": ("", 587, "starttls", "Your provider's help pages list its SMTP server."),
}


class SendError(Exception):
    pass


@dataclass
class SmtpConfig:
    host: str
    username: str
    from_addr: str
    to: str                       # comma separated
    port: int = 587
    security: str = "starttls"    # starttls, ssl, none

    @property
    def keyring_user(self) -> str:
        return f"smtp:{self.username}@{self.host}"

    @property
    def recipients(self) -> list[str]:
        return [a.strip() for a in self.to.replace(";", ",").split(",") if a.strip()]


def get_password(cfg: SmtpConfig) -> str:
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, cfg.keyring_user) or ""
    except Exception:  # noqa: BLE001
        return ""


def set_password(cfg: SmtpConfig, password: str) -> bool:
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, cfg.keyring_user, password)
        return True
    except Exception:  # noqa: BLE001
        return False


def send(cfg: SmtpConfig, password: str, subject: str, html: str, text: str) -> None:
    if not cfg.host or not cfg.recipients or not cfg.from_addr:
        raise SendError("Fill in the mail server, sender and recipients first.")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg.from_addr, ", ".join(cfg.recipients)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    ctx = ssl.create_default_context()
    try:
        if cfg.security == "ssl":
            server = smtplib.SMTP_SSL(cfg.host, cfg.port, context=ctx, timeout=30)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=30)
        with server:
            if cfg.security == "starttls":
                server.starttls(context=ctx)
            if cfg.username:
                server.login(cfg.username, password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise SendError("The mail server rejected the user name or password. Many providers "
                        "need an app password.") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise SendError(f"Couldn't send the email: {exc}") from exc


def weekly_message(analysis, findings, previous_pct: float | None, alerts: list,
                   print_html) -> tuple[str, str, str]:
    """(subject, html, text) for the weekly summary."""
    domains = ", ".join(sorted(analysis.policies)) or "your domains"
    active = [f for f in findings if f.severity != "good"]
    change = ""
    if previous_pct is not None:
        diff = analysis.pass_pct - previous_pct
        change = (f" ({'up' if diff >= 0 else 'down'} {abs(diff):.1f} points from the week "
                  "before)") if abs(diff) >= 0.1 else " (the same as the week before)"
    subject = f"XML-ray weekly: {domains} graded {analysis.grade}, {len(active)} to do"
    lines = [f"Weekly email security summary for {domains}", "",
             f"Grade: {analysis.grade} ({analysis.grade_label}), score {analysis.score}/100",
             f"Email passing DMARC: {analysis.pass_pct:.1f}%{change}",
             f"Messages checked: {analysis.total:,}", ""]
    if active:
        lines.append("Top items to address:")
        lines += [f"- [{f.severity.title()}] {f.title}" for f in active[:5]]
    else:
        lines.append("Nothing needs attention right now.")
    if alerts:
        lines += ["", "Alerts this week:"] + [f"- {a['title']}" for a in alerts[:10]]
    text = "\n".join(lines)
    intro = ("<p style='font-family:Segoe UI,Arial;color:#17324A'>"
             + "<br>".join(lines[:5]).replace("\n", "<br>") + "</p>")
    if alerts:
        intro += ("<p style='font-family:Segoe UI,Arial'><b>Alerts this week</b><br>"
                  + "<br>".join(a["title"] for a in alerts[:10]) + "</p>")
    body = print_html(analysis, findings)
    html = body.replace("<body style='font-family:Segoe UI, Arial'>",
                        "<body style='font-family:Segoe UI, Arial'>" + intro, 1)
    return subject, html, text
