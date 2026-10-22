"""Warn before mail server certificates expire (or if they're already broken).

Checks each MX host over SMTP STARTTLS on port 25, and the MTA-STS policy website over
HTTPS. Many home and office networks block outgoing port 25; that shows as “couldn't
check”, not as a problem with your server."""
from __future__ import annotations

import smtplib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from .analyzer import Finding


@dataclass
class CertResult:
    host: str
    service: str            # "Mail server" or "MTA-STS website"
    status: str             # ok, expiring, expired, invalid, no_tls, unreachable
    expires: str = ""
    days_left: int | None = None
    detail: str = ""


def _from_cert(host, service, cert) -> CertResult:
    try:
        exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    except (KeyError, ValueError):
        return CertResult(host, service, "ok", detail="Valid")
    days = (exp - datetime.now(timezone.utc)).days
    status = "expired" if days < 0 else ("expiring" if days <= 30 else "ok")
    return CertResult(host, service, status, exp.date().isoformat(), days,
                      f"Expires in {days} days" if days >= 0 else "Expired")


def check_smtp(host: str, timeout: int = 10) -> CertResult:
    try:
        with smtplib.SMTP(host, 25, timeout=timeout) as s:
            s.ehlo()
            if not s.has_extn("starttls"):
                return CertResult(host, "Mail server", "no_tls",
                                  detail="Doesn't offer encrypted connections (STARTTLS)")
            try:
                s.starttls(context=ssl.create_default_context())
            except ssl.SSLCertVerificationError as exc:
                return CertResult(host, "Mail server", "invalid", detail=exc.verify_message or str(exc))
            return _from_cert(host, "Mail server", s.sock.getpeercert())
    except (socket.timeout, TimeoutError, ConnectionError, OSError, smtplib.SMTPException) as exc:
        return CertResult(host, "Mail server", "unreachable",
                          detail=f"Couldn't connect on port 25 ({exc.__class__.__name__}); "
                                 "your network may block it")


def check_https(host: str, timeout: int = 10) -> CertResult:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return _from_cert(host, "MTA-STS website", tls.getpeercert())
    except ssl.SSLCertVerificationError as exc:
        return CertResult(host, "MTA-STS website", "invalid", detail=exc.verify_message or str(exc))
    except OSError as exc:
        return CertResult(host, "MTA-STS website", "unreachable", detail=str(exc))


def check_domain(res, smtp=check_smtp, https=check_https) -> list[CertResult]:
    out = [smtp(h) for h in [m for m in res.mx if m][:3]]
    if res.mta_sts:
        out.append(https(f"mta-sts.{res.domain}"))
    return out


def findings(results: list[CertResult], domain: str) -> list[Finding]:
    out = []
    for r in results:
        if r.status in ("expired", "invalid"):
            out.append(Finding("high", f"Certificate problem on {r.host}",
                               f"The {r.service.lower()} certificate is "
                               f"{'expired' if r.status == 'expired' else 'not valid'}: {r.detail}. "
                               "Senders that require encryption may not deliver to you.",
                               [f"Renew or replace the certificate on {r.host}, or ask your "
                                "email or hosting provider to."], 0, [],
                               key=f"cert:{r.host}:{domain}", source="dns"))
        elif r.status == "expiring":
            out.append(Finding("high" if (r.days_left or 0) <= 7 else "medium",
                               f"Certificate on {r.host} expires in {r.days_left} days",
                               f"The {r.service.lower()} certificate expires on {r.expires}.",
                               [f"Renew the certificate on {r.host} before {r.expires}. Most "
                                "hosts can renew automatically (for example with Let's Encrypt)."],
                               0, [], key=f"cert:{r.host}:{domain}", source="dns"))
        elif r.status == "no_tls":
            out.append(Finding("high", f"{r.host} doesn't accept encrypted email",
                               "Your mail server doesn't offer STARTTLS, so email sent to you "
                               "travels unencrypted.",
                               [f"Turn on STARTTLS on {r.host}, or ask your email provider."],
                               0, [], key=f"cert:{r.host}:{domain}", source="dns"))
    return out
