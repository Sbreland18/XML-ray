"""SMTP TLS reports (TLS-RPT, RFC 8460).

Big mail providers send these alongside DMARC reports when your domain publishes a
_smtp._tls TXT record. They answer a different question: when other servers delivered
email *to* you, could they do it over an encrypted connection?
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .parser import ReportParseError

# Plain-English meaning of each failure type, and how bad it is.
FAILURE_TYPES: dict[str, tuple[str, str, str]] = {
    # type: (severity, short label, explanation)
    "starttls-not-supported": ("high", "Encryption not offered",
                               "Your mail server didn't offer encryption (STARTTLS), so mail "
                               "was sent unencrypted or not delivered."),
    "certificate-expired": ("high", "Certificate expired",
                            "Your mail server's TLS certificate has expired."),
    "certificate-host-mismatch": ("high", "Certificate name doesn't match",
                                  "Your mail server's certificate doesn't match its host name."),
    "certificate-not-trusted": ("high", "Certificate not trusted",
                                "Your mail server's certificate isn't signed by a trusted "
                                "authority (often self-signed)."),
    "validation-failure": ("medium", "Certificate check failed",
                           "The sending server couldn't validate your mail server's "
                           "certificate."),
    "sts-policy-fetch-error": ("medium", "MTA-STS policy couldn't be downloaded",
                               "Your MTA-STS policy file at https://mta-sts.<your domain>/"
                               ".well-known/mta-sts.txt couldn't be fetched."),
    "sts-policy-invalid": ("medium", "MTA-STS policy is invalid",
                           "Your MTA-STS policy file has a mistake in it."),
    "sts-webpki-invalid": ("medium", "MTA-STS website certificate problem",
                           "The website hosting your MTA-STS policy has a certificate problem."),
    "tlsa-invalid": ("medium", "DANE (TLSA) record problem",
                     "Your DANE TLSA record doesn't match your mail server's certificate."),
    "dnssec-invalid": ("medium", "DNSSEC problem",
                       "DNSSEC validation failed for your domain."),
    "dane-required": ("medium", "DANE required but missing",
                      "DANE was required but couldn't be used."),
}


@dataclass
class TlsFailure:
    result_type: str
    count: int
    sending_ip: str = ""
    receiving_mx: str = ""
    receiving_ip: str = ""
    info: str = ""


@dataclass
class TlsPolicy:
    policy_type: str
    policy_domain: str
    mx_hosts: list[str]
    success: int
    failure: int
    failures: list[TlsFailure] = field(default_factory=list)


@dataclass
class TlsReport:
    org_name: str
    report_id: str
    begin: datetime
    end: datetime
    contact: str
    policies: list[TlsPolicy]
    source_file: str = ""
    raw: bytes = field(default=b"", repr=False)

    @property
    def key(self) -> tuple[str, str]:
        return (self.org_name.lower(), self.report_id)

    @property
    def domains(self) -> set[str]:
        return {p.policy_domain for p in self.policies}


def _dt(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _int(v) -> int:
    try:
        return max(int(v), 0)
    except (TypeError, ValueError):
        return 0


def parse_tls_bytes(data: bytes, source: str = "") -> TlsReport:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReportParseError(f"not valid JSON ({exc})") from exc
    if not isinstance(doc, dict) or "policies" not in doc:
        raise ReportParseError("this JSON file is not an SMTP TLS report")
    rng = doc.get("date-range") or {}
    policies = []
    for p in doc.get("policies") or []:
        pol = p.get("policy") or {}
        summ = p.get("summary") or {}
        failures = [TlsFailure(
            result_type=str(f.get("result-type", "unknown")).lower(),
            count=_int(f.get("failed-session-count")),
            sending_ip=str(f.get("sending-mta-ip", "")),
            receiving_mx=str(f.get("receiving-mx-hostname", "")).rstrip(".").lower(),
            receiving_ip=str(f.get("receiving-ip", "")),
            info=str(f.get("additional-information", "") or f.get("failure-reason-code", "")),
        ) for f in p.get("failure-details") or []]
        policies.append(TlsPolicy(
            policy_type=str(pol.get("policy-type", "no-policy-found")).lower(),
            policy_domain=str(pol.get("policy-domain", "")).rstrip(".").lower(),
            mx_hosts=[str(m) for m in pol.get("mx-host") or []],
            success=_int(summ.get("total-successful-session-count")),
            failure=_int(summ.get("total-failure-session-count")),
            failures=failures,
        ))
    begin = _dt(str(rng.get("start-datetime", "")))
    return TlsReport(
        org_name=str(doc.get("organization-name") or "Unknown reporter"),
        report_id=str(doc.get("report-id") or f"{source}:{begin.timestamp()}"),
        begin=begin,
        end=_dt(str(rng.get("end-datetime", ""))),
        contact=str(doc.get("contact-info", "")),
        policies=policies,
        source_file=source,
        raw=data,
    )


def dedupe_tls(reports) -> list[TlsReport]:
    seen: dict = {}
    for r in reports:
        seen.setdefault(r.key, r)
    return sorted(seen.values(), key=lambda r: r.begin)


@dataclass
class TlsAnalysis:
    reports: list[TlsReport]
    success: int
    failure: int
    by_type: Counter
    by_mx: Counter
    policy_types: Counter
    findings: list            # list[analyzer.Finding]

    @property
    def total(self) -> int:
        return self.success + self.failure

    @property
    def success_pct(self) -> float:
        return 100.0 * self.success / self.total if self.total else 0.0


def analyze_tls(reports: list[TlsReport], domain: str | None = None,
                since: datetime | None = None) -> TlsAnalysis:
    from .analyzer import Finding  # local import avoids a cycle
    sel = []
    for r in reports:
        if since and r.end < since:
            continue
        pols = [p for p in r.policies if not domain or p.policy_domain == domain]
        if pols:
            sel.append((r, pols))
    success = failure = 0
    by_type, by_mx, ptypes = Counter(), Counter(), Counter()
    for _r, pols in sel:
        for p in pols:
            success += p.success
            failure += p.failure
            ptypes[p.policy_type] += p.success + p.failure
            for f in p.failures:
                by_type[f.result_type] += f.count
                if f.receiving_mx:
                    by_mx[f.receiving_mx] += f.count

    findings = []
    for ftype, n in by_type.most_common():
        sev, label, text = FAILURE_TYPES.get(
            ftype, ("medium", ftype.replace("-", " ").capitalize(),
                    "Sending servers reported a problem connecting securely."))
        mx = ", ".join(m for m, _ in by_mx.most_common(3)) or "your mail server"
        steps = {
            "certificate-expired": ["Renew the TLS certificate on your mail server ({mx}) "
                                    "or ask your email provider to."],
            "certificate-host-mismatch": ["Make sure the certificate on {mx} includes that "
                                          "exact host name."],
            "certificate-not-trusted": ["Install a certificate from a trusted authority "
                                        "(Let's Encrypt is free) on {mx}."],
            "starttls-not-supported": ["Turn on STARTTLS on {mx}, or ask your email provider "
                                       "why encryption isn't offered."],
        }.get(ftype, ["Check your mail server ({mx}) and, if you use it, your MTA-STS policy. "
                      "Your email provider's support team can help."])
        findings.append(Finding(
            sev, f"Secure delivery problem: {label.lower()}",
            f"{n:,} delivery attempt{'s' if n != 1 else ''} to you couldn't be encrypted. "
            + text, [s.format(mx=mx) for s in steps], n, [], key=f"tls:{ftype}",
            source="tls"))
    if sel and not failure and success:
        findings.append(Finding(
            "good", "Incoming email is delivered securely",
            f"All {success:,} reported connections to your mail servers were encrypted "
            "successfully.", [], success, [], key="tls:ok", source="tls"))
    return TlsAnalysis([r for r, _ in sel], success, failure, by_type, by_mx, ptypes, findings)


def label_for(ftype: str) -> str:
    return FAILURE_TYPES.get(ftype, ("", ftype.replace("-", " ").capitalize(), ""))[1]
