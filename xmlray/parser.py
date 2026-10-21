"""Read DMARC aggregate (RUA) reports.

Accepts plain .xml, gzip (.gz / .xml.gz), .zip archives, .eml emails that carry a
report as an attachment, and whole folders of any of those. Reports come from
outside your organisation, so XML is parsed with defusedxml when it's installed
and every decompression step is size-limited.
"""
from __future__ import annotations

import email
import email.policy
import gzip
import io
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

try:  # Safer parser for untrusted XML (blocks entity-expansion attacks)
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET  # type: ignore

MAX_REPORT_BYTES = 200 * 1024 * 1024  # 200 MB per decompressed report
SUPPORTED_SUFFIXES = {".xml", ".gz", ".gzip", ".zip", ".eml"}
FORWARD_REASONS = {"forwarded", "mailing_list", "trusted_forwarder"}


class ReportParseError(Exception):
    pass


@dataclass
class AuthResult:
    domain: str
    result: str
    selector: str = ""
    scope: str = ""


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str
    dkim_aligned: str
    spf_aligned: str
    header_from: str
    envelope_from: str = ""
    envelope_to: str = ""
    reasons: list[tuple[str, str]] = field(default_factory=list)
    dkim_results: list[AuthResult] = field(default_factory=list)
    spf_results: list[AuthResult] = field(default_factory=list)

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_aligned == "pass" or self.spf_aligned == "pass"

    @property
    def forwarded(self) -> bool:
        return any(r[0] in FORWARD_REASONS for r in self.reasons)


@dataclass
class PolicyPublished:
    domain: str
    p: str = "none"
    sp: str = ""
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    np: str = ""
    testing: str = ""


@dataclass
class Report:
    org_name: str
    email: str
    report_id: str
    begin: datetime
    end: datetime
    policy: PolicyPublished
    records: list[Record]
    source_file: str = ""

    @property
    def total_messages(self) -> int:
        return sum(r.count for r in self.records)

    @property
    def passed_messages(self) -> int:
        return sum(r.count for r in self.records if r.dmarc_pass)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.org_name.lower(), self.report_id, self.policy.domain.lower())


# --------------------------------------------------------------------------- XML

def _strip_namespaces(root) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _t(el, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _ts(value: str) -> datetime:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def parse_report_bytes(data: bytes, source: str = "") -> Report:
    try:
        root = ET.fromstring(data)
    except Exception as exc:  # noqa: BLE001 - any parser failure means "not a report"
        raise ReportParseError(f"not valid XML ({exc})") from exc

    _strip_namespaces(root)
    if root.tag != "feedback":
        raise ReportParseError("this XML file is not a DMARC aggregate report")

    meta = root.find("report_metadata")
    pol = root.find("policy_published")
    if meta is None or pol is None:
        raise ReportParseError("report is missing its metadata or published policy")

    policy = PolicyPublished(
        domain=_t(pol, "domain").lower(),
        p=_t(pol, "p", "none").lower() or "none",
        sp=_t(pol, "sp").lower(),
        pct=_int(_t(pol, "pct", "100"), 100),
        adkim=_t(pol, "adkim", "r").lower() or "r",
        aspf=_t(pol, "aspf", "r").lower() or "r",
        np=_t(pol, "np").lower(),
        testing=_t(pol, "testing").lower(),
    )

    records: list[Record] = []
    for rec in root.findall("record"):
        row = rec.find("row")
        pe = row.find("policy_evaluated") if row is not None else None
        ident = rec.find("identifiers")
        auth = rec.find("auth_results")

        reasons = []
        if pe is not None:
            for reason in pe.findall("reason"):
                reasons.append((_t(reason, "type").lower(), _t(reason, "comment")))

        dkim_results, spf_results = [], []
        if auth is not None:
            for d in auth.findall("dkim"):
                dkim_results.append(AuthResult(
                    domain=_t(d, "domain").lower(),
                    result=_t(d, "result", "none").lower(),
                    selector=_t(d, "selector"),
                ))
            for s in auth.findall("spf"):
                spf_results.append(AuthResult(
                    domain=_t(s, "domain").lower(),
                    result=_t(s, "result", "none").lower(),
                    scope=_t(s, "scope", "mfrom").lower(),
                ))

        records.append(Record(
            source_ip=_t(row, "source_ip", "unknown"),
            count=max(_int(_t(row, "count", "0")), 0),
            disposition=_t(pe, "disposition", "none").lower() or "none",
            dkim_aligned=_t(pe, "dkim", "fail").lower(),
            spf_aligned=_t(pe, "spf", "fail").lower(),
            header_from=_t(ident, "header_from", policy.domain).lower(),
            envelope_from=_t(ident, "envelope_from").lower(),
            envelope_to=_t(ident, "envelope_to").lower(),
            reasons=reasons,
            dkim_results=dkim_results,
            spf_results=spf_results,
        ))

    begin = _ts(_t(meta, "date_range/begin"))
    end = _ts(_t(meta, "date_range/end"))
    return Report(
        org_name=_t(meta, "org_name", "Unknown reporter"),
        email=_t(meta, "email"),
        report_id=_t(meta, "report_id") or f"{source}:{begin.timestamp()}",
        begin=begin,
        end=end,
        policy=policy,
        records=records,
        source_file=source,
    )


# ------------------------------------------------------------------ containers

def _gunzip(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        out = gz.read(MAX_REPORT_BYTES + 1)
    if len(out) > MAX_REPORT_BYTES:
        raise ReportParseError("compressed report is too large to open safely")
    return out


def _unzip(data: bytes, label: str) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.file_size > MAX_REPORT_BYTES:
                raise ReportParseError(f"{info.filename} is too large to open safely")
            yield from _unpack(zf.read(info), f"{label} › {info.filename}")


def _from_email(data: bytes, label: str) -> Iterator[tuple[str, bytes]]:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    found = False
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename() or ""
        ctype = part.get_content_type()
        if name.lower().endswith((".xml", ".gz", ".zip")) or ctype in (
            "application/zip", "application/gzip", "application/x-gzip",
            "text/xml", "application/xml",
        ):
            payload = part.get_payload(decode=True)
            if payload:
                found = True
                yield from _unpack(payload, f"{label} › {name or ctype}")
    if not found:
        raise ReportParseError("no DMARC report attachment found in this email")


def _unpack(data: bytes, label: str) -> Iterator[tuple[str, bytes]]:
    """Yield (label, xml_bytes) for every report inside *data*, whatever the wrapper."""
    if data[:2] == b"\x1f\x8b":
        yield from _unpack(_gunzip(data), label)
    elif data[:4] == b"PK\x03\x04":
        yield from _unzip(data, label)
    elif label.lower().endswith(".eml") or data.lstrip()[:5].lower() in (b"from:", b"recei", b"retur", b"mime-", b"deliv"):
        yield from _from_email(data, label)
    else:
        yield label, data


def _expand(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(sorted(f for f in p.rglob("*")
                                if f.is_file() and f.suffix.lower() in SUPPORTED_SUFFIXES))
        elif p.is_file():
            files.append(p)
    return files


def load_paths(paths: Iterable[str | Path]) -> tuple[list[Report], list[str]]:
    """Load every report found in *paths*. Returns (reports, human-readable errors)."""
    reports: list[Report] = []
    errors: list[str] = []
    for f in _expand(paths):
        try:
            for label, xml_bytes in _unpack(f.read_bytes(), f.name):
                try:
                    reports.append(parse_report_bytes(xml_bytes, source=label))
                except ReportParseError as exc:
                    errors.append(f"{label}: {exc}")
        except (ReportParseError, OSError, zipfile.BadZipFile, EOFError, gzip.BadGzipFile) as exc:
            errors.append(f"{f.name}: {exc}")
    return dedupe(reports), errors


def dedupe(reports: Iterable[Report]) -> list[Report]:
    """Drop duplicate reports (same reporter, report ID and domain)."""
    seen: dict[tuple[str, str, str], Report] = {}
    for r in reports:
        seen.setdefault(r.key, r)
    return sorted(seen.values(), key=lambda r: r.begin)
