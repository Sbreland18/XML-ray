"""Check a domain's live DNS records (DMARC, SPF, DKIM, MX, TLS reporting, MTA-STS, BIMI).

Reports describe the past; this checks what is published right now. Lookups use
DNS-over-HTTPS (Cloudflare, then Google), so nothing extra needs installing.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .analyzer import Finding

ENDPOINTS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
SPF_LIMIT = 10
COMMON_SELECTORS = ["google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
                    "default", "dkim", "mail", "smtpapi", "mte1", "mte2", "sig1",
                    "mandrill", "zendesk1", "zendesk2", "pm", "everlytickey1", "mxvault"]
PARKED_SPF = "v=spf1 -all"


class DnsError(Exception):
    pass


class DohResolver:
    """DNS over HTTPS with a small per-run cache. Remembers each answer's TTL."""

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self._cache: dict[tuple[str, str], list[tuple[int, str]]] = {}
        self.ttls: dict[tuple[str, str], int] = {}
        self.queries = 0

    def query(self, name: str, rtype: str) -> list[tuple[int, str]]:
        key = (name.lower().rstrip("."), rtype)
        if key in self._cache:
            return self._cache[key]
        last = None
        for ep in ENDPOINTS:
            url = f"{ep}?name={urllib.parse.quote(key[0])}&type={rtype}"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json",
                                                       "User-Agent": "XML-ray"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    doc = json.load(resp)
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                last = exc
                continue
            self.queries += 1
            status = doc.get("Status", 2)
            if status not in (0, 3):          # 0 = OK, 3 = name doesn't exist
                last = DnsError(f"DNS server returned status {status} for {name}")
                continue
            answers = doc.get("Answer") or []
            out = [(a.get("type", 0), str(a.get("data", ""))) for a in answers]
            if answers:
                self.ttls[key] = min(int(a.get("TTL", 0) or 0) for a in answers)
            self._cache[key] = out
            return out
        raise DnsError(f"Couldn't look up {name}: {last}")

    def txt(self, name: str) -> list[str]:
        return [_txt_value(d) for t, d in self.query(name, "TXT") if t == 16]

    def mx(self, name: str) -> list[str]:
        """Mail server host names. A null MX ("0 .") is returned as ""."""
        out = []
        for t, d in self.query(name, "MX"):
            if t == 15:
                parts = d.split()
                out.append((parts[-1] if parts else d).rstrip(".").lower())
        return out

    def ns(self, name: str) -> list[str]:
        return [d.rstrip(".").lower() for t, d in self.query(name, "NS") if t == 2]

    def exists(self, name: str) -> bool:
        return bool(self.query(name, "NS")) or bool(self.query(name, "A"))

    def ttl(self, name: str, rtype: str = "TXT") -> int:
        return self.ttls.get((name.lower().rstrip("."), rtype), 0)


def _txt_value(data: str) -> str:
    """TXT answers arrive as '"part1" "part2"' (Cloudflare) or plain text (Google)."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if not parts:
        return data
    return "".join(p.replace('\\"', '"').replace("\\\\", "\\") for p in parts)


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _http_get(url: str, timeout: int = 8, limit: int = 512 * 1024) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "XML-ray"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(limit).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise DnsError(str(exc)) from exc


@dataclass
class RecordView:
    kind: str
    name: str
    value: str
    status: str          # ok, warn, bad, missing, info
    note: str = ""


@dataclass
class DnsResult:
    domain: str
    checked_at: datetime
    records: list[RecordView] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    dmarc_tags: dict = field(default_factory=dict)
    dmarc_record: str = ""
    dmarc_records: list = field(default_factory=list)
    spf_record: str = ""
    spf_records: list = field(default_factory=list)
    spf_terms: list = field(default_factory=list)      # [(term, lookups it costs)]
    spf_term_nets: dict = field(default_factory=dict)  # term -> ([ip ranges], complete?)
    spf_void: list = field(default_factory=list)       # include targets with no SPF
    spf_lookups: int = 0
    dkim_found: dict = field(default_factory=dict)     # selector -> record
    mx: list = field(default_factory=list)
    ns: list = field(default_factory=list)
    mta_sts: dict = field(default_factory=dict)
    bimi: dict = field(default_factory=dict)
    parked: bool = False
    ttls: dict = field(default_factory=dict)            # record name -> seconds
    error: str = ""


def _finding(sev, title, summary, steps, key, domain) -> Finding:
    return Finding(sev, title, summary, steps, 0, [], key=f"dns:{key}:{domain}", source="dns")


def _org_related(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


# ------------------------------------------------------------------- DMARC

def _check_dmarc(d: str, r, res: DnsResult, report_p: str | None) -> None:
    name = f"_dmarc.{d}"
    recs = [t for t in r.txt(name) if t.lower().replace(" ", "").startswith("v=dmarc1")]
    res.dmarc_records = recs
    res.ttls[name] = r.ttl(name) if hasattr(r, "ttl") else 0
    if not recs:
        res.records.append(RecordView("DMARC", name, "", "missing", "No DMARC record"))
        res.findings.append(_finding(
            "critical" if not res.parked else "high", f"{d} has no DMARC record right now",
            "DNS has no DMARC record for this domain, so receivers aren't checking or "
            "reporting on email that uses your name.",
            [f"Add a TXT record at {name}. “Show me how to fix this” gives you the exact record."],
            "dmarc-missing", d))
        return
    if len(recs) > 1:
        res.findings.append(_finding(
            "high", f"{d} has {len(recs)} DMARC records",
            "When there's more than one DMARC record, receivers ignore all of them.",
            [f"Delete the extra TXT records at {name} so only one remains."],
            "dmarc-multiple", d))
    res.dmarc_record = recs[0]
    tags = parse_tags(recs[0])
    res.dmarc_tags = tags
    p = tags.get("p", "").lower()
    status, note = "ok", f"p={p or '?'}"
    if p not in ("none", "quarantine", "reject"):
        status, note = "bad", "Missing or invalid p= tag"
        res.findings.append(_finding(
            "high", f"{d}'s DMARC record is invalid",
            "The record has no valid p= policy, so receivers may ignore it.",
            [f"Fix the TXT record at {name}. It should start with `v=DMARC1; p=none;` "
             "(or quarantine/reject)."], "dmarc-invalid", d))
    rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    if not rua and not res.parked:
        status = "warn" if status == "ok" else status
        res.findings.append(_finding(
            "medium", f"{d}'s DMARC record has no report address",
            "Without rua=, providers have nowhere to send the reports XML-ray reads.",
            [f"Add `rua=mailto:dmarc-reports@{d}` (or any mailbox you check) to the record "
             f"at {name}."], "dmarc-no-rua", d))
    for uri in rua:
        m = re.match(r"mailto:([^@!\s]+)@([^!\s]+)", uri, re.I)
        if not m:
            continue
        rdom = m.group(2).lower().rstrip(".")
        if _org_related(rdom, d):
            continue
        auth = f"{d}._report._dmarc.{rdom}"
        try:
            ok = any(t.lower().replace(" ", "").startswith("v=dmarc1") for t in r.txt(auth))
        except DnsError:
            continue
        if not ok:
            status = "warn" if status == "ok" else status
            res.findings.append(_finding(
                "high", f"Reports for {d} sent to {rdom} may be thrown away",
                f"Your reports go to an address at {rdom}, a different domain. Receivers "
                f"only send them if {rdom} publishes a record agreeing to accept them.",
                [f"Ask whoever runs {rdom} to add a TXT record at {auth} with the value "
                 "`v=DMARC1`, or send reports to an address at your own domain."],
                f"dmarc-rua-auth-{rdom}", d))
    if report_p and p and p != report_p:
        res.findings.append(_finding(
            "good", f"{d}'s policy has changed to p={p}",
            f"DNS now says p={p}, but the reports loaded so far were written under "
            f"p={report_p}. New reports will reflect the change within a day or two.",
            [], "dmarc-changed", d))
    res.records.append(RecordView("DMARC", name, recs[0], status, note))


# --------------------------------------------------------------------- SPF

def spf_of(r, domain: str) -> list[str]:
    return [t for t in r.txt(domain) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def count_spf(r, record: str, seen: set, problems: list, depth: int = 0,
              nets: list | None = None, flags: dict | None = None) -> int:
    """DNS lookups an SPF record needs, following include: and redirect=.
    If *nets* is given, every ip4:/ip6: range found is added to it; *flags*["complete"]
    is set to False when the record also uses a/mx/exists/ptr, which can't be expanded."""
    lookups = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        mech, _, arg = t.partition(":")
        if mech in ("ip4", "ip6") and nets is not None:
            nets.append(arg)
            continue
        if mech.startswith("redirect="):
            mech, arg = "redirect", t.split("=", 1)[1]
        if mech in ("include", "redirect"):
            lookups += 1
            if not arg or arg in seen or depth > 9:
                continue
            seen.add(arg)
            try:
                sub = spf_of(r, arg)
            except DnsError:
                continue
            if not sub:
                problems.append(f"{mech}:{arg} points to a domain with no SPF record")
                continue
            lookups += count_spf(r, sub[0], seen, problems, depth + 1, nets, flags)
        elif mech.split("/")[0] in ("a", "mx", "exists"):
            lookups += 1
            if flags is not None:
                flags["complete"] = False
        elif mech == "ptr":
            lookups += 1
            if flags is not None:
                flags["complete"] = False
            if depth == 0:
                problems.append("uses ptr, which is slow and discouraged")
    return lookups


def _check_spf(d: str, r, res: DnsResult) -> None:
    recs = spf_of(r, d)
    res.spf_records = recs
    res.ttls[d] = r.ttl(d) if hasattr(r, "ttl") else 0
    if not recs:
        res.records.append(RecordView("SPF", d, "", "missing", "No SPF record"))
        if res.parked:
            return
        res.findings.append(_finding(
            "high", f"{d} has no SPF record",
            "SPF lists the servers allowed to send email for your domain. Without it, "
            "mail that relies on SPF fails DMARC.",
            [f"Add a TXT record at {d} that starts with `v=spf1` and lists your email "
             "services. “Show me how to fix this” builds it from the senders in your reports."],
            "spf-missing", d))
        return
    if len(recs) > 1:
        res.findings.append(_finding(
            "high", f"{d} has {len(recs)} SPF records",
            "Having more than one SPF record is an error, so SPF fails for all your email.",
            ["Merge them into a single TXT record that starts with v=spf1 and contains "
             "every include you need."], "spf-multiple", d))
    rec = recs[0]
    res.spf_record = rec
    problems: list[str] = []
    total = 0
    for term in rec.split()[1:]:
        term_problems: list[str] = []
        nets: list[str] = []
        flags = {"complete": True}
        cost = count_spf(r, "v=spf1 " + term, {d}, term_problems, 0, nets, flags)
        res.spf_terms.append((term, cost))
        res.spf_term_nets[term] = (nets, flags["complete"])
        total += cost
        for p in term_problems:
            if p not in problems:
                problems.append(p)
            m = re.match(r"(?:include|redirect):(\S+) points to", p)
            if m and m.group(1) not in res.spf_void:
                res.spf_void.append(m.group(1))
    n = total
    res.spf_lookups = n
    status, note = "ok", f"{n} of {SPF_LIMIT} DNS lookups"
    if n > SPF_LIMIT:
        status = "bad"
        res.findings.append(_finding(
            "high", f"{d}'s SPF record needs too many lookups ({n} of {SPF_LIMIT})",
            "SPF allows at most 10 DNS lookups. Above that, receivers treat SPF as broken, so "
            "every message relying on SPF fails. This is a common silent problem.",
            ["Remove include: entries for services you no longer use.",
             "Move marketing or bulk senders to a subdomain (like news.yourdomain) with its "
             "own SPF record.",
             "Rely on DKIM for services that support it; they don't need to be in SPF."],
            "spf-too-many", d))
    elif n >= SPF_LIMIT - 1:
        status = "warn"
        res.findings.append(_finding(
            "low", f"{d}'s SPF record is close to the lookup limit ({n} of {SPF_LIMIT})",
            "Adding one more service could push SPF over the limit and break it.",
            ["Before adding another include:, remove ones you no longer use."],
            "spf-near-limit", d))
    terms = [t.lower() for t in rec.split()]
    alls = [t for t in terms if t.lstrip("+-~?") == "all"]
    has_redirect = any(t.startswith("redirect=") for t in terms)
    if any(t in ("+all", "all") for t in alls):
        status = "bad"
        res.findings.append(_finding(
            "critical", f"{d}'s SPF record allows any server to send",
            "+all tells receivers that every server on the internet may send as you.",
            [f"Change `+all` to `~all` (or `-all`) in the SPF record for {d}."],
            "spf-plus-all", d))
    elif "?all" in alls:
        status = "warn" if status == "ok" else status
        res.findings.append(_finding(
            "medium", f"{d}'s SPF record ends with ?all",
            "?all means “no opinion”, so SPF gives almost no protection.",
            ["Change `?all` to `~all` (or `-all`)."], "spf-neutral", d))
    elif not alls and not has_redirect:
        status = "warn" if status == "ok" else status
        res.findings.append(_finding(
            "low", f"{d}'s SPF record doesn't end with ~all or -all",
            "Without an all mechanism, servers that aren't listed get a neutral result.",
            ["Add `~all` to the end of the SPF record."], "spf-no-all", d))
    for prob in problems:
        status = "warn" if status == "ok" else status
        note += f"; {prob}"
    if res.spf_void:
        res.findings.append(_finding(
            "medium", f"{d}'s SPF record includes a domain with no SPF",
            "One of your include: entries points at nothing. That counts as an error and "
            "can make SPF fail.", ["Remove or correct: " + ", ".join(
                f"include:{v}" for v in res.spf_void)], "spf-void", d))
    res.records.append(RecordView("SPF", d, rec, status, note))


# -------------------------------------------------------------------- DKIM

def _check_dkim(d: str, r, res: DnsResult, seen_selectors: set[str]) -> None:
    found = 0
    for sel in list(dict.fromkeys(list(seen_selectors) + COMMON_SELECTORS)):
        name = f"{sel}._domainkey.{d}"
        try:
            recs = [t for t in r.txt(name) if "p=" in t.replace(" ", "")]
        except DnsError:
            continue
        reported = sel in seen_selectors
        if not recs:
            if reported:
                res.records.append(RecordView("DKIM", name, "", "missing",
                                              "Seen in reports but not in DNS"))
                res.findings.append(_finding(
                    "high", f"DKIM key “{sel}” is missing from {d}'s DNS",
                    "Reports show email signed with this key, but receivers can't find it, "
                    "so those signatures fail.",
                    [f"Publish the DKIM record for selector {sel} at {name}. Copy it from the "
                     "sending service's settings."], f"dkim-missing-{sel}", d))
            continue
        found += 1
        res.dkim_found[sel] = recs[0]
        tags = parse_tags(recs[0])
        key = tags.get("p", "").replace(" ", "")
        status, note = "ok", ""
        if not key:
            status, note = "warn", "Revoked (empty key)"
        elif tags.get("k", "rsa").lower() == "rsa":
            try:
                bits = 1024 if len(base64.b64decode(key + "==")) < 200 else 2048
            except ValueError:
                bits = 0
            note = f"RSA {bits}-bit" if bits else "Couldn't read key"
            if bits == 1024:
                status = "warn"
                res.findings.append(_finding(
                    "low", f"DKIM key “{sel}” on {d} is 1024-bit",
                    "1024-bit keys still work but are considered weak. 2048-bit is the "
                    "current standard.",
                    ["In the sending service's DKIM settings, generate a new 2048-bit key "
                     "and publish it."], f"dkim-weak-{sel}", d))
        else:
            note = tags.get("k", "").upper()
        if not reported:
            note = (note + "; " if note else "") + "common selector, not seen in reports"
        res.records.append(RecordView("DKIM", name, recs[0][:120] + ("…" if len(recs[0]) > 120 else ""),
                                      status, note))
    if not found and not res.parked:
        res.findings.append(_finding(
            "medium", f"No DKIM keys found for {d}",
            "XML-ray checked the selectors in your reports and the most common ones and "
            "found no DKIM keys. Without DKIM, forwarded mail is likely to fail DMARC.",
            ["Turn on DKIM in each service that sends your email and publish the keys it "
             "gives you. (If you use an unusual selector name, DKIM may already be set up.)"],
            "dkim-none", d))


# ------------------------------------------------- MX / TLS-RPT / MTA-STS

def _mx_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return pattern == host


def parse_sts_policy(text: str) -> dict:
    pol: dict = {"mx": []}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        k = k.lower()
        if k == "mx":
            pol["mx"].append(v)
        else:
            pol[k] = v
    return pol


def _check_mta_sts(d: str, r, res: DnsResult, fetch) -> None:
    sts = [t for t in r.txt(f"_mta-sts.{d}") if t.lower().replace(" ", "").startswith("v=stsv1")]
    real_mx = [m for m in res.mx if m]
    if not sts:
        res.records.append(RecordView("MTA-STS", f"_mta-sts.{d}", "", "info",
                                      "Optional: requires encrypted delivery to you"))
        res.findings.append(_finding(
            "low", f"Require encrypted delivery to {d} with MTA-STS",
            "MTA-STS tells other mail servers they must use an encrypted, verified "
            "connection when delivering to you, which stops eavesdropping and tampering.",
            ["Publish an MTA-STS policy in testing mode, check your TLS reports for a few "
             "weeks, then switch it to enforce. “Show me how to fix this” has the files."],
            "mta-sts-missing", d))
        return
    url = f"https://mta-sts.{d}/.well-known/mta-sts.txt"
    res.mta_sts = {"record": sts[0], "url": url}
    try:
        code, body = fetch(url)
    except DnsError as exc:
        code, body = 0, ""
        res.mta_sts["error"] = str(exc)
    pol = parse_sts_policy(body) if code == 200 else {}
    res.mta_sts["policy"] = pol
    if not pol or pol.get("version", "").upper() != "STSV1":
        res.records.append(RecordView("MTA-STS", url, "", "bad", "Policy file couldn't be read"))
        res.findings.append(_finding(
            "medium", f"{d}'s MTA-STS policy file can't be downloaded",
            f"DNS says you use MTA-STS, but the policy file at mta-sts.{d} didn't load "
            "or isn't valid, so senders can't use it.",
            [f"Make sure {url} loads over HTTPS with a valid certificate and starts with "
             "`version: STSv1`."], "mta-sts-fetch", d))
        return
    mode = pol.get("mode", "").lower()
    unmatched = [m for m in real_mx if not any(_mx_matches(p, m) for p in pol["mx"])]
    status, note = "ok", f"mode: {mode}"
    if unmatched:
        status = "bad"
        sev = "high" if mode == "enforce" else "medium"
        res.findings.append(_finding(
            sev, f"{d}'s MTA-STS policy doesn't list all your mail servers",
            f"These mail servers aren't in the policy: {', '.join(unmatched)}. "
            + ("In enforce mode, senders may refuse to deliver to them." if mode == "enforce"
               else "Fix this before switching to enforce mode."),
            ["Add an `mx:` line for each mail server to the policy file, then change the id= "
             f"value in the _mta-sts.{d} record so senders fetch it again."],
            "mta-sts-mx", d))
    if mode == "testing" and not unmatched:
        status = "warn"
        res.findings.append(_finding(
            "low", f"{d}'s MTA-STS policy is in testing mode",
            "Testing mode only reports problems; it doesn't require encryption yet.",
            ["When your TLS reports have been clean for a few weeks, change `mode: testing` "
             "to `mode: enforce` and update the id= value in the TXT record."],
            "mta-sts-testing", d))
    try:
        if int(pol.get("max_age", "0")) < 86400:
            note += "; max_age under 1 day"
    except ValueError:
        pass
    res.records.append(RecordView("MTA-STS", url, f"mode: {mode}; mx: {', '.join(pol['mx'])}",
                                  status, note))


def _check_mail_receiving(d: str, r, res: DnsResult, fetch) -> None:
    mx = r.mx(d)
    res.mx = mx
    real = [m for m in mx if m]
    null_mx = bool(mx) and not real
    res.records.append(RecordView(
        "MX", d, ", ".join(real) if real else ("0 . (null MX)" if null_mx else ""),
        "ok" if (real or null_mx) else "info",
        "Doesn't accept email (null MX)" if null_mx else
        ("" if real else "This domain doesn't receive email")))
    if not real or res.parked:
        return
    tls = [t for t in r.txt(f"_smtp._tls.{d}") if t.lower().replace(" ", "").startswith("v=tlsrptv1")]
    if tls:
        res.records.append(RecordView("TLS reporting", f"_smtp._tls.{d}", tls[0], "ok"))
    else:
        res.records.append(RecordView("TLS reporting", f"_smtp._tls.{d}", "", "info",
                                      "Not turned on (optional, recommended)"))
        res.findings.append(_finding(
            "low", f"Turn on TLS reporting for {d}",
            "TLS reports tell you whether email sent to you arrives encrypted. XML-ray "
            "reads them alongside DMARC reports.",
            [f"Add a TXT record at _smtp._tls.{d} with the value "
             f"`v=TLSRPTv1; rua=mailto:dmarc-reports@{d}` (any mailbox you check)."],
            "tlsrpt-missing", d))
    _check_mta_sts(d, r, res, fetch)


# -------------------------------------------------------------------- BIMI

def _check_bimi(d: str, r, res: DnsResult, fetch) -> None:
    name = f"default._bimi.{d}"
    recs = [t for t in r.txt(name) if t.lower().replace(" ", "").startswith("v=bimi1")]
    tags = res.dmarc_tags
    enforced = tags.get("p", "").lower() == "reject" or (
        tags.get("p", "").lower() == "quarantine" and tags.get("pct", "100") == "100")
    if not recs:
        res.records.append(RecordView("BIMI", name, "", "info", "Optional: your logo in inboxes"))
        if enforced:
            res.findings.append(_finding(
                "low", f"{d} qualifies for BIMI (your logo in inboxes)",
                "Your DMARC policy is strong enough for BIMI, which shows your logo next to "
                "your emails in Gmail, Yahoo and Apple Mail.",
                ["Prepare your logo as an SVG Tiny P/S file, then publish a BIMI record. "
                 "Gmail and Apple Mail also need a VMC or CMC certificate."],
                "bimi-ready", d))
        return
    bt = parse_tags(recs[0])
    res.bimi = {"record": recs[0], "logo": bt.get("l", ""), "cert": bt.get("a", "")}
    problems = []
    if not enforced:
        problems.append("DMARC must be p=quarantine (100%) or p=reject before logos appear")
    logo = bt.get("l", "")
    if not logo.lower().startswith("https://") or not logo.lower().split("?")[0].endswith(".svg"):
        problems.append("l= must be an https:// link to an .svg file")
    else:
        try:
            code, body = fetch(logo)
            if code != 200 or "<svg" not in body[:4000].lower():
                problems.append("the logo link didn't return an SVG image")
            elif "tiny-ps" not in body[:4000].lower():
                problems.append("the logo isn't in SVG Tiny P/S format (baseProfile=\"tiny-ps\")")
        except DnsError:
            problems.append("the logo couldn't be downloaded")
    status = "ok" if not problems else "warn"
    note = "Ready" if not problems else "; ".join(problems)
    if not bt.get("a"):
        note += "; no certificate (a=): Yahoo only, not Gmail/Apple"
    res.records.append(RecordView("BIMI", name, recs[0], status, note))
    if problems:
        res.findings.append(_finding(
            "medium", f"{d}'s BIMI logo won't be shown yet",
            "Your BIMI record is published, but: " + "; ".join(problems) + ".",
            ["Fix the items above. Logos usually appear a few days after everything checks out."],
            "bimi-problem", d))


# ------------------------------------------------------------------ parked

def _check_parked(d: str, res: DnsResult) -> None:
    missing = []
    if [s.lower().strip() for s in res.spf_records] != [PARKED_SPF]:
        missing.append("SPF that allows no servers")
    if res.dmarc_tags.get("p", "").lower() != "reject":
        missing.append("DMARC set to reject")
    if res.mx != [""]:
        missing.append("null MX")
    if missing:
        res.findings.append(_finding(
            "high", f"Parked domain {d} isn't locked down",
            "Domains that never send email are easy to spoof, because nothing tells receivers "
            "to block fakes. Missing: " + ", ".join(missing) + ".",
            ["Publish the lock-down records. “Show me how to fix this” has them ready to copy."],
            "parked-unlocked", d))
    else:
        res.findings.append(_finding(
            "good", f"Parked domain {d} is locked down",
            "SPF, DMARC and a null MX tell receivers this domain never sends email.",
            [], "parked-ok", d))


def check_domain(domain: str, resolver=None, report_policy: str | None = None,
                 dkim_selectors: set[str] | None = None, parked: bool = False,
                 fetch=None) -> DnsResult:
    d = domain.lower().rstrip(".")
    r = resolver or DohResolver()
    fetch = fetch or _http_get
    res = DnsResult(domain=d, checked_at=datetime.now(timezone.utc), parked=parked)
    try:
        if hasattr(r, "ns"):
            try:
                res.ns = r.ns(d)
            except DnsError:
                pass
        _check_dmarc(d, r, res, report_policy)
        _check_spf(d, r, res)
        if not parked:
            _check_dkim(d, r, res, set(dkim_selectors or ()))
        _check_mail_receiving(d, r, res, fetch)
        if parked:
            _check_parked(d, res)
        else:
            _check_bimi(d, r, res, fetch)
    except DnsError as exc:
        res.error = str(exc)
    return res


def selectors_from_reports(reports, domain: str) -> set[str]:
    """DKIM selectors that signed mail with *domain* itself."""
    out = set()
    for rep in reports:
        if rep.policy.domain != domain:
            continue
        for rec in rep.records:
            for dk in rec.dkim_results:
                if dk.selector and dk.domain == domain:
                    out.add(dk.selector.lower())
    return out
