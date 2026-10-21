"""Turn raw DMARC records into plain-English, prioritised findings."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from .parser import Report
from .senders import identify_provider

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "good": 4}
POLICY_STRENGTH = {"none": 0, "quarantine": 1, "reject": 2}

CATEGORY_LABELS = {
    "authorized": "Passing",
    "partial": "Sometimes failing",
    "service_failing": "Failing, known service",
    "unknown": "Failing, unknown sender",
    "forwarded": "Forwarded",
}

DISPOSITION_WORDS = {"none": "delivered", "quarantine": "sent to spam", "reject": "rejected"}


@dataclass
class SourceSummary:
    ip: str
    messages: int = 0
    dmarc_pass: int = 0
    spf_aligned: int = 0
    dkim_aligned: int = 0
    spf_auth_pass: int = 0
    dkim_auth_pass: int = 0
    dkim_signed: int = 0
    forwarded: int = 0
    fail_blocked: int = 0      # failed DMARC and receiver quarantined/rejected it
    fail_delivered: int = 0    # failed DMARC but was delivered anyway
    dispositions: Counter = field(default_factory=Counter)
    header_from: Counter = field(default_factory=Counter)
    envelope_from: Counter = field(default_factory=Counter)
    dkim_domains: Counter = field(default_factory=Counter)   # "domain|selector|result"
    spf_domains: Counter = field(default_factory=Counter)    # "domain|result"
    reasons: Counter = field(default_factory=Counter)
    by_domain: dict = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    hostname: str = ""
    provider: str = ""
    category: str = ""

    @property
    def failed(self) -> int:
        return self.messages - self.dmarc_pass

    @property
    def pass_rate(self) -> float:
        return self.dmarc_pass / self.messages if self.messages else 0.0

    @property
    def name(self) -> str:
        return self.provider or self.hostname or "Unrecognised server"

    @property
    def label(self) -> str:
        """Short name for sentences: service, hostname or IP address."""
        return self.provider or self.hostname or self.ip

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    @property
    def delivered_summary(self) -> str:
        parts = [f"{n:,} {DISPOSITION_WORDS.get(d, d)}" for d, n in self.dispositions.most_common()]
        return ", ".join(parts)

    @property
    def meaning(self) -> str:
        c = self.category
        if c == "authorized":
            return "Allowed to send as you. Nothing to do."
        if c == "partial":
            return (f"Mostly legitimate, but {self.failed:,} of {self.messages:,} messages "
                    "failed. Check its SPF and DKIM setup.")
        if c == "service_failing":
            return (f"Looks like {self.provider}. If you use {self.provider}, it isn't set up "
                    "to send as your domain yet.")
        if c == "forwarded":
            return "Passed through a forwarder or mailing list. Usually nothing to do."
        return "Not recognised and not authorised. Likely spoofing unless you know this server."


@dataclass
class DomainPolicy:
    domain: str
    p: str
    sp: str
    pct: int
    testing: str
    messages: int = 0
    passed: int = 0
    legit_messages: int = 0
    legit_passed: int = 0
    unknown_delivered: int = 0
    has_failing_service: bool = False

    @property
    def legit_pass_rate(self) -> float:
        return self.legit_passed / self.legit_messages if self.legit_messages else 1.0

    @property
    def ready_to_enforce(self) -> bool:
        return self.legit_pass_rate >= 0.98 and not self.has_failing_service


@dataclass
class Finding:
    severity: str
    title: str
    summary: str
    steps: list[str] = field(default_factory=list)
    affected: int = 0
    ips: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    reports: list[Report]
    sources: list[SourceSummary]
    findings: list[Finding]
    policies: dict[str, DomainPolicy]
    total: int
    passed: int
    score: int
    grade: str
    grade_label: str
    begin: datetime | None
    end: datetime | None
    reporters: Counter

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def pass_pct(self) -> float:
        return 100.0 * self.passed / self.total if self.total else 0.0

    @property
    def action_count(self) -> int:
        return sum(1 for f in self.findings if f.severity != "good")


# ------------------------------------------------------------------ aggregation

def _aggregate(reports: Iterable[Report], hostnames: dict[str, str]) -> dict[str, SourceSummary]:
    sources: dict[str, SourceSummary] = {}
    for rep in reports:
        dom = rep.policy.domain
        for rec in rep.records:
            s = sources.get(rec.source_ip)
            if s is None:
                s = sources[rec.source_ip] = SourceSummary(ip=rec.source_ip)
            n = rec.count
            s.messages += n
            s.by_domain[dom][0] += n
            if rec.dmarc_pass:
                s.dmarc_pass += n
                s.by_domain[dom][1] += n
            elif rec.disposition in ("quarantine", "reject"):
                s.fail_blocked += n
            else:
                s.fail_delivered += n
            if rec.spf_aligned == "pass":
                s.spf_aligned += n
            if rec.dkim_aligned == "pass":
                s.dkim_aligned += n
            if any(r.result == "pass" for r in rec.spf_results):
                s.spf_auth_pass += n
            if any(r.result == "pass" for r in rec.dkim_results):
                s.dkim_auth_pass += n
            if any(r.result not in ("none", "") for r in rec.dkim_results):
                s.dkim_signed += n
            if rec.forwarded:
                s.forwarded += n
            s.dispositions[rec.disposition] += n
            s.header_from[rec.header_from] += n
            if rec.envelope_from:
                s.envelope_from[rec.envelope_from] += n
            for d in rec.dkim_results:
                s.dkim_domains[f"{d.domain}|{d.selector}|{d.result}"] += n
            for sp in rec.spf_results:
                s.spf_domains[f"{sp.domain}|{sp.result}"] += n
            for rtype, _comment in rec.reasons:
                s.reasons[rtype] += n

    for s in sources.values():
        s.hostname = hostnames.get(s.ip, "")
        hint_domains = list(s.envelope_from) + [k.split("|")[0] for k in s.dkim_domains] \
            + [k.split("|")[0] for k in s.spf_domains]
        s.provider = identify_provider(s.hostname, hint_domains)
        if s.pass_rate >= 0.9:
            s.category = "authorized"
        elif s.dmarc_pass > 0:
            s.category = "partial"
        elif s.forwarded >= s.messages * 0.5:
            s.category = "forwarded"
        elif s.provider:
            s.category = "service_failing"
        else:
            s.category = "unknown"
    return sources


def _latest_policies(reports: list[Report]) -> dict[str, DomainPolicy]:
    latest: dict[str, Report] = {}
    for r in reports:
        d = r.policy.domain
        if d not in latest or r.end > latest[d].end:
            latest[d] = r
    return {
        d: DomainPolicy(domain=d, p=r.policy.p, sp=r.policy.sp, pct=r.policy.pct,
                        testing=r.policy.testing)
        for d, r in latest.items()
    }


# --------------------------------------------------------------------- findings

def _fmt_domains(counter: Counter, limit: int = 3) -> str:
    names = [k.split("|")[0] for k, _ in counter.most_common(limit) if k.split("|")[0]]
    return ", ".join(dict.fromkeys(names)) or "unknown"


def _service_steps(name: str, group: list[SourceSummary], domains: str) -> list[str]:
    steps: list[str] = []
    dkim_aligned = sum(s.dkim_aligned for s in group)
    dkim_pass = sum(s.dkim_auth_pass for s in group)
    spf_aligned = sum(s.spf_aligned for s in group)
    spf_pass = sum(s.spf_auth_pass for s in group)
    dkim_doms, env_doms = Counter(), Counter()
    for s in group:
        dkim_doms.update(s.dkim_domains)
        env_doms.update(s.envelope_from)

    if dkim_aligned == 0:
        if dkim_pass:
            steps.append(
                f"{name} signs these emails with its own domain ({_fmt_domains(dkim_doms)}) "
                f"instead of yours. In {name}'s settings, find “domain authentication” or "
                f"“custom DKIM” and publish the DNS records it gives you for {domains}.")
        else:
            steps.append(
                f"Turn on DKIM signing for {domains} in {name}'s settings, then add the DKIM "
                "DNS record (usually a CNAME or TXT) that it provides.")
    if spf_aligned == 0:
        if spf_pass:
            steps.append(
                f"SPF passes, but for {name}'s own bounce domain ({_fmt_domains(env_doms)}), so it "
                "doesn't count for DMARC. Fixing DKIM above is enough. Optionally, set up a custom "
                f"return-path (bounce) domain in {name} as well.")
        else:
            steps.append(
                f"If {name} sends with your domain as the envelope sender, add it to your SPF "
                "record using the include: value from its setup guide.")
    if not steps:
        steps.append("Some messages pass and some fail. Check whether a second account or "
                     "server for this service is sending without your DKIM key.")
    steps.append("After fixing it, new reports (usually within 1–2 days) should show this "
                 "sender as Passing.")
    return steps


def _source_findings(sources: list[SourceSummary], domains: str) -> list[Finding]:
    findings: list[Finding] = []

    groups: dict[str, list[SourceSummary]] = defaultdict(list)
    for s in sources:
        if s.category in ("service_failing", "partial"):
            groups[s.provider or "__unnamed__"].append(s)

    for provider, group in groups.items():
        name = provider if provider != "__unnamed__" else "Unrecognised servers"
        failed = sum(s.failed for s in group)
        blocked = sum(s.fail_blocked for s in group)
        known = provider != "__unnamed__"
        mostly_failing = any(s.category == "service_failing" for s in group)
        ips = [s.ip for s in group]

        if blocked and (known or not mostly_failing):
            sev = "critical"
            title = f"{name}: your real email is being blocked or sent to spam"
            summary = (f"{blocked:,} messages from {name} failed DMARC and receivers acted on "
                       "your policy. If this is a service you use, people aren't getting "
                       "those emails.")
        elif mostly_failing:
            sev = "high"
            title = f"{name} is failing DMARC"
            summary = (f"{failed:,} messages sent through {name} failed. They're being "
                       "delivered today only because your policy isn't blocking anything. "
                       "Once you enforce DMARC, this mail would be blocked.")
        else:
            sev = "medium"
            title = f"{name}: some messages are failing"
            summary = (f"{failed:,} of {sum(s.messages for s in group):,} messages from "
                       f"{name} failed. The rest passed, so this is usually a partial "
                       "setup problem rather than spoofing.")
        steps = _service_steps(name if known else "the sending service", group, domains)
        findings.append(Finding(sev, title, summary, steps, failed, ips))

    unknown = [s for s in sources if s.category == "unknown"]
    delivered = sum(s.fail_delivered for s in unknown)
    blocked = sum(s.fail_blocked for s in unknown)
    if delivered:
        findings.append(Finding(
            "high",
            "Unrecognised servers sent email as you and it was delivered",
            f"{delivered:,} messages from {len(unknown)} unrecognised server"
            f"{'s' if len(unknown) != 1 else ''} failed every check but still reached "
            "inboxes. This is usually spoofing or phishing using your name.",
            [
                "Open the Senders tab and filter to “Unknown or suspicious”.",
                "If you recognise any of them (your website, a copier or scanner, a CRM, "
                "billing system or helpdesk), set up SPF or DKIM for that service.",
                "If you don't recognise them, move your DMARC policy to p=quarantine, then "
                "p=reject, so receivers block these messages.",
            ],
            delivered, [s.ip for s in unknown if s.fail_delivered]))
    if blocked:
        findings.append(Finding(
            "good",
            "Your policy stopped suspicious email",
            f"{blocked:,} messages from unrecognised servers failed DMARC and were sent to "
            "spam or rejected. That's DMARC protecting your domain.",
            [], blocked, [s.ip for s in unknown if s.fail_blocked]))

    fwd = [s for s in sources if s.category == "forwarded"]
    if fwd:
        n = sum(s.messages for s in fwd)
        findings.append(Finding(
            "good",
            "Some email was forwarded",
            f"{n:,} messages passed through forwarding services or mailing lists, which "
            "can break SPF. Receivers recognised this, so there's nothing to fix.",
            [], n, [s.ip for s in fwd]))

    spf_only = [s for s in sources if s.category == "authorized" and s.dkim_aligned == 0]
    if spf_only:
        names = ", ".join(dict.fromkeys(s.label for s in spf_only[:5]))
        findings.append(Finding(
            "low",
            "Add DKIM for senders that rely on SPF alone",
            f"These senders pass only because of SPF: {names}. SPF breaks when email is "
            "forwarded, so adding DKIM makes your mail more reliable.",
            ["Turn on DKIM signing with your own domain for each of these services, and "
             "publish the DKIM record each one provides."],
            sum(s.messages for s in spf_only), [s.ip for s in spf_only]))
    return findings


def _policy_findings(policies: dict[str, DomainPolicy]) -> list[Finding]:
    findings: list[Finding] = []
    for d, dp in sorted(policies.items()):
        record_name = f"_dmarc.{d}"
        if dp.p == "none":
            ready = dp.ready_to_enforce
            summary = (f"{d} only monitors email. Receivers are told not to act on mail that "
                       f"fails, so anyone can still send fake email that appears to come from {d}.")
            if ready:
                summary += " Your legitimate senders are passing, so you look ready to start enforcing."
            steps = []
            if not ready:
                steps.append("First fix the failing senders listed above, so real email isn't "
                             "blocked when you turn on enforcement.")
            steps += [
                f"Edit the TXT record at {record_name} and change p=none to `p=quarantine; "
                "pct=25` (keep your existing rua= address).",
                "Watch the next few weeks of reports. If nothing legitimate fails, raise pct "
                "to 100, then change the policy to p=reject.",
            ]
            findings.append(Finding("medium", f"{d} is in monitoring mode (p=none)", summary,
                                    steps, dp.messages))
        elif dp.p == "quarantine" and dp.pct >= 100 and dp.ready_to_enforce:
            findings.append(Finding(
                "low", f"{d} is ready for p=reject",
                "Failing email is going to spam, and your legitimate senders are passing. "
                "Rejecting it outright gives the strongest protection.",
                [f"Edit the TXT record at {record_name} and change p=quarantine to `p=reject`."],
                dp.messages))
        elif dp.p == "reject" and dp.pct >= 100 and dp.testing != "y":
            findings.append(Finding(
                "good", f"{d} is fully protected (p=reject)",
                "Receivers are told to reject email that fails DMARC. This is the strongest setting.",
                [], dp.messages))

        if dp.p in ("quarantine", "reject") and dp.pct < 100:
            findings.append(Finding(
                "medium", f"{d}'s policy only covers {dp.pct}% of failing email",
                f"pct={dp.pct} means receivers apply your {dp.p} policy to only some failing "
                "messages and deliver the rest normally.",
                [f"When reports look clean, raise pct to 100 in the {record_name} record "
                 "(or remove pct entirely; 100 is the default)."],
                dp.messages))
        if dp.testing == "y":
            findings.append(Finding(
                "medium", f"{d}'s policy is in test mode (t=y)",
                "Test mode tells receivers not to fully apply your policy.",
                [f"Remove t=y from the {record_name} record when you're ready to enforce."],
                dp.messages))
        if dp.sp and POLICY_STRENGTH.get(dp.sp, 0) < POLICY_STRENGTH.get(dp.p, 0):
            findings.append(Finding(
                "low", f"Subdomains of {d} are less protected",
                f"Your main domain uses p={dp.p}, but subdomains use sp={dp.sp}. Attackers "
                f"can spoof addresses like billing.{d}.",
                [f"Set sp={dp.p} in the {record_name} record, or remove sp= so subdomains "
                 "inherit your main policy."],
                0))
    return findings


# ------------------------------------------------------------------------ score

def _score(policies: dict[str, DomainPolicy]) -> tuple[int, str, str]:
    total = sum(dp.messages for dp in policies.values()) or 1
    auth = enforcement = 0.0
    for dp in policies.values():
        weight = (dp.messages or 0) / total if len(policies) > 1 else 1.0
        auth += weight * dp.legit_pass_rate
        pct = max(0, min(dp.pct, 100)) / 100
        if dp.testing == "y":
            pct = 0
        e = {"none": 0.25, "quarantine": 0.25 + 0.5 * pct, "reject": 0.25 + 0.75 * pct}.get(dp.p, 0.0)
        enforcement += weight * e
    score = round(60 * auth + 40 * enforcement)
    for cutoff, grade, label in ((90, "A", "Well protected"), (80, "B", "Good"),
                                 (65, "C", "Needs attention"), (50, "D", "At risk")):
        if score >= cutoff:
            return score, grade, label
    return score, "F", "Exposed"


# ------------------------------------------------------------------------- main

def analyze(reports: list[Report], domain: str | None = None,
            hostnames: dict[str, str] | None = None) -> Analysis:
    if domain:
        reports = [r for r in reports if r.policy.domain == domain.lower()]
    hostnames = hostnames or {}

    sources = sorted(_aggregate(reports, hostnames).values(), key=lambda s: -s.messages)
    policies = _latest_policies(reports)

    for s in sources:
        legit = s.category not in ("unknown", "forwarded")
        for d, (msgs, passed) in s.by_domain.items():
            dp = policies.get(d)
            if not dp:
                continue
            dp.messages += msgs
            dp.passed += passed
            if legit:
                dp.legit_messages += msgs
                dp.legit_passed += passed
            if s.category in ("service_failing", "partial") and msgs > passed:
                dp.has_failing_service = True
            if s.category == "unknown":
                dp.unknown_delivered += s.fail_delivered

    domain_text = ", ".join(sorted(policies)) or "your domain"
    findings = _source_findings(sources, domain_text) + _policy_findings(policies)
    if reports and not any(f.severity in ("critical", "high", "medium") for f in findings):
        findings.append(Finding(
            "good", "Everything looks healthy",
            "Your legitimate email is passing DMARC and nothing urgent needs attention.",
            [], sum(s.messages for s in sources)))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.affected))

    total = sum(s.messages for s in sources)
    passed = sum(s.dmarc_pass for s in sources)
    score, grade, label = _score(policies) if policies else (0, "–", "No data")
    reporters = Counter()
    for r in reports:
        reporters[r.org_name] += r.total_messages
    return Analysis(
        reports=reports, sources=sources, findings=findings, policies=policies,
        total=total, passed=passed, score=score, grade=grade, grade_label=label,
        begin=min((r.begin for r in reports), default=None),
        end=max((r.end for r in reports), default=None),
        reporters=reporters,
    )
