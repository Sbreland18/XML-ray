"""The road to full protection: where a domain is, what's next, and when it's safe."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .analyzer import Finding
from .recordbuilder import stage_from_tags

SAFE_DAYS = 14
SAFE_RATE = 0.98


@dataclass
class Step:
    key: str
    title: str
    status: str            # done, current, todo, optional, optional-done
    detail: str
    fix: Finding | None = None


def _days_at_current_stage(reports, domain: str) -> tuple[str, int]:
    reps = sorted((r for r in reports if r.policy.domain == domain), key=lambda r: r.begin)
    if not reps:
        return "monitor", 0
    stage = stage_from_tags({"p": reps[-1].policy.p, "pct": str(reps[-1].policy.pct)})
    start = reps[-1].begin
    for r in reversed(reps):
        if stage_from_tags({"p": r.policy.p, "pct": str(r.policy.pct)}) != stage:
            break
        start = r.begin
    return stage, max(0, (reps[-1].end - start).days)


def _find(findings, *prefixes) -> Finding | None:
    return next((f for f in findings if f.key.startswith(prefixes)), None)


def build_roadmap(domain: str, analysis, dns, reports, all_findings) -> list[Step]:
    d = domain
    pol = analysis.policies.get(d) if analysis else None
    dns_tags = dns.dmarc_tags if dns else {}
    if dns_tags.get("p"):
        stage = stage_from_tags(dns_tags)
    elif pol:
        stage = stage_from_tags({"p": pol.p, "pct": str(pol.pct)})
    else:
        stage = "monitor"
    report_stage, days = _days_at_current_stage(reports, d)
    if report_stage != stage:
        days = 0                         # policy changed in DNS; reports haven't caught up
    rate = pol.legit_pass_rate if pol else 0.0
    mine = [f for f in all_findings if f.key.endswith(":" + d) or f.key.startswith("service:")
            or f.key in ("dkim-missing", "unknown-delivered")]
    n_reports = len([r for r in reports if r.policy.domain == d])
    order = ["monitor", "q25", "q100", "reject"]
    at = order.index(stage)

    steps: list[Step] = []
    steps.append(Step("reports", "Collect DMARC reports",
                      "done" if n_reports else "todo",
                      f"{n_reports} report{'s' if n_reports != 1 else ''} received."
                      if n_reports else "Publish a DMARC record with a rua= address so "
                      "providers start sending reports.",
                      _find(mine, "dns:dmarc-missing", "dns:dmarc-no-rua")))
    spf_bad = _find([f for f in mine if f.severity in ("critical", "high", "medium")], "dns:spf-")
    steps.append(Step("spf", "SPF record is correct",
                      "todo" if (spf_bad or not dns) else "done",
                      spf_bad.title if spf_bad else (
                          f"{dns.spf_lookups} of 10 lookups." if dns else "Run the DNS check."),
                      spf_bad))
    dkim_bad = _find(mine, "dns:dkim-missing-", "dns:dkim-none", "dkim-missing")
    steps.append(Step("dkim", "DKIM signs your email",
                      "todo" if (dkim_bad or not dns) else "done",
                      dkim_bad.title if dkim_bad else (
                          f"Keys found: {', '.join(dns.dkim_found) or 'none'}." if dns
                          else "Run the DNS check."), dkim_bad))
    svc = _find(sorted(mine, key=lambda f: -f.affected), "service:")
    ready = bool(pol and pol.ready_to_enforce)
    steps.append(Step("senders", "All your legitimate senders pass",
                      "done" if ready else "todo",
                      f"{rate * 100:.1f}% of legitimate email passes (98% needed)."
                      + (f" Start with: {svc.title}." if svc and not ready else ""), svc))

    labels = {"q25": "Start enforcing: 25% of failing mail to spam",
              "q100": "All failing mail to spam", "reject": "Block failing mail (p=reject)"}
    for i, key in enumerate(["q25", "q100", "reject"], start=1):
        why = {"q25": "This tells receivers to send a quarter of the email that fails DMARC to "
                      "spam. Starting small means any sender you missed causes little harm.",
               "q100": "This sends all email that fails DMARC to spam, so spoofed mail no "
                       "longer reaches inboxes.",
               "reject": "This tells receivers to refuse email that fails DMARC outright. "
                         "It's the strongest protection for your domain."}[key]
        fix = Finding("medium", labels[key], why, [], 0, [], key=f"roadmap:{key}:{d}")
        if at >= i:
            steps.append(Step(key, labels[key], "done", "In place.", None))
            continue
        if at == i - 1:
            if i == 1:
                ok = ready
                why = ("Your legitimate senders pass, so this step is safe now." if ok else
                       "Finish the steps above first.")
            else:
                ok = ready and days >= SAFE_DAYS and rate >= SAFE_RATE
                why = (f"Safe now: {days} days at the current step with {rate * 100:.1f}% of "
                       "legitimate email passing." if ok else
                       f"Wait {max(0, SAFE_DAYS - days)} more day(s) at the current step"
                       + ("" if ready else " and fix the remaining failures") + ".")
            steps.append(Step(key, labels[key], "current" if ok else "todo", why, fix))
        else:
            steps.append(Step(key, labels[key], "todo", "Comes after the step above.", fix))

    if dns and any(m for m in dns.mx if m):
        tls_ok = any(v.kind == "TLS reporting" and v.status == "ok" for v in dns.records)
        steps.append(Step("tlsrpt", "Optional: TLS reporting", "optional-done" if tls_ok else
                          "optional", "Shows whether email to you arrives encrypted.",
                          _find(mine, "dns:tlsrpt-missing")))
        mode = (dns.mta_sts.get("policy") or {}).get("mode", "")
        steps.append(Step("mtasts", "Optional: MTA-STS in enforce mode",
                          "optional-done" if mode == "enforce" else "optional",
                          f"Current mode: {mode}." if mode else "Requires encrypted delivery to you.",
                          _find(mine, "dns:mta-sts-")))
    if dns:
        bimi_ok = bool(dns.bimi) and not _find(mine, "dns:bimi-problem")
        steps.append(Step("bimi", "Optional: your logo in inboxes (BIMI)",
                          "optional-done" if bimi_ok else "optional",
                          "Needs p=quarantine at 100% or p=reject first." if at < 2 else
                          "Your policy qualifies.", _find(mine, "dns:bimi-")))
    # make the first unfinished core step "current" if none is
    core = [s for s in steps if s.status in ("todo", "current", "done")]
    if not any(s.status == "current" for s in core):
        nxt = next((s for s in core if s.status == "todo"), None)
        if nxt and nxt.key in ("reports", "spf", "dkim", "senders"):
            nxt.status = "current"
    return steps


def next_review(days_needed: int) -> timedelta:
    return timedelta(days=max(0, days_needed))
