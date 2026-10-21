"""Spot changes worth interrupting someone for, each time new reports arrive."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .analyzer import analyze


@dataclass
class Alert:
    kind: str      # new_sender, service_failing, pass_drop
    title: str
    body: str


def find_alerts(history, new_reports, hostnames=None, labels=None) -> list[Alert]:
    """Compare newly arrived reports with everything received before them.
    *history* must NOT include *new_reports*. Nothing is raised on the very first import,
    because then everything would look new."""
    if not history or not new_reports:
        return []
    alerts: list[Alert] = []
    before = analyze(history, hostnames=hostnames, labels=labels)
    now = analyze(new_reports, hostnames=hostnames, labels=labels)
    known_ips = {s.ip for s in before.sources}
    prev = {s.ip: s for s in before.sources}

    fresh = [s for s in now.sources if s.category == "unknown" and s.ip not in known_ips]
    if fresh:
        n = sum(s.messages for s in fresh)
        names = ", ".join(s.label for s in fresh[:3]) + (" and others" if len(fresh) > 3 else "")
        alerts.append(Alert(
            "new_sender",
            f"{len(fresh)} new unrecognised sender{'s' if len(fresh) != 1 else ''}",
            f"{n:,} messages using your domain came from servers never seen before: {names}."))

    for s in now.sources:
        p = prev.get(s.ip)
        if p and p.category == "authorized" and s.category in ("service_failing", "partial") \
                and s.failed:
            alerts.append(Alert(
                "service_failing", f"{s.label} started failing DMARC",
                f"It passed before, but {s.failed:,} of {s.messages:,} new messages failed. "
                "Its SPF or DKIM settings may have changed."))

    # Pass rate of legitimate mail: new reports vs the 30 days before them.
    start = min(r.begin for r in new_reports)
    window = [r for r in history if r.end >= start - timedelta(days=30)]
    if window:
        base = analyze(window, hostnames=hostnames, labels=labels)

        def legit_rate(a):
            legit = [x for x in a.sources if x.category not in ("unknown", "forwarded", "ignored")]
            msgs = sum(x.messages for x in legit)
            return (sum(x.dmarc_pass for x in legit) / msgs * 100) if msgs else None

        old, new = legit_rate(base), legit_rate(now)
        if old is not None and new is not None and old - new >= 5:
            alerts.append(Alert(
                "pass_drop", "Fewer of your emails are passing DMARC",
                f"Legitimate mail passing dropped from {old:.0f}% to {new:.0f}% in the "
                "newest reports."))
    return alerts
