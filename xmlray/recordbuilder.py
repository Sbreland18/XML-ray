"""Write DMARC records for each step of the usual rollout."""
from __future__ import annotations

from dataclasses import dataclass

STAGES = [  # (key, label, p, pct)
    ("monitor", "Monitor only (p=none)", "none", 100),
    ("q25", "Start enforcing: 25% to spam (p=quarantine; pct=25)", "quarantine", 25),
    ("q100", "All failing mail to spam (p=quarantine)", "quarantine", 100),
    ("reject", "Block failing mail (p=reject)", "reject", 100),
]


@dataclass
class RecordOptions:
    domain: str
    stage: str = "monitor"
    rua: str = ""
    ruf: str = ""
    sp: str = ""            # "" = same as p
    strict_dkim: bool = False
    strict_spf: bool = False


def build_record(o: RecordOptions) -> str:
    _key, _label, p, pct = next(s for s in STAGES if s[0] == o.stage)
    parts = ["v=DMARC1", f"p={p}"]
    if o.sp:
        parts.append(f"sp={o.sp}")
    if pct < 100:
        parts.append(f"pct={pct}")
    if o.rua.strip():
        parts.append("rua=" + ",".join(_mailto(a) for a in o.rua.split(",") if a.strip()))
    if o.ruf.strip():
        parts.append("ruf=" + ",".join(_mailto(a) for a in o.ruf.split(",") if a.strip()))
        parts.append("fo=1")
    if o.strict_dkim:
        parts.append("adkim=s")
    if o.strict_spf:
        parts.append("aspf=s")
    return "; ".join(parts)


def _mailto(addr: str) -> str:
    addr = addr.strip()
    return addr if addr.lower().startswith("mailto:") else f"mailto:{addr}"


def external_report_domains(o: RecordOptions) -> list[str]:
    """Report addresses at other domains need an authorization record there."""
    out = []
    for addr in (o.rua + "," + o.ruf).split(","):
        addr = addr.strip().removeprefix("mailto:")
        if "@" not in addr:
            continue
        dom = addr.split("@", 1)[1].lower()
        d = o.domain.lower()
        if not (dom == d or dom.endswith("." + d) or d.endswith("." + dom)):
            out.append(dom)
    return sorted(set(out))


def recommend_stage(policy, ready: bool) -> tuple[str, str]:
    """(stage key, reason) for the next sensible step, given the current policy."""
    if policy is None:
        return "monitor", "Start by monitoring so you can see who sends email as you."
    p, pct = policy.p, policy.pct
    if p == "none":
        if ready:
            return "q25", "Your legitimate senders are passing, so you're ready to start enforcing."
        return "monitor", "Fix the failing senders in the action plan before enforcing."
    if p == "quarantine" and pct < 100:
        return ("q100", "Reports look clean, so apply quarantine to all failing mail.") if ready \
            else ("q25", "Stay here until the remaining failures are fixed.")
    if p == "quarantine":
        return ("reject", "Everything legitimate passes, so you can block failures outright.") \
            if ready else ("q100", "Stay here until the remaining failures are fixed.")
    return "reject", "You're at the strongest setting. Keep it."


def stage_from_tags(tags: dict) -> str:
    p = (tags.get("p") or "none").lower()
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100
    if p == "reject":
        return "reject"
    if p == "quarantine":
        return "q100" if pct >= 100 else "q25"
    return "monitor"
