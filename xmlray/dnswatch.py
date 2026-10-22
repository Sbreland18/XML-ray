"""Notice when someone changes a domain's email DNS records."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Change:
    kind: str
    before: str
    after: str


def snapshot(res) -> dict:
    snap = {"DMARC": res.dmarc_record, "SPF": res.spf_record,
            "MX": ", ".join(sorted(m or "0 ." for m in res.mx)),
            "MTA-STS": res.mta_sts.get("record", ""), "BIMI": res.bimi.get("record", "")}
    for v in res.records:
        if v.kind == "TLS reporting":
            snap["TLS reporting"] = v.value
    for sel, rec in sorted(res.dkim_found.items()):
        snap[f"DKIM ({sel})"] = rec
    return snap


def diff(old: dict, new: dict) -> list[Change]:
    out = []
    for kind in sorted(set(old) | set(new)):
        a, b = old.get(kind, ""), new.get(kind, "")
        if a != b:
            out.append(Change(kind, a, b))
    return out


def describe(c: Change) -> str:
    if not c.before:
        return f"{c.kind} record added: {c.after[:140]}"
    if not c.after:
        return f"{c.kind} record removed (was: {c.before[:140]})"
    return f"{c.kind} record changed from “{c.before[:100]}” to “{c.after[:100]}”"


def record(storage, res) -> list[Change]:
    """Compare with the last snapshot, save the new one, log changes. Returns the changes."""
    if res.error:
        return []
    key = f"dns:snapshot:{res.domain}"
    old = storage.get_json(key)
    new = snapshot(res)
    storage.set_json(key, new)
    if old is None:
        return []                          # first check: nothing to compare with
    changes = diff(old, new)
    if changes:
        log = storage.get_json(f"dns:changes:{res.domain}") or []
        now = datetime.now().isoformat(timespec="minutes")
        log = [{"when": now, "kind": c.kind, "before": c.before, "after": c.after}
               for c in changes] + log
        storage.set_json(f"dns:changes:{res.domain}", log[:100])
    return changes
