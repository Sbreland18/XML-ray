"""Spot registered domains that imitate yours (typos, look-alike characters, other endings).

Lookalikes with mail servers can send convincing phishing. Registration dates and the
registrar come from RDAP, so newly registered ones can be flagged."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from .analyzer import Finding
from .dnscheck import DnsError, DohResolver

TLDS = ["com", "net", "org", "co", "io", "us", "info", "biz", "online", "app", "email",
        "site", "xyz", "support"]
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"],
              "m": ["rn"], "rn": ["m"], "w": ["vv"], "vv": ["w"], "e": ["3"], "a": ["4"],
              "s": ["5"], "g": ["q"], "q": ["g"], "d": ["cl"], "cl": ["d"]}
ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
WORDS = ["mail", "secure", "login", "support", "billing", "account", "my", "team"]
NEW_DAYS = 90


def _neighbours() -> dict[str, str]:
    pos = {c: (r, i) for r, row in enumerate(ROWS) for i, c in enumerate(row)}
    out = {}
    for c, (r, i) in pos.items():
        near = []
        for dr in (-1, 0, 1):
            for di in (-1, 0, 1):
                if (dr or di) and 0 <= r + dr < len(ROWS) and 0 <= i + di < len(ROWS[r + dr]):
                    near.append(ROWS[r + dr][i + di])
        out[c] = "".join(near)
    return out


NEAR = _neighbours()


def split_domain(domain: str) -> tuple[str, str]:
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def variants(domain: str, limit: int = 400) -> list[str]:
    name, tld = split_domain(domain)
    if "." in name:            # subdomain given: only vary the last label
        prefix, name = name.rsplit(".", 1)
        prefix += "."
    else:
        prefix = ""
    names: list[str] = []
    n = len(name)
    for i in range(n):                                   # omission
        names.append(name[:i] + name[i + 1:])
    for i in range(n):                                   # repetition
        names.append(name[:i] + name[i] + name[i:])
    for i in range(n - 1):                               # transposition
        names.append(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    for src, subs in HOMOGLYPHS.items():                 # look-alike characters
        start = name.find(src)
        while start != -1:
            for sub in subs:
                names.append(name[:start] + sub + name[start + len(src):])
            start = name.find(src, start + 1)
    for i, c in enumerate(name):                         # keyboard slips
        for k in NEAR.get(c, ""):
            names.append(name[:i] + k + name[i + 1:])
    for i in range(1, n):                                # hyphenation
        names.append(name[:i] + "-" + name[i:])
    for w in WORDS:                                      # added words
        names += [f"{name}-{w}", f"{w}-{name}", f"{name}{w}"]
    out = [f"{prefix}{x}.{tld}" for x in names]
    out += [f"{prefix}{name}.{t}" for t in TLDS if t != tld]   # other endings
    clean = []
    for v in dict.fromkeys(out):
        label = v.split(".")[0]
        if v != domain and label and not label.startswith("-") and not label.endswith("-") \
                and len(label) <= 63:
            clean.append(v)
    return clean[:limit]


@dataclass
class Lookalike:
    domain: str
    has_mx: bool = False
    has_web: bool = False
    created: str = ""          # ISO date
    registrar: str = ""
    abuse: str = ""

    @property
    def age_days(self) -> int | None:
        try:
            dt = datetime.fromisoformat(self.created.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except ValueError:
            return None

    @property
    def risk(self) -> str:
        new = self.age_days is not None and self.age_days <= NEW_DAYS
        if self.has_mx:
            return "high" if new else "medium"
        return "low" if self.has_web else "info"


def rdap_domain(domain: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": "XML-ray"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {}
    return parse_rdap_domain(doc)


def parse_rdap_domain(doc: dict) -> dict:
    created = next((e.get("eventDate", "") for e in doc.get("events") or []
                    if e.get("eventAction") == "registration"), "")
    registrar = abuse = ""
    for ent in doc.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn":
                    registrar = str(item[3])
            for sub in ent.get("entities") or []:
                if "abuse" in (sub.get("roles") or []):
                    for item in (sub.get("vcardArray") or [None, []])[1]:
                        if item[0] == "email":
                            abuse = str(item[3])
    return {"created": created, "registrar": registrar, "abuse": abuse}


def scan(domain: str, resolver=None, rdap=rdap_domain, progress=None) -> list[Lookalike]:
    r = resolver or DohResolver(timeout=6)
    cands = variants(domain)

    def probe(v):
        try:
            if not r.query(v, "NS") and not r.query(v, "A"):
                return None
            mx = [m for m in r.mx(v) if m]
            web = bool(r.query(v, "A"))
        except DnsError:
            return None
        return Lookalike(v, has_mx=bool(mx), has_web=web)

    found: list[Lookalike] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i, res in enumerate(pool.map(probe, cands), 1):
            if res:
                found.append(res)
            if progress:
                progress(i, len(cands))
    for lk in found:
        info = rdap(lk.domain)
        lk.created, lk.registrar, lk.abuse = (info.get("created", ""), info.get("registrar", ""),
                                              info.get("abuse", ""))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(found, key=lambda x: (order[x.risk], x.domain))


def findings(results: list[Lookalike], owned: set[str], your_domain: str) -> list[Finding]:
    out = []
    for lk in results:
        if lk.domain in owned or lk.risk not in ("high", "medium"):
            continue
        age = lk.age_days
        when = f"registered {age} days ago" if age is not None else "registered"
        steps = [f"Warn your staff and customers to be careful with email from {lk.domain}."]
        if lk.abuse:
            steps.append(f"If it's impersonating you, report it to the registrar"
                         f"{' (' + lk.registrar + ')' if lk.registrar else ''} at {lk.abuse}.")
        elif lk.registrar:
            steps.append(f"If it's impersonating you, report it to the registrar, {lk.registrar}.")
        steps += ["Consider registering the most likely lookalikes yourself, then add them in "
                  "Settings > Domains as parked domains so XML-ray locks them down.",
                  "If this domain is yours, click “This is mine” in the Lookalikes tab."]
        out.append(Finding(
            lk.risk, f"Lookalike domain {lk.domain} can send email",
            f"{lk.domain} looks like {your_domain}, was {when}, and has mail servers, so it "
            "could be used for convincing phishing.", steps, 0, [],
            key=f"lookalike:{lk.domain}", source="lookalike"))
    return out
