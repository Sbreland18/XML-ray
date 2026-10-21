"""Find who owns an IP address and where it's registered, using RDAP.

RDAP is the free, official successor to WHOIS run by the regional internet registries.
rdap.org forwards each question to the right registry (ARIN, RIPE, APNIC, ...).
"""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request

from .countries import country_name

RDAP_URL = "https://rdap.org/ip/{ip}"


def _vcard_name(entity: dict) -> str:
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) > 1:
        for item in card[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3]).strip()
    return ""


def parse_rdap(doc: dict) -> dict:
    """Pull owner, country and network range out of an RDAP IP-network answer."""
    owner = ""
    # Prefer the registrant (the organisation the range is assigned to).
    entities = doc.get("entities") or []
    for wanted in ("registrant", "administrative", "technical", "abuse"):
        for ent in entities:
            if wanted in (ent.get("roles") or []):
                owner = _vcard_name(ent)
                if not owner:
                    for sub in ent.get("entities") or []:
                        owner = _vcard_name(sub)
                        if owner:
                            break
            if owner:
                break
        if owner:
            break
    network = doc.get("name") or doc.get("handle") or ""
    cidrs = doc.get("cidr0_cidrs") or []
    if cidrs:
        c = cidrs[0]
        prefix = c.get("v4prefix") or c.get("v6prefix") or ""
        rng = f"{prefix}/{c.get('length')}" if prefix else ""
    else:
        start, end = doc.get("startAddress", ""), doc.get("endAddress", "")
        rng = f"{start} – {end}" if start and end else ""
    code = (doc.get("country") or "").upper()
    return {
        "owner": owner or network,
        "network": network,
        "range": rng,
        "country_code": code,
        "country": country_name(code) if code else "",
    }


def lookup(ip: str, timeout: int = 10) -> dict:
    """Owner info for *ip*, or {} for private/invalid addresses or failed lookups."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.is_private or addr.is_reserved or addr.is_loopback:
        return {"owner": "Private or reserved address", "country": "", "network": "",
                "range": "", "country_code": ""}
    req = urllib.request.Request(RDAP_URL.format(ip=ip), headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": "XML-ray"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return parse_rdap(json.load(resp))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {}


def describe(info: dict) -> str:
    """'Hetzner Online GmbH, Germany'"""
    if not info:
        return ""
    parts = [info.get("owner", "")]
    if info.get("country"):
        parts.append(info["country"])
    return ", ".join(p for p in parts if p)
