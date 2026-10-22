"""Check whether your sending servers are on major spam blocklists (DNSBLs).

Blocklists are queried through this computer's own DNS server, because several lists
refuse queries from big public resolvers. A list that refuses the query is shown as
"couldn't check" rather than "clear"."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .analyzer import Finding

LISTS = [  # name, zone, where to look up and request removal
    ("Spamhaus", "zen.spamhaus.org", "https://check.spamhaus.org/"),
    ("SpamCop", "bl.spamcop.net", "https://www.spamcop.net/bl.shtml"),
    ("Barracuda", "b.barracudacentral.org", "https://www.barracudacentral.org/lookups"),
    ("PSBL", "psbl.surriel.com", "https://psbl.org/"),
]
SHARED = {"Google", "Microsoft 365", "Microsoft Outlook.com", "Amazon SES", "SendGrid",
          "Mailchimp", "Mailgun", "Yahoo", "Apple iCloud"}


def query(ip: str, zone: str, resolve=socket.gethostbyname) -> str:
    """'listed', 'clear' or 'unavailable'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unavailable"
    if addr.version != 4 or addr.is_private:
        return "unavailable"
    name = ".".join(reversed(ip.split("."))) + "." + zone
    try:
        answer = resolve(name)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return "clear"
    if answer.startswith("127.255.255.") or not answer.startswith("127."):
        return "unavailable"   # the list refused or rate-limited this DNS server
    return "listed"


def check_ips(ips, resolve=socket.gethostbyname, progress=None) -> dict[str, dict[str, str]]:
    jobs = [(ip, name, zone) for ip in ips for name, zone, _url in LISTS]
    out: dict[str, dict[str, str]] = {ip: {} for ip in ips}
    with ThreadPoolExecutor(max_workers=12) as pool:
        for i, ((ip, name, _z), status) in enumerate(
                zip(jobs, pool.map(lambda j: query(j[0], j[2], resolve), jobs)), 1):
            out[ip][name] = status
            if progress:
                progress(i, len(jobs))
    return out


def summary(statuses: dict[str, str]) -> str:
    listed = [n for n, s in statuses.items() if s == "listed"]
    if listed:
        return "Listed: " + ", ".join(listed)
    if statuses and all(s == "unavailable" for s in statuses.values()):
        return "Couldn't check"
    return "Clear" if statuses else ""


def findings(results: dict, sources) -> list[Finding]:
    out = []
    urls = {n: u for n, _z, u in LISTS}
    for s in sources:
        listed = [n for n, st in results.get(s.ip, {}).items() if st == "listed"]
        if not listed:
            continue
        shared = s.provider in SHARED
        sev = "medium" if shared or listed == ["PSBL"] else "high"
        steps = []
        if shared:
            steps.append(f"This is a shared server run by {s.provider}. Listings like this are "
                         f"usually handled by {s.provider}; contact their support if your "
                         "mail is being rejected.")
        else:
            steps.append("Find out why first: a hacked email account, a website form sending "
                         "spam, or a misconfigured server. Fix that, or the server will be "
                         "listed again.")
        steps += [f"Look up the listing and request removal: [{n}]({urls[n]})" for n in listed]
        out.append(Finding(
            sev, f"{s.label} ({s.ip}) is on a spam blocklist",
            f"This server sends your email and is listed on {', '.join(listed)}. Many "
            "receivers reject or junk mail from listed servers.",
            steps, s.messages, [s.ip], key=f"blocklist:{s.ip}", source="blocklist"))
    return out
