"""Bulk sender requirements (Gmail, Yahoo and Outlook.com) as a pass/fail checklist.

Applies to domains sending about 5,000+ messages a day to personal Gmail, Yahoo or
Outlook.com addresses; the same checks help every sender. Sources: the providers'
published sender guidelines (Gmail and Yahoo since Feb 2024, Outlook.com since May 2025).
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

from .analyzer import Finding

BIG_PROVIDERS = {"Google", "Microsoft 365", "Microsoft Outlook.com", "Amazon SES", "SendGrid",
                 "Mailchimp", "Mailchimp Transactional", "Mailgun", "Postmark", "SparkPost",
                 "Mailjet", "Brevo", "Klaviyo", "HubSpot", "Salesforce Marketing Cloud",
                 "Zoho Mail", "Constant Contact", "Zendesk", "Freshdesk", "Salesforce",
                 "Yahoo", "Apple iCloud"}


@dataclass
class Requirement:
    key: str
    title: str
    who: str
    status: str          # pass, fail, warn, unknown, manual
    detail: str
    fix: Finding | None = None


def fcrdns(ip: str, hostname: str) -> bool:
    """Forward-confirmed reverse DNS: the PTR name resolves back to the same IP."""
    if not hostname:
        return False
    try:
        return ip in socket.gethostbyname_ex(hostname)[2]
    except (OSError, UnicodeError):
        return False


def own_servers(analysis) -> list:
    """Servers that send your mail and aren't run by a big email service."""
    return [s for s in analysis.sources
            if s.category in ("authorized", "partial", "service_failing")
            and s.provider not in BIG_PROVIDERS and ":" not in s.ip]


def build_checklist(domain: str, analysis, dns, ptr_ok: dict, postmaster: dict | None,
                    findings: list) -> list[Requirement]:
    def fix(*prefixes):
        return next((f for f in findings if f.key.startswith(prefixes)
                     and f.key.endswith(domain)), None)

    out: list[Requirement] = []
    if dns is None:
        spf = dkim = dmarc = ("unknown", "Run the DNS check to see this.")
    else:
        bad_spf = fix("dns:spf-missing", "dns:spf-multiple", "dns:spf-too-many", "dns:spf-void",
                      "dns:spf-plus-all")
        spf = ("fail", bad_spf.title) if bad_spf else ("pass", f"Valid, {dns.spf_lookups} of 10 lookups.")
        dkim = (("pass", "Keys found: " + ", ".join(dns.dkim_found)) if dns.dkim_found
                else ("fail", "No DKIM keys found. SPF and DMARC without DKIM fail Gmail's check."))
        dmarc = (("pass", f"Published (p={dns.dmarc_tags.get('p', '?')}). p=none is enough for "
                          "these rules.") if dns.dmarc_record else ("fail", "No DMARC record."))
    out.append(Requirement("spf", "SPF record", "Gmail, Yahoo, Outlook.com", *spf,
                           fix("dns:spf-")))
    out.append(Requirement("dkim", "DKIM signing", "Gmail, Yahoo, Outlook.com", *dkim,
                           fix("dns:dkim-")))
    out.append(Requirement("dmarc", "DMARC record", "Gmail, Yahoo, Outlook.com", *dmarc,
                           fix("dns:dmarc-")))

    pol = analysis.policies.get(domain) if analysis else None
    if pol and pol.legit_messages:
        rate = pol.legit_pass_rate * 100
        st = "pass" if rate >= 98 else ("warn" if rate >= 90 else "fail")
        svc = next((f for f in findings if f.key.startswith("service:")), None)
        out.append(Requirement("align", "Mail passes DMARC (aligned SPF or DKIM)",
                               "Gmail, Yahoo, Outlook.com", st,
                               f"{rate:.1f}% of your legitimate mail passes.", svc))
    else:
        out.append(Requirement("align", "Mail passes DMARC (aligned SPF or DKIM)",
                               "Gmail, Yahoo, Outlook.com", "unknown", "Needs DMARC reports."))

    servers = own_servers(analysis) if analysis else []
    if not servers:
        out.append(Requirement("ptr", "Reverse DNS (PTR) for sending servers", "Gmail, Yahoo",
                               "pass", "Your mail is sent by email services, which handle this."))
    else:
        bad = [s for s in servers if ptr_ok.get(s.ip) is False]
        unknown = [s for s in servers if s.ip not in ptr_ok]
        if bad:
            names = ", ".join(f"{s.label} ({s.ip})" for s in bad[:4])
            out.append(Requirement("ptr", "Reverse DNS (PTR) for sending servers", "Gmail, Yahoo",
                                   "fail", f"No matching reverse DNS for: {names}. Ask the "
                                   "company that runs these servers to set a PTR record."))
        elif unknown:
            out.append(Requirement("ptr", "Reverse DNS (PTR) for sending servers", "Gmail, Yahoo",
                                   "unknown", "Checking…"))
        else:
            out.append(Requirement("ptr", "Reverse DNS (PTR) for sending servers", "Gmail, Yahoo",
                                   "pass", f"All {len(servers)} of your own servers match."))

    out.append(Requirement("tls", "Encrypted connections (TLS)", "Gmail, Yahoo", "manual",
                           "Email services use TLS automatically. Only your own mail servers "
                           "need checking."))
    spam = (postmaster or {}).get("spam_rate")
    if spam is None:
        out.append(Requirement("spam", "Spam complaint rate under 0.3%", "Gmail, Yahoo",
                               "unknown", "Connect Gmail Postmaster Tools in Settings to see "
                               "your rate. Aim for under 0.1%."))
    else:
        st = "pass" if spam < 0.001 else ("warn" if spam < 0.003 else "fail")
        out.append(Requirement("spam", "Spam complaint rate under 0.3%", "Gmail, Yahoo", st,
                               f"Gmail reports {spam * 100:.2f}% over the last week (aim for "
                               "under 0.1%)."))
    unsub = (postmaster or {}).get("unsubscribe")
    out.append(Requirement(
        "unsub", "One-click unsubscribe (RFC 8058)", "Gmail, Yahoo (Outlook.com recommends)",
        unsub or "manual",
        "Gmail's compliance check reports this." if unsub else
        "Marketing mail needs List-Unsubscribe and List-Unsubscribe-Post headers, honoured "
        "within 2 days. Check your newsletter service's settings; most turn it on by default. "
        "Not needed for receipts or password resets."))
    return out


def findings(reqs: list[Requirement], domain: str) -> list[Finding]:
    out = []
    for r in reqs:
        if r.status == "fail" and r.key in ("ptr", "spam"):
            out.append(Finding(
                "high" if r.key == "spam" else "medium",
                f"Bulk sender rule not met for {domain}: {r.title.lower()}", r.detail,
                ["If you send 5,000+ messages a day to Gmail, Yahoo or Outlook.com users, "
                 "this can get your mail rejected. See the Bulk sender rules tab."],
                0, [], key=f"senderreqs:{r.key}:{domain}", source="senderreqs"))
    return out
