"""Turn a finding into a step-by-step fix: the exact DNS change, where to make it, how to
check it worked, and an email to send to whoever manages DNS."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote_plus

from . import recordbuilder
from .dnscheck import PARKED_SPF, DnsError
from .guides import guide_step
from .senders import identify_provider

# SPF include for services whose value is long-established and documented.
SPF_INCLUDES = {
    "Google": "_spf.google.com",
    "Microsoft 365": "spf.protection.outlook.com",
    "SendGrid": "sendgrid.net",
    "Mailchimp": "servers.mcsv.net",
    "Mailchimp Transactional": "spf.mandrillapp.com",
    "Amazon SES": "amazonses.com",
    "Mailgun": "mailgun.org",
    "Postmark": "spf.mtasv.net",
    "SparkPost": "_spf.sparkpostmail.com",
    "Mailjet": "spf.mailjet.com",
    "Salesforce": "_spf.salesforce.com",
    "Zendesk": "mail.zendesk.com",
    "Freshdesk": "email.freshdesk.com",
    "Constant Contact": "spf.constantcontact.com",
    "GoDaddy": "secureserver.net",
    "Rackspace Email": "emailsrvr.com",
}


# ================================================================ DNS hosts

@dataclass
class HostGuide:
    name: str
    url: str
    steps: list[str]
    quirks: list[str] = field(default_factory=list)
    relative_names: bool = True      # enter "_dmarc" rather than "_dmarc.example.com"


GENERIC_STEPS = ["Sign in where your domain's DNS is managed (often your domain registrar or "
                 "web host).", "Open the DNS settings (sometimes called DNS zone, DNS "
                 "management or Advanced DNS) for your domain.",
                 "Add or edit the record below, then save."]

_HOSTS: list[tuple[tuple[str, ...], HostGuide]] = [
    ((".ns.cloudflare.com",), HostGuide(
        "Cloudflare", "https://dash.cloudflare.com/",
        ["Sign in and select your domain.", "Go to DNS > Records.",
         "Click Add record (or Edit on an existing one), choose the type, fill in Name and "
         "Content, and click Save."],
        ["In Name, enter only the part before your domain (for example `_dmarc`). Use `@` "
         "for the domain itself.",
         "For CNAME records used by DKIM, set Proxy status to DNS only (grey cloud)."])),
    (("domaincontrol.com",), HostGuide(
        "GoDaddy", "https://dcc.godaddy.com/",
        ["Sign in and open your domain portfolio.", "Select the domain, then DNS.",
         "Click Add New Record (or the pencil to edit one), fill it in, and save."],
        ["Name is only the prefix (for example `_dmarc`); use `@` for the domain itself. "
         "GoDaddy adds your domain automatically.",
         "If an SPF record already exists, edit it instead of adding a second one."])),
    (("registrar-servers.com",), HostGuide(
        "Namecheap", "https://ap.www.namecheap.com/domains/list/",
        ["Sign in and open Domain List.", "Click Manage next to the domain, then Advanced DNS.",
         "Click Add New Record, fill it in, and click the tick to save."],
        ["Host is only the prefix (for example `_dmarc`); use `@` for the domain itself."])),
    (("awsdns-",), HostGuide(
        "Amazon Route 53", "https://console.aws.amazon.com/route53/v2/hostedzones",
        ["Open Hosted zones and select the domain.", "Click Create record (or select a "
         "record and Edit).", "Fill in Record name, Record type and Value, then save."],
        ["Put TXT values in double quotes. Values longer than 255 characters must be split "
         "into several quoted strings in the same record (XML-ray shows the split version)."])),
    (("azure-dns.",), HostGuide(
        "Azure DNS", "https://portal.azure.com/#browse/Microsoft.Network%2FdnsZones",
        ["Open DNS zones and select the zone.", "Click + Record set (or select one to edit).",
         "Fill in Name, Type and Value, then click OK."], [])),
    (("bdm.microsoftonline.com",), HostGuide(
        "Microsoft 365", "https://admin.microsoft.com/#/Domains",
        ["Open Settings > Domains in the Microsoft 365 admin center.",
         "Select the domain, then the DNS records tab.",
         "Click Add record, fill it in, and save."], [])),
    (("googledomains.com",), HostGuide(
        "Google Cloud DNS or Squarespace Domains (formerly Google Domains)",
        "https://console.cloud.google.com/net-services/dns/zones",
        ["If you use Google Cloud, open Cloud DNS, select the zone and click Add standard.",
         "If your domain moved from Google Domains to Squarespace, sign in at "
         "account.squarespace.com, open Domains, select the domain and choose DNS.",
         "Add or edit the record and save."], [])),
    (("digitalocean.com",), HostGuide(
        "DigitalOcean", "https://cloud.digitalocean.com/networking/domains",
        ["Open Networking > Domains and select the domain.",
         "Choose the record type, fill in Hostname and Value, and click Create Record."],
        ["Use `@` for the domain itself."])),
    (("ui-dns.",), HostGuide(
        "IONOS", "https://my.ionos.com/domains",
        ["Open Domains & SSL, select the domain, then DNS.", "Click Add record, choose the "
         "type, fill it in and save."], [])),
]
_NAMED = {  # recognised, but without verified links: generic steps plus a search link
    "worldnic.com": "Network Solutions", "bluehost.com": "Bluehost",
    "hostgator.com": "HostGator", "wixdns.net": "Wix", "hover.com": "Hover",
    "porkbun.com": "Porkbun", "gandi.net": "Gandi", "name.com": "Name.com",
    "dnsimple.com": "DNSimple", "nsone.net": "NS1", "linode.com": "Akamai (Linode)",
    "dreamhost.com": "DreamHost", "siteground.net": "SiteGround", "squarespacedns.com":
    "Squarespace", "squarespace.com": "Squarespace", "hostinger.com": "Hostinger",
}


def detect_host(ns: list[str]) -> HostGuide:
    for host in ns:
        for patterns, guide in _HOSTS:
            if any(p in host for p in patterns):
                return guide
        for suffix, name in _NAMED.items():
            if host.endswith(suffix):
                q = quote_plus(f"{name} add TXT record DNS")
                return HostGuide(name, f"https://www.google.com/search?q={q}", GENERIC_STEPS)
    return HostGuide("your DNS provider", "", GENERIC_STEPS)


def display_name(fqdn: str, domain: str, guide: HostGuide) -> str:
    if not guide.relative_names:
        return fqdn
    if fqdn == domain:
        return "@"
    return fqdn[: -len(domain) - 1] if fqdn.endswith("." + domain) else fqdn


def split_txt(value: str) -> str:
    """Quoted 255-character chunks, for hosts that need long TXT values split."""
    if len(value) <= 255:
        return value
    return " ".join(f'"{value[i:i + 255]}"' for i in range(0, len(value), 255))


def human_ttl(seconds: int) -> str:
    if seconds <= 0:
        return "a few minutes"
    if seconds < 3600:
        return f"{max(1, seconds // 60)} minutes"
    if seconds < 86400:
        h = seconds // 3600
        return f"{h} hour{'s' if h != 1 else ''}"
    d = seconds // 86400
    return f"{d} day{'s' if d != 1 else ''}"


# =================================================================== plans

@dataclass
class RecordChange:
    action: str          # add, change, delete, from_provider
    host: str            # full DNS name
    rtype: str           # TXT, CNAME, MX, ...
    current: str = ""
    proposed: str = ""
    note: str = ""
    exact: bool = True   # False when the value must come from a service's settings


@dataclass
class FileToHost:
    url: str
    content: str
    note: str = ""


@dataclass
class FixPlan:
    title: str
    why: str
    domain: str
    changes: list[RecordChange] = field(default_factory=list)
    files: list[FileToHost] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verify_key: str = ""         # the finding key that should disappear once fixed
    dns_fix: bool = True         # False: nothing to change in your DNS


@dataclass
class FixContext:
    dns: dict                    # domain -> DnsResult
    analysis: object = None      # analyzer.Analysis (may be None)
    domains: list = field(default_factory=list)


def _domain_of(finding, ctx: FixContext) -> str:
    key = finding.key
    if ":" in key and (key.startswith(("dns:", "policy-", "pct:", "sp:", "testing:",
                                       "parked", "roadmap:"))):
        return key.rsplit(":", 1)[-1]
    if ctx.analysis is not None and getattr(ctx.analysis, "policies", None):
        return sorted(ctx.analysis.policies)[0]
    return ctx.domains[0] if ctx.domains else ""


def _sources_for(ctx: FixContext, domain: str) -> list:
    if ctx.analysis is None:
        return []
    return [s for s in ctx.analysis.sources if domain in s.by_domain and s.category != "ignored"]


# ------------------------------------------------------------------ DMARC

def proposed_dmarc(domain: str, ctx: FixContext, stage: str | None = None) -> tuple[str, str]:
    """(current record, proposed record) for the recommended next step."""
    res = ctx.dns.get(domain)
    current = res.dmarc_record if res else ""
    tags = dict(res.dmarc_tags) if res else {}
    pol = ctx.analysis.policies.get(domain) if ctx.analysis is not None else None
    if stage is None:
        if res and tags.get("p"):
            cur_stage = recordbuilder.stage_from_tags(tags)
            ready = bool(pol and pol.ready_to_enforce)
            order = [s[0] for s in recordbuilder.STAGES]
            stage = order[min(order.index(cur_stage) + 1, len(order) - 1)] if ready else cur_stage
        else:
            stage, _ = recordbuilder.recommend_stage(pol, bool(pol and pol.ready_to_enforce))
    rua = ",".join(u.strip().removeprefix("mailto:") for u in tags.get("rua", "").split(",")
                   if u.strip()) or f"dmarc-reports@{domain}"
    ruf = ",".join(u.strip().removeprefix("mailto:") for u in tags.get("ruf", "").split(",")
                   if u.strip())
    strength = {"none": 0, "quarantine": 1, "reject": 2}
    p_new = next(s[2] for s in recordbuilder.STAGES if s[0] == stage)
    sp = tags.get("sp", "").lower()
    if sp and strength.get(sp, 0) < strength.get(p_new, 0):
        sp = ""                                          # don't leave subdomains weaker
    opts = recordbuilder.RecordOptions(domain, stage, rua=rua, ruf=ruf, sp=sp,
                                       strict_dkim=tags.get("adkim") == "s",
                                       strict_spf=tags.get("aspf") == "s")
    return current, recordbuilder.build_record(opts)


def _dmarc_plan(f, d: str, ctx: FixContext, stage: str | None = None) -> FixPlan:
    current, proposed = proposed_dmarc(d, ctx, stage)
    res = ctx.dns.get(d)
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    plan.changes.append(RecordChange("change" if current else "add", f"_dmarc.{d}", "TXT",
                                     current, proposed))
    if res and len(res.dmarc_records) > 1:
        for extra in res.dmarc_records[1:]:
            plan.changes.append(RecordChange("delete", f"_dmarc.{d}", "TXT", extra, "",
                                             "Remove this extra copy. Keep only one DMARC record."))
    if "p=quarantine" in proposed or "p=reject" in proposed:
        plan.notes.append("Enforcing DMARC blocks or junks email that fails. Only take this "
                          "step when the action plan shows no failing services of yours.")
    if "pct=25" in proposed:
        plan.notes.append("After two weeks of clean reports, come back here: XML-ray will "
                          "suggest the next step (all failing mail to spam).")
        plan.notes.append("Important: the updated DMARC standard (RFC 9989, May 2026) no longer "
                          "includes pct, so receivers that follow it may send all failing mail "
                          "to spam, not just 25%. Only take this step when none of your own "
                          "services are failing.")
    return plan


# -------------------------------------------------------------------- SPF

def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _covers(nets: list[str], ips: list) -> bool:
    """True if any of *ips* falls inside any of the SPF ranges in *nets*."""
    parsed = []
    for n in nets:
        try:
            parsed.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            return True          # can't read a range: be safe and keep the include
    return any(ip in net for ip in ips for net in parsed if ip.version == net.version)


def _include_target(term: str) -> str:
    t = term.lstrip("+-~?").lower()
    return t.split(":", 1)[1] if t.startswith("include:") else ""


def proposed_spf(d: str, ctx: FixContext) -> tuple[str, str, list[str], int]:
    """(current, proposed, explanations, lookups after the change)."""
    res = ctx.dns.get(d)
    sources = _sources_for(ctx, d)
    seen_providers = {s.provider for s in sources if s.provider and s.category != "unknown"}
    seen_providers |= {s.nickname for s in sources if s.nickname}
    notes: list[str] = []
    if not res or not res.spf_records:
        terms = []
        for prov in sorted(seen_providers):
            group = [s for s in sources if s.provider == prov]
            uses_our_envelope = any(e == d or e.endswith("." + d)
                                    for s in group for e in s.envelope_from)
            if prov in SPF_INCLUDES and uses_our_envelope:
                terms.append(f"include:{SPF_INCLUDES[prov]}")
                notes.append(f"Added {prov}, which sends with your domain as the envelope sender.")
        for s in sources:
            if s.status == "mine" and not s.provider and ":" not in s.ip:
                terms.append(f"ip4:{s.ip}")
                notes.append(f"Added {s.label} ({s.ip}), which you marked as yours.")
        if not terms:
            notes.append("No service in your reports needs SPF yet. Add each service's include "
                         "from its setup guide as you start using it.")
        return "", " ".join(["v=spf1", *dict.fromkeys(terms), "~all"]), notes, 0

    current = res.spf_record
    terms = current.split()[1:]
    # merge any duplicate SPF records into one
    for extra in res.spf_records[1:]:
        for t in extra.split()[1:]:
            if t.lstrip("+-~?").lower() != "all" and t not in terms:
                terms.insert(len([x for x in terms if x.lstrip("+-~?").lower() != "all"]), t)
        notes.append("Merged the second SPF record into this one.")
    costs = dict(res.spf_terms)
    source_ips = [ipaddress.ip_address(s.ip) for s in sources if _is_ip(s.ip)]
    kept = []
    for t in terms:
        target = _include_target(t)
        if target and target in res.spf_void:
            notes.append(f"Removed include:{target}, which points to a domain with no SPF.")
            continue
        nets, complete = res.spf_term_nets.get(t, ([], False))
        if target and res.spf_lookups > 8 and source_ips and complete and nets \
                and not _covers(nets, source_ips):
            prov = identify_provider(target)
            notes.append(f"Removed include:{target}{f' ({prov})' if prov else ''}: none of the "
                         "servers in your reports belong to it. Put it back if you still "
                         "use that service.")
            continue
        kept.append(t)
    # the all mechanism: keep -all/~all, fix +all/?all, add ~all if missing
    alls = [t for t in kept if t.lstrip("+-~?").lower() == "all"]
    kept = [t for t in kept if t.lstrip("+-~?").lower() != "all"]
    has_redirect = any(t.lower().startswith("redirect=") for t in kept)
    final_all = "-all" if "-all" in [a.lower() for a in alls] else "~all"
    if any(a.lower() in ("+all", "all", "?all") for a in alls):
        notes.append(f"Changed {alls[0]} to {final_all}.")
    elif not alls and not has_redirect:
        notes.append("Added ~all at the end.")
    proposed = " ".join(["v=spf1", *kept] + ([] if has_redirect and not alls else [final_all]))
    lookups = sum(costs.get(t, 1 if _include_target(t) else 0) for t in kept)
    return current, proposed, notes, lookups


def _spf_plan(f, d: str, ctx: FixContext) -> FixPlan:
    current, proposed, notes, lookups = proposed_spf(d, ctx)
    res = ctx.dns.get(d)
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    plan.changes.append(RecordChange("change" if current else "add", d, "TXT", current,
                                     proposed, " ".join(notes)))
    if res and len(res.spf_records) > 1:
        for extra in res.spf_records[1:]:
            plan.changes.append(RecordChange("delete", d, "TXT", extra, "",
                                             "Delete this second SPF record after updating the first."))
    if current and lookups:
        plan.notes.append(f"The new record needs {lookups} of 10 DNS lookups.")
    if lookups > 10:
        big = sorted(((t, c) for t, c in res.spf_terms if c > 1), key=lambda x: -x[1])[:3]
        plan.steps += [
            "Even after the clean-up, SPF needs more than 10 lookups. The biggest are: "
            + ", ".join(f"{t} ({c})" for t, c in big) + ".",
            "Move a bulk or marketing service to a subdomain (for example news." + d +
            ") with its own SPF record, and send that mail from the subdomain.",
            "For services that sign with DKIM using your domain, you can remove their "
            "include: from SPF, because DKIM alone passes DMARC.",
        ]
    return plan


# ---------------------------------------------------------------- others

def _dkim_plan(f, d: str, ctx: FixContext, selector: str = "", provider: str = "") -> FixPlan:
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    host = f"{selector}._domainkey.{d}" if selector else f"<selector>._domainkey.{d}"
    who = provider or "the sending service"
    plan.changes.append(RecordChange(
        "from_provider", host, "CNAME or TXT", "",
        f"Copy the exact value from {who}'s DKIM or domain authentication settings.",
        "Each service generates its own key, so XML-ray can't know the value in advance.",
        exact=False))
    plan.steps = list(f.steps)
    if provider and not any(provider in s for s in plan.steps):
        plan.steps.append(guide_step(provider))
    return plan


def _parked_plan(f, d: str, ctx: FixContext) -> FixPlan:
    res = ctx.dns.get(d)
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    cur_spf = res.spf_record if res else ""
    if cur_spf.lower().strip() != PARKED_SPF:
        plan.changes.append(RecordChange("change" if cur_spf else "add", d, "TXT", cur_spf,
                                         PARKED_SPF, "No server may send email for this domain."))
    rua = (res.dmarc_tags.get("rua", "") if res else "")
    dm = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s" + (f"; rua={rua}" if rua else "")
    if not res or res.dmarc_tags.get("p", "").lower() != "reject":
        plan.changes.append(RecordChange("change" if res and res.dmarc_record else "add",
                                         f"_dmarc.{d}", "TXT",
                                         res.dmarc_record if res else "", dm))
    if not res or res.mx != [""]:
        plan.changes.append(RecordChange(
            "add", d, "MX", ", ".join(m for m in (res.mx if res else []) if m), "0 .",
            "A “null MX”: priority 0, mail server “.”. Delete any other MX records first. "
            "Some DNS hosts don't accept a lone dot; if so, skip this record.", exact=True))
    plan.changes.append(RecordChange("add", f"*._domainkey.{d}", "TXT", "", "v=DKIM1; p=",
                                     "Optional: says no DKIM key is valid for this domain."))
    plan.notes.append("Only use these records for domains that never send or receive email.")
    return plan


def _mta_sts_plan(f, d: str, ctx: FixContext) -> FixPlan:
    res = ctx.dns.get(d)
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    mx = [m for m in (res.mx if res else []) if m] or [f"mail.{d}"]
    pol = (res.mta_sts.get("policy") or {}) if res else {}
    mode = "enforce" if f.key.startswith("dns:mta-sts-testing") else (pol.get("mode") or "testing")
    if f.key.startswith("dns:mta-sts-missing"):
        mode = "testing"
    new_id = datetime.now().strftime("%Y%m%d%H%M")
    content = "version: STSv1\nmode: " + mode + "\n" + "".join(f"mx: {m}\n" for m in mx) \
        + "max_age: " + ("1209600" if mode == "enforce" else "86400") + "\n"
    cur = res.mta_sts.get("record", "") if res else ""
    plan.changes.append(RecordChange("change" if cur else "add", f"_mta-sts.{d}", "TXT", cur,
                                     f"v=STSv1; id={new_id}",
                                     "Change the id every time you edit the policy file."))
    if res and not any(v.kind == "TLS reporting" and v.status == "ok" for v in res.records):
        plan.changes.append(RecordChange("add", f"_smtp._tls.{d}", "TXT", "",
                                         f"v=TLSRPTv1; rua=mailto:dmarc-reports@{d}",
                                         "TLS reports show whether MTA-STS is working."))
    plan.files.append(FileToHost(f"https://mta-sts.{d}/.well-known/mta-sts.txt", content,
                                 "A plain text file, served over HTTPS with a valid certificate."))
    if not cur:
        plan.steps += [
            f"Create the website mta-sts.{d} on any host that supports HTTPS, for example "
            "your current web host, GitHub Pages or Cloudflare Pages, and point "
            f"mta-sts.{d} at it with the CNAME or A record that host gives you.",
            "Upload the policy file to the address shown, then publish the TXT record(s).",
            "After two to four clean weeks of TLS reports, come back and switch to enforce.",
        ]
    return plan


def _bimi_plan(f, d: str, ctx: FixContext) -> FixPlan:
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    res = ctx.dns.get(d)
    cur = res.bimi.get("record", "") if res else ""
    plan.changes.append(RecordChange(
        "change" if cur else "add", f"default._bimi.{d}", "TXT", cur,
        f"v=BIMI1; l=https://www.{d}/bimi/logo.svg; a=https://www.{d}/bimi/certificate.pem",
        "Replace the two links with where you host your logo and certificate.", exact=False))
    plan.steps = [
        "Make sure DMARC is p=quarantine (at 100%) or p=reject.",
        "Convert your logo to SVG Tiny P/S format (many design tools and online converters "
        "can export it) and host it at an https:// address.",
        "For Gmail and Apple Mail, buy a VMC (needs a registered trademark) or CMC certificate "
        "from a certificate authority such as DigiCert or Sectigo. Yahoo shows logos without one.",
        "Publish the BIMI record. Logos can take several days to appear.",
    ]
    return plan


def _rua_auth_plan(f, d: str, ctx: FixContext) -> FixPlan:
    other = f.key.split("dmarc-rua-auth-", 1)[1].rsplit(":", 1)[0]
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    plan.changes.append(RecordChange("add", f"{d}._report._dmarc.{other}", "TXT", "",
                                     "v=DMARC1", f"This record goes in {other}'s DNS, not yours."))
    plan.notes.append(f"If you don't manage {other}, use “Send these steps to someone” to ask "
                      "its owner, or change your report address to one at your own domain.")
    return plan


def _tlsrpt_plan(f, d: str, ctx: FixContext) -> FixPlan:
    plan = FixPlan(f.title, f.summary, d, verify_key=f.key)
    plan.changes.append(RecordChange("add", f"_smtp._tls.{d}", "TXT", "",
                                     f"v=TLSRPTv1; rua=mailto:dmarc-reports@{d}",
                                     "Use any mailbox you check; XML-ray can import from it."))
    return plan


def build_plan(finding, ctx: FixContext) -> FixPlan:
    """The fix for any finding. Unknown kinds fall back to the finding's own steps."""
    key = finding.key or ""
    d = _domain_of(finding, ctx)
    if key.startswith("roadmap:"):                       # "roadmap:<stage>:<domain>"
        return _dmarc_plan(finding, d, ctx, key.split(":")[1])
    k = key.split(":")[1] if key.startswith("dns:") else key.split(":")[0]

    if key.startswith("dns:dmarc-rua-auth-"):
        return _rua_auth_plan(finding, d, ctx)
    if k in ("dmarc-missing", "dmarc-invalid", "dmarc-multiple", "dmarc-no-rua"):
        return _dmarc_plan(finding, d, ctx)
    if k in ("policy-none", "policy-ready", "pct", "sp", "testing", "unknown-delivered"):
        stage = {"policy-ready": "reject"}.get(k)
        if k == "pct":
            stage = "q100" if "quarantine" in (ctx.dns.get(d).dmarc_record
                                               if ctx.dns.get(d) else "quarantine") else "reject"
        if k == "unknown-delivered":
            res = ctx.dns.get(d)
            p = (res.dmarc_tags.get("p") if res else None) or (
                ctx.analysis.policies[d].p if ctx.analysis and d in ctx.analysis.policies else "none")
            stage = "q25" if p == "none" else None
        plan = _dmarc_plan(finding, d, ctx, stage)
        plan.steps = [s for s in finding.steps if "Senders tab" in s or "recognise" in s]
        return plan
    if k in ("spf-missing", "spf-too-many", "spf-near-limit", "spf-plus-all", "spf-neutral",
             "spf-no-all", "spf-multiple", "spf-void"):
        return _spf_plan(finding, d, ctx)
    if k.startswith("dkim-missing-") or k.startswith("dkim-weak-"):
        return _dkim_plan(finding, d, ctx, selector=k.split("-", 2)[2])
    if k == "dkim-none":
        return _dkim_plan(finding, d, ctx)
    if key.startswith("service:"):
        provider = ""
        if ctx.analysis is not None:
            group = [s for s in ctx.analysis.sources if s.ip in finding.ips]
            provider = next((s.provider for s in group if s.provider), "")
        plan = _dkim_plan(finding, d, ctx, provider=provider)
        plan.title, plan.verify_key = finding.title, ""
        plan.notes.append("Fixes for a sending service show up in new reports within one or "
                          "two days. The Senders tab will then show it as Passing.")
        return plan
    if k in ("parked-unlocked", "parked-suggest"):
        return _parked_plan(finding, d, ctx)
    if k in ("tlsrpt-missing",):
        return _tlsrpt_plan(finding, d, ctx)
    if k.startswith("mta-sts"):
        return _mta_sts_plan(finding, d, ctx)
    if k.startswith("bimi"):
        return _bimi_plan(finding, d, ctx)
    # report, TLS, blocklist and lookalike findings: no DNS record to change
    plan = FixPlan(finding.title, finding.summary, d, steps=list(finding.steps),
                   verify_key="", dns_fix=False)
    return plan


# =================================================================== email

_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _plain(text: str) -> str:
    """Markdown-style links and `code` to plain text for emails."""
    return _LINK.sub(r"\1 (\2)", text).replace("`", "")


def email_text(plan: FixPlan, guide: HostGuide) -> tuple[str, str]:
    """(subject, body) for asking someone else to make the change."""
    d = plan.domain
    subject = f"DNS change needed for {d}" if plan.changes else f"Email security fix for {d}"
    lines = ["Hi,", "", f"Could you please make the following change for {d}?", "",
             f"Why: {plan.why}", ""]
    words = {"add": "Add", "change": "Change", "delete": "Delete",
             "from_provider": "Add (value from the service)"}
    for i, c in enumerate(plan.changes, 1):
        lines += [f"{i}. {words.get(c.action, c.action)} a {c.rtype} record",
                  f"   Name/host: {display_name(c.host, d, guide)}   (full name: {c.host})"]
        if c.current:
            lines.append(f"   Current value: {c.current}")
        if c.proposed:
            lines.append(f"   {'New value' if c.action != 'delete' else 'Value to delete'}: "
                         f"{c.proposed if c.action != 'delete' else c.current}")
        if c.note:
            lines.append(f"   Note: {c.note}")
        lines.append("")
    for fh in plan.files:
        lines += [f"Host this file at {fh.url}:", "", fh.content, ""]
    if plan.steps:
        lines.append("Other steps:")
        lines += ["- " + _plain(s) for s in plan.steps]
        lines.append("")
    if guide.name != "your DNS provider":
        lines.append(f"Our DNS appears to be hosted at {guide.name}.")
    lines += ["", "Thank you!"]
    return subject, "\n".join(lines)


# ================================================================== verify

@dataclass
class CheckResult:
    change: RecordChange
    ok: bool
    message: str


def _norm(v: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\s*;\s*", "; ", v.strip().rstrip(";"))).lower()


def verify_changes(plan: FixPlan, resolver) -> tuple[list[CheckResult], int]:
    """Look each change up in live DNS. Returns (results, longest TTL seen)."""
    out, ttl = [], 0
    for c in plan.changes:
        if "<" in c.host:
            out.append(CheckResult(c, True, "Check this one in the service's own settings "
                                            "(XML-ray doesn't know its exact name)."))
            continue
        try:
            if c.rtype == "MX":
                values = resolver.mx(c.host)
                ok = values == [""] if c.proposed.strip() == "0 ." else bool(values)
                live = ", ".join(v or "0 ." for v in values)
            elif c.rtype.startswith("CNAME"):
                values = resolver.txt(c.host)
                ok, live = any("p=" in v for v in values), (values[0] if values else "")
            else:
                values = resolver.txt(c.host)
                live = values[0] if values else ""
                if c.action == "delete":
                    ok = _norm(c.current) not in [_norm(v) for v in values]
                elif c.exact:
                    ok = _norm(c.proposed) in [_norm(v) for v in values]
                else:
                    ok = bool(values)
            ttl = max(ttl, resolver.ttl(c.host, "MX" if c.rtype == "MX" else "TXT")
                      if hasattr(resolver, "ttl") else 0)
        except DnsError as exc:
            out.append(CheckResult(c, False, f"Couldn't look it up: {exc}"))
            continue
        if ok:
            msg = "Done. DNS shows the new value." if c.action != "delete" else "Done. It's gone."
        elif c.action == "delete":
            msg = "Still there."
        elif not values:
            msg = "Not found in DNS yet."
        elif c.current and _norm(live) == _norm(c.current):
            msg = "DNS still shows the old value."
        else:
            msg = f"DNS shows a different value: {live[:160]}"
        out.append(CheckResult(c, ok, msg))
    return out, ttl



# ========================================================== new service

def service_plan(service, domain: str, dns) -> FixPlan:
    """Steps to set up a new email service for *domain* (from services.CATALOG)."""
    name = service.name if service.name != "Other service" else "the service"
    plan = FixPlan(
        f"Set up {name} to send email for {domain}",
        f"So that email {name} sends using {domain} passes DMARC, it must sign with your "
        "domain (DKIM). Do this before sending, so nothing gets blocked or junked.",
        domain, verify_key="")
    plan.changes.append(RecordChange(
        "from_provider", f"<selector>._domainkey.{domain}", "CNAME or TXT", "",
        f"Copy each record exactly as {name} shows it (usually two or three CNAME records).",
        f"Find them in {name}: {service.where}." if service.where else
        f"Look in {name}'s settings for “domain authentication”, “sender authentication” or "
        "“DKIM”.", exact=False))
    include = service.spf_include
    if service.spf == "required":
        current = dns.spf_record if dns else ""
        if include and current and f"include:{include}" in current.lower():
            plan.notes.append(f"Your SPF record already includes {name}.")
        elif include:
            if current:
                terms = current.split()
                pos = next((i for i, t in enumerate(terms) if t.lstrip("+-~?").lower() == "all"
                            or t.lower().startswith("redirect=")), len(terms))
                proposed = " ".join(terms[:pos] + [f"include:{include}"] + terms[pos:])
                est = (dns.spf_lookups if dns else 0) + 1
                note = (f"About {est} of 10 DNS lookups afterwards (the include can add a few "
                        "more; run the DNS check after saving).")
            else:
                proposed, note = f"v=spf1 include:{include} ~all", ""
            plan.changes.append(RecordChange("change" if current else "add", domain, "TXT",
                                             current, proposed, note))
        else:
            plan.steps.append(f"Add the SPF include: value from {name}'s setup guide to your "
                              "SPF record.")
    elif include:
        plan.notes.append(f"SPF isn't needed for {name}: it uses its own bounce address, and "
                          "DKIM alone passes DMARC. Only add include:" + include +
                          f" if you set up a custom return-path (bounce) domain in {name}.")
    plan.steps = [
        f"In {name}, add {domain} as a sending domain and start domain authentication.",
        f"Add the records {name} shows at your DNS host, as described above, exactly as shown.",
        f"Back in {name}, click Verify (or Authenticate). It can take up to an hour to confirm.",
    ] + plan.steps
    if service.provider or service.name != "Other service":
        plan.steps.append(guide_step(service.provider or service.name))
    plan.notes.append(f"XML-ray will confirm from your reports, within a day or two of "
                      f"{name} sending mail, that it passes.")
    return plan
