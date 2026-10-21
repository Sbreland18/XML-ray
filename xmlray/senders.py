"""Put a friendly name on the servers that appear in DMARC reports."""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable

# Domain suffix -> friendly service name. Matched against the server's reverse-DNS
# name, its SPF envelope domain and any DKIM signing domains seen in the report.
PROVIDERS: list[tuple[str, str]] = [
    ("google.com", "Google"),
    ("googlemail.com", "Google"),
    ("1e100.net", "Google"),
    ("protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("onmicrosoft.com", "Microsoft 365"),
    ("hotmail.com", "Microsoft Outlook.com"),
    ("amazonses.com", "Amazon SES"),
    ("sendgrid.net", "SendGrid"),
    ("mcsv.net", "Mailchimp"),
    ("mcdlv.net", "Mailchimp"),
    ("rsgsv.net", "Mailchimp"),
    ("mandrillapp.com", "Mailchimp Transactional"),
    ("mailgun.org", "Mailgun"),
    ("mailgun.net", "Mailgun"),
    ("sparkpostmail.com", "SparkPost"),
    ("postmarkapp.com", "Postmark"),
    ("mtasv.net", "Postmark"),
    ("mailjet.com", "Mailjet"),
    ("sendinblue.com", "Brevo"),
    ("brevo.com", "Brevo"),
    ("klaviyomail.com", "Klaviyo"),
    ("hubspotemail.net", "HubSpot"),
    ("hubspot.com", "HubSpot"),
    ("exacttarget.com", "Salesforce Marketing Cloud"),
    ("salesforce.com", "Salesforce"),
    ("zendesk.com", "Zendesk"),
    ("freshdesk.com", "Freshdesk"),
    ("zoho.com", "Zoho Mail"),
    ("zohomail.com", "Zoho Mail"),
    ("constantcontact.com", "Constant Contact"),
    ("ctctcdn.com", "Constant Contact"),
    ("intuit.com", "Intuit QuickBooks"),
    ("docusign.net", "DocuSign"),
    ("atlassian.net", "Atlassian"),
    ("shopify.com", "Shopify"),
    ("squarespace.com", "Squarespace"),
    ("mimecast.com", "Mimecast"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint Essentials"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("barracudanetworks.com", "Barracuda"),
    ("yahoo.com", "Yahoo"),
    ("yahoodns.net", "Yahoo"),
    ("icloud.com", "Apple iCloud"),
    ("apple.com", "Apple iCloud"),
    ("secureserver.net", "GoDaddy"),
    ("emailsrvr.com", "Rackspace Email"),
    ("smtp2go.com", "SMTP2GO"),
]


def _matches(name: str, suffix: str) -> bool:
    name = name.lower().rstrip(".")
    return name == suffix or name.endswith("." + suffix)


def identify_provider(hostname: str = "", domains: Iterable[str] = ()) -> str:
    """Return a friendly provider name, or "" if the sender isn't recognised."""
    candidates = [hostname] + [d for d in domains if d]
    for candidate in candidates:
        if not candidate:
            continue
        for suffix, name in PROVIDERS:
            if _matches(candidate, suffix):
                return name
    return ""


def reverse_lookup(ip: str) -> str:
    """Best-effort reverse DNS (PTR) lookup. Returns "" when there's no name."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except (OSError, UnicodeError):
        return ""
