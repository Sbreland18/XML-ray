"""Catalog for the “Add a new email service” wizard."""
from __future__ import annotations

from dataclasses import dataclass

from .fixguide import SPF_INCLUDES
from .guides import GUIDES


@dataclass
class Service:
    name: str
    category: str
    provider: str = ""          # name used by sender recognition (senders.PROVIDERS)
    spf: str = "optional"       # required: mail uses your domain as envelope sender
    where: str = ""             # where the setting lives, in the service's own words

    @property
    def spf_include(self) -> str:
        return SPF_INCLUDES.get(self.provider or self.name, "")

    @property
    def has_official_guide(self) -> bool:
        return (self.provider or self.name) in GUIDES


CATALOG = [
    Service("Google Workspace", "Mailboxes", "Google", "required",
            "Admin console > Apps > Google Workspace > Gmail > Authenticate email"),
    Service("Microsoft 365", "Mailboxes", "Microsoft 365", "required",
            "Microsoft Defender portal > Email authentication settings > DKIM"),
    Service("Zoho Mail", "Mailboxes", "Zoho Mail", "required", "Mail admin console > Domains"),
    Service("Mailchimp", "Newsletters and marketing", "Mailchimp", "optional",
            "Account > Domains > Authenticate"),
    Service("Constant Contact", "Newsletters and marketing", "Constant Contact", "optional"),
    Service("Klaviyo", "Newsletters and marketing", "Klaviyo", "optional"),
    Service("HubSpot", "Newsletters and marketing", "HubSpot", "optional"),
    Service("Brevo", "Newsletters and marketing", "Brevo", "optional"),
    Service("Salesforce Marketing Cloud", "Newsletters and marketing",
            "Salesforce Marketing Cloud", "optional"),
    Service("SendGrid", "Transactional email (apps, websites)", "SendGrid", "optional",
            "Settings > Sender Authentication > Authenticate Your Domain"),
    Service("Amazon SES", "Transactional email (apps, websites)", "Amazon SES", "optional",
            "SES console > Verified identities > your domain > Authentication"),
    Service("Mailgun", "Transactional email (apps, websites)", "Mailgun", "optional"),
    Service("Postmark", "Transactional email (apps, websites)", "Postmark", "optional"),
    Service("SparkPost", "Transactional email (apps, websites)", "SparkPost", "optional"),
    Service("Mailjet", "Transactional email (apps, websites)", "Mailjet", "optional"),
    Service("Mailchimp Transactional (Mandrill)", "Transactional email (apps, websites)",
            "Mailchimp Transactional", "optional"),
    Service("Zendesk", "Helpdesk and CRM", "Zendesk", "optional"),
    Service("Freshdesk", "Helpdesk and CRM", "Freshdesk", "optional"),
    Service("Salesforce", "Helpdesk and CRM", "Salesforce", "optional"),
    Service("QuickBooks / Intuit", "Billing and invoicing", "Intuit QuickBooks", "optional"),
    Service("Shopify", "Online store", "Shopify", "optional"),
    Service("Squarespace", "Website", "Squarespace", "optional"),
    Service("Other service", "Other", "", "optional"),
]


def by_name(name: str) -> Service | None:
    return next((s for s in CATALOG if s.name == name), None)
