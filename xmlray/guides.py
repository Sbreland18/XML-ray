"""Links to each service's own setup instructions, shown inside findings.

Official pages are listed for the most common services. Anything else gets a web search
link, which never goes stale."""
from urllib.parse import quote_plus

GUIDES: dict[str, tuple[str, str]] = {
    "Google": ("Google Workspace: Set up DKIM",
               "https://knowledge.workspace.google.com/admin/security/set-up-dkim"),
    "Microsoft 365": ("Microsoft 365: Set up DKIM for your domain",
                      "https://learn.microsoft.com/en-us/defender-office-365/"
                      "email-authentication-dkim-configure"),
    "SendGrid": ("SendGrid: Configure domain authentication",
                 "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/"
                 "how-to-set-up-domain-authentication"),
    "Mailchimp": ("Mailchimp: Set up email domain authentication",
                  "https://mailchimp.com/help/set-up-email-domain-authentication/"),
    "Mailchimp Transactional": ("Mailchimp Transactional: Authentication and delivery",
                                "https://mailchimp.com/developer/transactional/docs/"
                                "authentication-delivery/"),
    "Amazon SES": ("Amazon SES: Easy DKIM",
                   "https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-easy.html"),
}


def guide_for(provider: str) -> tuple[str, str]:
    """(link text, url) for a service's DKIM / domain authentication instructions."""
    if provider in GUIDES:
        return GUIDES[provider]
    query = quote_plus(f"{provider} DKIM domain authentication setup")
    return (f"Search for {provider}'s setup guide", f"https://www.google.com/search?q={query}")


def guide_step(provider: str) -> str:
    title, url = guide_for(provider)
    lead = "Official guide" if provider in GUIDES else "Guide"
    return f"{lead}: [{title}]({url})"
