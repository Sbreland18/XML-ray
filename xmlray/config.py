"""Central settings for XML-ray. Change the GitHub owner/repo here if it ever moves."""
from pathlib import Path

APP_NAME = "XML-ray"
TAGLINE = "See through your DMARC reports"
ORG_NAME = "XML-ray"

GITHUB_OWNER = "Sbreland18"
GITHUB_REPO = "XML-ray"
GITHUB_URL = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}"

# Installer files published to GitHub Releases are named XML-ray-Setup-<version>.exe
INSTALLER_PREFIX = "XML-ray-Setup"

ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def asset(name: str) -> str:
    return str(ASSETS_DIR / name)
