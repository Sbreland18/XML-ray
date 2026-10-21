"""Check GitHub Releases for a newer XML-ray and install it.

Releases are published by builder/release_manager.py. Each release carries:
  XML-ray-Setup-<version>.exe          the Inno Setup installer
  XML-ray-Setup-<version>.exe.sha256   its SHA-256 checksum (verified before running)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from .config import APP_NAME, GITHUB_OWNER, GITHUB_REPO, INSTALLER_PREFIX

LATEST_URL = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
TIMEOUT = 15


class UpdateError(Exception):
    pass


@dataclass
class ReleaseInfo:
    version: str
    tag: str
    name: str
    notes: str
    html_url: str
    asset_name: str = ""
    asset_url: str = ""
    asset_size: int = 0
    sha256_url: str = ""


def parse_version(text: str) -> tuple:
    """'v1.2.10' -> (1, 2, 10). Pre-release suffixes sort before the plain release."""
    text = text.strip().lstrip("vV")
    main, _, suffix = text.partition("-")
    nums = [int(n) for n in re.findall(r"\d+", main)[:4]]
    while len(nums) < 3:
        nums.append(0)
    return (*nums, 0 if suffix else 1)


def is_newer(candidate: str, current: str) -> bool:
    return parse_version(candidate) > parse_version(current)


def _request(url: str, accept: str = "application/vnd.github+json"):
    req = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": f"{APP_NAME}-updater",
    })
    return urllib.request.urlopen(req, timeout=TIMEOUT)


def fetch_latest() -> ReleaseInfo | None:
    """Return the latest published (non-draft, non-prerelease) release, or None."""
    try:
        with _request(LATEST_URL) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # repository has no releases yet (or is private)
        if exc.code in (403, 429):
            raise UpdateError("GitHub is limiting update checks right now. "
                              "Try again in about an hour.") from exc
        raise UpdateError(f"GitHub answered with error {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError("Couldn't reach GitHub. Check your internet connection.") from exc

    tag = data.get("tag_name", "")
    info = ReleaseInfo(
        version=tag.lstrip("vV"),
        tag=tag,
        name=data.get("name") or tag,
        notes=data.get("body") or "",
        html_url=data.get("html_url", ""),
    )
    assets = data.get("assets", [])
    for a in assets:
        n = a.get("name", "")
        if n.startswith(INSTALLER_PREFIX) and n.lower().endswith(".exe"):
            info.asset_name = n
            info.asset_url = a.get("browser_download_url", "")
            info.asset_size = int(a.get("size") or 0)
    for a in assets:
        if info.asset_name and a.get("name") == info.asset_name + ".sha256":
            info.sha256_url = a.get("browser_download_url", "")
    return info


def check_for_update(current_version: str) -> ReleaseInfo | None:
    """Return release info when a newer version exists, otherwise None."""
    latest = fetch_latest()
    if latest and latest.version and is_newer(latest.version, current_version):
        return latest
    return None


def can_self_install(info: ReleaseInfo) -> bool:
    """Only the installed Windows build can update itself in place."""
    return sys.platform == "win32" and getattr(sys, "frozen", False) and bool(info.asset_url)


def download_installer(info: ReleaseInfo,
                       progress: Callable[[int, int], None] | None = None,
                       cancelled: Callable[[], bool] | None = None) -> str:
    """Download and verify the installer. Returns the local file path."""
    if not info.asset_url:
        raise UpdateError("This release has no Windows installer attached.")
    target_dir = tempfile.mkdtemp(prefix="xmlray-update-")
    target = os.path.join(target_dir, info.asset_name)
    digest = hashlib.sha256()
    try:
        with _request(info.asset_url, accept="application/octet-stream") as resp, \
                open(target, "wb") as fh:
            total = int(resp.headers.get("Content-Length") or info.asset_size or 0)
            done = 0
            while True:
                if cancelled and cancelled():
                    raise UpdateError("cancelled")
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"Download failed: {exc}") from exc

    if info.sha256_url:
        try:
            with _request(info.sha256_url, accept="application/octet-stream") as resp:
                expected = resp.read().decode("utf-8", "replace").split()[0].lower()
        except (urllib.error.URLError, OSError, IndexError) as exc:
            raise UpdateError("Couldn't download the checksum to verify the installer.") from exc
        if digest.hexdigest().lower() != expected:
            os.remove(target)
            raise UpdateError("The downloaded installer failed its integrity check and was "
                              "deleted. Try again later.")
    return target


def launch_installer(path: str) -> None:
    """Run the installer silently. It closes XML-ray, upgrades it and relaunches it."""
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    subprocess.Popen([path, "/SILENT", "/NORESTART", "/CLOSEAPPLICATIONS"],
                     creationflags=flags, close_fds=True)
