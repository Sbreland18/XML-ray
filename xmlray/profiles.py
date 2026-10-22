"""Several organizations (clients) in one XML-ray, each with its own reports and settings.

The first organization keeps the original data file and settings, so upgrading changes
nothing for people who only manage one. Others live in
%LOCALAPPDATA%\\XML-ray\\profiles\\<id>\\history.db with settings under profile/<id>/.
"""
from __future__ import annotations

import json
import re
import shutil
import uuid
from pathlib import Path

from .storage import default_path

GLOBAL_PREFIXES = ("appearance/", "updates/", "tray/", "paths/", "profiles/", "app/")


class Profiles:
    def __init__(self, qsettings):
        self.s = qsettings

    def _extra(self) -> list[dict]:
        try:
            return json.loads(self.s.value("profiles/list", "[]") or "[]")
        except ValueError:
            return []

    def list(self) -> list[dict]:
        first = {"id": "default", "name": self.s.value("profiles/default_name", "My organization")}
        return [first] + self._extra()

    def name(self, pid: str) -> str:
        return next((p["name"] for p in self.list() if p["id"] == pid), "My organization")

    def active(self) -> str:
        pid = self.s.value("profiles/active", "default")
        return pid if any(p["id"] == pid for p in self.list()) else "default"

    def set_active(self, pid: str) -> None:
        self.s.setValue("profiles/active", pid)

    def add(self, name: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24] or "org"
        pid = f"{slug}-{uuid.uuid4().hex[:6]}"
        self.s.setValue("profiles/list", json.dumps(self._extra() + [{"id": pid, "name": name}]))
        return pid

    def rename(self, pid: str, name: str) -> None:
        if pid == "default":
            self.s.setValue("profiles/default_name", name)
            return
        items = [dict(p, name=name) if p["id"] == pid else p for p in self._extra()]
        self.s.setValue("profiles/list", json.dumps(items))

    def remove(self, pid: str) -> None:
        if pid == "default":
            raise ValueError("The first organization can't be removed.")
        self.s.setValue("profiles/list", json.dumps([p for p in self._extra() if p["id"] != pid]))
        self.s.remove(f"profile/{pid}")
        shutil.rmtree(storage_path(pid).parent, ignore_errors=True)
        if self.active() == pid:
            self.set_active("default")


def storage_path(pid: str) -> Path:
    if pid == "default":
        return default_path()
    return default_path().parent / "profiles" / pid / "history.db"


class ProfileSettings:
    """A QSettings stand-in that keeps each organization's settings separate.
    Appearance, updates and similar app-wide settings stay shared."""

    def __init__(self, qsettings, pid: str):
        self.qs, self.pid = qsettings, pid

    def _k(self, key: str) -> str:
        if self.pid == "default" or key.startswith(GLOBAL_PREFIXES):
            return key
        return f"profile/{self.pid}/{key}"

    def value(self, key, default=None, type=None):  # noqa: A002 - mirrors QSettings
        if type is None:
            return self.qs.value(self._k(key), default)
        return self.qs.value(self._k(key), default, type=type)

    def setValue(self, key, value):  # noqa: N802 - mirrors QSettings
        self.qs.setValue(self._k(key), value)

    def remove(self, key):
        self.qs.remove(self._k(key))

    def allKeys(self):  # noqa: N802 - mirrors QSettings
        keys = self.qs.allKeys()
        if self.pid == "default":
            return [k for k in keys if not k.startswith(("profile/", "profiles/"))]
        prefix = f"profile/{self.pid}/"
        return [k[len(prefix):] for k in keys if k.startswith(prefix)] + \
            [k for k in keys if k.startswith(GLOBAL_PREFIXES)]
