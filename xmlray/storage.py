"""Everything XML-ray remembers between sessions, in one SQLite file.

Location: %LOCALAPPDATA%\\XML-ray\\history.db on Windows, ~/.local/share/XML-ray elsewhere.
Reports are stored as their original (compressed) XML or JSON, so a future version of
XML-ray can always re-read them with better analysis.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
import zlib
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    kind TEXT NOT NULL,            -- 'dmarc' or 'tls'
    rkey TEXT NOT NULL PRIMARY KEY,
    org TEXT, domain TEXT,
    begin_ts REAL, end_ts REAL,
    source TEXT,
    added_ts REAL,
    raw BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_end ON reports(end_ts);
CREATE TABLE IF NOT EXISTS labels (ip TEXT PRIMARY KEY, label TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS acks (fkey TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS rdap (ip TEXT PRIMARY KEY, ts REAL, data TEXT);
CREATE TABLE IF NOT EXISTS seen (skey TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, ts REAL, data TEXT);
CREATE TABLE IF NOT EXISTS domains (name TEXT PRIMARY KEY, parked INTEGER DEFAULT 0, added REAL);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, title TEXT, body TEXT,
    read INTEGER DEFAULT 0
);
"""


def default_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "XML-ray" / "history.db"


class Storage:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._db() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        # A short-lived connection per call keeps this safe to use from worker threads.
        with self._lock:
            conn = sqlite3.connect(self.path, timeout=30)
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------ reports

    def add_reports(self, dmarc=(), tls=(), forensic=None) -> tuple[list, list]:
        """Save reports not already stored. Returns (new_dmarc, new_tls). New failure
        (forensic) reports are appended to the *forensic* list if one is given."""
        new_d, new_t = [], []
        now = time.time()
        with self._db() as c:
            for r in dmarc:
                key = "dmarc|" + "|".join(r.key)
                cur = c.execute(
                    "INSERT OR IGNORE INTO reports VALUES (?,?,?,?,?,?,?,?,?)",
                    ("dmarc", key, r.org_name, r.policy.domain, r.begin.timestamp(),
                     r.end.timestamp(), r.source_file, now, zlib.compress(r.raw or b"")))
                if cur.rowcount:
                    new_d.append(r)
            for r in tls:
                key = "tls|" + "|".join(r.key)
                cur = c.execute(
                    "INSERT OR IGNORE INTO reports VALUES (?,?,?,?,?,?,?,?,?)",
                    ("tls", key, r.org_name, ",".join(sorted(r.domains)), r.begin.timestamp(),
                     r.end.timestamp(), r.source_file, now, zlib.compress(r.raw or b"")))
                if cur.rowcount:
                    new_t.append(r)
            for r in list(forensic or []):
                key = "ruf|" + "|".join(r.key)
                cur = c.execute(
                    "INSERT OR IGNORE INTO reports VALUES (?,?,?,?,?,?,?,?,?)",
                    ("ruf", key, r.reporter, r.reported_domain, r.arrival.timestamp(),
                     r.arrival.timestamp(), r.source_file, now, zlib.compress(r.raw or b"")))
                if not cur.rowcount:
                    forensic.remove(r)          # already saved: not new
        return new_d, new_t

    def iter_raw(self) -> Iterator[tuple[str, bytes, str]]:
        with self._db() as c:
            rows = c.execute("SELECT kind, raw, source FROM reports ORDER BY begin_ts").fetchall()
        for kind, raw, source in rows:
            yield kind, zlib.decompress(raw), source or ""

    def report_count(self) -> int:
        with self._db() as c:
            return c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    def delete_all_reports(self) -> None:
        with self._db() as c:
            c.execute("DELETE FROM reports")
            c.execute("DELETE FROM seen")

    def delete_older_than(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        with self._db() as c:
            return c.execute("DELETE FROM reports WHERE end_ts < ?", (cutoff,)).rowcount

    # ------------------------------------------------------------------- labels

    def labels(self) -> dict[str, tuple[str, str]]:
        with self._db() as c:
            return {ip: (label or "", status or "")
                    for ip, label, status in c.execute("SELECT ip, label, status FROM labels")}

    def set_label(self, ip: str, label: str | None = None, status: str | None = None) -> None:
        cur_label, cur_status = self.labels().get(ip, ("", ""))
        label = cur_label if label is None else label.strip()
        status = cur_status if status is None else status
        with self._db() as c:
            if not label and not status:
                c.execute("DELETE FROM labels WHERE ip=?", (ip,))
            else:
                c.execute("INSERT OR REPLACE INTO labels VALUES (?,?,?)", (ip, label, status))

    # --------------------------------------------------------------------- acks

    def acks(self) -> dict[str, float]:
        with self._db() as c:
            return dict(c.execute("SELECT fkey, ts FROM acks"))

    def set_ack(self, key: str, done: bool) -> None:
        with self._db() as c:
            if done:
                c.execute("INSERT OR REPLACE INTO acks VALUES (?,?)", (key, time.time()))
            else:
                c.execute("DELETE FROM acks WHERE fkey=?", (key,))

    # -------------------------------------------------------------------- RDAP

    def rdap_get(self, max_age_days: int = 30) -> dict[str, dict]:
        cutoff = time.time() - max_age_days * 86400
        with self._db() as c:
            return {ip: json.loads(data) for ip, data in
                    c.execute("SELECT ip, data FROM rdap WHERE ts >= ?", (cutoff,))}

    def rdap_put(self, results: dict[str, dict]) -> None:
        now = time.time()
        with self._db() as c:
            c.executemany("INSERT OR REPLACE INTO rdap VALUES (?,?,?)",
                          [(ip, now, json.dumps(d)) for ip, d in results.items()])

    # --------------------------------------------- seen mail messages / files

    def seen(self, keys) -> set[str]:
        keys = list(keys)
        found: set[str] = set()
        with self._db() as c:
            for i in range(0, len(keys), 500):
                chunk = keys[i:i + 500]
                q = "SELECT skey FROM seen WHERE skey IN (%s)" % ",".join("?" * len(chunk))
                found.update(k for (k,) in c.execute(q, chunk))
        return found

    def mark_seen(self, keys) -> None:
        now = time.time()
        with self._db() as c:
            c.executemany("INSERT OR IGNORE INTO seen VALUES (?,?)", [(k, now) for k in keys])

    # ------------------------------------------------------------------- alerts

    def add_alerts(self, alerts) -> None:
        now = time.time()
        with self._db() as c:
            c.executemany("INSERT INTO alerts (ts, kind, title, body) VALUES (?,?,?,?)",
                          [(now, a.kind, a.title, a.body) for a in alerts])

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        with self._db() as c:
            rows = c.execute("SELECT id, ts, kind, title, body, read FROM alerts "
                             "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(id=r[0], ts=r[1], kind=r[2], title=r[3], body=r[4], read=bool(r[5]))
                for r in rows]

    def unread_alerts(self) -> int:
        with self._db() as c:
            return c.execute("SELECT COUNT(*) FROM alerts WHERE read=0").fetchone()[0]

    def mark_alerts_read(self) -> None:
        with self._db() as c:
            c.execute("UPDATE alerts SET read=1")

    def clear_alerts(self) -> None:
        with self._db() as c:
            c.execute("DELETE FROM alerts")

    # ------------------------------------------------------------ key/value

    def get_json(self, key: str, max_age_days: float | None = None):
        with self._db() as c:
            row = c.execute("SELECT ts, data FROM kv WHERE k=?", (key,)).fetchone()
        if not row or (max_age_days is not None and time.time() - row[0] > max_age_days * 86400):
            return None
        return json.loads(row[1])

    def set_json(self, key: str, value) -> None:
        with self._db() as c:
            c.execute("INSERT OR REPLACE INTO kv VALUES (?,?,?)",
                      (key, time.time(), json.dumps(value, default=str)))

    # ------------------------------------------------------------ my domains

    def my_domains(self) -> dict[str, bool]:
        """{domain: parked} for domains the user added or XML-ray found in reports."""
        with self._db() as c:
            return {n: bool(p) for n, p in c.execute("SELECT name, parked FROM domains ORDER BY name")}

    def set_domain(self, name: str, parked: bool = False) -> None:
        with self._db() as c:
            c.execute("INSERT INTO domains VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET "
                      "parked=excluded.parked", (name.lower().strip("."), int(parked), time.time()))

    def add_domains(self, names) -> None:
        with self._db() as c:
            c.executemany("INSERT OR IGNORE INTO domains VALUES (?,?,?)",
                          [(n.lower().strip("."), 0, time.time()) for n in names])

    def remove_domain(self, name: str) -> None:
        with self._db() as c:
            c.execute("DELETE FROM domains WHERE name=?", (name,))
