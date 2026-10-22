"""Gmail Postmaster Tools (API v2): Gmail's own view of your spam rate and authentication.

Setup needs a Google Cloud OAuth client of type "Desktop app" (free). XML-ray signs in with
the standard loopback flow plus PKCE: the browser opens, you approve read-only access, and
only the refresh token is stored, in Windows Credential Manager. The v1 API was retired in
2025-2026, so this uses v2 (domains.domainStats.query and domains.getComplianceStatus).
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API = "https://gmailpostmastertools.googleapis.com/v2"
SCOPE = "https://www.googleapis.com/auth/postmaster.traffic.readonly"
KEYRING_SERVICE = "XML-ray"

METRICS = [  # (name in response, standard metric, filter)
    ("spam_rate", "SPAM_RATE", ""),
    ("dmarc", "AUTH_SUCCESS_RATE", 'auth_type = "dmarc"'),
    ("dkim", "AUTH_SUCCESS_RATE", 'auth_type = "dkim"'),
    ("spf", "AUTH_SUCCESS_RATE", 'auth_type = "spf"'),
    ("delivery_errors", "DELIVERY_ERROR_RATE", ""),
]


class PostmasterError(Exception):
    pass


# ------------------------------------------------------------- credentials

def read_client_file(path: str) -> tuple[str, str]:
    """(client_id, client_secret) from the JSON file Google Cloud lets you download."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PostmasterError(f"Couldn't read that file: {exc}") from exc
    block = doc.get("installed") or doc.get("web") or {}
    if not block.get("client_id"):
        raise PostmasterError("That isn't an OAuth client file. In Google Cloud, create an "
                              "OAuth client ID of type “Desktop app” and download its JSON.")
    return block["client_id"], block.get("client_secret", "")


def _keyring():
    import keyring
    return keyring


def save_credentials(client_id: str, client_secret: str, refresh_token: str) -> None:
    _keyring().set_password(KEYRING_SERVICE, "postmaster", json.dumps(
        {"client_id": client_id, "client_secret": client_secret, "refresh": refresh_token}))


def load_credentials() -> dict | None:
    try:
        raw = _keyring().get_password(KEYRING_SERVICE, "postmaster")
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def forget_credentials() -> None:
    try:
        _keyring().delete_password(KEYRING_SERVICE, "postmaster")
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ OAuth

def _post_form(url: str, fields: dict) -> dict:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise PostmasterError(f"Google refused the sign-in ({exc.code}): {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise PostmasterError(f"Couldn't reach Google: {exc}") from exc


def authorize(client_id: str, client_secret: str, open_browser, timeout: int = 300) -> str:
    """Run the browser sign-in. Returns a refresh token."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    result: dict = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("state", [""])[0] == state:
                result["code"] = q.get("code", [""])[0]
                result["error"] = q.get("error", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            ok = bool(result.get("code"))
            self.wfile.write((
                "<html><body style='font-family:Segoe UI,Arial;padding:40px'>"
                f"<h2>{'XML-ray is connected to Postmaster Tools.' if ok else 'Sign-in was cancelled.'}"
                "</h2><p>You can close this window and return to XML-ray.</p></body></html>").encode())

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 1
    redirect = f"http://127.0.0.1:{server.server_port}"
    url = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": client_id, "redirect_uri": redirect, "response_type": "code",
        "scope": SCOPE, "access_type": "offline", "prompt": "consent", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256"})
    open_browser(url)
    stop = threading.Event()
    timer = threading.Timer(timeout, stop.set)
    timer.start()
    try:
        while not result and not stop.is_set():
            server.handle_request()
    finally:
        timer.cancel()
        server.server_close()
    if not result.get("code"):
        raise PostmasterError("Sign-in didn't finish" + (f": {result['error']}" if result.get("error")
                                                         else " in time."))
    tokens = _post_form(TOKEN_URL, {
        "code": result["code"], "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect, "grant_type": "authorization_code", "code_verifier": verifier})
    if not tokens.get("refresh_token"):
        raise PostmasterError("Google didn't return a long-lived token. Try connecting again.")
    return tokens["refresh_token"]


def access_token(creds: dict) -> str:
    tokens = _post_form(TOKEN_URL, {
        "client_id": creds["client_id"], "client_secret": creds.get("client_secret", ""),
        "refresh_token": creds["refresh"], "grant_type": "refresh_token"})
    return tokens["access_token"]


# -------------------------------------------------------------------- API

def _api(token: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        f"{API}/{path}", data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(detail).get("error", {}).get("message", detail)
        except ValueError:
            pass
        raise PostmasterError(f"Postmaster Tools answered {exc.code}: {detail[:300]}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise PostmasterError(f"Couldn't reach Postmaster Tools: {exc}") from exc


def list_domains(token: str) -> list[str]:
    doc = _api(token, "domains")
    return [d.get("name", "").split("/", 1)[-1] for d in doc.get("domains", [])]


def _number(value) -> float | None:
    """StatisticValue holds one number under a type-specific key; take whichever is there."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    if isinstance(value, dict):
        for v in value.values():
            n = _number(v)
            if n is not None:
                return n
    return None


def parse_stats(doc: dict) -> dict[str, list[tuple[str, float]]]:
    out: dict[str, list[tuple[str, float]]] = {}
    for stat in doc.get("domainStats", []):
        n = _number(stat.get("value"))
        d = stat.get("date") or {}
        if n is None or not d:
            continue
        day = f"{d.get('year', 0):04d}-{d.get('month', 0):02d}-{d.get('day', 0):02d}"
        out.setdefault(stat.get("metric", ""), []).append((day, n))
    for v in out.values():
        v.sort()
    return out


def query_stats(token: str, domain: str, days: int = 14) -> dict[str, list[tuple[str, float]]]:
    end = date.today() - timedelta(days=1)            # Gmail data lags about a day
    start = end - timedelta(days=days - 1)

    def ymd(x):
        return {"year": x.year, "month": x.month, "day": x.day}
    body = {
        "metricDefinitions": [
            {"name": n, "baseMetric": {"standardMetric": m}, **({"filter": f} if f else {})}
            for n, m, f in METRICS],
        "timeQuery": {"dateRanges": {"dateRanges": [{"start": ymd(start), "end": ymd(end)}]}},
        "aggregationGranularity": "DAILY",
        "pageSize": 200,
    }
    merged: dict[str, list] = {}
    token_page = ""
    for _ in range(10):
        doc = _api(token, f"domains/{domain}/domainStats:query",
                   {**body, **({"pageToken": token_page} if token_page else {})})
        for k, v in parse_stats(doc).items():
            merged.setdefault(k, []).extend(v)
        token_page = doc.get("nextPageToken", "")
        if not token_page:
            break
    return {k: sorted(v) for k, v in merged.items()}


def compliance(token: str, domain: str) -> dict | None:
    """Gmail's compliance verdicts, or None if this account isn't allowed to read them."""
    try:
        return _api(token, f"domains/{domain}/complianceStatus")
    except PostmasterError:
        return None


def summarize(series: dict, compliance_doc: dict | None) -> dict:
    """Averages over the last 7 days with data, for the bulk sender checklist."""
    def avg(name):
        vals = [v for _d, v in series.get(name, [])][-7:]
        return sum(vals) / len(vals) if vals else None
    unsub = None
    if compliance_doc:
        text = json.dumps(compliance_doc).upper()
        if "UNSUB" in text:
            unsub = "fail" if "NO_UNSUB" in text else "pass"
    return {"spam_rate": avg("spam_rate"), "dmarc": avg("dmarc"), "dkim": avg("dkim"),
            "spf": avg("spf"), "delivery_errors": avg("delivery_errors"), "unsubscribe": unsub}


def fetch_all(domains: list[str], creds: dict) -> dict:
    """{domain: {"series", "summary", "compliance", "error"}} for domains you've verified."""
    token = access_token(creds)
    available = set(list_domains(token))
    out = {}
    for d in domains:
        if d not in available:
            out[d] = {"error": "Not added to your Postmaster Tools account yet."}
            continue
        series = query_stats(token, d)
        comp = compliance(token, d)
        out[d] = {"series": series, "compliance": comp, "summary": summarize(series, comp),
                  "error": "" if series else "No data yet. Gmail only shows statistics for "
                                            "domains sending enough mail to Gmail users."}
    return out
