"""Tests for history, labels, trends, DNS checks, RDAP, alerts, TLS-RPT and the record builder."""
import base64
import gzip
import json
from datetime import timedelta
from pathlib import Path

from xmlray import alerts, dnscheck, rdap, recordbuilder
from xmlray.analyzer import analyze, daily_series
from xmlray.mailimport import scan_folder
from xmlray.parser import load_all
from xmlray.storage import Storage
from xmlray.tlsrpt import analyze_tls

ASSETS = Path(__file__).resolve().parent.parent / "xmlray" / "assets"
SAMPLES = ASSETS / "sample_reports.zip"


def _samples():
    return load_all([SAMPLES])


# ------------------------------------------------------------------ storage
def test_history_roundtrip_and_dedupe(tmp_path):
    st = Storage(tmp_path / "h.db")
    r = _samples()
    new_d, new_t = st.add_reports(r.dmarc, r.tls)
    assert len(new_d) == 28 and len(new_t) == 14
    assert st.add_reports(r.dmarc, r.tls) == ([], [])          # already stored
    kinds = [k for k, _raw, _src in st.iter_raw()]
    assert kinds.count("dmarc") == 28 and kinds.count("tls") == 14
    st.delete_all_reports()
    assert st.report_count() == 0


def test_labels_and_acks(tmp_path):
    st = Storage(tmp_path / "h.db")
    st.set_label("203.0.113.45", "Office copier", "mine")
    st.set_label("192.0.2.77", status="ignore")
    labels = st.labels()
    a = analyze(_samples().dmarc, labels=labels)
    by_ip = {s.ip: s for s in a.sources}
    assert by_ip["203.0.113.45"].name == "Office copier"
    assert by_ip["203.0.113.45"].category == "service_failing"
    assert by_ip["192.0.2.77"].category == "ignored"
    assert any(f.key == "service:Office copier" for f in a.findings)
    assert not any("192.0.2.77" in f.ips for f in a.findings)
    st.set_ack("policy-none:example.com", True)
    assert "policy-none:example.com" in st.acks()
    st.set_ack("policy-none:example.com", False)
    assert not st.acks()


# ------------------------------------------------------------------- trends
def test_period_filter_and_daily_series():
    reps = _samples().dmarc
    latest = max(r.end for r in reps)
    recent = analyze(reps, since=latest - timedelta(days=4))
    sg = next(s for s in recent.sources if s.ip == "167.89.12.34")
    assert sg.category == "authorized"                     # fixed in the last few days
    series = daily_series(reps, ips={"167.89.12.34"})
    assert len(series) == 14 and series[0][2] == 0 and series[-1][1] == series[-1][2]


# ---------------------------------------------------------------------- TLS
def test_tls_reports():
    t = analyze_tls(_samples().tls, "example.com")
    assert t.failure == 20 and t.by_type["certificate-expired"] == 20
    assert t.findings[0].severity == "high" and "certificate" in t.findings[0].title
    later = analyze_tls(_samples().tls, since=max(r.end for r in _samples().tls) - timedelta(days=3))
    assert later.failure == 0 and later.findings[0].key == "tls:ok"


# ---------------------------------------------------------------------- DNS
class FakeResolver:
    def __init__(self, txt, mx=None):
        self._txt, self._mx = txt, mx or {}

    def txt(self, name):
        return self._txt.get(name, [])

    def mx(self, name):
        return self._mx.get(name, [])


KEY_2048 = base64.b64encode(b"x" * 294).decode()
KEY_1024 = base64.b64encode(b"x" * 162).decode()


def _keys(findings):
    return {f.key.split(":")[1] for f in findings}


def test_dns_healthy_domain():
    r = FakeResolver({
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        "example.com": ["v=spf1 include:_spf.google.com ~all", "google-site-verification=x"],
        "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
        "_netblocks.google.com": ["v=spf1 ip4:1.2.3.0/24 ~all"],
        "google._domainkey.example.com": [f"v=DKIM1; k=rsa; p={KEY_2048}"],
        "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:t@example.com"],
    }, {"example.com": ["aspmx.l.google.com"]})
    res = dnscheck.check_domain("example.com", r, report_policy="reject",
                                dkim_selectors={"google"})
    assert res.spf_lookups == 2 and not res.error
    assert all(f.severity in ("good", "low") for f in res.findings), res.findings
    assert {v.kind for v in res.records} >= {"DMARC", "SPF", "DKIM", "MX", "TLS reporting"}


def test_dns_problems():
    txt = {
        "_dmarc.example.com": ["v=DMARC1; p=quarantine; rua=mailto:x@reports.vendor.net"],
        "example.com": ["v=spf1 " + " ".join(f"include:s{i}.net" for i in range(12)) + " +all"],
        "k1._domainkey.example.com": [f"v=DKIM1; p={KEY_1024}"],
    }
    for i in range(12):
        txt[f"s{i}.net"] = ["v=spf1 ip4:1.1.1.1 -all"]
    res = dnscheck.check_domain("example.com", FakeResolver(txt, {"example.com": ["mx.example.com"]}),
                                report_policy="none", dkim_selectors={"smtpapi"})
    keys = _keys(res.findings)
    assert {"spf-too-many", "spf-plus-all", "dmarc-rua-auth-reports.vendor.net",
            "dmarc-changed", "dkim-missing-smtpapi", "dkim-weak-k1", "tlsrpt-missing"} <= keys
    assert res.spf_lookups == 12


def test_dns_missing_everything():
    res = dnscheck.check_domain("nothing.test", FakeResolver({}))
    keys = _keys(res.findings)
    assert {"dmarc-missing", "spf-missing", "dkim-none"} <= keys


def test_txt_value_parsing():
    assert dnscheck._txt_value('"v=spf1 " "include:x ~all"') == "v=spf1 include:x ~all"
    assert dnscheck._txt_value("v=DMARC1; p=none") == "v=DMARC1; p=none"


# --------------------------------------------------------------------- RDAP
def test_rdap_parse():
    doc = {"name": "HETZNER-DC", "country": "DE", "startAddress": "5.9.0.0",
           "endAddress": "5.9.255.255",
           "entities": [{"roles": ["registrant"],
                         "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                  ["fn", {}, "text", "Hetzner Online GmbH"]]]}]}
    info = rdap.parse_rdap(doc)
    assert info["owner"] == "Hetzner Online GmbH" and info["country"] == "Germany"
    assert rdap.describe(info) == "Hetzner Online GmbH, Germany"
    assert rdap.lookup("10.0.0.1")["owner"].startswith("Private")


# ------------------------------------------------------------------- alerts
def test_alerts():
    reps = _samples().dmarc
    cut = sorted({r.begin for r in reps})[-2]           # last two days are "new"
    history = [r for r in reps if r.begin < cut]
    new = [r for r in reps if r.begin >= cut]
    found = alerts.find_alerts(history, new)
    assert any(a.kind == "new_sender" and "192.0.2.77" in a.body for a in found)
    assert alerts.find_alerts([], new) == []             # first import never alerts


# ----------------------------------------------------------- record builder
def test_record_builder():
    o = recordbuilder.RecordOptions("example.com", "q25", rua="dmarc@example.com,x@vendor.net")
    rec = recordbuilder.build_record(o)
    assert rec == ("v=DMARC1; p=quarantine; pct=25; "
                   "rua=mailto:dmarc@example.com,mailto:x@vendor.net")
    assert recordbuilder.external_report_domains(o) == ["vendor.net"]
    assert recordbuilder.stage_from_tags({"p": "quarantine", "pct": "25"}) == "q25"


# ------------------------------------------------------------ watch folder
def test_watch_folder(tmp_path):
    st = Storage(tmp_path / "h.db")
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "a.xml").write_bytes((ASSETS / "sample_report.xml").read_bytes())
    tls = json.dumps({"organization-name": "X", "report-id": "1", "policies": [],
                      "date-range": {"start-datetime": "2026-10-01T00:00:00Z",
                                     "end-datetime": "2026-10-01T23:59:59Z"}})
    (inbox / "t.json.gz").write_bytes(gzip.compress(tls.encode()))
    first = scan_folder(str(inbox), st)
    assert len(first.dmarc) == 1 and len(first.tls) == 1
    again = scan_folder(str(inbox), st)
    assert not again.dmarc and not again.tls             # only new files are read
