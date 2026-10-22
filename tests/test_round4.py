"""Organizations, service wizard data, bulk sender rules, DNS change alerts, certificates,
failure reports, From-domain breakdown, JSON export and Postmaster Tools parsing."""
import json
import ssl
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import QSettings

from xmlray import (certcheck, dnswatch, forensic, postmaster, profiles,
                    senderreqs, services)
from xmlray.analyzer import analyze, from_domain_stats, subdomain_findings
from xmlray.export import json_summary
from xmlray.parser import load_all
from xmlray.storage import Storage
from tests.test_features import SAMPLES, _samples
from tests.test_fixes import _check


# ---------------------------------------------------------------- profiles
def test_profiles_keep_settings_and_data_apart(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "default_path", lambda: tmp_path / "history.db")
    qs = QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat)
    pr = profiles.Profiles(qs)
    assert [p["id"] for p in pr.list()] == ["default"]
    pid = pr.add("Acme Dental")
    assert pid.startswith("acme-dental-") and pr.name(pid) == "Acme Dental"
    a, b = profiles.ProfileSettings(qs, "default"), profiles.ProfileSettings(qs, pid)
    a.setValue("mail/host", "imap.one")
    b.setValue("mail/host", "imap.two")
    b.setValue("appearance/theme", "dark")           # app-wide setting stays shared
    assert a.value("mail/host") == "imap.one" and b.value("mail/host") == "imap.two"
    assert a.value("appearance/theme") == "dark"
    assert profiles.storage_path(pid) == tmp_path / "profiles" / pid / "history.db"
    pr.rename(pid, "Acme")
    pr.set_active(pid)
    assert pr.active() == pid
    pr.remove(pid)
    assert pr.active() == "default" and len(pr.list()) == 1


# ---------------------------------------------------------- service catalog
def test_service_catalog():
    sg = services.by_name("SendGrid")
    assert sg.spf_include == "sendgrid.net" and sg.has_official_guide
    gw = services.by_name("Google Workspace")
    assert gw.spf == "required" and gw.spf_include == "_spf.google.com"
    assert services.by_name("Other service").spf_include == ""


# ------------------------------------------------------- bulk sender rules
def test_bulk_sender_checklist():
    res, _ = _check({"example.com": ["v=spf1 include:_spf.google.com ~all"],
                     "_spf.google.com": ["v=spf1 ip4:209.85.128.0/17 ~all"]})
    a = analyze(_samples().dmarc, hostnames={"209.85.220.41": "mail-sor-f41.google.com",
                                             "167.89.12.34": "o1.ptr1234.sendgrid.net"})
    own = senderreqs.own_servers(a)
    assert [s.ip for s in own] == ["198.51.100.23"]
    reqs = senderreqs.build_checklist("example.com", a, res, {"198.51.100.23": False},
                                      {"spam_rate": 0.004}, a.findings + res.findings)
    by = {r.key: r for r in reqs}
    assert by["spf"].status == "pass" and by["dkim"].status == "pass"
    assert by["dmarc"].status == "pass" and by["ptr"].status == "fail"
    assert by["spam"].status == "fail" and by["unsub"].status == "manual"
    keys = {f.key for f in senderreqs.findings(reqs, "example.com")}
    assert keys == {"senderreqs:ptr:example.com", "senderreqs:spam:example.com"}


# ------------------------------------------------------------- DNS changes
def test_dns_change_detection(tmp_path):
    st = Storage(tmp_path / "h.db")
    first, _ = _check({"example.com": ["v=spf1 include:_spf.google.com ~all"],
                       "_spf.google.com": ["v=spf1 ip4:1.1.1.0/24 ~all"]})
    assert dnswatch.record(st, first) == []                 # first look: nothing to compare
    second, _ = _check({"example.com": ["v=spf1 -all"]})
    changes = dnswatch.record(st, second)
    assert [c.kind for c in changes] == ["SPF"]
    assert "changed" in dnswatch.describe(changes[0])
    assert st.get_json("dns:changes:example.com")[0]["kind"] == "SPF"


# ---------------------------------------------------------- certificates
def test_certificates():
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    later = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    assert certcheck._from_cert("mx", "Mail server", {"notAfter": soon}).status == "expiring"
    assert certcheck._from_cert("mx", "Mail server", {"notAfter": later}).status == "ok"
    res, _ = _check({}, mx={"example.com": ["mx1.example.com", "mx2.example.com"]})
    results = certcheck.check_domain(
        res, smtp=lambda h: certcheck._from_cert(h, "Mail server", {"notAfter": soon})
        if h.startswith("mx1") else certcheck.CertResult(h, "Mail server", "unreachable"))
    fs = certcheck.findings(results, "example.com")
    assert len(fs) == 1 and fs[0].severity == "high" and "mx1" in fs[0].title
    assert ssl  # imported for the real checks


# --------------------------------------------------------- failure reports
def test_failure_report_from_samples(tmp_path):
    r = load_all([SAMPLES])
    assert len(r.dmarc) == 28 and len(r.tls) == 14 and len(r.forensic) == 1
    fr = r.forensic[0]
    assert fr.source_ip == "203.0.113.45" and fr.auth_failure == "dmarc"
    assert fr.subject.startswith("Your invoice") and fr.reported_domain == "example.com"
    st = Storage(tmp_path / "h.db")
    new = list(r.forensic)
    st.add_reports([], [], new)
    assert len(new) == 1
    again = list(r.forensic)
    st.add_reports([], [], again)
    assert again == []                                       # already saved
    assert forensic.parse_forensic(b"From: a\n\nhello") is None


# -------------------------------------------------------------- From domains
def test_from_domain_breakdown_and_json():
    reps = _samples().dmarc
    stats = from_domain_stats(reps)
    assert set(stats) == {"example.com"}
    fake = {"news.example.com": {"messages": 50, "passed": 5, "ips": {"1.2.3.4"}}, **stats}
    fs = subdomain_findings(fake, {"example.com": None})
    assert len(fs) == 1 and fs[0].key == "subdomain:news.example.com"
    doc = json_summary(analyze(reps))
    json.dumps(doc)                                           # must be serialisable
    assert doc["grade"] and doc["senders"] and "findings" in doc


# --------------------------------------------------------- Postmaster Tools
def test_postmaster_parsing(tmp_path):
    doc = {"domainStats": [
        {"metric": "spam_rate", "date": {"year": 2026, "month": 10, "day": 2},
         "value": {"doubleValue": 0.0012}},
        {"metric": "spam_rate", "date": {"year": 2026, "month": 10, "day": 1},
         "value": {"doubleValue": 0.0008}},
        {"metric": "dmarc", "date": {"year": 2026, "month": 10, "day": 1}, "value": {"intValue": "1"}}]}
    series = postmaster.parse_stats(doc)
    assert series["spam_rate"] == [("2026-10-01", 0.0008), ("2026-10-02", 0.0012)]
    s = postmaster.summarize(series, {"oneClickUnsubscribeVerdict": {"status": "NON_COMPLIANT",
                                                                      "reason": "NO_UNSUB_GENERAL"}})
    assert abs(s["spam_rate"] - 0.001) < 1e-9 and s["dmarc"] == 1.0 and s["unsubscribe"] == "fail"
    f = tmp_path / "client.json"
    f.write_text(json.dumps({"installed": {"client_id": "abc.apps.googleusercontent.com",
                                           "client_secret": "s"}}))
    assert postmaster.read_client_file(str(f)) == ("abc.apps.googleusercontent.com", "s")
