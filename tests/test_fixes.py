"""Fix guides, roadmap, blocklists, lookalikes, MTA-STS/BIMI/parked checks, summary email, logs."""
import socket
import zipfile
from datetime import datetime, timedelta, timezone

from xmlray import blocklist, dnscheck, fixguide, lookalike, logs, mailsend, roadmap
from xmlray.analyzer import Finding, analyze
from xmlray.export import print_html
from xmlray.storage import Storage
from tests.test_features import FakeResolver, KEY_2048, _samples


class TtlResolver(FakeResolver):
    def ns(self, name):
        return ["anna.ns.cloudflare.com", "bob.ns.cloudflare.com"]

    def ttl(self, name, rtype="TXT"):
        return 3600


def _ctx(dns_map, reports=None):
    a = analyze(reports if reports is not None else _samples().dmarc)
    return fixguide.FixContext(dns=dns_map, analysis=a, domains=list(dns_map))


def _finding(key, title="t"):
    return Finding("high", title, "why", ["step"], 0, [], key=key, source="dns")


BASE = {"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
        "google._domainkey.example.com": [f"v=DKIM1; k=rsa; p={KEY_2048}"]}


def _check(txt, mx=None, **kw):
    r = TtlResolver({**BASE, **txt}, mx if mx is not None else {"example.com": ["mx.example.com"]})
    return dnscheck.check_domain("example.com", r, "none", {"google"},
                                 fetch=kw.pop("fetch", lambda u: (404, "")), **kw), r


# ------------------------------------------------------------------ DMARC
def test_dmarc_fix_keeps_rua_and_waits_until_ready():
    res, _ = _check({"example.com": ["v=spf1 include:_spf.google.com ~all"],
                     "_spf.google.com": ["v=spf1 ip4:1.1.1.0/24 ~all"]})
    plan = fixguide.build_plan(_finding("policy-none:example.com"), _ctx({"example.com": res}))
    ch = plan.changes[0]
    assert ch.action == "change" and ch.current.startswith("v=DMARC1; p=none")
    assert "rua=mailto:dmarc@example.com" in ch.proposed
    # sample data still has a failing service, so it stays at p=none for now
    assert "p=none" in ch.proposed
    road = fixguide.build_plan(_finding("roadmap:q25:example.com"), _ctx({"example.com": res}))
    assert "p=quarantine; pct=25" in road.changes[0].proposed


# -------------------------------------------------------------------- SPF
def test_spf_fix_removes_unused_and_void_includes_and_fixes_all():
    txt = {"example.com": ["v=spf1 include:_spf.google.com include:servers.mcsv.net "
                           "include:spf.protection.outlook.com include:gone.example.net "
                           "include:big.example.org +all"],
           "_spf.google.com": ["v=spf1 include:a.g include:b.g include:c.g ~all"],
           "a.g": ["v=spf1 ip4:209.85.128.0/17 ~all"], "b.g": ["v=spf1 ip4:2.0.0.0/8 ~all"],
           "c.g": ["v=spf1 ip4:3.0.0.0/8 ~all"],
           "servers.mcsv.net": ["v=spf1 ip4:4.0.0.0/8 ~all"],
           "spf.protection.outlook.com": ["v=spf1 include:x.o include:y.o -all"],
           "x.o": ["v=spf1 ip4:40.107.0.0/16 -all"], "y.o": ["v=spf1 ip4:6.0.0.0/8 -all"],
           "big.example.org": ["v=spf1 a mx include:z.e ~all"], "z.e": ["v=spf1 a ~all"]}
    res, _ = _check(txt)
    assert res.spf_lookups == 14 and "gone.example.net" in res.spf_void
    plan = fixguide.build_plan(_finding("dns:spf-too-many:example.com"), _ctx({"example.com": res}))
    new = plan.changes[0].proposed
    assert "gone.example.net" not in new          # points at nothing
    assert "servers.mcsv.net" not in new          # no server in the reports is in its ranges
    assert "_spf.google.com" in new and "outlook" in new   # these cover servers in reports
    assert "big.example.org" in new               # uses a/mx, so it can't be ruled out
    assert new.endswith("~all") and "+all" not in new
    assert "of 10 DNS lookups" in " ".join(plan.notes)


def test_spf_never_removes_an_include_that_covers_a_sender():
    txt = {"example.com": ["v=spf1 include:_spf.google.com " + " ".join(
        f"include:s{i}.net" for i in range(9)) + " ~all"],
        "_spf.google.com": ["v=spf1 ip4:209.85.128.0/17 ~all"]}
    for i in range(9):
        txt[f"s{i}.net"] = [f"v=spf1 ip4:10.{i}.0.0/16 ~all"]
    res, _ = _check(txt)
    plan = fixguide.build_plan(_finding("dns:spf-too-many:example.com"), _ctx({"example.com": res}))
    new = plan.changes[0].proposed
    assert "_spf.google.com" in new and "s0.net" not in new


def test_spf_missing_built_from_reports():
    res, _ = _check({})
    plan = fixguide.build_plan(_finding("dns:spf-missing:example.com"), _ctx({"example.com": res}))
    assert plan.changes[0].action == "add" and plan.changes[0].proposed.startswith("v=spf1")
    assert plan.changes[0].proposed.endswith("~all")


# --------------------------------------------------------- hosts / email
def test_host_detection_names_and_email():
    g = fixguide.detect_host(["kate.ns.cloudflare.com"])
    assert g.name == "Cloudflare" and g.url.startswith("https://dash.cloudflare.com")
    assert fixguide.display_name("_dmarc.example.com", "example.com", g) == "_dmarc"
    assert fixguide.display_name("example.com", "example.com", g) == "@"
    assert fixguide.detect_host(["ns1.unknown-host.test"]).name == "your DNS provider"
    assert fixguide.detect_host(["ns1.porkbun.com"]).name == "Porkbun"
    res, _ = _check({"example.com": ["v=spf1 +all"]})
    plan = fixguide.build_plan(_finding("dns:spf-plus-all:example.com"), _ctx({"example.com": res}))
    subject, body = fixguide.email_text(plan, g)
    assert "example.com" in subject and "Name/host: @" in body and "Cloudflare" in body
    assert fixguide.split_txt("x" * 300).count('"') == 4


# ------------------------------------------------------------------ verify
def test_verify_detects_done_and_old_values():
    res, r = _check({"example.com": ["v=spf1 ?all"]})
    plan = fixguide.build_plan(_finding("dns:spf-neutral:example.com"), _ctx({"example.com": res}))
    results, ttl = fixguide.verify_changes(plan, r)
    assert not results[0].ok and "old value" in results[0].message and ttl == 3600
    r._txt["example.com"] = [plan.changes[0].proposed]
    results, _ = fixguide.verify_changes(plan, r)
    assert results[0].ok
    assert fixguide.human_ttl(3600) == "1 hour"


# ------------------------------------------------ parked / MTA-STS / BIMI
def test_parked_domain():
    res, r = _check({}, mx={}, parked=True)
    assert any(f.key == "dns:parked-unlocked:example.com" for f in res.findings)
    plan = fixguide.build_plan(next(f for f in res.findings if "parked" in f.key),
                               _ctx({"example.com": res}))
    vals = {c.rtype + ":" + c.proposed for c in plan.changes}
    assert "TXT:v=spf1 -all" in vals and "MX:0 ." in vals
    locked, _ = _check({"example.com": ["v=spf1 -all"],
                        "_dmarc.example.com": ["v=DMARC1; p=reject"]},
                       mx={"example.com": [""]}, parked=True)
    assert any(f.key == "dns:parked-ok:example.com" for f in locked.findings)


def test_mta_sts_checks():
    policy = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"
    ok, _ = _check({"_mta-sts.example.com": ["v=STSv1; id=1"],
                    "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:a@example.com"]},
                   fetch=lambda u: (200, policy))
    assert not [f for f in ok.findings if "mta-sts" in f.key]
    bad, _ = _check({"_mta-sts.example.com": ["v=STSv1; id=1"]},
                    mx={"example.com": ["mx.example.com", "backup.example.net"]},
                    fetch=lambda u: (200, policy))
    f = next(f for f in bad.findings if "mta-sts-mx" in f.key)
    assert f.severity == "high" and "backup.example.net" in f.summary
    missing, _ = _check({})
    plan = fixguide.build_plan(next(f for f in missing.findings if "mta-sts-missing" in f.key),
                               _ctx({"example.com": missing}))
    assert "mode: testing" in plan.files[0].content and "mx: mx.example.com" in plan.files[0].content


def test_bimi_checks():
    rec = {"_dmarc.example.com": ["v=DMARC1; p=reject"],
           "default._bimi.example.com": ["v=BIMI1; l=https://x.example.com/logo.svg"]}
    good, _ = _check(rec, fetch=lambda u: (200, '<svg baseProfile="tiny-ps"></svg>'))
    assert not [f for f in good.findings if "bimi-problem" in f.key]
    plain, _ = _check(rec, fetch=lambda u: (200, "<svg></svg>"))
    assert any("tiny-ps" in f.summary.lower() for f in plain.findings if "bimi" in f.key)


# ----------------------------------------------------------------- roadmap
def test_roadmap():
    res, _ = _check({"example.com": ["v=spf1 include:_spf.google.com ~all"],
                     "_spf.google.com": ["v=spf1 ip4:1.1.1.0/24 ~all"]})
    reps = _samples().dmarc
    a = analyze(reps)
    steps = roadmap.build_roadmap("example.com", a, res, reps, a.findings + res.findings)
    by = {s.key: s for s in steps}
    assert by["reports"].status == "done" and by["spf"].status == "done"
    assert by["senders"].status in ("todo", "current")        # SendGrid failures in sample
    assert by["q25"].status == "todo" and by["q25"].fix.key == "roadmap:q25:example.com"
    latest = max(r.end for r in reps)
    clean = analyze(reps, since=latest - timedelta(days=4))
    steps = roadmap.build_roadmap("example.com", clean, res, reps, clean.findings)
    assert {s.key: s for s in steps}["q25"].status == "current"


# --------------------------------------------------------------- blocklist
def test_blocklist():
    def fake(name):
        if name.startswith("41.220.85.209.zen"):
            return "127.0.0.2"
        if "barracuda" in name:
            return "127.255.255.254"
        raise socket.gaierror()
    res = blocklist.check_ips(["209.85.220.41", "198.51.100.23"], resolve=fake)
    assert res["209.85.220.41"]["Spamhaus"] == "listed"
    assert res["209.85.220.41"]["Barracuda"] == "unavailable"
    assert blocklist.summary(res["209.85.220.41"]) == "Listed: Spamhaus"
    assert blocklist.summary(res["198.51.100.23"]) == "Couldn't check"   # documentation range
    a = analyze(_samples().dmarc)
    found = blocklist.findings(res, a.sources)
    assert found and found[0].severity == "high" and "check.spamhaus.org" in " ".join(found[0].steps)


# --------------------------------------------------------------- lookalike
def test_lookalike_variants_and_scan():
    v = lookalike.variants("example.com")
    assert "examp1e.com" in v and "exmaple.com" in v and "example.net" in v
    assert "example.com" not in v and len(v) <= 400
    assert lookalike.split_domain("shop.example.co.uk") == ("shop.example", "co.uk")

    class R:
        def query(self, name, rtype):
            return [(2, "ns")] if name in ("examp1e.com", "example.net") else []

        def mx(self, name):
            return ["mx.bad"] if name == "examp1e.com" else []
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    found = lookalike.scan("example.com", R(), rdap=lambda d: {"created": recent,
                                                             "registrar": "Reg", "abuse": "a@reg"})
    assert found[0].domain == "examp1e.com" and found[0].risk == "high"
    fs = lookalike.findings(found, owned=set(), your_domain="example.com")
    assert len(fs) == 1 and "a@reg" in " ".join(fs[0].steps)
    assert not lookalike.findings(found, owned={"examp1e.com"}, your_domain="example.com")
    doc = {"events": [{"eventAction": "registration", "eventDate": "2026-10-01T00:00:00Z"}],
           "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "R1"]]],
                         "entities": [{"roles": ["abuse"], "vcardArray": [
                             "vcard", [["email", {}, "text", "abuse@r1"]]]}]}]}
    assert lookalike.parse_rdap_domain(doc) == {"created": "2026-10-01T00:00:00Z",
                                                "registrar": "R1", "abuse": "abuse@r1"}


# ---------------------------------------------------- summary email / logs
def test_weekly_message():
    a = analyze(_samples().dmarc)
    subject, html, text = mailsend.weekly_message(a, a.findings, 80.0,
                                                  [{"title": "New sender"}], print_html)
    assert "graded" in subject and "up 8.0 points" in text and "New sender" in html
    cfg = mailsend.SmtpConfig("smtp.x", "u", "a@x", "b@x; c@x")
    assert cfg.recipients == ["b@x", "c@x"]


def test_storage_kv_and_diagnostics(tmp_path, monkeypatch):
    st = Storage(tmp_path / "h.db")
    st.set_json("lookalikes:example.com", ["a.com"])
    assert st.get_json("lookalikes:example.com") == ["a.com"] and st.get_json("missing") is None
    st.set_domain("parked.example", parked=True)
    st.add_domains(["example.com"])
    assert st.my_domains() == {"example.com": False, "parked.example": True}
    monkeypatch.setattr(logs, "default_path", lambda: tmp_path / "h.db")
    (logs.log_dir() / "xmlray.log").write_text("hello")
    out = logs.diagnostics_zip(str(tmp_path / "d.zip"), {"Reports": 3},
                               {"mail/host": "imap.x", "mail/password": "secret"})
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        assert "about.txt" in names and "logs/xmlray.log" in names
        assert "secret" not in z.read("settings.txt").decode()
