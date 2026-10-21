"""Run with:  python -m pytest tests"""
import gzip
import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

from xmlray.analyzer import analyze
from xmlray.export import html_summary
from xmlray.parser import load_paths, parse_report_bytes
from xmlray.updater import is_newer, parse_version

SAMPLE = Path(__file__).resolve().parent.parent / "xmlray" / "assets" / "sample_report.xml"


def test_sample_parses_and_prioritises():
    reports, errors = load_paths([SAMPLE])
    assert not errors and len(reports) == 1
    a = analyze(reports)
    assert a.total == 1670
    assert a.findings[0].severity == "high"
    assert any("SendGrid" in f.title for f in a.findings)
    assert any(f.title.startswith("example.com is in monitoring mode") for f in a.findings)


def test_containers(tmp_path):
    data = SAMPLE.read_bytes()
    (tmp_path / "a.xml.gz").write_bytes(gzip.compress(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("r.xml", data.replace(b"14725830291834567201", b"zip-1"))
    (tmp_path / "b.zip").write_bytes(buf.getvalue())
    msg = EmailMessage()
    msg["From"] = "noreply@google.com"
    msg["Subject"] = "Report domain: example.com"
    msg.set_content("attached")
    msg.add_attachment(gzip.compress(data.replace(b"14725830291834567201", b"eml-1")),
                       maintype="application", subtype="gzip", filename="r.xml.gz")
    (tmp_path / "c.eml").write_bytes(msg.as_bytes())
    (tmp_path / "junk.xml").write_text("<html></html>")
    reports, errors = load_paths([tmp_path])
    assert len(reports) == 3          # gz copy duplicates nothing; zip and eml have new IDs
    assert len(errors) == 1 and "junk.xml" in errors[0]


def test_dmarc2_namespace():
    xml = SAMPLE.read_bytes().replace(
        b"<feedback>", b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">')
    rep = parse_report_bytes(xml)
    assert rep.policy.domain == "example.com" and len(rep.records) == 6


def test_enforced_policy_flags_blocked_real_mail():
    xml = SAMPLE.read_bytes().replace(b"<p>none</p>", b"<p>reject</p>") \
        .replace(b"<disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>",
                 b"<disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf>")
    a = analyze([parse_report_bytes(xml)])
    assert a.findings[0].severity == "critical"
    assert any(f.severity == "good" and "stopped" in f.title for f in a.findings)


def test_versions():
    assert is_newer("v1.0.10", "1.0.9")
    assert not is_newer("1.0.0", "1.0.0")
    assert parse_version("2.0.0-beta") < parse_version("2.0.0")


def test_html_export():
    reports, _ = load_paths([SAMPLE])
    out = html_summary(analyze(reports))
    assert "XML-ray summary" in out and "SendGrid" in out
