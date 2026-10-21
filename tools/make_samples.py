"""Regenerate xmlray/assets/sample_reports.zip: two weeks of realistic sample data.

The story: SendGrid fails until it's fixed on day 9, a spoofer appears now and then,
a new unknown server shows up on day 13, and an expired certificate is fixed on day 5.
Run:  python tools/make_samples.py
"""
import gzip
import io
import json
import random
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "xmlray" / "assets" / "sample_reports.zip"
START = datetime(2026, 10, 1, tzinfo=timezone.utc)
DOMAIN = "example.com"


def record(ip, count, dkim, spf, env, dkim_dom=None, sel="google", spf_res="pass",
           disp="none", reason=None, dkim_res="pass"):
    r = f"<reason><type>{reason}</type></reason>" if reason else ""
    dk = (f"<dkim><domain>{dkim_dom}</domain><selector>{sel}</selector>"
          f"<result>{dkim_res}</result></dkim>") if dkim_dom else ""
    return (f"<record><row><source_ip>{ip}</source_ip><count>{count}</count><policy_evaluated>"
            f"<disposition>{disp}</disposition><dkim>{dkim}</dkim><spf>{spf}</spf>{r}"
            f"</policy_evaluated></row><identifiers><header_from>{DOMAIN}</header_from>"
            f"<envelope_from>{env}</envelope_from></identifiers><auth_results>{dk}"
            f"<spf><domain>{env}</domain><scope>mfrom</scope><result>{spf_res}</result></spf>"
            f"</auth_results></record>")


def dmarc(org, email, rid, day, records):
    b = int((START + timedelta(days=day)).timestamp())
    return (f'<?xml version="1.0" encoding="UTF-8"?><feedback><version>1.0</version>'
            f"<report_metadata><org_name>{org}</org_name><email>{email}</email>"
            f"<report_id>{rid}</report_id><date_range><begin>{b}</begin><end>{b + 86399}</end>"
            f"</date_range></report_metadata><policy_published><domain>{DOMAIN}</domain>"
            f"<adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct>"
            f"</policy_published>{''.join(records)}</feedback>").encode()


def tls(day, failures):
    b = START + timedelta(days=day)
    fail_total = sum(n for _, n in failures)
    doc = {
        "organization-name": "Google Inc.", "contact-info": "smtp-tls-reporting@google.com",
        "report-id": f"2026-10-{day + 1:02d}T00:00:00Z_{DOMAIN}",
        "date-range": {"start-datetime": b.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "end-datetime": (b + timedelta(seconds=86399)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "policies": [{
            "policy": {"policy-type": "no-policy-found", "policy-domain": DOMAIN},
            "summary": {"total-successful-session-count": 400 + day * 7,
                        "total-failure-session-count": fail_total},
            "failure-details": [{"result-type": t, "sending-mta-ip": "209.85.220.69",
                                 "receiving-mx-hostname": "mail.example.com",
                                 "failed-session-count": n} for t, n in failures],
        }],
    }
    return json.dumps(doc, indent=1).encode()


def main():
    rnd = random.Random(7)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for day in range(14):
            fixed = day >= 8
            for org, email, scale in (("google.com", "noreply-dmarc-support@google.com", 1.0),
                                      ("Enterprise Outlook", "dmarcreport@microsoft.com", 0.45)):
                recs = [
                    record("209.85.220.41", int(rnd.randint(1100, 1400) * scale), "pass", "pass",
                           DOMAIN, DOMAIN),
                    record("198.51.100.23", int(rnd.randint(40, 70) * scale), "fail", "pass", DOMAIN),
                ]
                sg = int(rnd.randint(250, 340) * scale)
                if fixed:
                    recs.append(record("167.89.12.34", sg, "pass", "fail", "bounces.sendgrid.net",
                                       DOMAIN, sel="s1"))
                else:
                    recs.append(record("167.89.12.34", sg, "fail", "fail", "bounces.sendgrid.net",
                                       "sendgrid.net", sel="smtpapi"))
                if day % 3 == 0:
                    recs.append(record("203.0.113.45", int(rnd.randint(20, 45) * scale), "fail",
                                       "fail", DOMAIN, spf_res="fail"))
                if day >= 12:
                    recs.append(record("192.0.2.77", int(rnd.randint(8, 15) * scale) + 1, "fail",
                                       "fail", "mail-relay.example.net", spf_res="softfail"))
                recs.append(record("40.107.22.91", rnd.randint(5, 15), "fail", "fail",
                                   "contoso.onmicrosoft.com", DOMAIN, dkim_res="fail",
                                   reason="forwarded"))
                rid = f"{org[:3]}-{day:02d}-{rnd.randint(10**8, 10**9)}"
                name = f"{org}!{DOMAIN}!{int((START + timedelta(days=day)).timestamp())}.xml.gz"
                z.writestr(name.replace(" ", "_"), gzip.compress(dmarc(org, email, rid, day, recs)))
            fails = [("certificate-expired", 6 - day)] if day < 5 else []
            z.writestr(f"google.com!{DOMAIN}!2026-10-{day + 1:02d}.json.gz", gzip.compress(tls(day, fails)))
    OUT.write_bytes(buf.getvalue())
    print("wrote", OUT, len(buf.getvalue()), "bytes")


if __name__ == "__main__":
    main()
