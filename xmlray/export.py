"""Save an analysis as a shareable HTML summary or a CSV of senders."""
from __future__ import annotations

import csv
import html
import re
from datetime import datetime

from .analyzer import Analysis
from .config import APP_NAME, TAGLINE
from .__version__ import __version__

SEV_COLORS = {
    "critical": ("#9F1D1D", "#FDE8E8"),
    "high": ("#B4470F", "#FDEEDC"),
    "medium": ("#8A6100", "#FDF4D6"),
    "low": ("#1F5D8C", "#E3EFF8"),
    "good": ("#1E6B43", "#E1F3E8"),
}


def _e(text) -> str:
    return html.escape(str(text))


def _rich(text: str) -> str:
    out = _e(text).replace("`", "")
    return re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r"<a href='\2'>\1</a>", out)


def _steps(steps: list[str]) -> str:
    if not steps:
        return ""
    items = "".join(f"<li>{_rich(s)}</li>" for s in steps)
    return f"<p class='todo'>What to do</p><ol>{items}</ol>"


def _period(a) -> str:
    if a.begin and a.end:
        return f"{a.begin:%b %d, %Y} to {a.end:%b %d, %Y}"
    return ""


def html_summary(a: Analysis, findings=None, dns_results=None, tls=None) -> str:
    """Self-contained web page. *findings* defaults to the report findings only."""
    period = _period(a)
    findings = a.findings if findings is None else findings
    domains = ", ".join(sorted(a.policies)) or "No domain"
    cards = []
    for f in findings:
        fg, bg = SEV_COLORS[f.severity]
        cards.append(
            f"<section class='finding' style='border-left-color:{fg}'>"
            f"<span class='pill' style='color:{fg};background:{bg}'>{f.severity.title()}</span>"
            f"<h3>{_e(f.title)}</h3><p>{_e(f.summary)}</p>{_steps(f.steps)}</section>")
    rows = "".join(
        f"<tr><td>{_e(s.category_label)}</td><td>{_e(s.name)}</td><td>{_e(s.ip)}</td>"
        f"<td class='n'>{s.messages:,}</td><td class='n'>{s.pass_rate*100:.0f}%</td>"
        f"<td>{_e(s.meaning)}</td></tr>" for s in a.sources)
    policies = "".join(
        f"<li><b>{_e(d)}</b>: p={_e(p.p)}{', sp='+_e(p.sp) if p.sp else ''}, pct={p.pct}</li>"
        for d, p in sorted(a.policies.items()))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME} summary for {_e(domains)}</title>
<style>
:root{{--ink:#17324A;--muted:#5B7083;--line:#D5DFE6;--bg:#EEF3F6;--card:#fff}}
@media (prefers-color-scheme:dark){{:root{{--ink:#E3EDF4;--muted:#9DB2C2;--line:#2C4255;--bg:#0F1E2B;--card:#16293A}}}}
body{{font-family:"Segoe UI",system-ui,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:32px;line-height:1.5}}
main{{max-width:980px;margin:auto}} h1{{margin:0;font-size:28px}} .tag{{color:var(--muted);margin:0 0 24px}}
.grade{{display:flex;gap:24px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:24px}}
.grade b{{font-size:56px;line-height:1}} .finding{{background:var(--card);border:1px solid var(--line);border-left:6px solid;border-radius:8px;padding:16px 20px;margin:12px 0}}
.finding h3{{margin:8px 0 4px}} .pill{{font-size:12px;font-weight:600;padding:2px 10px;border-radius:9px}} .todo{{font-weight:600;margin-bottom:0}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;background:var(--card)}} th,td{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
td.n{{text-align:right;white-space:nowrap}} footer{{color:var(--muted);font-size:12px;margin-top:32px}}
</style></head><body><main>
<h1>{APP_NAME} summary</h1><p class="tag">{_e(domains)}. {_e(period)}</p>
<div class="grade"><b>{_e(a.grade)}</b><div><div><strong>{_e(a.grade_label)}</strong>, score {a.score} of 100</div>
<div>{a.total:,} messages checked, {a.pass_pct:.1f}% passed DMARC, {a.failed:,} failed.</div>
<ul>{policies}</ul></div></div>
<h2>Action plan</h2>{''.join(cards)}
{_dns_html(dns_results)}{_tls_html(tls)}
<h2>Who is sending email as you</h2><div class="wrap"><table><thead><tr><th>Status</th><th>Sender</th><th>IP address</th>
<th>Messages</th><th>Passed</th><th>What this means</th></tr></thead><tbody>{rows}</tbody></table></div>
<footer>Created by {APP_NAME} {__version__} ({TAGLINE.lower()}) on {datetime.now():%B %d, %Y}.</footer>
</main></body></html>"""


def _dns_html(dns_results) -> str:
    if not dns_results:
        return ""
    rows = ""
    for d, res in sorted(dns_results.items()):
        for v in res.records:
            rows += (f"<tr><td>{_e(v.kind)}</td><td>{_e(v.name)}</td><td>{_e(v.status)}</td>"
                     f"<td style='word-break:break-all'>{_e(v.value or '(none)')}</td>"
                     f"<td>{_e(v.note)}</td></tr>")
    return ("<h2>Live DNS records</h2><div class='wrap'><table><thead><tr><th>Record</th>"
            "<th>Name</th><th>Status</th><th>Value</th><th>Notes</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>")


def _tls_html(tls) -> str:
    if not tls or not tls.total:
        return ""
    rows = "".join(f"<tr><td>{_e(t)}</td><td class='n'>{n:,}</td></tr>"
                   for t, n in tls.by_type.most_common())
    table = (f"<div class='wrap'><table><thead><tr><th>Problem</th><th>Attempts</th></tr>"
             f"</thead><tbody>{rows}</tbody></table></div>") if rows else ""
    return (f"<h2>Secure delivery to you (TLS reports)</h2><p>{tls.total:,} connections "
            f"reported, {tls.success_pct:.1f}% encrypted successfully.</p>{table}")


def print_html(a: Analysis, findings=None, dns_results=None, tls=None) -> str:
    """Simple HTML for the PDF export (Qt's renderer supports only basic CSS)."""
    findings = a.findings if findings is None else findings
    domains = ", ".join(sorted(a.policies)) or "No domain"
    parts = [f"<h1 style='color:#17324A'>{APP_NAME} summary</h1>"
             f"<p style='color:#5B7083'>{_e(domains)}. {_e(_period(a))}</p>",
             "<table width='100%' cellpadding='8' style='background:#17324A;color:white'><tr>"
             f"<td width='18%' align='center'><span style='font-size:30pt;color:white'><b>"
             f"{_e(a.grade)}</b></span></td><td><b style='font-size:13pt'>{_e(a.grade_label)}"
             f"</b><br>Health score {a.score} of 100<br>{a.total:,} messages checked, "
             f"{a.pass_pct:.1f}% passed DMARC, {a.failed:,} failed.</td></tr></table>",
             "<h2 style='color:#17324A'>Action plan</h2>"]
    for f in findings:
        fg, bg = SEV_COLORS[f.severity]
        steps = "".join(f"<li>{_rich(s)}</li>" for s in f.steps)
        parts.append(
            "<table width='100%' cellspacing='0' cellpadding='6' style='margin-bottom:8px'>"
            f"<tr><td width='6' style='background:{fg}'></td><td style='background:#F6F9FB'>"
            f"<span style='color:{fg}'><b>{f.severity.title()}</b></span><br>"
            f"<b style='font-size:11pt'>{_e(f.title)}</b><br>{_e(f.summary)}"
            + (f"<br><b>What to do</b><ol>{steps}</ol>" if steps else "")
            + "</td></tr></table>")
    if dns_results:
        parts.append("<h2 style='color:#17324A'>Live DNS records</h2><table width='100%' "
                     "cellpadding='4' border='1' cellspacing='0' style='border-color:#D5DFE6'>"
                     "<tr style='background:#F3F7F9'><th>Record</th><th>Status</th><th>Notes</th></tr>")
        for d, res in sorted(dns_results.items()):
            for v in res.records:
                parts.append(f"<tr><td>{_e(v.kind)}<br><small>{_e(v.name)}</small></td>"
                             f"<td>{_e(v.status)}</td><td>{_e(v.note)}</td></tr>")
        parts.append("</table>")
    if tls and tls.total:
        parts.append(f"<h2 style='color:#17324A'>Secure delivery to you</h2><p>{tls.total:,} "
                     f"connections reported, {tls.success_pct:.1f}% encrypted successfully.</p>")
    parts.append("<h2 style='color:#17324A'>Who is sending email as you</h2><table width='100%' "
                 "cellpadding='4' border='1' cellspacing='0' style='border-color:#D5DFE6'>"
                 "<tr style='background:#F3F7F9'><th>Status</th><th>Sender</th><th>IP address</th>"
                 "<th>Messages</th><th>Passed</th></tr>")
    for s in a.sources[:200]:
        parts.append(f"<tr><td>{_e(s.category_label)}</td><td>{_e(s.name)}</td><td>{_e(s.ip)}"
                     f"</td><td align='right'>{s.messages:,}</td><td align='right'>"
                     f"{s.pass_rate*100:.0f}%</td></tr>")
    parts.append("</table>")
    parts.append(f"<p style='color:#5B7083'><small>Created by {APP_NAME} {__version__} on "
                 f"{datetime.now():%B %d, %Y}.</small></p>")
    return "<html><body style='font-family:Segoe UI, Arial'>" + "".join(parts) + "</body></html>"


def senders_csv(a: Analysis, path: str, owners: dict | None = None) -> None:
    owners = owners or {}
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Status", "Sender", "Hostname", "IP address", "Network owner", "Messages",
                    "Passed DMARC", "Failed DMARC", "SPF aligned", "DKIM aligned",
                    "Delivered as", "From domains", "First seen", "Last seen", "What this means"])
        for s in a.sources:
            w.writerow([s.category_label, s.name, s.hostname, s.ip, owners.get(s.ip, ""),
                        s.messages, s.dmarc_pass, s.failed, s.spf_aligned, s.dkim_aligned,
                        s.delivered_summary, "; ".join(s.header_from),
                        f"{s.first_seen:%Y-%m-%d}" if s.first_seen else "",
                        f"{s.last_seen:%Y-%m-%d}" if s.last_seen else "", s.meaning])


def json_summary(a: Analysis, findings=None, dns_results=None, tls=None, owners=None) -> dict:
    """Everything XML-ray knows, as plain JSON for dashboards and other tools."""
    findings = a.findings if findings is None else findings
    owners = owners or {}
    return {
        "generator": f"{APP_NAME} {__version__}",
        "created": datetime.now().isoformat(timespec="seconds"),
        "period": {"from": a.begin.isoformat() if a.begin else None,
                   "to": a.end.isoformat() if a.end else None},
        "grade": a.grade, "score": a.score, "messages": a.total, "passed": a.passed,
        "pass_percent": round(a.pass_pct, 2),
        "policies": {d: {"p": p.p, "sp": p.sp, "pct": p.pct,
                         "legit_pass_percent": round(p.legit_pass_rate * 100, 2)}
                     for d, p in a.policies.items()},
        "findings": [{"severity": f.severity, "title": f.title, "summary": f.summary,
                      "steps": f.steps, "key": f.key, "source": f.source,
                      "affected": f.affected, "ips": f.ips} for f in findings],
        "senders": [{"ip": s.ip, "name": s.name, "hostname": s.hostname,
                     "owner": owners.get(s.ip, ""), "status": s.category_label,
                     "messages": s.messages, "passed": s.dmarc_pass,
                     "spf_aligned": s.spf_aligned, "dkim_aligned": s.dkim_aligned,
                     "from_domains": dict(s.header_from),
                     "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                     "last_seen": s.last_seen.isoformat() if s.last_seen else None}
                    for s in a.sources],
        "dns": {d: [{"kind": v.kind, "name": v.name, "value": v.value, "status": v.status,
                     "note": v.note} for v in r.records] for d, r in (dns_results or {}).items()},
        "tls": {"connections": tls.total, "success_percent": round(tls.success_pct, 2),
                "failures": dict(tls.by_type)} if tls and tls.total else None,
    }
