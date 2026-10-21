"""Save an analysis as a shareable HTML summary or a CSV of senders."""
from __future__ import annotations

import csv
import html
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


def _steps(steps: list[str]) -> str:
    if not steps:
        return ""
    items = "".join(f"<li>{_e(s).replace('`', '')}</li>" for s in steps)
    return f"<p class='todo'>What to do</p><ol>{items}</ol>"


def html_summary(a: Analysis) -> str:
    period = ""
    if a.begin and a.end:
        period = f"{a.begin:%b %d, %Y} to {a.end:%b %d, %Y}"
    domains = ", ".join(sorted(a.policies)) or "No domain"
    cards = []
    for f in a.findings:
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
<h2>Who is sending email as you</h2><div class="wrap"><table><thead><tr><th>Status</th><th>Sender</th><th>IP address</th>
<th>Messages</th><th>Passed</th><th>What this means</th></tr></thead><tbody>{rows}</tbody></table></div>
<footer>Created by {APP_NAME} {__version__} ({TAGLINE.lower()}) on {datetime.now():%B %d, %Y}.</footer>
</main></body></html>"""


def senders_csv(a: Analysis, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Status", "Sender", "Hostname", "IP address", "Messages", "Passed DMARC",
                    "Failed DMARC", "SPF aligned", "DKIM aligned", "Delivered as",
                    "From domains", "What this means"])
        for s in a.sources:
            w.writerow([s.category_label, s.name, s.hostname, s.ip, s.messages, s.dmarc_pass,
                        s.failed, s.spf_aligned, s.dkim_aligned, s.delivered_summary,
                        "; ".join(s.header_from), s.meaning])
