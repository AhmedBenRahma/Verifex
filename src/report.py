"""
Generate a self-contained HTML report of a triage (and optional verification).

    from src.report import build_report
    html = build_report(target, triaged_rows, verdicts, meta)

The report is one standalone HTML file (no external assets) a tester can open,
print to PDF, or attach. Real data only — it renders what it is given.
"""
from __future__ import annotations

import datetime
import html as _html

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0a0e14;color:#e6edf3}
.wrap{max-width:900px;margin:0 auto;padding:32px}
h1{color:#00ff9d;margin:0 0 4px} h2{color:#00e5ff;border-bottom:1px solid #223;padding-bottom:6px;margin-top:32px}
.meta{color:#8b949e;font-size:14px;margin-bottom:24px}
.kpis{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}
.kpi{background:#0d1117;border:1px solid #00ff9d33;border-radius:8px;padding:12px 18px;min-width:120px}
.kpi .v{font-size:1.8rem;color:#00ff9d;font-weight:700}.kpi .l{color:#8b949e;font-size:12px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #223}
th{color:#8b949e;text-transform:uppercase;font-size:12px}
.CONFIRMED{color:#ff4d6d;font-weight:700}.UNCONFIRMED{color:#ffb703}.REAL{color:#ff4d6d;font-weight:700}
.NOISE{color:#8b949e}.SKIPPED{color:#8b949e}.ERROR{color:#ffb703}
code{background:#0d1117;border:1px solid #223;border-radius:4px;padding:1px 6px;color:#00e5ff}
.foot{color:#8b949e;font-size:12px;margin-top:40px;border-top:1px solid #223;padding-top:12px}
"""


def _esc(x) -> str:
    return _html.escape(str(x))


def build_report(target: str, rows: list[dict], verdicts: list[dict] | None, meta: dict) -> str:
    verdicts = verdicts or []
    real = [r for r in rows if r.get("Verdict") == "REAL"]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    kpis = f"""
    <div class="kpis">
      <div class="kpi"><div class="v">{len(rows)}</div><div class="l">Total alerts</div></div>
      <div class="kpi"><div class="v">{len(real)}</div><div class="l">Real findings</div></div>
      <div class="kpi"><div class="v">{len(rows) - len(real)}</div><div class="l">Noise filtered</div></div>
      <div class="kpi"><div class="v">{meta.get('model','')}</div><div class="l">Model</div></div>
    </div>"""

    findings_rows = "".join(
        f"<tr><td>{_esc(r['Vulnerability'])}</td><td><code>{_esc(r['URL'])}</code></td>"
        f"<td>{_esc(r.get('Risk',''))}</td><td class='{_esc(r['Verdict'])}'>{_esc(r['Verdict'])}</td>"
        f"<td>{r.get('Confidence',0)*100:.0f}%</td></tr>"
        for r in real
    ) or "<tr><td colspan=5>No real findings.</td></tr>"

    verify_section = ""
    if verdicts:
        vrows = "".join(
            f"<tr><td>{_esc(v['finding'])}</td><td><code>{_esc(v['url'])}</code></td>"
            f"<td>{_esc(v['technique'])}</td><td class='{_esc(v['result'])}'>{_esc(v['result'])}</td>"
            f"<td>{_esc(v.get('evidence',''))}</td></tr>"
            for v in verdicts
        )
        n_conf = sum(1 for v in verdicts if v["result"] == "CONFIRMED")
        verify_section = f"""
        <h2>Active verification (closed loop)</h2>
        <p class="meta">{n_conf} of {len(verdicts)} findings confirmed exploitable by sending a probe payload
        and inspecting the response. Authorised target only.</p>
        <table><tr><th>Finding</th><th>Endpoint</th><th>Technique</th><th>Verdict</th><th>Evidence</th></tr>
        {vrows}</table>"""

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Security triage report — {_esc(target)}</title><style>{CSS}</style></head>
<body><div class="wrap">
<h1>Smart Security Testing Module — Report</h1>
<div class="meta">Target: <code>{_esc(target)}</code> · Generated {now} · Model: {_esc(meta.get('model',''))}</div>
{kpis}
<h2>Confirmed findings (model triage)</h2>
<table><tr><th>Vulnerability</th><th>Endpoint</th><th>Risk</th><th>Verdict</th><th>Confidence</th></tr>
{findings_rows}</table>
{verify_section}
<div class="foot">Triage model trained on OWASP Benchmark. On targets outside that distribution, verdicts are
indicative; active verification confirms exploitability directly. For authorised testing only.</div>
</div></body></html>"""


def save_report(path, target, rows, verdicts, meta) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_report(target, rows, verdicts, meta))
