"""Generate executive HTML report for CRS findings."""
from __future__ import annotations
from pathlib import Path
from models import CRSResult, ValidationResult

_SEV_COLOR = {"Critical": "#ff4444", "High": "#ff8800", "Medium": "#ffcc00", "Low": "#44bb44"}
_VAL_COLOR = {
    ValidationResult.FIXED:   ("#44bb44", "✓ FIXED"),
    ValidationResult.PARTIAL: ("#ffcc00", "~ PARTIAL"),
    ValidationResult.FAILED:  ("#ff4444", "✗ FAILED"),
    ValidationResult.SKIPPED: ("#888888", "— SKIPPED"),
}


def _val_badge(v: ValidationResult) -> str:
    color, label = _VAL_COLOR[v]
    return f'<span style="color:{color};font-weight:700;font-family:monospace">{label}</span>'


def _sev_badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity, "#888")
    return f'<span style="color:{color};font-weight:700;border:1px solid {color};padding:1px 8px;border-radius:4px;font-size:12px">{severity}</span>'


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate_html(result: CRSResult, output_path: str) -> None:
    findings_html = ""
    for f in result.findings:
        c = f.crash
        a = f.analysis
        p = f.patch

        diff_html = ""
        if p.diff:
            lines = []
            for line in p.diff.splitlines():
                if line.startswith("+") and not line.startswith("+++"):
                    lines.append(f'<span style="color:#44bb44">{_escape(line)}</span>')
                elif line.startswith("-") and not line.startswith("---"):
                    lines.append(f'<span style="color:#ff4444">{_escape(line)}</span>')
                elif line.startswith("@@"):
                    lines.append(f'<span style="color:#38bdf8">{_escape(line)}</span>')
                else:
                    lines.append(_escape(line))
            diff_html = f'<pre class="code-block">{"<br>".join(lines)}</pre>'

        cwe_link = f'<a href="https://cwe.mitre.org/data/definitions/{a.cwe_id.replace("CWE-","")}.html" target="_blank">{_escape(a.cwe_id)}</a>' if a.cwe_id else "—"

        findings_html += f"""
        <div class="finding-card">
          <div class="finding-header">
            <div>
              <span class="crash-id">{c.crash_id}</span>
              <span class="finding-title">{_escape(c.crash_type.value)}</span>
              {_sev_badge(a.severity or "High")}
            </div>
            <div style="display:flex;gap:12px;align-items:center">
              {_val_badge(p.validation)}
              <span style="font-family:monospace;color:#555;font-size:11px">{c.stack_hash}</span>
            </div>
          </div>

          <div class="finding-grid">
            <div>
              <div class="field-label">Crash Details</div>
              <table class="meta-table">
                <tr><td>Signal</td><td><code>{_escape(c.signal)}</code></td></tr>
                <tr><td>Top Frame</td><td><code>{_escape(c.top_frame)}</code></td></tr>
                <tr><td>Crash Address</td><td><code>{_escape(c.crash_address)}</code></td></tr>
                <tr><td>CWE</td><td>{cwe_link} — {_escape(a.cwe_name)}</td></tr>
                <tr><td>Exploitability</td><td>{_escape(a.exploitability)}</td></tr>
              </table>

              <div class="field-label" style="margin-top:16px">Root Cause</div>
              <div class="field-val">{_escape(a.root_cause)}</div>

              <div class="field-label" style="margin-top:12px">Attack Scenario</div>
              <div class="field-val impact-text">{_escape(a.attack_scenario)}</div>

              <div class="field-label" style="margin-top:12px">Fix Approach</div>
              <div class="field-val">{_escape(a.fix_approach)}</div>
            </div>

            <div>
              <div class="field-label">ASan Output</div>
              <pre class="code-block">{_escape(c.asan_output[:1500])}</pre>

              <div class="field-label" style="margin-top:16px">
                Generated Patch
                {"— " + _val_badge(p.validation) if p.applied else "— not applied"}
              </div>
              {diff_html if diff_html else '<div style="color:#555;font-size:13px">No patch generated</div>'}
            </div>
          </div>
        </div>"""

    fixed = result.fixed_count
    total_findings = len(result.findings)
    fix_rate = int(fixed / total_findings * 100) if total_findings else 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Mini-CRS Report — {_escape(result.target_name)}</title>
<style>
  :root {{
    --bg:#0d0d0d;--bg2:#141414;--bg3:#1a1a1a;
    --text1:#f0f0f0;--text2:#b0b0b0;--text3:#666;
    --accent:#00ffb2;--border:#222;
    --font:'Segoe UI',system-ui,sans-serif;--mono:'JetBrains Mono','Fira Code',monospace;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text1);font-family:var(--font);font-size:14px;line-height:1.6}}
  a{{color:var(--accent)}}

  .header{{background:linear-gradient(135deg,#0a1500,#0d0d0d);border-bottom:1px solid var(--border);padding:40px 48px}}
  .header .label{{font-family:var(--mono);font-size:11px;color:var(--accent);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}}
  .header h1{{font-size:30px;font-weight:700;margin-bottom:6px}}
  .header .meta{{color:var(--text3);font-size:12px}}

  .stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;padding:28px 48px;background:var(--bg2);border-bottom:1px solid var(--border)}}
  .stat-card{{background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center}}
  .stat-val{{font-size:32px;font-weight:800}}
  .stat-lbl{{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-top:4px}}

  .section{{padding:36px 48px;border-bottom:1px solid var(--border)}}
  .section-title{{font-size:18px;font-weight:700;margin-bottom:24px}}

  .finding-card{{background:var(--bg2);border:1px solid var(--border);border-left:3px solid #ff8800;border-radius:10px;padding:24px;margin-bottom:20px}}
  .finding-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px}}
  .crash-id{{font-family:var(--mono);font-size:11px;color:var(--text3);margin-right:10px}}
  .finding-title{{font-size:16px;font-weight:600;margin-right:10px}}
  .finding-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:12px}}

  .field-label{{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:6px}}
  .field-val{{font-size:13px;color:var(--text2);line-height:1.6}}
  .impact-text{{color:#ffb347;font-size:13px}}

  .meta-table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:4px}}
  .meta-table td{{padding:4px 8px;border-bottom:1px solid var(--border);color:var(--text2)}}
  .meta-table td:first-child{{color:var(--text3);width:120px}}

  .code-block{{background:#0a0a0a;border:1px solid var(--border);border-radius:6px;padding:12px;font-family:var(--mono);font-size:11px;color:#ccc;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:280px;overflow-y:auto;line-height:1.5}}

  .footer{{padding:20px 48px;color:var(--text3);font-size:12px;display:flex;justify-content:space-between}}
  code{{font-family:var(--mono);background:#1a1a1a;padding:1px 5px;border-radius:3px;font-size:12px}}

  @media(max-width:900px){{
    .stats{{grid-template-columns:repeat(2,1fr)}}
    .finding-grid{{grid-template-columns:1fr}}
    .section{{padding:24px 20px}}
    .header{{padding:24px 20px}}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="label">// mini-crs report · autonomous vulnerability analysis</div>
  <h1>🤖 {_escape(result.target_name)}</h1>
  <div class="meta">
    <strong>Target:</strong> {_escape(result.target_source)} &nbsp;·&nbsp;
    <strong>Generated:</strong> {_escape(result.generated_at)} &nbsp;·&nbsp;
    <strong>Fuzzing Duration:</strong> {result.fuzzing_duration_seconds}s &nbsp;·&nbsp;
    <strong>Executions:</strong> {result.total_executions:,}
  </div>
</div>

<div class="stats">
  <div class="stat-card"><div class="stat-val" style="color:#ff8800">{result.crashes_found}</div><div class="stat-lbl">Crashes Found</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#ff4444">{result.unique_crashes}</div><div class="stat-lbl">Unique Crashes</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#a78bfa">{result.patched_count}</div><div class="stat-lbl">Patches Generated</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#44bb44">{fixed}</div><div class="stat-lbl">Patches Verified</div></div>
  <div class="stat-card"><div class="stat-val" style="color:{'#44bb44' if fix_rate >= 50 else '#ff8800'}">{fix_rate}%</div><div class="stat-lbl">Fix Rate</div></div>
</div>

<div class="section">
  <div class="section-title">🔍 Findings ({total_findings} unique vulnerabilities)</div>
  {findings_html if findings_html else '<p style="color:var(--text3)">No crashes found during fuzzing.</p>'}
</div>

<div class="footer">
  <span>Generated by P4 Mini-CRS · {_escape(result.generated_at)}</span>
  <span>Pipeline: AFL++ → ASan → GDB → {_escape(result.llm_provider) if result.llm_provider else "LLM"} → patch validation</span>
</div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
