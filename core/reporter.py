"""
Reporter — generates a rich HTML report + JSON report from all findings.
"""

import json
from datetime import datetime
from pathlib import Path


class Reporter:
    def __init__(self, apk, sha256, decompile_result,
                 root_findings, ssl_findings, ai_analysis,
                 frida_scripts, out: Path, console):
        self.apk             = apk
        self.sha256          = sha256
        self.dr              = decompile_result
        self.root_findings   = root_findings
        self.ssl_findings    = ssl_findings
        self.ai_analysis     = ai_analysis
        self.frida_scripts   = frida_scripts
        self.out             = out
        self.console         = console
        self.ts              = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self):
        self._json_report()
        self._html_report()
        self.console.print(
            f"  [green]✔ Reports saved to {self.out}/report.*[/green]\n"
        )

    # ── JSON ──────────────────────────────────────────────────────
    def _json_report(self):
        report = {
            "meta": {
                "apk":       str(self.apk),
                "sha256":    self.sha256,
                "timestamp": self.ts,
                "tool":      "APKShield-PT",
            },
            "root_findings": self._serialise(self.root_findings),
            "ssl_findings":  self._serialise(self.ssl_findings),
            "ai_analysis":   self.ai_analysis,
            "frida_scripts": [
                {"name": s["name"], "purpose": s["purpose"], "path": str(s["path"])}
                for s in self.frida_scripts
            ],
        }
        p = self.out / "report.json"
        p.write_text(json.dumps(report, indent=2, default=str))

    def _serialise(self, findings):
        out = []
        for f in findings:
            row = {}
            for k, v in f.items():
                row[k] = str(v) if not isinstance(v, (str, int, float, bool, list, dict, type(None))) else v
            out.append(row)
        return out

    # ── HTML ──────────────────────────────────────────────────────
    def _html_report(self):
        sev_badge = {
            "CRITICAL": '<span class="badge badge-critical">CRITICAL</span>',
            "HIGH":     '<span class="badge badge-high">HIGH</span>',
            "MEDIUM":   '<span class="badge badge-medium">MEDIUM</span>',
            "LOW":      '<span class="badge badge-low">LOW</span>',
            "INFO":     '<span class="badge badge-info">INFO</span>',
        }

        def rows(findings):
            html = ""
            for f in findings:
                badge = sev_badge.get(f.get("severity",""), f.get("severity",""))
                html += f"""
                <tr>
                  <td><code>{f.get('id','')}</code></td>
                  <td>{badge}</td>
                  <td>{f.get('category','')}</td>
                  <td>{f.get('description','')}</td>
                  <td><code>{f.get('bypass_type','')}</code></td>
                  <td class="file-cell">{Path(str(f.get('file',''))).name}</td>
                </tr>"""
            return html or "<tr><td colspan='6' style='text-align:center;color:#6ee7b7'>None detected ✔</td></tr>"

        def script_cards():
            html = ""
            for s in self.frida_scripts:
                try:
                    code = Path(s["path"]).read_text()[:1200] + "\n// ... truncated"
                except Exception:
                    code = "// Script not found"
                html += f"""
            <div class="script-card">
              <h3>📜 {s['name']}</h3>
              <p class="purpose">{s['purpose']}</p>
              <pre><code class="language-javascript">{_esc(code)}</code></pre>
              <div class="usage">
                <strong>Usage:</strong>
                <code>frida -U -f &lt;package&gt; -l frida/{s['name']} --no-pause</code>
              </div>
            </div>"""
            return html

        ai_risk    = self.ai_analysis.get("risk_summary", "N/A")
        ai_notes   = self.ai_analysis.get("bypass_notes", "N/A")
        ai_approach = self.ai_analysis.get("recommended_approach", "N/A")
        ai_native  = self.ai_analysis.get("native_lib_notes", "N/A")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APKShield-PT Report — {self.apk.name}</title>
<style>
  :root {{
    --bg: #0f1117; --card: #1a1d27; --border: #2d3047;
    --cyan: #00d4ff; --yellow: #fbbf24; --green: #6ee7b7;
    --red: #ef4444; --orange: #f97316; --blue: #60a5fa;
    --text: #e2e8f0; --muted: #94a3b8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; }}
  header {{ background: linear-gradient(135deg, #0f1117 0%, #1e2235 100%);
            border-bottom: 1px solid var(--cyan); padding: 2rem 3rem; }}
  header h1 {{ color: var(--cyan); font-size: 1.8rem; letter-spacing: 2px; }}
  header p  {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
               gap: 1rem; padding: 1.5rem 3rem; background: var(--card);
               border-bottom: 1px solid var(--border); }}
  .meta-item label {{ color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; }}
  .meta-item span  {{ display: block; color: var(--cyan); font-family: monospace; font-size: 0.85rem; margin-top: 0.2rem; word-break: break-all; }}
  main {{ padding: 2rem 3rem; max-width: 1400px; margin: 0 auto; }}
  section {{ margin-bottom: 3rem; }}
  h2 {{ color: var(--yellow); font-size: 1.1rem; letter-spacing: 1px;
        border-left: 3px solid var(--yellow); padding-left: 0.75rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #252836; color: var(--muted); font-size: 0.75rem;
        text-transform: uppercase; letter-spacing: 1px; padding: 0.6rem 1rem; text-align: left; }}
  td {{ padding: 0.6rem 1rem; border-top: 1px solid var(--border); font-size: 0.85rem; vertical-align: top; }}
  tr:hover td {{ background: rgba(0,212,255,0.04); }}
  .file-cell {{ color: var(--muted); font-size: 0.75rem; font-family: monospace; }}
  .badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }}
  .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-high     {{ background: #78350f; color: #fcd34d; }}
  .badge-medium   {{ background: #1e3a5f; color: #93c5fd; }}
  .badge-low      {{ background: #1a2e1a; color: var(--green); }}
  .badge-info     {{ background: #1e2235; color: var(--muted); }}
  .ai-card {{ background: var(--card); border: 1px solid var(--border);
              border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
  .ai-card h3 {{ color: var(--cyan); margin-bottom: 0.5rem; font-size: 0.9rem; }}
  .ai-card p  {{ color: var(--text); font-size: 0.85rem; line-height: 1.6; }}
  .script-card {{ background: var(--card); border: 1px solid var(--border);
                  border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .script-card h3  {{ color: var(--cyan); margin-bottom: 0.4rem; }}
  .script-card .purpose {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 1rem; }}
  .script-card pre {{ background: #0d1117; border: 1px solid var(--border);
                      border-radius: 6px; padding: 1rem; overflow-x: auto;
                      font-size: 0.78rem; line-height: 1.5; max-height: 300px; }}
  .usage {{ margin-top: 0.75rem; background: #0d1117; padding: 0.5rem 1rem;
            border-radius: 4px; font-size: 0.8rem; color: var(--green); }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.75rem;
            padding: 2rem; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <h1>⚡ APKShield-PT Analysis Report</h1>
  <p>AI-Powered Android Penetration Testing — Authorized Testing Only</p>
</header>

<div class="meta-grid">
  <div class="meta-item"><label>APK File</label><span>{self.apk.name}</span></div>
  <div class="meta-item"><label>SHA-256</label><span>{self.sha256[:32]}…</span></div>
  <div class="meta-item"><label>Timestamp</label><span>{self.ts}</span></div>
  <div class="meta-item"><label>Root Findings</label><span>{len(self.root_findings)}</span></div>
  <div class="meta-item"><label>SSL Findings</label><span>{len(self.ssl_findings)}</span></div>
  <div class="meta-item"><label>Frida Scripts</label><span>{len(self.frida_scripts)}</span></div>
</div>

<main>

<section>
  <h2>🔴 Root Detection Findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Description</th><th>Bypass Type</th><th>File</th></tr></thead>
    <tbody>{rows(self.root_findings)}</tbody>
  </table>
</section>

<section>
  <h2>🟡 SSL Pinning Findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Description</th><th>Bypass Type</th><th>File</th></tr></thead>
    <tbody>{rows(self.ssl_findings)}</tbody>
  </table>
</section>

<section>
  <h2>🤖 AI Deep Analysis</h2>
  <div class="ai-card"><h3>Risk Summary</h3><p>{_esc(ai_risk)}</p></div>
  <div class="ai-card"><h3>Bypass Notes</h3><p>{_esc(ai_notes)}</p></div>
  <div class="ai-card"><h3>Recommended Approach</h3><p>{_esc(ai_approach)}</p></div>
  <div class="ai-card"><h3>Native Library Notes</h3><p>{_esc(ai_native)}</p></div>
</section>

<section>
  <h2>📜 Generated Frida Scripts</h2>
  {script_cards()}
</section>

</main>
<footer>Generated by APKShield-PT · {self.ts} · For authorized penetration testing only</footer>
</body>
</html>"""

        (self.out / "report.html").write_text(html)

def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
