"""
AIAnalyzer — uses Claude (Anthropic API) to perform deep code analysis,
identify custom/obfuscated bypass mechanisms, and generate tailored Frida hooks.
"""

import json, re
from pathlib import Path
import anthropic


MAX_SNIPPET_CHARS = 6000   # per code block sent to API
MAX_FILES_AI      = 20     # max suspicious files to send for AI review


class AIAnalyzer:
    def __init__(self, api_key: str | None, console):
        self.api_key = api_key
        self.console = console
        self._client = None

    def _client_get(self):
        if not self._client:
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    # ── public ────────────────────────────────────────────────────
    def analyze(self, root_findings: list, ssl_findings: list,
                decompile_result: dict) -> dict:
        """
        Returns:
          {
            "custom_hooks": [...],      # extra Frida hooks AI found
            "obfuscated_methods": [...],
            "bypass_notes": str,
            "risk_summary": str,
            "raw_response": str,
          }
        """
        client = self._client_get()

        # ── Build context for AI ──────────────────────────────────
        snippets = self._collect_suspicious_snippets(root_findings, ssl_findings)
        manifest_text = self._read_manifest(decompile_result)
        nsc_text      = self._read_nsc(decompile_result)

        prompt = self._build_prompt(root_findings, ssl_findings,
                                    snippets, manifest_text, nsc_text)

        self.console.print("  [cyan]Sending analysis to Claude AI…[/cyan]")

        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=(
                    "You are an expert Android penetration tester and reverse engineer. "
                    "You analyze Android APK code for security mechanisms like root detection "
                    "and SSL/TLS certificate pinning. You output structured JSON with detailed "
                    "technical analysis and precise Frida hook recommendations. "
                    "Respond ONLY with valid JSON — no markdown, no preamble."
                ),
                messages=[{"role": "user", "content": prompt}]
            )

            raw = response.content[0].text
            result = self._parse_response(raw)
            self.console.print(
                f"  [green]✔ AI analysis complete — "
                f"{len(result.get('custom_hooks', []))} custom hooks identified[/green]\n"
            )
            return result

        except Exception as e:
            self.console.print(f"  [yellow][!] AI analysis error: {e}[/yellow]\n")
            return {"error": str(e), "custom_hooks": [], "bypass_notes": "",
                    "risk_summary": "AI analysis unavailable."}

    # ── private ───────────────────────────────────────────────────
    def _collect_suspicious_snippets(self, root_findings, ssl_findings) -> str:
        """Pull relevant code snippets from matched files."""
        files_seen = set()
        snippets   = []

        for f in (root_findings + ssl_findings):
            fp = f.get("file")
            if not fp or str(fp) in files_seen:
                continue
            files_seen.add(str(fp))
            if len(files_seen) > MAX_FILES_AI:
                break
            try:
                content = Path(fp).read_text(errors="ignore")[:MAX_SNIPPET_CHARS]
                snippets.append(f"=== {Path(fp).name} ===\n{content}")
            except Exception:
                pass

        return "\n\n".join(snippets)

    def _read_manifest(self, dr: dict) -> str:
        mf = dr.get("manifest")
        if mf and Path(mf).exists():
            return Path(mf).read_text(errors="ignore")[:3000]
        return ""

    def _read_nsc(self, dr: dict) -> str:
        nc = dr.get("net_config")
        if nc and Path(nc).exists():
            return Path(nc).read_text(errors="ignore")[:2000]
        return ""

    def _build_prompt(self, root_findings, ssl_findings,
                      snippets, manifest, nsc) -> str:
        root_summary = json.dumps(
            [{"id": f["id"], "category": f["category"], "severity": f["severity"],
              "bypass_type": f["bypass_type"], "description": f["description"]}
             for f in root_findings], indent=2)

        ssl_summary = json.dumps(
            [{"id": f["id"], "category": f["category"], "severity": f["severity"],
              "bypass_type": f["bypass_type"], "library": f.get("library", "")}
             for f in ssl_findings], indent=2)

        return f"""
You are analyzing an Android APK for a penetration test (authorized testing).

## Detected Root Detection Techniques:
{root_summary}

## Detected SSL Pinning Techniques:
{ssl_summary}

## AndroidManifest.xml (excerpt):
{manifest[:1500] if manifest else "Not available"}

## Network Security Config (if present):
{nsc[:1000] if nsc else "Not present"}

## Suspicious Code Snippets:
{snippets[:8000] if snippets else "Not available"}

## Task:
Analyze the above and return a JSON object with these exact keys:

{{
  "risk_summary": "<2-3 sentence overall risk assessment>",
  "bypass_notes": "<technical notes on any custom/obfuscated checks not covered by standard patterns>",
  "obfuscated_methods": [
    {{"class": "...", "method": "...", "note": "..."}}
  ],
  "custom_hooks": [
    {{
      "purpose": "<what this hook bypasses>",
      "target_class": "<fully qualified class>",
      "target_method": "<method name>",
      "frida_snippet": "<working Frida JS snippet>",
      "priority": "HIGH|MEDIUM|LOW"
    }}
  ],
  "recommended_approach": "<step-by-step bypass strategy for a pentester>",
  "native_lib_notes": "<notes about native libraries detected and how to handle them>"
}}

Be precise. Include actual class/method names found in the code snippets.
For Frida snippets use Java.use() and method.implementation = function() pattern.
"""

    def _parse_response(self, raw: str) -> dict:
        # Strip any accidental markdown fences
        clean = re.sub(r"```json|```", "", raw).strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            # Try to extract JSON object
            m = re.search(r"\{.*\}", clean, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return {
            "risk_summary": "Could not parse AI response.",
            "custom_hooks": [],
            "bypass_notes": raw[:500],
            "raw_response": raw,
        }
