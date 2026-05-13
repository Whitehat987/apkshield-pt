#!/usr/bin/env python3
"""
APKShield-PT — Android Penetration Testing Tool
Automatic APK decompilation, root detection analysis,
SSL pinning analysis, and Frida bypass script generation.
For authorized penetration testing only.
"""

import sys, os

# ── path fix — must be before any local imports ────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── dependency bootstrap ───────────────────────────────────────
import subprocess

def _install(pkg):
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", pkg, "-q",
        "--break-system-packages"
    ])

for dep in ["rich", "anthropic"]:
    try:
        __import__(dep)
    except ImportError:
        print(f"[*] Installing {dep}...")
        try:
            _install(dep)
        except Exception:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep, "-q"])

# ── imports ────────────────────────────────────────────────────
import json, re, shutil, hashlib, argparse
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.rule    import Rule
from rich         import box

from core.decompiler    import Decompiler
from core.root_detector import RootDetector
from core.ssl_detector  import SSLDetector
from core.frida_gen     import FridaScriptGenerator
from core.ai_analyzer   import AIAnalyzer
from core.reporter      import Reporter

console   = Console()
SCRIPT_DIR = Path(__file__).parent

BANNER = """[bold cyan]
   █████╗ ██████╗ ██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ███████║██████╔╝█████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██╔══██║██╔═══╝ ██╔═██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║  ██║██║     ██║  ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
[/bold cyan][bold yellow]
  ─────────  Android PT  |  Root Detection  ·  SSL Pinning  ─────────
[/bold yellow]"""


def print_banner():
    console.print(BANNER)
    console.print(Panel(
        "[dim]For authorized penetration testing only. "
        "Ensure written permission before testing any application.[/dim]",
        border_style="red", expand=False
    ))
    console.print()


def check_dependencies():
    tools = {
        "apktool":   shutil.which("apktool"),
        "jadx":      shutil.which("jadx"),
        "adb":       shutil.which("adb"),
        "frida":     shutil.which("frida"),
        "objection": shutil.which("objection"),
    }
    t = Table(title="[bold]Dependency Check[/bold]", box=box.ROUNDED,
              border_style="cyan")
    t.add_column("Tool",   style="bold white")
    t.add_column("Status")
    t.add_column("Path",   style="dim")
    for tool, path in tools.items():
        if path:
            t.add_row(tool, "[green]✔ Found[/green]", path)
        else:
            t.add_row(tool, "[red]✘ Missing[/red]", "install required")
    console.print(t)
    return tools


def run(apk_path, output_dir, api_key, no_ai=False, verbose=False):
    apk = Path(apk_path).resolve()
    if not apk.exists():
        console.print(f"[red][!] APK not found: {apk}[/red]")
        sys.exit(1)

    out = Path(output_dir) / apk.stem
    out.mkdir(parents=True, exist_ok=True)

    sha256 = hashlib.sha256(apk.read_bytes()).hexdigest()

    console.print(Rule("[bold cyan]APK Information[/bold cyan]"))
    info = Table(box=box.SIMPLE, show_header=False)
    info.add_column("K", style="bold cyan", width=18)
    info.add_column("V")
    info.add_row("File",     str(apk))
    info.add_row("Size",     f"{apk.stat().st_size / 1_048_576:.2f} MB")
    info.add_row("SHA-256",  sha256)
    info.add_row("Output",   str(out))
    info.add_row("Time",     datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(info)
    console.print()

    # Phase 1 — Decompile
    console.print(Rule("[bold yellow]Phase 1 — Decompilation[/bold yellow]"))
    dr = Decompiler(apk, out, console, verbose).run()

    # Phase 2 — Root Detection
    console.print(Rule("[bold yellow]Phase 2 — Root Detection[/bold yellow]"))
    root_findings = RootDetector(dr, console, verbose).analyze()

    # Phase 3 — SSL Pinning
    console.print(Rule("[bold yellow]Phase 3 — SSL Pinning[/bold yellow]"))
    ssl_findings = SSLDetector(dr, console, verbose).analyze()

    # Phase 4 — AI Analysis (optional)
    ai_analysis = {}
    if not no_ai:
        console.print(Rule("[bold yellow]Phase 4 — AI Deep Analysis[/bold yellow]"))
        ai_analysis = AIAnalyzer(api_key, console).analyze(root_findings, ssl_findings, dr)
    else:
        console.print("[dim]  AI analysis skipped (--no-ai)[/dim]\n")

    # Phase 5 — Frida Scripts
    console.print(Rule("[bold yellow]Phase 5 — Frida Script Generation[/bold yellow]"))
    frida_scripts = FridaScriptGenerator(
        root_findings, ssl_findings, ai_analysis, out, console, SCRIPT_DIR
    ).generate()

    # Phase 6 — Reports
    console.print(Rule("[bold yellow]Phase 6 — Report Generation[/bold yellow]"))
    Reporter(apk, sha256, dr, root_findings, ssl_findings,
             ai_analysis, frida_scripts, out, console).generate()

    # Summary
    console.print()
    console.print(Rule("[bold green]Analysis Complete[/bold green]"))
    _summary(root_findings, ssl_findings, frida_scripts, out)


def _sev_summary(findings):
    if not findings:
        return "[green]None detected[/green]"
    counts = {}
    for f in findings:
        counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"), 0) + 1
    clr = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"dim","INFO":"dim"}
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    return "\n".join(
        f"[{clr.get(s,'white')}]{s}: {counts[s]}[/{clr.get(s,'white')}]"
        for s in order if s in counts
    )


def _summary(root_findings, ssl_findings, frida_scripts, out):
    grid = Table.grid(expand=True, padding=(0,2))
    grid.add_column(ratio=1); grid.add_column(ratio=1)
    grid.add_row(
        Panel(_sev_summary(root_findings), title="[bold red]Root Detection[/bold red]", border_style="red"),
        Panel(_sev_summary(ssl_findings),  title="[bold yellow]SSL Pinning[/bold yellow]",  border_style="yellow"),
    )
    console.print(grid)

    if frida_scripts:
        console.print()
        t = Table(title="[bold green]Generated Frida Scripts[/bold green]",
                  box=box.ROUNDED, border_style="green")
        t.add_column("Script",  style="bold cyan")
        t.add_column("Purpose")
        t.add_column("Path",    style="dim")
        for s in frida_scripts:
            t.add_row(s["name"], s["purpose"], str(s["path"]))
        console.print(t)

    console.print()
    console.print(Panel(
        f"[bold green]Output:[/bold green] {out}\n\n"
        f"[bold yellow]Run master bypass:[/bold yellow]\n"
        f"  [cyan]frida -U -f <package> -l {out}/frida/master_bypass.js --no-pause[/cyan]",
        title="[bold]Next Steps[/bold]", border_style="cyan"
    ))


def main():
    parser = argparse.ArgumentParser(
        description="APKShield-PT — Android Penetration Testing Tool",
        epilog="""
Examples:
  python3 apkshield.py App.apk --no-ai
  python3 apkshield.py App.apk -o ./results
  python3 apkshield.py --check-deps
        """
    )
    parser.add_argument("apk",          nargs="?", help="Path to APK file")
    parser.add_argument("-o","--output", default="./apkshield_output")
    parser.add_argument("--api-key",    help="API key for AI analysis")
    parser.add_argument("--no-ai",      action="store_true", help="Skip AI analysis")
    parser.add_argument("--check-deps", action="store_true")
    parser.add_argument("-v","--verbose",action="store_true")
    args = parser.parse_args()

    print_banner()

    if args.check_deps:
        check_dependencies()
        return

    if not args.apk:
        parser.print_help()
        return

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key and not args.no_ai:
        console.print("[yellow][!] No API key found. Using --no-ai mode.[/yellow]\n")
        args.no_ai = True

    check_dependencies()
    console.print()

    try:
        run(args.apk, args.output, api_key, args.no_ai, args.verbose)
    except KeyboardInterrupt:
        console.print("\n[red][!] Interrupted.[/red]")
    except Exception as e:
        console.print(f"\n[red][!] Error: {e}[/red]")
        if args.verbose:
            import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
