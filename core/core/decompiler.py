"""
Decompiler — wraps apktool + jadx for APK decompilation.
"""

import subprocess, shutil, time
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn


class Decompiler:
    def __init__(self, apk: Path, out: Path, console, verbose: bool = False):
        self.apk     = apk
        self.out     = out
        self.console = console
        self.verbose = verbose

    # ── public ────────────────────────────────────────────────────
    def run(self) -> dict:
        result = {
            "smali_dir":  None,
            "java_dir":   None,
            "manifest":   None,
            "res_dir":    None,
            "lib_dir":    None,
            "net_config": None,
            "all_smali":  [],
            "all_java":   [],
        }

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      console=self.console) as prog:

            # apktool
            smali_out = self.out / "apktool_out"
            if not smali_out.exists():
                t = prog.add_task("[cyan]Running apktool (smali + resources)…")
                ok = self._run_apktool(smali_out)
                prog.update(t, description=
                    "[green]✔ apktool done[/green]" if ok else
                    "[red]✘ apktool failed[/red]")
            else:
                self.console.print("[dim]  apktool output already exists, skipping.[/dim]")

            if smali_out.exists():
                result["smali_dir"] = smali_out / "smali"
                result["res_dir"]   = smali_out / "res"
                result["lib_dir"]   = smali_out / "lib"
                mf = smali_out / "AndroidManifest.xml"
                result["manifest"]  = mf if mf.exists() else None
                result["all_smali"] = list(smali_out.rglob("*.smali"))
                # network_security_config
                for nc in smali_out.rglob("network_security_config.xml"):
                    result["net_config"] = nc
                    break

            # jadx
            java_out = self.out / "jadx_out"
            if not java_out.exists():
                t = prog.add_task("[cyan]Running jadx (Java decompilation)…")
                ok = self._run_jadx(java_out)
                prog.update(t, description=
                    "[green]✔ jadx done[/green]" if ok else
                    "[yellow]⚠ jadx failed (smali-only mode)[/yellow]")
            else:
                self.console.print("[dim]  jadx output already exists, skipping.[/dim]")

            if java_out.exists():
                result["java_dir"]  = java_out
                result["all_java"]  = list(java_out.rglob("*.java"))

        self._print_summary(result)
        return result

    # ── private ───────────────────────────────────────────────────
    def _run_apktool(self, smali_out: Path) -> bool:
        if not shutil.which("apktool"):
            self.console.print(
                "[yellow]  [!] apktool not found. Install: sudo apt install apktool[/yellow]")
            return False
        cmd = ["apktool", "d", str(self.apk), "-o", str(smali_out), "-f"]
        return self._exec(cmd, "apktool")

    def _run_jadx(self, java_out: Path) -> bool:
        jadx = shutil.which("jadx") or shutil.which("jadx-gui")
        if not jadx:
            self.console.print(
                "[yellow]  [!] jadx not found. Install: sudo apt install jadx[/yellow]")
            return False
        cmd = [jadx, "-d", str(java_out), str(self.apk),
               "--no-res",         # resources already from apktool
               "--show-bad-code",
               "--threads-count", "4"]
        return self._exec(cmd, "jadx")

    def _exec(self, cmd: list, name: str) -> bool:
        try:
            r = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=300
            )
            if self.verbose:
                self.console.print(f"[dim]{r.stdout[-2000:]}[/dim]")
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            self.console.print(f"[red]  [!] {name} timed out[/red]")
            return False
        except Exception as e:
            self.console.print(f"[red]  [!] {name} error: {e}[/red]")
            return False

    def _print_summary(self, result: dict):
        smali_count = len(result["all_smali"])
        java_count  = len(result["all_java"])
        self.console.print(
            f"  [green]Smali files:[/green] {smali_count}   "
            f"[green]Java files:[/green] {java_count}   "
            f"[green]Manifest:[/green] {'✔' if result['manifest'] else '✘'}   "
            f"[green]NetConfig:[/green] {'✔' if result['net_config'] else '✘'}"
        )
        self.console.print()
