"""
RootDetector — finds every root-detection technique used in an APK.
Covers: binary checks, property checks, app-detection, native checks,
SafetyNet/Play Integrity, build-tag checks, RootBeer/RootTools libraries.
"""

import re
from pathlib import Path
from rich.table import Table
from rich import box


# ── Pattern Database ──────────────────────────────────────────────────────────

ROOT_PATTERNS = [

    # ── Binary / Path Existence Checks ───────────────────────────
    {
        "id": "RD-001", "category": "Binary Check",
        "severity": "HIGH",
        "description": "Checks for 'su' binary on common root paths",
        "patterns": [
            r'["\']\/system\/bin\/su["\']',
            r'["\']\/system\/xbin\/su["\']',
            r'["\']\/sbin\/su["\']',
            r'["\']\/su\/bin\/su["\']',
            r'["\']\/data\/local\/su["\']',
            r'["\']\/data\/local\/bin\/su["\']',
            r'["\']\/data\/local\/xbin\/su["\']',
        ],
        "smali_patterns": [
            r'const-string.*?"/system/bin/su"',
            r'const-string.*?"/system/xbin/su"',
            r'const-string.*?"/sbin/su"',
        ],
        "bypass_type": "root_binary"
    },
    {
        "id": "RD-002", "category": "Binary Check",
        "severity": "HIGH",
        "description": "Checks for busybox binary",
        "patterns": [r'busybox', r'\/system\/xbin\/busybox'],
        "smali_patterns": [r'const-string.*?"busybox"'],
        "bypass_type": "root_binary"
    },
    {
        "id": "RD-003", "category": "App Detection",
        "severity": "HIGH",
        "description": "Detects SuperSU / Magisk / root manager apps",
        "patterns": [
            r'eu\.chainfire\.supersu',
            r'com\.noshufou\.android\.su',
            r'com\.koushikdutta\.superuser',
            r'com\.thirdparty\.superuser',
            r'com\.topjohnwu\.magisk',
            r'io\.github\.huskydg\.magisk',
            r'com\.kingroot\.kinguser',
            r'com\.kingo\.root',
            r'com\.smedialink\.oneclickroot',
            r'com\.zhiqupk\.root\.global',
            r'com\.alephzain\.framaroot',
        ],
        "smali_patterns": [
            r'const-string.*?"com\.topjohnwu\.magisk"',
            r'const-string.*?"eu\.chainfire\.supersu"',
        ],
        "bypass_type": "app_detection"
    },
    {
        "id": "RD-004", "category": "Build Tag Check",
        "severity": "MEDIUM",
        "description": "Checks Build.TAGS for 'test-keys' (custom ROM indicator)",
        "patterns": [
            r'Build\.TAGS',
            r'test-keys',
            r'ro\.build\.tags',
        ],
        "smali_patterns": [
            r'sget-object.*?Landroid/os/Build;->TAGS',
            r'const-string.*?"test-keys"',
        ],
        "bypass_type": "build_props"
    },
    {
        "id": "RD-005", "category": "Build Tag Check",
        "severity": "MEDIUM",
        "description": "Checks ro.build.type / ro.secure system properties",
        "patterns": [
            r'ro\.build\.type',
            r'ro\.secure',
            r'ro\.debuggable',
            r'getprop',
        ],
        "smali_patterns": [
            r'const-string.*?"ro\.secure"',
            r'const-string.*?"ro\.debuggable"',
            r'const-string.*?"ro\.build\.type"',
        ],
        "bypass_type": "build_props"
    },
    {
        "id": "RD-006", "category": "RootBeer Library",
        "severity": "CRITICAL",
        "description": "Uses RootBeer root detection library",
        "patterns": [
            r'com\.scottyab\.rootbeer',
            r'RootBeer',
            r'isRooted\(\)',
            r'isRootedWithBusyBoxCheck',
        ],
        "smali_patterns": [
            r'Lcom/scottyab/rootbeer',
            r'isRooted\(\)Z',
        ],
        "bypass_type": "rootbeer"
    },
    {
        "id": "RD-007", "category": "RootTools Library",
        "severity": "CRITICAL",
        "description": "Uses RootTools library for root detection",
        "patterns": [
            r'com\.stericson\.roottools',
            r'RootTools',
            r'isAccessGiven',
        ],
        "smali_patterns": [r'Lcom/stericson/RootTools'],
        "bypass_type": "roottools"
    },
    {
        "id": "RD-008", "category": "SafetyNet / Play Integrity",
        "severity": "CRITICAL",
        "description": "Uses Google SafetyNet Attestation API",
        "patterns": [
            r'SafetyNet',
            r'com\.google\.android\.gms\.safetynet',
            r'SafetyNetApi',
            r'attest\(',
            r'SafetyNetClient',
        ],
        "smali_patterns": [
            r'Lcom/google/android/gms/safetynet',
            r'SafetyNetApi',
        ],
        "bypass_type": "safetynet"
    },
    {
        "id": "RD-009", "category": "Play Integrity API",
        "severity": "CRITICAL",
        "description": "Uses Play Integrity API (successor to SafetyNet)",
        "patterns": [
            r'com\.google\.android\.play\.core\.integrity',
            r'IntegrityManager',
            r'IntegrityTokenRequest',
            r'requestIntegrityToken',
        ],
        "smali_patterns": [r'Lcom/google/android/play/core/integrity'],
        "bypass_type": "play_integrity"
    },
    {
        "id": "RD-010", "category": "Native Root Check",
        "severity": "HIGH",
        "description": "Native library (JNI) performs root detection",
        "patterns": [
            r'System\.loadLibrary',
            r'native.*?isRooted',
            r'native.*?detectRoot',
            r'native.*?checkRoot',
        ],
        "smali_patterns": [
            r'invoke-static.*?System;->loadLibrary',
            r'\.method.*?native.*?isRooted',
            r'\.method.*?native.*?checkRoot',
        ],
        "bypass_type": "native_root"
    },
    {
        "id": "RD-011", "category": "Dangerous Props / Paths",
        "severity": "MEDIUM",
        "description": "Checks for /data/local/tmp or writable system paths",
        "patterns": [
            r'\/data\/local\/tmp',
            r'\/system\/bin\/failsafe',
            r'\/system\/sd\/xbin',
            r'canWrite.*?\/system',
        ],
        "smali_patterns": [
            r'const-string.*?"/data/local/tmp"',
        ],
        "bypass_type": "root_paths"
    },
    {
        "id": "RD-012", "category": "Frida / Xposed Detection",
        "severity": "CRITICAL",
        "description": "Actively detects Frida or Xposed framework",
        "patterns": [
            r'frida',
            r'XposedBridge',
            r'de\.robv\.android\.xposed',
            r'substrate',
            r'grindr.*?frida',
            r'fridagadget',
            r'lspatch',
        ],
        "smali_patterns": [
            r'const-string.*?"frida"',
            r'const-string.*?"XposedBridge"',
            r'Lde/robv/android/xposed',
        ],
        "bypass_type": "frida_detection"
    },
    {
        "id": "RD-013", "category": "Emulator Detection",
        "severity": "MEDIUM",
        "description": "Checks for emulator / AVD environment",
        "patterns": [
            r'Build\.FINGERPRINT.*?generic',
            r'Build\.MODEL.*?Emulator',
            r'Build\.MANUFACTURER.*?Genymotion',
            r'isEmulator',
            r'GOLDFISH',
            r'ro\.hardware.*?goldfish',
        ],
        "smali_patterns": [
            r'const-string.*?"generic"',
            r'sget-object.*?Build;->FINGERPRINT',
        ],
        "bypass_type": "emulator"
    },
    {
        "id": "RD-014", "category": "File Integrity / Tampering",
        "severity": "HIGH",
        "description": "Checks APK signature or file hash for tampering",
        "patterns": [
            r'getSignatures\(\)',
            r'GET_SIGNATURES',
            r'PackageInfo.*?signatures',
            r'Signature.*?toCharsString',
            r'MessageDigest.*?getInstance.*?SHA',
        ],
        "smali_patterns": [
            r'GET_SIGNATURES',
            r'getSignatures',
            r'Landroid/content/pm/Signature',
        ],
        "bypass_type": "signature"
    },
]


class RootDetector:
    def __init__(self, decompile_result: dict, console, verbose: bool = False):
        self.dr      = decompile_result
        self.console = console
        self.verbose = verbose

    def analyze(self) -> list:
        findings = []

        files_smali = self.dr.get("all_smali", [])
        files_java  = self.dr.get("all_java", [])

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        total = len(files_smali) + len(files_java)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=self.console) as prog:
            t = prog.add_task("[cyan]Scanning for root detection patterns…", total=total)

            for f in files_smali:
                self._scan_file(f, "smali", findings)
                prog.advance(t)

            for f in files_java:
                self._scan_file(f, "java", findings)
                prog.advance(t)

        # De-duplicate by pattern id + file
        seen = set()
        unique = []
        for f in findings:
            key = (f["id"], str(f["file"])[:60])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self._print_results(unique)
        return unique

    # ── private ──────────────────────────────────────────────────
    def _scan_file(self, filepath: Path, mode: str, findings: list):
        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            return

        for pattern in ROOT_PATTERNS:
            pats = pattern["smali_patterns"] if mode == "smali" else pattern["patterns"]
            for p in pats:
                matches = re.findall(p, content, re.IGNORECASE)
                if matches:
                    lines = self._get_context(content, p)
                    findings.append({
                        **{k: v for k, v in pattern.items() if k not in ("patterns","smali_patterns")},
                        "file":    filepath,
                        "mode":    mode,
                        "matches": matches[:3],
                        "context": lines[:2],
                    })
                    break   # one match per pattern per file is enough

    def _get_context(self, content: str, pattern: str) -> list:
        lines = content.splitlines()
        ctx = []
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.IGNORECASE):
                start = max(0, i - 1)
                end   = min(len(lines), i + 2)
                ctx.append("\n".join(lines[start:end]).strip())
                if len(ctx) >= 2:
                    break
        return ctx

    def _print_results(self, findings: list):
        if not findings:
            self.console.print("  [green]No root detection techniques found.[/green]\n")
            return

        # Group by category
        cats = {}
        for f in findings:
            cats.setdefault(f["category"], []).append(f)

        t = Table(box=box.ROUNDED, border_style="red", show_header=True,
                  title=f"[bold red]Root Detection — {len(findings)} finding(s)[/bold red]")
        t.add_column("ID",        style="bold", width=8)
        t.add_column("Severity",  width=10)
        t.add_column("Category",  width=22)
        t.add_column("Description")
        t.add_column("Bypass",    width=18)

        sev_color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"dim","INFO":"dim"}
        for f in sorted(findings, key=lambda x:
                        ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])
                        if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
            c = sev_color.get(f["severity"], "white")
            t.add_row(
                f["id"],
                f"[{c}]{f['severity']}[/{c}]",
                f["category"],
                f["description"],
                f"[cyan]{f['bypass_type']}[/cyan]",
            )
        self.console.print(t)
        self.console.print()
