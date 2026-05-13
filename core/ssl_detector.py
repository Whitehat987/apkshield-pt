"""
SSLDetector — identifies every SSL/TLS pinning mechanism in an APK.
Covers: OkHttp, Retrofit, Volley, custom TrustManager, Conscrypt,
network_security_config.xml, WebView, Cronet, gRPC, certificate transparency.
"""

import re
from pathlib import Path
from rich.table import Table
from rich import box


# ── Pattern Database ──────────────────────────────────────────────────────────

SSL_PATTERNS = [

    # ── OkHttp Certificate Pinner ─────────────────────────────────
    {
        "id": "SSL-001", "category": "OkHttp CertificatePinner",
        "severity": "HIGH",
        "description": "OkHttp CertificatePinner with pinned SHA-256 hashes",
        "patterns": [
            r'CertificatePinner',
            r'\.add\(.*?sha256/',
            r'okhttp.*?pin',
            r'CertificatePinner\.Builder',
        ],
        "smali_patterns": [
            r'Lokhttp3/CertificatePinner',
            r'const-string.*?"sha256/',
        ],
        "bypass_type": "okhttp_pinner",
        "library": "OkHttp"
    },

    # ── Custom TrustManager ───────────────────────────────────────
    {
        "id": "SSL-002", "category": "Custom TrustManager",
        "severity": "HIGH",
        "description": "Custom X509TrustManager implementation",
        "patterns": [
            r'X509TrustManager',
            r'checkServerTrusted',
            r'checkClientTrusted',
            r'TrustManager\[\]',
        ],
        "smali_patterns": [
            r'Ljavax/net/ssl/X509TrustManager',
            r'checkServerTrusted',
        ],
        "bypass_type": "trust_manager",
        "library": "javax.net.ssl"
    },

    # ── SSLContext / HostnameVerifier ─────────────────────────────
    {
        "id": "SSL-003", "category": "Custom HostnameVerifier",
        "severity": "HIGH",
        "description": "Custom HostnameVerifier (may accept all hosts)",
        "patterns": [
            r'HostnameVerifier',
            r'verify\(.*?String.*?SSLSession',
            r'AllowAllHostnameVerifier',
            r'ALLOW_ALL_HOSTNAME_VERIFIER',
        ],
        "smali_patterns": [
            r'Ljavax/net/ssl/HostnameVerifier',
            r'AllowAllHostnameVerifier',
        ],
        "bypass_type": "hostname_verifier",
        "library": "javax.net.ssl"
    },

    # ── Network Security Config ───────────────────────────────────
    {
        "id": "SSL-004", "category": "Network Security Config",
        "severity": "MEDIUM",
        "description": "Android Network Security Config with certificate pins",
        "patterns": [
            r'<pin-set',
            r'<pin digest=',
            r'network_security_config',
            r'android:networkSecurityConfig',
        ],
        "smali_patterns": [
            r'network_security_config',
        ],
        "bypass_type": "nsc",
        "library": "Android NSC"
    },

    # ── Conscrypt / Cronet Pinning ────────────────────────────────
    {
        "id": "SSL-005", "category": "Conscrypt / Cronet Pinning",
        "severity": "HIGH",
        "description": "Conscrypt or Cronet network stack with pinning",
        "patterns": [
            r'Conscrypt',
            r'org\.chromium\.net\.CronetEngine',
            r'addPublicKeyHashes',
            r'CronetEngine\.Builder',
        ],
        "smali_patterns": [
            r'Lorg/conscrypt',
            r'Lorg/chromium/net/CronetEngine',
        ],
        "bypass_type": "conscrypt",
        "library": "Conscrypt/Cronet"
    },

    # ── Retrofit / HttpsURLConnection ─────────────────────────────
    {
        "id": "SSL-006", "category": "HttpsURLConnection Pinning",
        "severity": "MEDIUM",
        "description": "HttpsURLConnection with custom SSL socket factory",
        "patterns": [
            r'HttpsURLConnection',
            r'setSSLSocketFactory',
            r'SSLSocketFactory',
            r'SSLContext\.getInstance',
        ],
        "smali_patterns": [
            r'Ljavax/net/ssl/SSLContext',
            r'setSSLSocketFactory',
            r'Ljavax/net/ssl/SSLSocketFactory',
        ],
        "bypass_type": "https_url_connection",
        "library": "java.net"
    },

    # ── Appcelerator Titanium Pinning ─────────────────────────────
    {
        "id": "SSL-007", "category": "Appcelerator / Titanium",
        "severity": "MEDIUM",
        "description": "Appcelerator Titanium SSL pinning",
        "patterns": [
            r'ti\.network',
            r'Titanium.*?ssl',
            r'appcelerator',
        ],
        "smali_patterns": [r'Lti/network'],
        "bypass_type": "titanium",
        "library": "Appcelerator"
    },

    # ── Volley Pinning ────────────────────────────────────────────
    {
        "id": "SSL-008", "category": "Volley HurlStack",
        "severity": "MEDIUM",
        "description": "Volley HurlStack with custom SSL configuration",
        "patterns": [
            r'HurlStack',
            r'com\.android\.volley',
            r'Volley.*?ssl',
        ],
        "smali_patterns": [r'Lcom/android/volley/toolbox/HurlStack'],
        "bypass_type": "volley",
        "library": "Volley"
    },

    # ── gRPC / Envoy Pinning ──────────────────────────────────────
    {
        "id": "SSL-009", "category": "gRPC TLS Pinning",
        "severity": "HIGH",
        "description": "gRPC channel with custom TLS credentials / pinning",
        "patterns": [
            r'io\.grpc',
            r'TlsChannelCredentials',
            r'GrpcSslContexts',
            r'SslContext',
        ],
        "smali_patterns": [r'Lio/grpc', r'TlsChannelCredentials'],
        "bypass_type": "grpc",
        "library": "gRPC"
    },

    # ── Native SSL Pinning ────────────────────────────────────────
    {
        "id": "SSL-010", "category": "Native SSL Pinning",
        "severity": "CRITICAL",
        "description": "Native library (JNI) implements SSL pinning",
        "patterns": [
            r'native.*?ssl.*?pin',
            r'native.*?verify.*?cert',
            r'SSL_CTX_set_verify',
            r'curl_easy_setopt.*?CURLOPT_PINNEDPUBLICKEY',
        ],
        "smali_patterns": [
            r'\.method.*?native.*?ssl',
            r'invoke-static.*?loadLibrary',
        ],
        "bypass_type": "native_ssl",
        "library": "Native/JNI"
    },

    # ── Firebase / Play Services TLS ─────────────────────────────
    {
        "id": "SSL-011", "category": "Firebase / GMS TLS",
        "severity": "LOW",
        "description": "Firebase or Google Play Services TLS configuration",
        "patterns": [
            r'com\.google\.firebase',
            r'FirebaseOptions.*?ssl',
            r'com\.google\.android\.gms.*?ssl',
        ],
        "smali_patterns": [r'Lcom/google/firebase'],
        "bypass_type": "firebase",
        "library": "Firebase"
    },

    # ── Certificate Transparency ──────────────────────────────────
    {
        "id": "SSL-012", "category": "Certificate Transparency",
        "severity": "MEDIUM",
        "description": "Certificate Transparency enforcement (CertificateTransparencyInterceptor)",
        "patterns": [
            r'CertificateTransparency',
            r'certificatetransparency',
            r'CTLogInfo',
        ],
        "smali_patterns": [r'CertificateTransparency'],
        "bypass_type": "cert_transparency",
        "library": "certificate-transparency-android"
    },

    # ── Public Key Pinning (HPKP style) ──────────────────────────
    {
        "id": "SSL-013", "category": "Public Key Pinning",
        "severity": "HIGH",
        "description": "Direct public key hash pinning (SubjectPublicKeyInfo)",
        "patterns": [
            r'getPublicKey\(\)',
            r'SubjectPublicKeyInfo',
            r'MessageDigest.*?SHA.*?PublicKey',
            r'publicKeyHash',
        ],
        "smali_patterns": [
            r'getPublicKey\(\)',
            r'SubjectPublicKeyInfo',
        ],
        "bypass_type": "public_key_pin",
        "library": "Custom"
    },

    # ── WebView SSL override ──────────────────────────────────────
    {
        "id": "SSL-014", "category": "WebView SSL Handling",
        "severity": "MEDIUM",
        "description": "WebViewClient overrides onReceivedSslError (may pin or block)",
        "patterns": [
            r'onReceivedSslError',
            r'WebViewClient',
            r'handler\.proceed\(\)',
            r'SslError',
        ],
        "smali_patterns": [
            r'onReceivedSslError',
            r'Landroid/webkit/WebViewClient',
        ],
        "bypass_type": "webview_ssl",
        "library": "WebView"
    },

    # ── TrustKit ─────────────────────────────────────────────────
    {
        "id": "SSL-015", "category": "TrustKit Pinning",
        "severity": "HIGH",
        "description": "TrustKit iOS/Android SSL pinning framework",
        "patterns": [
            r'com\.datatheorem\.android\.trustkit',
            r'TrustKit',
            r'TrustKitConfiguration',
        ],
        "smali_patterns": [r'Lcom/datatheorem/android/trustkit'],
        "bypass_type": "trustkit",
        "library": "TrustKit"
    },
]


class SSLDetector:
    def __init__(self, decompile_result: dict, console, verbose: bool = False):
        self.dr      = decompile_result
        self.console = console
        self.verbose = verbose

    def analyze(self) -> list:
        findings = []
        files = self.dr.get("all_smali", []) + self.dr.get("all_java", [])

        # Also check network_security_config.xml
        if self.dr.get("net_config"):
            self._scan_xml(self.dr["net_config"], findings)

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=self.console) as prog:
            t = prog.add_task("[cyan]Scanning for SSL pinning patterns…", total=len(files))
            for f in files:
                mode = "smali" if str(f).endswith(".smali") else "java"
                self._scan_file(f, mode, findings)
                prog.advance(t)

        # De-duplicate
        seen, unique = set(), []
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

        for pattern in SSL_PATTERNS:
            pats = pattern["smali_patterns"] if mode == "smali" else pattern["patterns"]
            for p in pats:
                if re.search(p, content, re.IGNORECASE):
                    findings.append({
                        **{k: v for k, v in pattern.items()
                           if k not in ("patterns", "smali_patterns")},
                        "file": filepath,
                        "mode": mode,
                    })
                    break

    def _scan_xml(self, filepath: Path, findings: list):
        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            return
        for pattern in SSL_PATTERNS:
            for p in pattern["patterns"]:
                if re.search(p, content, re.IGNORECASE):
                    findings.append({
                        **{k: v for k, v in pattern.items()
                           if k not in ("patterns", "smali_patterns")},
                        "file": filepath,
                        "mode": "xml",
                    })
                    break

    def _print_results(self, findings: list):
        if not findings:
            self.console.print("  [green]No SSL pinning techniques found.[/green]\n")
            return

        t = Table(box=box.ROUNDED, border_style="yellow", show_header=True,
                  title=f"[bold yellow]SSL Pinning — {len(findings)} finding(s)[/bold yellow]")
        t.add_column("ID",       style="bold", width=8)
        t.add_column("Severity", width=10)
        t.add_column("Category", width=26)
        t.add_column("Library",  width=16)
        t.add_column("Bypass")

        sev_color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"dim"}
        for f in sorted(findings, key=lambda x:
                        ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])
                        if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
            c = sev_color.get(f["severity"], "white")
            t.add_row(
                f["id"],
                f"[{c}]{f['severity']}[/{c}]",
                f["category"],
                f.get("library", ""),
                f"[cyan]{f['bypass_type']}[/cyan]",
            )
        self.console.print(t)
        self.console.print()
