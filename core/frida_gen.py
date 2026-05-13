"""
FridaScriptGenerator — assembles complete, targeted Frida bypass scripts
from root/SSL findings. Produces:
  - master_bypass.js   (all-in-one)
  - root_bypass.js     (root detection only)
  - ssl_bypass.js      (SSL pinning only)
  - safetynet_bypass.js
  - frida_detection_bypass.js
  - custom_bypass.js   (AI hooks)
"""

from pathlib import Path
from rich.syntax import Syntax

_HEADER = """\
/**
 * APKShield-PT — Generated Frida Bypass Script
 * For authorized penetration testing only.
 * Target: {target}
 * Generated: {timestamp}
 */

'use strict';

function log(tag, msg) {{
    console.log('[APKShield][' + tag + '] ' + msg);
}}
"""

BYPASS_ROOTBEER = """\
function bypass_rootbeer() {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        ['isRooted','isRootedWithoutBusyBoxCheck','detectRootManagementApps',
         'detectPotentiallyDangerousApps','checkForBinary','detectTestKeys',
         'checkForDangerousProps','checkForRWPaths','detectRootCloakingApps',
         'checkSuExists','checkForMagiskBinary'].forEach(function(m) {
            try {
                RootBeer[m].overload().implementation = function() {
                    log('ROOT', 'RootBeer.' + m + '() => false');
                    return false;
                };
            } catch(e) {}
        });
        log('ROOT', 'RootBeer fully bypassed');
    } catch(e) { log('ROOT', 'RootBeer not present: ' + e); }
}
"""

BYPASS_ROOT_BINARY = """\
function bypass_file_checks() {
    try {
        var File = Java.use('java.io.File');
        var SU_PATHS = [
            '/system/bin/su','/system/xbin/su','/sbin/su','/su/bin/su',
            '/data/local/su','/data/local/bin/su','/data/local/xbin/su',
            '/system/bin/failsafe/su','/system/sd/xbin/su',
            '/system/app/Superuser.apk','/system/app/SuperSU.apk',
            '/data/adb/magisk','/sbin/.magisk','/dev/.magisk.unblock',
        ];
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < SU_PATHS.length; i++) {
                if (path === SU_PATHS[i]) { log('ROOT', 'File.exists() blocked: ' + path); return false; }
            }
            return this.exists();
        };
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
                log('ROOT', 'Runtime.exec() blocked: ' + cmd);
                return this.exec('echo blocked');
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
            for (var i = 0; i < cmds.length; i++) {
                if (cmds[i] && cmds[i].indexOf('su') !== -1) {
                    log('ROOT', 'Runtime.exec[] blocked: ' + cmds[i]);
                    return this.exec(['echo','blocked']);
                }
            }
            return this.exec(cmds);
        };
        log('ROOT', 'File existence & Runtime.exec bypassed');
    } catch(e) { log('ROOT', 'bypass_file_checks error: ' + e); }
}
"""

BYPASS_BUILD_PROPS = """\
function bypass_build_props() {
    try {
        var Build = Java.use('android.os.Build');
        try { Build.TAGS.value = 'release-keys'; } catch(e) {}
        try { Build.TYPE.value = 'user'; }         catch(e) {}
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (key === 'ro.build.tags') return 'release-keys';
            if (key === 'ro.build.type') return 'user';
            if (key === 'ro.secure')     return '1';
            if (key === 'ro.debuggable') return '0';
            return this.get(key);
        };
        SystemProperties.get.overload('java.lang.String','java.lang.String')
            .implementation = function(key, def) {
            if (key === 'ro.build.tags') return 'release-keys';
            if (key === 'ro.secure')     return '1';
            if (key === 'ro.debuggable') return '0';
            return this.get(key, def);
        };
        log('ROOT', 'Build properties bypassed');
    } catch(e) { log('ROOT', 'bypass_build_props error: ' + e); }
}
"""

BYPASS_PACKAGE_MANAGER = """\
function bypass_package_manager() {
    try {
        var BLOCKED = [
            'com.topjohnwu.magisk','io.github.huskydg.magisk',
            'eu.chainfire.supersu','com.noshufou.android.su',
            'com.koushikdutta.superuser','com.thirdparty.superuser',
            'com.kingroot.kinguser','com.kingo.root','com.alephzain.framaroot',
            'de.robv.android.xposed.installer','org.meowcat.edxposed.manager',
            'io.github.lsposed.manager',
        ];
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getPackageInfo.overload('java.lang.String','int')
            .implementation = function(pkg, flags) {
            for (var i = 0; i < BLOCKED.length; i++) {
                if (BLOCKED[i] === pkg) {
                    log('ROOT', 'Blocked getPackageInfo: ' + pkg);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
        log('ROOT', 'Package manager bypass installed');
    } catch(e) { log('ROOT', 'bypass_package_manager error: ' + e); }
}
"""

BYPASS_SAFETYNET = """\
function bypass_safetynet() {
    try {
        var JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getBoolean.implementation = function(key) {
            if (key === 'basicIntegrity' || key === 'ctsProfileMatch') {
                log('SAFETYNET', 'Spoofing ' + key + ' => true');
                return true;
            }
            return this.getBoolean(key);
        };
    } catch(e) { log('SAFETYNET', 'error: ' + e); }
    log('ROOT', 'SafetyNet bypass hooks installed');
}
"""

BYPASS_FRIDA_DETECTION = """\
function bypass_frida_detection() {
    try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        var FileReader     = Java.use('java.io.FileReader');

        FileReader.$init.overload('java.lang.String').implementation = function(path) {
            if (path && path.indexOf('/proc/') !== -1 && path.indexOf('maps') !== -1) {
                log('FRIDA', 'Intercepting /proc maps: ' + path);
            }
            return this.$init(path);
        };

        var readLineOrig = BufferedReader.readLine.overload();
        readLineOrig.implementation = function() {
            var line = readLineOrig.call(this);
            if (line !== null && (
                line.indexOf('frida')       !== -1 ||
                line.indexOf('gum-js-loop') !== -1 ||
                line.indexOf('gmain')       !== -1 ||
                line.indexOf('linjector')   !== -1
            )) {
                log('FRIDA', 'Hiding frida entry from /proc/maps');
                return readLineOrig.call(this);
            }
            return line;
        };

        try {
            var Socket = Java.use('java.net.Socket');
            Socket.$init.overload('java.lang.String','int').implementation = function(host, port) {
                if (port === 27042 || port === 27043) {
                    log('FRIDA', 'Blocked port probe: ' + port);
                    throw Java.use('java.net.ConnectException').$new('Connection refused');
                }
                return this.$init(host, port);
            };
        } catch(e) {}

        log('ROOT', 'Anti-Frida detection bypass installed');
    } catch(e) { log('ROOT', 'bypass_frida_detection error: ' + e); }
}
"""

BYPASS_TRUST_MANAGER = """\
function bypass_trust_manager() {
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext        = Java.use('javax.net.ssl.SSLContext');

        var TrustAll = Java.registerClass({
            name: 'apkshield.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: {
                    returnType: 'void',
                    argumentTypes: ['[Ljava.security.cert.X509Certificate;','java.lang.String'],
                    implementation: function(chain, authType) {}
                },
                checkServerTrusted: {
                    returnType: 'void',
                    argumentTypes: ['[Ljava.security.cert.X509Certificate;','java.lang.String'],
                    implementation: function(chain, authType) {}
                },
                getAcceptedIssuers: {
                    returnType: '[Ljava.security.cert.X509Certificate;',
                    argumentTypes: [],
                    implementation: function() {
                        return Java.array('java.security.cert.X509Certificate', []);
                    }
                }
            }
        });

        var TrustAllArr = Java.array('javax.net.ssl.TrustManager', [TrustAll.$new()]);
        var sslCtx = SSLContext.getInstance('TLS');
        sslCtx.init(null, TrustAllArr, null);
        SSLContext.getDefault.implementation = function() { return sslCtx; };

        log('SSL', 'Universal TrustManager bypass active');
    } catch(e) { log('SSL', 'TrustManager bypass error: ' + e); }
}
"""

BYPASS_OKHTTP = """\
function bypass_okhttp() {
    try {
        var CP3 = Java.use('okhttp3.CertificatePinner');
        CP3.check.overload('java.lang.String','java.util.List')
            .implementation = function(h, c) { log('SSL', 'OkHttp3 check(List) bypassed: ' + h); };
        CP3.check.overload('java.lang.String','[Ljava.security.cert.Certificate;')
            .implementation = function(h, c) { log('SSL', 'OkHttp3 check(array) bypassed: ' + h); };
    } catch(e) { log('SSL', 'OkHttp3 not found: ' + e); }
    try {
        var CP2 = Java.use('com.squareup.okhttp.CertificatePinner');
        CP2.check.overload('java.lang.String','[Ljava.security.cert.Certificate;')
            .implementation = function(h, c) { log('SSL', 'OkHttp2 bypassed: ' + h); };
    } catch(e) {}
    log('SSL', 'OkHttp certificate pinning bypassed');
}
"""

BYPASS_HOSTNAME_VERIFIER = """\
function bypass_hostname_verifier() {
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAll = Java.registerClass({
            name: 'apkshield.AllowAllVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: {
                    returnType: 'boolean',
                    argumentTypes: ['java.lang.String','javax.net.ssl.SSLSession'],
                    implementation: function(hostname, session) {
                        log('SSL', 'HostnameVerifier => true: ' + hostname);
                        return true;
                    }
                }
            }
        });
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(v) {
            this.setDefaultHostnameVerifier(AllowAll.$new());
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function(v) {
            this.setHostnameVerifier(AllowAll.$new());
        };
        log('SSL', 'HostnameVerifier bypass active');
    } catch(e) { log('SSL', 'HostnameVerifier error: ' + e); }
}
"""

BYPASS_NSC = """\
function bypass_nsc() {
    try {
        var NSC = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSC.checkPins.implementation = function(chain) {
            log('SSL', 'NSC checkPins() bypassed');
        };
    } catch(e) { log('SSL', 'NSC hook fallback: ' + e); }
    log('SSL', 'NSC bypass attempted');
}
"""

BYPASS_WEBVIEW = """\
function bypass_webview_ssl() {
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            log('SSL', 'WebViewClient.onReceivedSslError() => proceed()');
            handler.proceed();
        };
        log('SSL', 'WebView SSL bypass active');
    } catch(e) { log('SSL', 'WebView hook error: ' + e); }
}
"""

BYPASS_TRUSTKIT = """\
function bypass_trustkit() {
    try {
        var PTM = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        PTM.checkServerTrusted.implementation = function(chain, authType) {
            log('SSL', 'TrustKit checkServerTrusted bypassed');
        };
    } catch(e) {}
    try {
        var OKH = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        OKH.verify.overload('java.lang.String','javax.net.ssl.SSLSession')
            .implementation = function(h, s) { log('SSL', 'TrustKit verify => true: ' + h); return true; };
    } catch(e) {}
    log('SSL', 'TrustKit bypass active');
}
"""

BYPASS_MAP = {
    "rootbeer":             ("bypass_rootbeer",          BYPASS_ROOTBEER),
    "roottools":            ("bypass_rootbeer",          BYPASS_ROOTBEER),
    "root_binary":          ("bypass_file_checks",       BYPASS_ROOT_BINARY),
    "root_paths":           ("bypass_file_checks",       BYPASS_ROOT_BINARY),
    "app_detection":        ("bypass_package_manager",   BYPASS_PACKAGE_MANAGER),
    "signature":            ("bypass_package_manager",   BYPASS_PACKAGE_MANAGER),
    "build_props":          ("bypass_build_props",       BYPASS_BUILD_PROPS),
    "emulator":             ("bypass_build_props",       BYPASS_BUILD_PROPS),
    "safetynet":            ("bypass_safetynet",         BYPASS_SAFETYNET),
    "play_integrity":       ("bypass_safetynet",         BYPASS_SAFETYNET),
    "frida_detection":      ("bypass_frida_detection",   BYPASS_FRIDA_DETECTION),
    "native_root":          (None, "// Native root check detected — use Magisk Hide or patch the native lib\n"),
    "trust_manager":        ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "okhttp_pinner":        ("bypass_okhttp",            BYPASS_OKHTTP),
    "hostname_verifier":    ("bypass_hostname_verifier", BYPASS_HOSTNAME_VERIFIER),
    "nsc":                  ("bypass_nsc",               BYPASS_NSC),
    "conscrypt":            ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "https_url_connection": ("bypass_hostname_verifier", BYPASS_HOSTNAME_VERIFIER),
    "volley":               ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "grpc":                 ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "firebase":             ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "cert_transparency":    ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "public_key_pin":       ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
    "native_ssl":           (None, "// Native SSL pinning — patch native library or use Frida Interceptor\n"),
    "webview_ssl":          ("bypass_webview_ssl",       BYPASS_WEBVIEW),
    "trustkit":             ("bypass_trustkit",          BYPASS_TRUSTKIT),
    "titanium":             ("bypass_trust_manager",     BYPASS_TRUST_MANAGER),
}


class FridaScriptGenerator:
    def __init__(self, root_findings, ssl_findings, ai_analysis,
                 out: Path, console, script_dir: Path):
        self.root_findings = root_findings
        self.ssl_findings  = ssl_findings
        self.ai_analysis   = ai_analysis
        self.out           = out / "frida"
        self.console       = console
        self.script_dir    = script_dir
        self.out.mkdir(parents=True, exist_ok=True)

    def generate(self) -> list:
        from datetime import datetime
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rbt  = list({f["bypass_type"] for f in self.root_findings})
        sbt  = list({f["bypass_type"] for f in self.ssl_findings})
        ch   = self.ai_analysis.get("custom_hooks", [])
        scripts = []

        if rbt:
            self._write(self._build(ts, rbt, "Root Detection Bypass"), "root_bypass.js")
            scripts.append({"name":"root_bypass.js","purpose":"Root detection bypass","path":self.out/"root_bypass.js"})

        if sbt:
            self._write(self._build(ts, sbt, "SSL Pinning Bypass"), "ssl_bypass.js")
            scripts.append({"name":"ssl_bypass.js","purpose":"SSL/TLS pinning bypass","path":self.out/"ssl_bypass.js"})

        if any(f["bypass_type"] in ("safetynet","play_integrity") for f in self.root_findings):
            self._write(self._build(ts, ["safetynet"], "SafetyNet Bypass"), "safetynet_bypass.js")
            scripts.append({"name":"safetynet_bypass.js","purpose":"SafetyNet / Play Integrity bypass","path":self.out/"safetynet_bypass.js"})

        if any(f["bypass_type"] == "frida_detection" for f in self.root_findings):
            self._write(self._build(ts, ["frida_detection"], "Anti-Frida Bypass"), "frida_detection_bypass.js")
            scripts.append({"name":"frida_detection_bypass.js","purpose":"Anti-Frida detection bypass","path":self.out/"frida_detection_bypass.js"})

        if ch:
            self._write(self._build_custom(ts, ch), "custom_bypass.js")
            scripts.append({"name":"custom_bypass.js","purpose":"AI-identified custom hooks","path":self.out/"custom_bypass.js"})

        master = self._build_master(ts, list(set(rbt + sbt)), ch)
        self._write(master, "master_bypass.js")
        scripts.append({"name":"master_bypass.js","purpose":"All-in-one master bypass","path":self.out/"master_bypass.js"})

        self.console.print(f"  [green]✔ {len(scripts)} Frida script(s) → {self.out}[/green]\n")
        self.console.print(Syntax(master[:700] + "\n// ...", "javascript", theme="monokai", line_numbers=True))
        return scripts

    def _collect(self, bypass_types):
        seen, blocks, calls = set(), [], []
        for bt in bypass_types:
            if bt not in BYPASS_MAP: continue
            fn, snippet = BYPASS_MAP[bt]
            if fn and fn not in seen:
                seen.add(fn); blocks.append(snippet); calls.append(f"    {fn}();")
        return blocks, calls

    def _build(self, ts, bypass_types, title) -> str:
        blocks, calls = self._collect(bypass_types)
        return (_HEADER.format(target=title, timestamp=ts)
                + "\n".join(blocks)
                + f"\nJava.perform(function() {{\n    log('MAIN', '{title}');\n"
                + "\n".join(calls) + "\n    log('MAIN', 'Done');\n}});\n")

    def _build_custom(self, ts, hooks) -> str:
        blocks, calls = [], []
        for i, h in enumerate(hooks):
            fn = f"custom_hook_{i+1}"; s = h.get("frida_snippet","")
            if not s: continue
            blocks.append(f"function {fn}() {{\n  try {{ {s} }} catch(e) {{ log('CUSTOM', '{fn}: ' + e); }}\n}}\n")
            calls.append(f"    {fn}();  // {h.get('purpose','')}")
        return (_HEADER.format(target="custom_bypass.js", timestamp=ts)
                + "\n".join(blocks)
                + "\nJava.perform(function() {\n" + "\n".join(calls) + "\n    log('MAIN', 'Custom hooks done');\n});\n")

    def _build_master(self, ts, all_types, hooks) -> str:
        if "frida_detection" not in all_types:
            all_types = ["frida_detection"] + all_types
        blocks, calls = self._collect(all_types)
        for i, h in enumerate(hooks):
            fn = f"custom_hook_{i+1}"; s = h.get("frida_snippet","")
            if s:
                blocks.append(f"function {fn}() {{\n  try {{ {s} }} catch(e) {{ log('CUSTOM','{fn}: '+e); }}\n}}\n")
                calls.append(f"    {fn}();  // AI: {h.get('purpose','')}")
        return (_HEADER.format(target="master_bypass.js", timestamp=ts)
                + "\n".join(blocks)
                + "\nJava.perform(function() {\n"
                + "    log('MAIN', 'APKShield-PT Master Bypass Script');\n"
                + "\n".join(calls) + "\n"
                + "    log('MAIN', 'All bypass hooks installed successfully');\n});\n")

    def _write(self, content: str, name: str):
        (self.out / name).write_text(content)
