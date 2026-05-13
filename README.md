<div align="center">

```
   █████╗ ██████╗ ██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ███████║██████╔╝█████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██╔══██║██╔═══╝ ██╔═██╗ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║  ██║██║     ██║  ██╗███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
```

**AI-Powered Android Penetration Testing Tool**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![Frida](https://img.shields.io/badge/Frida-17.x%20Compatible-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> ⚠️ **For authorized penetration testing only. Always obtain written permission before testing any application.**

</div>

---

## What is APKShield-PT?

APKShield-PT is an automated Android penetration testing tool that:

1. **Decompiles** the APK using `apktool` (smali + resources) and `jadx` (Java source)
2. **Detects** root detection techniques across 14 categories
3. **Detects** SSL/TLS certificate pinning across 15 categories
4. **Generates** ready-to-use Frida bypass scripts targeting exactly what was found
5. **Produces** a full HTML + JSON report

No manual code reading required. Drop in an APK, get working Frida scripts out.

---

## Features

| Feature | Details |
|---|---|
| Auto Decompilation | apktool + jadx, skips if already done |
| Root Detection Engine | 14 categories — RootBeer, SafetyNet, Play Integrity, Magisk, su binary, build props, Frida/Xposed self-detection, signature checks, emulator detection |
| SSL Pinning Engine | 15 categories — OkHttp, TrustManager, HostnameVerifier, NSC XML, TrustKit, WebView, gRPC, Conscrypt, Cronet, certificate transparency, native pinning |
| Frida Script Generator | Auto-generates targeted scripts — no generic one-size-fits-all hooks |
| AI Analysis (optional) | Deep code analysis to find obfuscated/custom checks |
| Reports | HTML report (dark theme) + JSON report |
| Frida 17.x Compatible | All overloads correctly specified, no crash on startup |

---

## Installation

### Requirements

- Kali Linux (recommended) or any Debian-based distro
- Python 3.10+
- Android device with frida-server running

### One-command setup

```bash
git clone https://github.com/YOUR_USERNAME/apkshield-pt
cd apkshield-pt
bash setup.sh
```

The setup script installs: `apktool`, `jadx`, `adb`, `frida-tools`, `objection`, and all Python dependencies.

### Manual install

```bash
sudo apt install apktool jadx adb -y
pip3 install frida-tools objection rich anthropic --break-system-packages
```

---

## Usage

```bash
# Basic usage — no AI (fully offline)
python3 apkshield.py App.apk --no-ai

# Custom output directory
python3 apkshield.py App.apk --no-ai -o /root/results

# With AI analysis (requires API key)
export ANTHROPIC_API_KEY=your_key_here
python3 apkshield.py App.apk

# Verbose output
python3 apkshield.py App.apk --no-ai -v

# Check all dependencies
python3 apkshield.py --check-deps
```

---

## Output Structure

```
apkshield_output/
└── AppName/
    ├── apktool_out/              # Smali + resources
    ├── jadx_out/                 # Decompiled Java source
    ├── frida/
    │   ├── master_bypass.js      ← Start here (all-in-one)
    │   ├── root_bypass.js
    │   ├── ssl_bypass.js
    │   ├── safetynet_bypass.js
    │   ├── frida_detection_bypass.js
    │   └── custom_bypass.js      ← AI-identified hooks (if AI used)
    ├── report.html               ← Visual report (open in browser)
    └── report.json               ← Machine-readable report
```

---

## Using the Frida Scripts

### Setup frida-server on device first

```bash
# Download frida-server matching your frida-tools version
# https://github.com/frida/frida/releases

adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Run bypass scripts

```bash
# Spawn app with master bypass (recommended — start here)
frida -U -f com.target.app -l frida/master_bypass.js --no-pause

# Attach to already running app
frida -U com.target.app -l frida/master_bypass.js

# SSL bypass only
frida -U -f com.target.app -l frida/ssl_bypass.js --no-pause

# Via objection (interactive shell)
objection -g com.target.app explore
```

---

## Root Detection Coverage

| ID | Category | Bypass Function |
|---|---|---|
| RD-001 | su binary path checks | `bypass_file_checks()` |
| RD-002 | busybox binary | `bypass_file_checks()` |
| RD-003 | Root manager apps (Magisk, SuperSU) | `bypass_package_manager()` |
| RD-004 | Build.TAGS test-keys | `bypass_build_props()` |
| RD-005 | ro.secure / ro.debuggable props | `bypass_build_props()` |
| RD-006 | RootBeer library | `bypass_rootbeer()` |
| RD-007 | RootTools library | `bypass_rootbeer()` |
| RD-008 | SafetyNet Attestation API | `bypass_safetynet()` |
| RD-009 | Play Integrity API | `bypass_safetynet()` |
| RD-010 | Native JNI root check | Manual / Magisk Hide |
| RD-011 | Writable path checks | `bypass_file_checks()` |
| RD-012 | Frida / Xposed self-detection | `bypass_frida_detection()` |
| RD-013 | Emulator detection | `bypass_build_props()` |
| RD-014 | APK signature / tamper check | `bypass_package_manager()` |

## SSL Pinning Coverage

| ID | Category | Bypass Function |
|---|---|---|
| SSL-001 | OkHttp3 CertificatePinner | `bypass_okhttp()` |
| SSL-002 | Custom X509TrustManager | `bypass_trust_manager()` |
| SSL-003 | Custom HostnameVerifier | `bypass_hostname_verifier()` |
| SSL-004 | Network Security Config XML | `bypass_nsc()` |
| SSL-005 | Conscrypt / Cronet | `bypass_trust_manager()` |
| SSL-006 | HttpsURLConnection | `bypass_hostname_verifier()` |
| SSL-007 | Appcelerator Titanium | `bypass_trust_manager()` |
| SSL-008 | Volley HurlStack | `bypass_trust_manager()` |
| SSL-009 | gRPC TLS credentials | `bypass_trust_manager()` |
| SSL-010 | Native JNI SSL pinning | Manual native patching |
| SSL-011 | Firebase / GMS TLS | `bypass_trust_manager()` |
| SSL-012 | Certificate Transparency | `bypass_trust_manager()` |
| SSL-013 | Public key pinning | `bypass_trust_manager()` |
| SSL-014 | WebView SSL handling | `bypass_webview_ssl()` |
| SSL-015 | TrustKit framework | `bypass_trustkit()` |

---

## Project Structure

```
apkshield-pt/
├── apkshield.py          # Main entry point
├── setup.sh              # Installer for Kali Linux
├── README.md
└── core/
    ├── __init__.py
    ├── decompiler.py     # apktool + jadx wrapper
    ├── root_detector.py  # Root detection pattern engine
    ├── ssl_detector.py   # SSL pinning pattern engine
    ├── frida_gen.py      # Frida script generator
    ├── ai_analyzer.py    # Optional AI deep analysis
    └── reporter.py       # HTML + JSON report generator
```

---

## Troubleshooting

**`No module named 'core'`**
```bash
# Make sure you run from inside the project folder
cd apkshield-pt
python3 apkshield.py App.apk --no-ai
```

**`pip install` fails on Kali**
```bash
pip3 install rich anthropic --break-system-packages
```

**`apktool not found`**
```bash
sudo apt install apktool -y
```

**`jadx not found`**
```bash
sudo apt install jadx -y
```

**Frida crash: `has more than one overload`**
This was fixed in the current version. Make sure you downloaded the latest `master_bypass.js`.

**App still detects root after bypass**
- The app may use native (C/C++) root detection — check the `native_root` note in the report
- Try running with Magisk Hide / Shamiko enabled alongside the Frida script
- Use `--verbose` and check which specific hooks logged output

---

## Contributing

Pull requests welcome. To add a new detection pattern, edit `core/root_detector.py` or `core/ssl_detector.py` and add an entry to the respective `*_PATTERNS` list following the existing format.

---

## Legal

This tool is intended for authorized security testing only. The authors are not responsible for any misuse. Always obtain explicit written permission from the application owner before testing.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
