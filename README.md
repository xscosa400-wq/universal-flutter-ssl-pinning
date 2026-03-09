# universal-flutter-ssl-pinning

One-shot **PyGhidra + Frida** toolkit that automatically reverse-engineers `libflutter.so`, discovers the SSL certificate-verification function, and emits a ready-to-use Frida bypass script — no manual Ghidra GUI needed.

Tested and working on both **standard Google Flutter** apps and **Shorebird**-patched Flutter builds. Both share the same `libflutter.so` BoringSSL engine, so the auto-generated script bypasses certificate pinning on either without any changes.

---

## How it works

```
libflutter.so
     │
     ▼
flutter_ssl_pinning.py  (PyGhidra headless analysis)
  • Scan defined strings for "ssl_client"
  • Resolve cross-references → containing functions
  • Decompile to resolve parameter counts
  • Select 3-param candidates  ← ssl_crypto_x509_session_verify_cert_chain shape
     │
     ▼
flutter_ssl_pinning.js  ← Frida script with real RVAs baked in
```

The generated script hooks the SSL verify function and patches its return value to `ptr(1)` (= `SSL_VERIFY_OK`) at runtime, bypassing certificate pinning.

---

## Requirements

| Dependency | Install |
|---|---|
| [Ghidra](https://ghidra-sre.org/) | `brew install ghidra` |
| [pyghidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraBridge) | `pip install pyghidra` |
| [Frida](https://frida.re/) | `pip install frida-tools` |

> Set `GHIDRA_INSTALL_DIR` in your environment, or pass `--ghidra-install-dir` on the command line.

---

## Usage

### Step 1 — Generate the Frida script

```bash
# output defaults to flutter_ssl_pinning.js
python3 flutter_ssl_pinning.py libflutter.so

# specify a custom output path as a positional argument
python3 flutter_ssl_pinning.py libflutter.so bypass.js
```

Console output:
```
[*] Analyzing libflutter.so with PyGhidra ...
[*] Running Ghidra analysis, please wait...
[+] Recon done: 1 string hit(s), 1 3-param candidate(s)
[+] Cleaned up Ghidra project dir: .ghidra_projects
[*] Using 1 candidate(s) (3-param candidates):
    FUN_00c106d0  RVA=0xb106d0  params=3
      void FUN_00c106d0(long param_1,long *param_2,undefined1 *param_3);

[+] Generated : flutter_ssl_pinning.js
[+] Candidates: 1 embedded

Usage with Frida:
  frida -U -f <package_name> -l flutter_ssl_pinning.js
```

### Step 2 — Attach with Frida

```bash
frida -U -f com.example.app -l flutter_ssl_pinning.js
```

---

## Options

| Option | Default | Description |
|---|---|---|
| `binary` | *(required)* | Path to `libflutter.so` |
| `output` | `flutter_ssl_pinning.js` | Output Frida script path (positional, optional) |
| `--module MODULE` | `libflutter.so` | Module name as seen in the target process |
| `--keyword KEYWORD` | `ssl_client` | SSL string to search for in the binary |
| `--all-funcs` | off | Hook all xref functions, not only 3-param candidates |
| `--save-json [PATH]` | off | Also save the recon report as JSON |
| `--ghidra-install-dir DIR` | auto | Override Ghidra installation directory |
| `--project-dir DIR` | `.ghidra_projects` | Temporary Ghidra project directory |
| `--project-name NAME` | `flutter_ssl_recon` | Ghidra project name |

---

## Files

| File | Description |
|---|---|
| `flutter_ssl_pinning.py` | Main script — PyGhidra recon + Frida JS generation in one |
| `flutter_ssl_pinning.js` | Auto-generated Frida bypass script (created after running) |

---

## Tested on

| Target | Status |
|---|---|
| Google Flutter `libflutter.so` (arm64-v8a) | ✅ Working |
| Shorebird-patched Flutter builds | ✅ Working |
| Ghidra 12.x + pyghidra | ✅ Working |

> Both Google Flutter and Shorebird use the same `libflutter.so` SSL engine.
> The auto-discovered RVA is identical across build types for the same Flutter engine version.

---

## Disclaimer

This tool is intended for **authorised security research and penetration testing only**.  
Do not use against apps you do not own or have explicit written permission to test.
