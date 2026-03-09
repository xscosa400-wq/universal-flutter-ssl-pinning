#!/usr/bin/env python3
"""
flutter_ssl_pinning.py

One-shot pipeline: libflutter.so → PyGhidra SSL recon → flutter_ssl_pinning.js

Runs Ghidra analysis in-memory and immediately emits a ready-to-use Frida
bypass script.  No intermediate JSON file required.

Usage
-----
    python3 flutter_ssl_pinning.py libflutter.so
    python3 flutter_ssl_pinning.py libflutter.so bypass.js
    python3 flutter_ssl_pinning.py libflutter.so bypass.js --all-funcs
    python3 flutter_ssl_pinning.py libflutter.so bypass.js --save-json   # also write recon JSON

Options
-------
  output (positional) Output .js path          (default: flutter_ssl_pinning.js)
  --module          Module name in Frida      (default: libflutter.so)
  --keyword         SSL string keyword        (default: ssl_client)
  --all-funcs       Hook all xref functions, not only 3-param candidates
  --save-json [PATH]  Optionally persist the recon JSON beside the JS
  --ghidra-install-dir  Override Ghidra install path
  --project-dir     Ghidra temp project dir   (default: .ghidra_projects)
  --project-name    Ghidra project name       (default: flutter_ssl_recon)
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import sys
import time
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# ===========================================================================
# PyGhidra analysis helpers
# ===========================================================================

def _safe_str(value: object) -> str:
    try:
        return str(value)
    except Exception:
        return "<unprintable>"


def _to_hex_offset(program, address) -> Optional[str]:
    image_base = program.getImageBase()
    if image_base is None or address is None:
        return None
    try:
        return hex(int(address.subtract(image_base)))
    except Exception:
        return None


@dataclass
class FunctionRecord:
    name: str
    entry: str
    rva: Optional[str]
    parameter_count: int
    signature: str


@dataclass
class XrefRecord:
    from_address: str
    from_rva: Optional[str]
    ref_type: str
    from_function: Optional[FunctionRecord]


@dataclass
class StringHit:
    address: str
    rva: Optional[str]
    value: str
    xrefs: List[XrefRecord]


def _iter_defined_strings(listing) -> Iterable:
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        try:
            if data.hasStringValue():
                yield data
        except Exception:
            continue


def _extract_function_record(program, func) -> FunctionRecord:
    entry = func.getEntryPoint()
    return FunctionRecord(
        name=_safe_str(func.getName()),
        entry=_safe_str(entry),
        rva=_to_hex_offset(program, entry),
        parameter_count=int(func.getParameterCount()),
        signature=_safe_str(func.getSignature()),
    )


def _count_params_from_signature(signature: str) -> Optional[int]:
    match = re.search(r"\((.*)\)", signature)
    if not match:
        return None
    content = match.group(1).strip()
    if not content or content == "void":
        return 0
    parts = [p.strip() for p in content.split(",") if p.strip()]
    return len(parts)


def _decompile_signature_and_count(decomp_ifc, func) -> Tuple[Optional[str], Optional[int]]:
    try:
        result = decomp_ifc.decompileFunction(func, 60, None)
        if not result or not result.decompileCompleted():
            return None, None
        decompiled_fn = result.getDecompiledFunction()
        if decompiled_fn is None:
            return None, None
        signature = _safe_str(decompiled_fn.getSignature())
        return signature, _count_params_from_signature(signature)
    except Exception:
        return None, None


def _extract_function_record_with_fallback(program, func, decomp_ifc) -> FunctionRecord:
    record = _extract_function_record(program, func)
    if record.parameter_count != 0:
        return record
    decomp_sig, decomp_count = _decompile_signature_and_count(decomp_ifc, func)
    if decomp_sig is None or decomp_count is None:
        return record
    return FunctionRecord(
        name=record.name,
        entry=record.entry,
        rva=record.rva,
        parameter_count=int(decomp_count),
        signature=decomp_sig,
    )


def _analyze_program(flat_api, keyword: str) -> dict:
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp_ifc = DecompInterface()
    decomp_ifc.openProgram(program)

    keyword_lc = keyword.lower()

    string_hits: List[StringHit] = []
    unique_function_keys: Set[str] = set()
    unique_functions: List[FunctionRecord] = []
    candidate_three_arg: Dict[str, FunctionRecord] = {}

    try:
        for data in _iter_defined_strings(listing):
            value_obj = data.getValue()
            value_text = _safe_str(value_obj)
            if keyword_lc not in value_text.lower():
                continue

            string_addr = data.getAddress()
            xref_records: List[XrefRecord] = []

            refs_iter = reference_manager.getReferencesTo(string_addr)
            while refs_iter.hasNext():
                ref = refs_iter.next()
                from_addr = ref.getFromAddress()
                from_func = function_manager.getFunctionContaining(from_addr)

                func_record = None
                if from_func is not None:
                    func_record = _extract_function_record_with_fallback(
                        program, from_func, decomp_ifc
                    )
                    func_key = func_record.entry
                    if func_key not in unique_function_keys:
                        unique_function_keys.add(func_key)
                        unique_functions.append(func_record)
                    if func_record.parameter_count == 3:
                        candidate_three_arg[func_key] = func_record

                xref_records.append(
                    XrefRecord(
                        from_address=_safe_str(from_addr),
                        from_rva=_to_hex_offset(program, from_addr),
                        ref_type=_safe_str(ref.getReferenceType()),
                        from_function=func_record,
                    )
                )

            string_hits.append(
                StringHit(
                    address=_safe_str(string_addr),
                    rva=_to_hex_offset(program, string_addr),
                    value=value_text,
                    xrefs=xref_records,
                )
            )
    finally:
        try:
            decomp_ifc.dispose()
        except Exception:
            pass

    string_hits_sorted = sorted(string_hits, key=lambda s: s.address)
    unique_functions_sorted = sorted(unique_functions, key=lambda f: f.entry)
    candidate_three_arg_sorted = sorted(candidate_three_arg.values(), key=lambda f: f.entry)

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "program": {
            "name": _safe_str(program.getName()),
            "path": _safe_str(program.getExecutablePath()),
            "language": _safe_str(program.getLanguageID()),
            "compiler": _safe_str(program.getCompiler()),
            "image_base": _safe_str(program.getImageBase()),
        },
        "query": {"string_keyword": keyword},
        "stats": {
            "string_hits": len(string_hits_sorted),
            "unique_functions_on_xrefs": len(unique_functions_sorted),
            "candidate_functions_param_count_3": len(candidate_three_arg_sorted),
        },
        "string_hits": [
            {
                "address": h.address,
                "rva": h.rva,
                "value": h.value,
                "xrefs": [
                    {
                        "from_address": x.from_address,
                        "from_rva": x.from_rva,
                        "ref_type": x.ref_type,
                        "from_function": asdict(x.from_function) if x.from_function else None,
                    }
                    for x in h.xrefs
                ],
            }
            for h in string_hits_sorted
        ],
        "unique_functions_on_xrefs": [asdict(f) for f in unique_functions_sorted],
        "candidate_functions_param_count_3": [asdict(f) for f in candidate_three_arg_sorted],
    }


@contextlib.contextmanager
def _suppress_java_output():
    """Redirect C-level stdout/stderr to /dev/null to silence JVM/Ghidra noise."""
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    os.dup2(devnull_fd, 1)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)
    try:
        yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)


def _open_program_with_fallbacks(
    pyghidra_mod, binary_path: str, project_dir: str, project_name: str
):
    attempts = [
        {
            "binary_path": binary_path,
            "project_location": project_dir,
            "project_name": project_name,
            "analyze": True,
        },
        {
            "binary_path": binary_path,
            "analyze": True,
        },
    ]
    last_error = None
    for params in attempts:
        try:
            return pyghidra_mod.open_program(**params)
        except TypeError as exc:
            last_error = exc
            continue
    raise RuntimeError(
        f"Unable to open program with pyghidra.open_program: {last_error}"
    )


# ===========================================================================
# Frida JS generation
# ===========================================================================

def _js_escape(text: str) -> str:
    """Escape text for safe embedding in a JS single-line comment."""
    return text.replace("*/", "* /").replace("\n", " ").replace("\r", "")


def _build_candidates_block(candidates: list[dict]) -> str:
    lines = ["var HOOK_CANDIDATES = ["]
    for i, fn in enumerate(candidates):
        comma = "," if i < len(candidates) - 1 else ""
        sig_escaped = _js_escape(fn.get("signature", ""))
        lines.append(
            f'  {{ name: "{fn["name"]}", rva: "{fn["rva"]}", '
            f'params: {fn["parameter_count"]}, '
            f'sig: "{sig_escaped}" }}{comma}'
        )
    lines.append("];")
    return "\n".join(lines)


def _build_comment_header(report: dict, candidates: list[dict]) -> str:
    prog = report.get("program", {})
    gen_at = report.get("generated_at_utc", "unknown")
    now_utc = datetime.now(timezone.utc).isoformat()
    lines = [
        "/**",
        " * flutter / Flutter SSL Pinning Bypass",
        " * Auto-generated by flutter_ssl_pinning.py",
        f" * Generated at    : {now_utc}",
        f" * Recon run at    : {gen_at}",
        f" * Binary          : {prog.get('name', '?')}",
        f" * Language        : {prog.get('language', '?')}",
        f" * Image base      : 0x{prog.get('image_base', '?')}",
        " *",
        " * Candidate functions discovered by PyGhidra recon:",
    ]
    for fn in candidates:
        lines.append(
            f" *   {fn['name']}  RVA={fn['rva']}  params={fn['parameter_count']}"
        )
        lines.append(f" *     {fn.get('signature', '')}")
    lines.append(" *")
    lines.append(
        " * Hook logic: patch retval → ptr(1)  (= SSL_VERIFY_OK / success)"
    )
    lines.append(" */")
    return "\n".join(lines)


def generate_js(report: dict, candidates: list[dict], module_name: str) -> str:
    header = _build_comment_header(report, candidates)
    candidates_block = _build_candidates_block(candidates)

    script = f"""{header}

"use strict";

// --- configuration -----------------------------------------------------------
var TARGET_MODULE = "{module_name}";
// flutter bundles patched Dart code in libapp.so but the BoringSSL/Flutter
// SSL engine lives in libflutter.so.  Change TARGET_MODULE if your build
// places the SSL code elsewhere.

// --- candidate table (auto-filled by in-memory PyGhidra recon) ---------------
{candidates_block}

// --- hook implementation -----------------------------------------------------
function hookCandidate(mod, candidate) {{
    var addr = mod.base.add(candidate.rva);
    var modEnd = mod.base.add(mod.size);
    if (addr.compare(modEnd) >= 0) {{
        console.log("[-] " + candidate.name + ": RVA " + candidate.rva +
                    " outside module bounds – skipping");
        return;
    }}
    console.log("[*] Hooking " + candidate.name +
                "  RVA=" + candidate.rva + "  addr=" + addr);
    try {{
        Interceptor.attach(addr, {{
            onEnter: function (args) {{
                this._name = candidate.name;
            }},
            onLeave: function (retval) {{
                console.log("[+] " + this._name +
                            " retval " + retval + " → patching to 1 (bypass)");
                retval.replace(ptr(1));
            }}
        }});
        console.log("[+] " + candidate.name + " hooked successfully");
    }} catch (e) {{
        console.log("[-] Failed to hook " + candidate.name + ": " + e.message);
    }}
}}

// --- entry point -------------------------------------------------------------
function bypassSslPinning() {{
    console.log("=== flutter / Flutter SSL Pinning Bypass ===");
    console.log("[*] Looking for module: " + TARGET_MODULE);

    var mod = Process.findModuleByName(TARGET_MODULE);
    if (!mod) {{
        console.log("[-] " + TARGET_MODULE + " not found in process.");
        console.log("[*] Loaded modules:");
        Process.enumerateModules().forEach(function (m) {{
            console.log("    " + m.name + "  base=" + m.base + "  size=" + m.size);
        }});
        return;
    }}

    console.log("[+] Found " + TARGET_MODULE +
                "  base=" + mod.base + "  size=0x" + mod.size.toString(16));
    console.log("[*] Hooking " + HOOK_CANDIDATES.length + " candidate(s)...");

    HOOK_CANDIDATES.forEach(function (c) {{
        hookCandidate(mod, c);
    }});

    console.log("[+] SSL pinning bypass armed.");
}}

// Slight delay so the module is fully mapped before attaching.
setTimeout(bypassSslPinning, 1000);
"""
    return script


# ===========================================================================
# Main
# ===========================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "One-shot: libflutter.so → PyGhidra SSL recon → flutter_ssl_pinning.js\n"
            "No intermediate JSON file required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "binary",
        help="Path to target binary (e.g. libflutter.so)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        default="flutter_ssl_pinning.js",
        help="Output Frida script path (default: flutter_ssl_pinning.js)",
    )
    parser.add_argument(
        "--module",
        default="libflutter.so",
        help="Module name as seen in the target process (default: libflutter.so)",
    )
    parser.add_argument(
        "--keyword",
        default="ssl_client",
        help="SSL string keyword to search for in the binary (default: ssl_client)",
    )
    parser.add_argument(
        "--all-funcs",
        action="store_true",
        help="Hook all xref functions, not only 3-param candidates",
    )
    parser.add_argument(
        "--save-json",
        metavar="PATH",
        nargs="?",
        const="",
        help=(
            "Also save the recon JSON report.  If PATH is omitted, saves as "
            "<binary_name>_ssl_recon.json next to the binary."
        ),
    )
    parser.add_argument(
        "--ghidra-install-dir",
        default=None,
        help="Override Ghidra installation directory",
    )
    parser.add_argument(
        "--project-dir",
        default=".ghidra_projects",
        help="Temporary Ghidra project directory (default: .ghidra_projects)",
    )
    parser.add_argument(
        "--project-name",
        default="flutter_ssl_recon",
        help="Ghidra project name (default: flutter_ssl_recon)",
    )

    args = parser.parse_args()

    binary_path_obj = Path(args.binary).expanduser().resolve()
    if not binary_path_obj.exists():
        sys.exit(f"[!] Binary not found: {binary_path_obj}")

    binary_path = str(binary_path_obj)
    project_dir = str(Path(args.project_dir).expanduser().resolve())
    os.makedirs(project_dir, exist_ok=True)

    # ---- PyGhidra analysis --------------------------------------------------
    import pyghidra  # Late import so --help works without pyghidra installed
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    print(f"[*] Analyzing {binary_path_obj.name} with PyGhidra ...")
    print("[*] Running Ghidra analysis, please wait...")

    retry_project_name = None
    with _suppress_java_output():
        if args.ghidra_install_dir:
            pyghidra.start(args.ghidra_install_dir)
        else:
            pyghidra.start()

        try:
            with _open_program_with_fallbacks(
                pyghidra, binary_path, project_dir, args.project_name
            ) as flat_api:
                report = _analyze_program(flat_api, args.keyword)
        except Exception as exc:
            msg = _safe_str(exc)
            if "Unable to lock project" not in msg:
                raise
            retry_project_name = f"{args.project_name}_{int(time.time())}_{os.getpid()}"
            with _open_program_with_fallbacks(
                pyghidra, binary_path, project_dir, retry_project_name
            ) as flat_api:
                report = _analyze_program(flat_api, args.keyword)

    if retry_project_name:
        print(f"[!] Project was locked – retried as '{retry_project_name}'")

    print(
        f"[+] Recon done: {report['stats']['string_hits']} string hit(s), "
        f"{report['stats']['candidate_functions_param_count_3']} 3-param candidate(s)"
    )

    # Clean up Ghidra temp project files
    if os.path.exists(project_dir):
        shutil.rmtree(project_dir, ignore_errors=True)
        print(f"[+] Cleaned up Ghidra project dir: {project_dir}")

    # ---- Optionally save JSON -----------------------------------------------
    if args.save_json is not None:
        if args.save_json:
            json_path = Path(args.save_json).expanduser().resolve()
        else:
            json_path = binary_path_obj.parent / f"{binary_path_obj.stem}_ssl_recon.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Recon JSON saved: {json_path}")

    # ---- Select candidates --------------------------------------------------
    if args.all_funcs:
        raw_candidates = report.get("unique_functions_on_xrefs", [])
        mode = "all xref functions"
    else:
        raw_candidates = report.get("candidate_functions_param_count_3", [])
        mode = "3-param candidates"

    if not raw_candidates:
        print("[!] No 3-param candidates found; falling back to all xref functions.")
        raw_candidates = report.get("unique_functions_on_xrefs", [])
        mode = "all xref functions (fallback)"

    if not raw_candidates:
        sys.exit(
            "[!] No candidate functions found in the binary.\n"
            "    Try --all-funcs or a different --keyword."
        )

    candidates = [fn for fn in raw_candidates if fn.get("rva")]
    if not candidates:
        sys.exit("[!] All candidates are missing RVA data.")

    print(f"[*] Using {len(candidates)} candidate(s) ({mode}):")
    for fn in candidates:
        print(f"    {fn['name']}  RVA={fn['rva']}  params={fn['parameter_count']}")
        print(f"      {fn.get('signature', '')}")

    # ---- Generate Frida JS --------------------------------------------------
    js_text = generate_js(report, candidates, args.module)

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(js_text, encoding="utf-8")

    print(f"\n[+] Generated : {output_path}")
    print(f"[+] Candidates: {len(candidates)} embedded")
    print(f"\nUsage with Frida:")
    print(f"  frida -U -f <package_name> -l {output_path.name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
