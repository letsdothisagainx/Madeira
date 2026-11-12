#!/usr/bin/env python3
"""Exercise the staged Wine named-registry security functions on real Windows.

Only the three production function bodies are compiled into distinctly named
before/after wrappers. Registry opening and security descriptor operations use
the Windows DLLs, alongside independent stock Set/GetNamedSecurityInfoW calls.
No Steam file, registry key, process, security decision or credential is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path("dlls/advapi32/security.c")
FUNCTIONS = ("get_security_regkey", "SetNamedSecurityInfoW", "GetNamedSecurityInfoW")


def function(source, name):
    """Keep the actual definition, including all its unmodified branches."""
    import re
    match = re.search(r"^(?:static DWORD|DWORD WINAPI) " + name + r"\(", source, re.M)
    if not match:
        raise ValueError("production function unavailable: " + name)
    start = source.index("{", match.start())
    # Ignore braces within C strings/comments when finding the closing brace.
    token = re.compile(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]')
    depth = 0
    for item in token.finditer(source, start):
        if item.group() == "{":
            depth += 1
        elif item.group() == "}":
            depth -= 1
            if not depth:
                return source[match.start():item.end()]
    raise ValueError("unterminated production function: " + name)


def prepare(output):
    spec = importlib.util.spec_from_file_location("registry_security_stage", ROOT / "tools/build/stage-registry-security-views.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    staged = output / "staged"
    module.stage(staged, ROOT / "wine")
    original = (ROOT / "wine" / SOURCE).read_text()
    corrected = (staged / SOURCE).read_text()
    parts = ["/* Generated from the pinned and staged production Wine source. */"]
    for prefix, text in (("before", original), ("after", corrected)):
        for name in FUNCTIONS:
            parts.append(f"#define {name} {prefix}_{name}")
        parts.extend(function(text, name) for name in FUNCTIONS)
        for name in FUNCTIONS:
            parts.append(f"#undef {name}")
    header = output / "production-registry-security.h"
    header.write_text("\n\n".join(parts) + "\n")
    return {
        "pinnedSourceSHA256": hashlib.sha256(original.encode()).hexdigest(),
        "stagedSourceSHA256": hashlib.sha256(corrected.encode()).hexdigest(),
        "compiledBodiesSHA256": hashlib.sha256(header.read_bytes()).hexdigest(),
        "backend": "Windows RegOpenKeyExW, SetSecurityInfo and GetSecurityInfo; not mocked",
        "reference": "independent Windows SetNamedSecurityInfoW and GetNamedSecurityInfoW",
        "scope": "owned temporary HKLM\\SOFTWARE keys in distinct 32/64 registry views; no Steam data",
        "host": platform.platform(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true", help="Extract production bodies without claiming native execution")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty")
    report = prepare(output)
    report["nativeWindowsExecuted"] = False
    report["fixtureSHA256"] = hashlib.sha256((ROOT / "tests/integration/registry-security-views.c").read_bytes()).hexdigest()
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.prepare_only:
        print("PASS extracted pinned/staged production functions; native registry execution NOT performed")
        return
    if sys.platform != "win32":
        parser.error("native execution requires Windows; use --prepare-only for source extraction")
    executable = output / "registry-security-views.exe"
    command = ["cl", "/nologo", "/std:c11", "/O2", "/W4", "/DUNICODE", "/D_UNICODE",
               "/I" + str(output), str(ROOT / "tests/integration/registry-security-views.c"),
               "/Fe:" + str(executable), "/Fo:" + str(output / "fixture.obj"), "advapi32.lib"]
    build = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90, check=False)
    (output / "compile.log").write_bytes(build.stdout)
    print(build.stdout.decode(errors="replace"))
    if build.returncode:
        raise RuntimeError("native registry fixture compilation failed")
    run = subprocess.run([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90, check=False)
    if len(run.stdout) > 256 * 1024:
        raise RuntimeError("native fixture diagnostic bound exceeded")
    (output / "native-results.log").write_bytes(run.stdout)
    print(run.stdout.decode(errors="replace"))
    report.update(nativeWindowsExecuted=True, exitCode=run.returncode,
                  result="pass" if run.returncode == 0 else "fail")
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if run.returncode:
        raise RuntimeError("real Windows registry regression failed; inspect native-results.log")


if __name__ == "__main__":
    main()
