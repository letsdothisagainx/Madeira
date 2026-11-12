#!/usr/bin/env python3
"""Build and run actual native Windows or POSIX UDP destination semantics."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/integration/udp-destination-contract.c"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty")
    executable = output / ("udp-contract.exe" if sys.platform == "win32" else "udp-contract")
    if sys.platform == "win32":
        command = ["cl", "/nologo", "/std:c11", "/O2", "/W4", str(SOURCE),
                   "/Fe:" + str(executable), "/Fo:" + str(output / "contract.obj"), "/link", "ws2_32.lib"]
    else:
        command = [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(executable)]
    compile_result = subprocess.run(command, capture_output=True, timeout=90, check=False)
    (output / "compile.log").write_bytes(compile_result.stdout + compile_result.stderr)
    print((compile_result.stdout + compile_result.stderr).decode(errors="replace"))
    if compile_result.returncode:
        raise RuntimeError("native UDP contract compilation failed")
    result = subprocess.run([str(executable)], capture_output=True, timeout=20, check=False)
    raw = result.stdout + result.stderr
    if len(raw) > 64 * 1024:
        raise RuntimeError("native UDP output exceeded bound")
    (output / "observations.jsonl").write_bytes(raw)
    print(raw.decode(errors="replace"))
    rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line]
    summary = {"nativePlatform": platform.platform(), "sourceSHA256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
               "exitCode": result.returncode, "scope": "owned ephemeral loopback sockets; no Valve endpoint, packet, ticket or game code",
               "applicationImplementationChanged": False}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if result.returncode or not any(row.get("event") == "complete" and row["failures"] == 0 for row in rows):
        raise RuntimeError("mandatory native UDP loopback roundtrip failed")
    print("PASS mandatory native UDP roundtrips; unspecified destinations recorded without fabricated expectations")


if __name__ == "__main__":
    main()
