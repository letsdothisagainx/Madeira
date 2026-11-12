#!/usr/bin/env python3
"""Run ordinary native Windows self-write APIs against an owned compiled DLL."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/integration/native-self-write-contract.c"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("requires native Windows; no emulated/reference substitution is permitted")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty")
    dll, executable = output / "madeira-owned-marker.dll", output / "native-self-write-contract.exe"
    definition = output / "owned-marker.def"
    definition.write_text("LIBRARY madeira-owned-marker\nEXPORTS\n MadeiraOwnedMarker DATA\n")
    commands = [
        ["cl", "/nologo", "/std:c11", "/O2", "/W4", "/LD", "/DOWNED_MARKER_DLL", str(SOURCE),
         "/Fe:" + str(dll), "/Fo:" + str(output / "marker.obj"), "/link", "/DEF:" + str(definition),
         "/IMPLIB:" + str(output / "owned-marker.lib")],
        ["cl", "/nologo", "/std:c11", "/O2", "/W4", "/DUNICODE", "/D_UNICODE", str(SOURCE),
         "/Fe:" + str(executable), "/Fo:" + str(output / "reference.obj")],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90, check=False)
        (output / f"compile-{index}.log").write_bytes(result.stdout)
        print(result.stdout.decode(errors="replace"))
        if result.returncode:
            raise RuntimeError("owned native reference compilation failed")
    before = digest(dll)
    run = subprocess.run([str(executable), str(dll)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=60, check=False)
    after = digest(dll)
    if len(run.stdout) > 256 * 1024:
        raise RuntimeError("native reference output exceeded its bound")
    (output / "observations.jsonl").write_bytes(run.stdout)
    print(run.stdout.decode(errors="replace"))
    records = [json.loads(line) for line in run.stdout.decode("utf-8").splitlines() if line]
    summary = {
        "sourceSHA256": digest(SOURCE), "nativeWindows": True, "host": platform.platform(),
        "exitCode": run.returncode, "records": len(records),
        "ownedDLLSHA256Before": before, "ownedDLLSHA256After": after,
        "ownedDLLFileUnchanged": before == after,
        "scope": "owned compiled DLL marker never executed; real Windows self-write APIs; no Valve binaries",
        "applicationImplementationChanged": False,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if run.returncode or before != after or not any(row.get("event") == "complete" for row in records):
        raise RuntimeError("native Windows self-write contract failed; inspect observations.jsonl")
    print("PASS native Windows self-write reference; actual owned DLL file SHA256 unchanged")


if __name__ == "__main__":
    main()
