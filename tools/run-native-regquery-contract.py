#!/usr/bin/env python3
"""Build and run a small independent native-Windows registry contract probe.

This is reference research, not a Wine implementation or an app build. The
fixture touches only its exclusively created temporary keys and exports no
raw security descriptors, SIDs, account names or Steam data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/integration/regquery-security-contract.c"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("reference research requires real Windows; no Wine/mock fallback is permitted")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty")
    executable = output / "regquery-security-contract.exe"
    compiler = subprocess.run(["cl", "/nologo", "/std:c11", "/O2", "/W4", "/DUNICODE", "/D_UNICODE",
                               str(SOURCE), "/Fe:" + str(executable),
                               "/Fo:" + str(output / "fixture.obj"), "advapi32.lib"],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90, check=False)
    (output / "compile.log").write_bytes(compiler.stdout)
    print(compiler.stdout.decode(errors="replace"))
    if compiler.returncode:
        raise RuntimeError("independent native reference fixture did not compile")
    run = subprocess.run([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=60, check=False)
    if len(run.stdout) > 256 * 1024:
        raise RuntimeError("native reference output exceeded its bound")
    (output / "observations.jsonl").write_bytes(run.stdout)
    print(run.stdout.decode(errors="replace"))
    records = [json.loads(line) for line in run.stdout.decode("utf-8").splitlines() if line]
    summary = {
        "sourceSHA256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "nativeWindows": True,
        "host": platform.platform(),
        "exitCode": run.returncode,
        "rows": len(records),
        "implementationChanged": False,
        "applicationDataAccessed": False,
        "contractOutcomes": "measured, not assumed; an API error is a research result",
        "fillStatusSentinel": "feedbeef means the bounded descriptor-fill call was not attempted",
        "queryOnlyReadControlContrast": [row for row in records if row.get("event") == "query" and
                                         row.get("phase") in ("compact-DACL", "anonymous-with-preopened-handle") and
                                         row.get("handle") in ("query-value-only", "held-query-only")],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if run.returncode or not any(row.get("event") == "complete" for row in records):
        raise RuntimeError("native reference infrastructure/cleanup failed; inspect observations.jsonl")


if __name__ == "__main__":
    main()
