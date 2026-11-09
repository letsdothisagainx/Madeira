#!/usr/bin/env python3
"""Compile actual source-built FEX diagnostic DATA-contract binding and sync.

This fixture exercises the production parser/copy helpers. It cannot prove an
iPhone frame rate or owner-ledger quiescence; those remain runtime checks.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="madeira-fex-diagnostics-alias-") as folder:
    binary = Path(folder) / "check"
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-pthread",
        "-I" + str(root / "build/ntdll-unix"),
        str(root / "tests/host/native_fex_diagnostics_alias_test.c"),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
