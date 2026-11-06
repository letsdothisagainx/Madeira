#!/usr/bin/env python3
"""Compile the exact production counter-writer binder with sanitizers."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="madeira-counter-alias-") as folder:
    binary = Path(folder) / "counter-alias"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-I" + str(root / "build/ntdll-unix"),
                    str(root / "tests/host/native_counter_alias_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
