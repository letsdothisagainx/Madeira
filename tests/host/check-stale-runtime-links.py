#!/usr/bin/env python3
"""Compile the actual production stale-link repair against real local fixtures."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="madeira-stale-PRIVATE_TOKEN-") as folder:
    directory = Path(folder).resolve()
    binary = directory / "repair"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-I" + str(root / "app/Madeira"),
                    str(root / "tests/host/stale_runtime_links_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(directory)], check=True)
