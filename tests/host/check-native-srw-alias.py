#!/usr/bin/env python3
"""Compile the actual unpublished SRW-history binding and live data-sync code."""
import os
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-srw-alias-') as folder:
    binary=Path(folder)/'check'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
                    '-I'+str(root/'build/ntdll-unix'),
                    str(root/'tests/host/native_srw_alias_test.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
