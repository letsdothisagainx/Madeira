#!/usr/bin/env python3
"""Compile and execute the exact conservative fresh-copy address planner."""
from pathlib import Path
import os
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-native-atomic-plan-') as folder:
    binary=Path(folder)/'planner'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-I'+str(root/'build/ntdll-unix'),
                    str(root/'tests/host/native_atomic_alias_test.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
