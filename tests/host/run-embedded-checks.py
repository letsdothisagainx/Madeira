#!/usr/bin/env python3
"""Expose failing host-check output in Actions annotations as well as logs."""
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
commands = [
    ['python3', 'tests/host/check-embedded-signals.py'],
    ['python3', 'tests/host/check-dock-packaging.py'],
    ['bash', 'madeira-dock/tools/check.sh'],
]
for command in commands:
    result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout, end='', flush=True)
    if result.returncode:
        message = result.stdout[-6000:].replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::error::' + message, flush=True)
        raise SystemExit(result.returncode if result.returncode > 0 else 128-result.returncode)
