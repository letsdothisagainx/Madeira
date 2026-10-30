#!/usr/bin/env python3
"""Expose failing host-check output in Actions annotations as well as logs."""
import os
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
commands = [
    ['python3', 'tests/host/check-steam-ui-trace.py'],
    ['python3', 'tests/host/check-async-apc-trace.py'],
    ['python3', 'tests/host/check-window-visibility.py'],
    ['python3', 'tests/host/check-window-coordinates.py'],
    ['python3', 'tests/host/check-harmless-warnings.py', '--require-swift'],
    ['python3', 'tests/host/check-opengl-wow64.py'],
    ['python3', 'tests/host/check-steam-client-environment.py'],
    ['python3', 'tests/host/check-wow-context.py'],
    ['python3', 'tests/host/check-wow-cpu-area.py'],
    ['python3', 'tests/host/check-wow-guard.py'],
    ['python3', 'tests/host/check-wow-sweep.py'],
    ['python3', 'tests/host/check-scm-rpc-loader.py'],
    ['python3', 'tests/host/check-scm-rpc-sync.py'],
    ['python3', 'tests/host/check-tls-jit-sync.py'],
    ['python3', 'tests/host/check-steam-service.py'],
    ['python3', 'tests/host/check-dock-contract.py'],
    ['python3', 'tests/host/check-embedded-signals.py'],
    ['python3', 'tests/host/check-dock-packaging.py'],
    ['bash', 'madeira-dock/tools/check.sh'],
]
for command in commands:
    result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            env=dict(os.environ, PYTHONUNBUFFERED="1"))
    print(result.stdout, end='', flush=True)
    if result.returncode:
        failures = [line for line in result.stdout.splitlines()
                    if line.startswith(('FAIL:', 'Assertion failed:', 'error:')) or ': error:' in line]
        detail = '\n'.join(failures)[-1600:] if failures else result.stdout[-1600:]
        message = detail.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::error title=Host check failed::' + ' '.join(command) + ': ' + message, flush=True)
        raise SystemExit(result.returncode if result.returncode > 0 else 128-result.returncode)
