#!/usr/bin/env python3
"""Isolated host experiment: identical production Mach fixture, runtime vs trap.

Nothing in the iPhone app, allocator, debugger, placement policy, or fixture is
changed. Both modes retain all undefined-behavior checks. Only the trap mode's
compiler option prevents linking the standalone UBSan runtime. The ordinary
mode is permitted to fail so the comparison can record actual VM evidence.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'native-mach-ubsan-results'
OUT.mkdir(exist_ok=True)
assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
spec = importlib.util.spec_from_file_location('original_mach_test', ROOT / 'tests/host/check-jit-full-pool-placement.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
records = []
source_hashes = {}
compiler = os.environ.get('CC', 'clang')
print(subprocess.check_output([compiler, '--version'], text=True), flush=True)

def execute(mode, binary, attempt):
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
    print(f'===== MODE={mode} ATTEMPT={attempt} EXIT={result.returncode} =====', flush=True)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', flush=True)
    records.append({'mode': mode, 'attempt': attempt, 'returncode': result.returncode,
                    'stdout': result.stdout, 'stderr': result.stderr})
    return result

for mode in ('runtime', 'trap'):
    with tempfile.TemporaryDirectory(prefix=f'mach-ubsan-{mode}-') as temporary:
        directory = Path(temporary)
        def boundary(command, **kwargs):
            args = [str(value) for value in command]
            if '-std=c11' in args:
                assert '-fsanitize=undefined' in args and '-fno-sanitize-recover=all' in args
                if mode == 'trap': args.insert(1, '-fsanitize-trap=undefined')
                print('COMPILE ' + json.dumps(args), flush=True)
                result = subprocess.run(args, check=True, timeout=120, **kwargs)
                source_hashes[mode] = hashlib.sha256((directory/'real-mach.c').read_bytes()).hexdigest()
                libraries = subprocess.check_output(['otool', '-L', str(directory/'real-mach')], text=True)
                (OUT/f'{mode}-libraries.txt').write_text(libraries)
                print(libraries, flush=True)
                return result
            assert args == [str(directory/'real-mach')]
            result = execute(mode, directory/'real-mach', 0)
            if result.returncode: raise subprocess.CalledProcessError(result.returncode, args)
            return result
        module.run = boundary
        try:
            module.native_mach(directory, True)
        except subprocess.CalledProcessError as error:
            assert error.cmd == [str(directory/'real-mach')], 'actual compile failed'
        for attempt in range(1, 4): execute(mode, directory/'real-mach', attempt)
        # A real signed-overflow control proves that both configurations keep
        # UB fatal. ARM64 plain addition itself would wrap, not trap.
        control = directory/'ub.c'
        control.write_text('#include <limits.h>\nint main(void){volatile int value=INT_MAX;volatile int result=value+1;(void)result;return 0;}\n')
        commands = {'plain': [], mode: ['-fsanitize=undefined', '-fno-sanitize-recover=all'] +
                    (['-fsanitize-trap=undefined'] if mode == 'trap' else [])}
        for label, flags in commands.items():
            binary = directory/f'overflow-{label}'
            subprocess.run([compiler, '-std=c11', '-O1', *flags, str(control), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            print(f'UB_CONTROL mode={mode} instrumentation={label} exit={result.returncode}', flush=True)
            assert (result.returncode == 0) == (label == 'plain'), 'lost fatal UB control'
assert source_hashes['runtime'] == source_hashes['trap'], 'fixture source changed between modes'
(OUT/'results.json').write_text(json.dumps({'sourceCommit': subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
    'sourceSHA256': source_hashes, 'records': records}, indent=2)+'\n')
for mode in ('runtime','trap'):
    cases = [record for record in records if record['mode'] == mode]
    print(f'RESULT mode={mode} passed={sum(record["returncode"]==0 for record in cases)} total={len(cases)}', flush=True)
print('EXPERIMENT ONLY: host VM and linked-runtime comparison; no iPhone or VAC claim', flush=True)
