#!/usr/bin/env python3
"""Compile actual staged Wine trust body before/after the native feature guard."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'trust-native-objects'
OUT.mkdir(exist_ok=True)
TC = ROOT / 'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin'
WINE = ROOT / 'wine'
BUILD = WINE / 'build-arm64ec'
OBJECT = BUILD / 'dlls/wintrust/arm64ec-windows/wintrust_main.o'
OLD = '#if defined(__aarch64__) && defined(__clang__)'
NEW = '#if (defined(__aarch64__) || defined(__arm64ec__) || defined(_M_ARM64EC)) && defined(__clang__)'
HEADER = WINE / 'dlls/wintrust/madeira_trust_diagnostics.h'
source = WINE / 'dlls/wintrust/wintrust_main.c'
original = source.read_bytes()
spec = importlib.util.spec_from_file_location('trust_stage', ROOT / 'tools/build/stage-trust-diagnostics.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
env = dict(os.environ)
env['PATH'] = str(TC) + ':' + env['PATH']

def run(command, log):
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (OUT / log).write_bytes(result.stdout)
    return result

macros = run([str(TC / 'arm64ec-w64-mingw32-clang'), '-D__STDC__', '-target', 'arm64ec-windows',
              '--no-default-config', '-dM', '-E', '-x', 'c', '/dev/null'], 'arm64ec-macros.txt')
assert macros.returncode == 0, macros.stdout.decode(errors='replace')
for line in macros.stdout.decode().splitlines():
    if any(key in line for key in ('__aarch64__', '__arm64ec__', '_M_ARM64', '__GNUC__', '_MSC_VER', '__clang__')):
        print(line, flush=True)
assert (BUILD / 'Makefile').is_file(), 'configure Wine ARM64EC before compiling the actual body'
with tempfile.TemporaryDirectory(prefix='madeira-trust-native-source-') as folder:
    state = Path(folder) / 'source'
    stage.apply(state, WINE)
    staged = HEADER.read_bytes()
    text = staged.decode()
    assert text.count(OLD) + text.count(NEW) == 1, 'controlled native feature boundary changed'
    before = text.replace(NEW, OLD)
    after = text.replace(OLD, NEW)
    try:
        for label, header in [('before', before), ('after', after)]:
            HEADER.write_text(header)
            OBJECT.unlink(missing_ok=True)
            built = run(['make', '-C', str(BUILD), '-j8',
                         'dlls/wintrust/arm64ec-windows/wintrust_main.o'], label + '-build.txt')
            assert built.returncode == 0, built.stdout.decode(errors='replace')[-12000:]
            saved = OUT / (label + '-wintrust_main-arm64ec.o')
            shutil.copyfile(OBJECT, saved)
            (OUT / (label + '-trust_diagnostics.h')).write_text(header)
            symbols = run([str(TC / 'llvm-readobj'), '--file-headers', '--sections', '--symbols', str(saved)], label + '-symbols.txt')
            assert symbols.returncode == 0, symbols.stdout.decode(errors='replace')
            assembly = run([str(TC / 'llvm-objdump'), '-d', str(saved)], label + '-assembly.txt')
            assert assembly.returncode == 0, assembly.stdout.decode(errors='replace')
            checked = run(['python3', str(ROOT / 'tools/check-trust-diagnostics-object.py'), str(saved)], label + '-gate.txt')
            print(label, 'sha256=' + hashlib.sha256(saved.read_bytes()).hexdigest(), 'gate=' + str(checked.returncode), flush=True)
            print(checked.stdout.decode(errors='replace')[-3000:], flush=True)
            if label == 'before':
                assert checked.returncode != 0, 'original guard failure did not reproduce on the actual pinned compiler'
            else:
                assert checked.returncode == 0, 'corrected native guard did not pass the unchanged real COFF gate'
    finally:
        HEADER.write_bytes(staged)
        stage.restore(state)
assert source.read_bytes() == original and not HEADER.exists(), 'original verifier source was not restored exactly'
print('PASS actual ARM64EC Wine trust body: original failure reproduced, guarded native CAS32 producer verified, original source restored', flush=True)
