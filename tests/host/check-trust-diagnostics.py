#!/usr/bin/env python3
"""Exercise the actual observation wrapper and fail-closed staging/restoration."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('trust_stage', ROOT / 'tools/build/stage-trust-diagnostics.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    # Wine's actual ARM64EC Windows compile defines __arm64ec__ and _MSC_VER,
    # without __aarch64__ or __GNUC__. Exercise the production preprocessor
    # boundary directly for both spellings and the existing AArch64 target.
    header = (ROOT / 'build/wine-pe/trust_diagnostics.h').read_text()
    first = header.index('#if ', header.index('/* One ordinary CAS attempt'))
    last = header.index('\nstatic void madeira_trust_metadata', first)
    controlled = header[first:last]
    for architecture in ('__aarch64__', '__arm64ec__', '_M_ARM64EC'):
        preprocessed = subprocess.run([os.environ.get('CC', 'cc'), '-E', '-P', '-undef',
            '-D__clang__=1', '-D_MSC_VER=1933', '-D' + architecture + '=1', '-x', 'c', '-'],
            input=controlled, text=True, capture_output=True, check=True).stdout
        assert '__attribute__((target("lse"), noinline))' in preprocessed, architecture + ' lost the native CAS producer boundary'
    binary = temp / 'trust-test'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread',
                    str(ROOT / 'tests/host/trust_diagnostics_test.c'), '-o', str(binary)], check=True)
    for case in ('behavior', 'inaccessible', 'privacy', 'catalog', 'gate', 'concurrency'):
        subprocess.run([str(binary), case], check=True)
    source = temp / 'source'
    (source / stage.SOURCE).parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'wine' / stage.SOURCE, source / stage.SOURCE)
    original = (source / stage.SOURCE).read_bytes()
    stage.apply(temp / 'backup', source)
    transformed = (source / stage.SOURCE).read_text()
    expected = original.decode().replace(
        'LONG WINAPI WinVerifyTrust( HWND hwnd, GUID *ActionID, LPVOID ActionData )',
        'static LONG WINAPI madeira_real_WinVerifyTrust( HWND hwnd, GUID *ActionID, LPVOID ActionData )', 1)
    expected = expected.replace('/***********************************************************************\n *\t\tWinVerifyTrustEx (WINTRUST.@)',
        '#include "madeira_trust_diagnostics.h"\n\n/***********************************************************************\n *\t\tWinVerifyTrustEx (WINTRUST.@)', 1)
    assert transformed == expected, 'the genuine verifier body changed'
    stage.restore(temp / 'backup')
    assert (source / stage.SOURCE).read_bytes() == original and not (source / stage.HEADER).exists()
    outside = temp / 'outside-nonexistent'
    (source / stage.HEADER).symlink_to(outside)
    try:
        stage.apply(temp / 'symlink-backup', source)
    except ValueError:
        pass
    else:
        raise AssertionError('dangling diagnostic header symlink accepted')
    assert not outside.exists() and (source / stage.SOURCE).read_bytes() == original
    (source / stage.HEADER).unlink()
    original_file = temp / 'external-original.c'
    original_file.write_bytes(original)
    (source / stage.SOURCE).unlink()
    (source / stage.SOURCE).symlink_to(original_file)
    try:
        stage.apply(temp / 'source-symlink-backup', source)
    except ValueError:
        pass
    else:
        raise AssertionError('symlinked verifier source accepted')
    assert original_file.read_bytes() == original
    (source / stage.SOURCE).unlink()
    (source / stage.SOURCE).write_bytes(original)
    stage.apply(temp / 'tamper-backup', source)
    (source / stage.HEADER).write_text('build-time edit that must survive')
    try:
        stage.restore(temp / 'tamper-backup')
    except ValueError:
        pass
    else:
        raise AssertionError('restoration discarded a concurrent build-time edit')
    assert (source / stage.HEADER).read_text() == 'build-time edit that must survive'
    (source / stage.SOURCE).write_text('unexpected source revision')
    try:
        stage.stage(temp / 'bad', source)
    except ValueError:
        pass
    else:
        raise AssertionError('stale verifier boundary accepted')
print('trust observer wrapper, privacy, concurrency, original exceptions, and restoration: PASS')
