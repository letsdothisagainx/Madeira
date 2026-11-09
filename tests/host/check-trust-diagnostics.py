#!/usr/bin/env python3
"""Exercise the actual observation wrapper and fail-closed staging/restoration."""
import importlib.util
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
