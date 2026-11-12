#!/usr/bin/env python3
"""Execute source-staged SRW locks and their actual Win32 futex queues.

Only NtWaitForAlertByThreadId/NtAlertThreadByThreadId use a portable pthread
backend. Lock arithmetic, waiter registration, queue removal and wake selection
are extracted unchanged from the production PE source. No Wine/FEX edits.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def function(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    return source[start:source.index('\n}\n', start) + 3]


def production_header():
    stager = module('native_counter_stage', ROOT / 'tools/build/stage-native-counter-writes.py')
    wake = module('native_srw_wake', ROOT / 'tools/build/stage-native-srw-wake.py')
    sources = {name: (ROOT / 'wine' / name).read_text() for name in stager.FILES}
    original = sources[stager.FILES[1]]
    staged = stager.stage(sources)[stager.FILES[1]]
    assert wake.stage(original).replace(wake.GUARDED, wake.ORIGINAL, 1) == original
    for invalid in (staged, original.replace(wake.ORIGINAL, '/* absent wake */', 1),
                    original + '\n' + wake.SIGNATURE):
        try:
            wake.stage(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('SRW stager must reject missing, duplicate or already staged anchors')
    first = 'void WINAPI RtlAcquireSRWLockExclusive'
    end = '/* RtlWaitOnAddress()'
    bodies = staged[staged.index(first):staged.index(end)]
    assert bodies.count(wake.GUARDED) == 1
    assert bodies.replace(wake.GUARDED, wake.ORIGINAL, 1) == original[original.index(first):original.index(end)]
    # Public address-wait/wake APIs retain their exact bodies. Counters alone
    # use the previously established writer accessor in the composed overlay.
    futex_names = ['NTSTATUS WINAPI RtlWaitOnAddress(', 'void WINAPI RtlWakeAddressAll(',
                   'void WINAPI RtlWakeAddressSingle(']
    for signature in futex_names:
        assert function(staged, signature).replace('ios_xp_nt_writer()->', 'ios_xp_nt.') == function(original, signature)
    struct_start = staged.index('struct srw_lock\n')
    struct_end = staged.index('C_ASSERT( sizeof(struct srw_lock) == 4 );', struct_start)
    header = staged[struct_start:struct_end] + '\n'
    for signature in ['void WINAPI RtlInitializeSRWLock(',
                      'void WINAPI RtlAcquireSRWLockExclusive(', 'void WINAPI RtlAcquireSRWLockShared(',
                      'void WINAPI RtlReleaseSRWLockExclusive(', 'void WINAPI RtlReleaseSRWLockShared(',
                      'BOOLEAN WINAPI RtlTryAcquireSRWLockExclusive(', 'BOOLEAN WINAPI RtlTryAcquireSRWLockShared(']:
        header += function(staged, signature) + '\n'
    header += function(original, wake.SIGNATURE).replace('RtlReleaseSRWLockShared(', 'RtlReleaseSRWLockSharedOriginal(', 1) + '\n'
    start = staged.index('struct futex_entry\n')
    end = staged.index('/***********************************************************************\n *           RtlWaitOnAddress', start)
    header += staged[start:end]
    for signature in futex_names:
        header += function(staged, signature) + '\n'
    return header


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='madeira-native-srw-wake-') as directory:
        tmp = Path(directory)
        (tmp / 'production-srw-wake.h').write_text(production_header())
        binary = tmp / 'srw-wake'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-Wno-unused-variable', '-fno-strict-aliasing',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                        '-I', str(tmp), '-I', str(ROOT / 'wine/include'),
                        str(ROOT / 'tests/host/native-srw-wake-test.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=60)
