#!/usr/bin/env python3
"""Check actual owned submission policy and stage the production native path."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dxmt-root', type=Path, default=ROOT / 'dxmt')
args = parser.parse_args()
producer = args.dxmt_root / 'src/winemetal/unix/winemetal_unix.c'
original = producer.read_bytes()
digest = hashlib.sha256(original).hexdigest()


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ('tools/build/stage-dxmt-' + name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


diagnostics, lifecycle = module('diagnostics'), module('lifecycle')
observed = diagnostics.stage(original.decode())
staged = lifecycle.stage(observed)
start = staged.index('\n_MTLCommandBuffer_commit(void *obj) {')
commit = staged[start:staged.index('\n}', start) + 2]
assert 'md_metal_commit((id<MTLCommandBuffer>)params->handle);' in commit
assert 'event=command-submit-request n=' in commit and 'event=command-submit n=' not in commit
assert 'wmtr_call(RM_OP_COMMIT' in commit, 'remote backend must retain its own submission contract'
for unchanged in ('return STATUS_SUCCESS;', 'addCompletedHandler:', 'params->ret_error =',
                  'encodeSignalEvent:', 'waitUntilCompleted]', 'presentDrawable:'):
    assert staged.count(unchanged) == observed.count(unchanged), unchanged
assert lifecycle.stage(original.decode()).count('md_metal_commit(') == 1
for bad in (staged, original.decode().replace('  [(id<MTLCommandBuffer>)params->handle commit];', '  /* changed */')):
    try:
        lifecycle.stage(bad)
    except ValueError:
        pass
    else:
        raise AssertionError('changed or already staged native submission must fail closed')
adapter = (ROOT / 'build/dxmt-ios/metal_lifecycle.h').read_text()
assert '[NSThread isMainThread]' in adapter and '[buffer retain]' in adapter
assert '[pending->buffer commit];\n  [pending->buffer release];\n  free(pending);' in adapter
assert 'waitUntilCompleted' not in adapter and 'dispatch_sync' not in adapter
assert 'MTLCommandBufferStatusCompleted' not in adapter and 'STATUS_SUCCESS' not in adapter
build = (ROOT / 'build/dxmt-ios/build.sh').read_text()
assert build.index('stage-dxmt-diagnostics.py') < build.index('stage-dxmt-lifecycle.py') < build.index('compile_objc "$BUILD_DIR/staged/winemetal_unix.c"')
view = (ROOT / 'app/Madeira/ContentView.swift').read_text()
for notification, active in (('willResignActiveNotification', 0), ('didEnterBackgroundNotification', 0),
                             ('didBecomeActiveNotification', 1)):
    start = view.index('UIApplication.' + notification)
    assert 'madeira_metal_set_active(' + str(active) + ')' in view[start:start + 300], notification
assert 'madeira_metal_set_active(UIApplication.shared.applicationState == .active ? 1 : 0)' in view
assert 'void madeira_metal_set_active(int active);' in (ROOT / 'app/Madeira/Madeira-Bridging-Header.h').read_text()

with tempfile.TemporaryDirectory(prefix='madeira-metal-lifecycle-') as directory:
    temp = Path(directory)
    executable = temp / 'policy'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                    '-I', str(ROOT / 'build/dxmt-ios'), str(ROOT / 'tests/host/metal_submission_gate_test.c'),
                    '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
    observed_path = temp / 'winemetal_diagnostics.c'
    observed_path.write_text(observed)
    output = temp / 'winemetal_unix.c'
    subprocess.run(['python3', str(ROOT / 'tools/build/stage-dxmt-lifecycle.py'),
                    '--source', str(observed_path), '--output', str(output),
                    '--headers', str(ROOT / 'build/dxmt-ios')], check=True)
    assert output.read_text() == staged
    assert hashlib.sha256(producer.read_bytes()).hexdigest() == digest
    if sys.platform == 'darwin':
        (temp / 'graphics_diagnostics.h').write_bytes((ROOT / 'build/dxmt-ios/graphics_diagnostics.h').read_bytes())
        sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        command = ['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', 'arm64', '-isysroot', sdk,
                   '-miphoneos-version-min=18.0', '-fblocks', '-x', 'objective-c', '-fsyntax-only']
        for include in ('include', 'libs', 'src/winemetal', 'src/winemetal/unix', 'src/airconv'):
            command += ['-I', str(args.dxmt_root / include)]
        subprocess.run(command + [str(output)], check=True)
        print('PASS actual combined diagnostics/lifecycle Objective-C source against iPhoneOS SDK')
print('PASS real native Metal commit staging: input immutable, remote path/status/error/completion/event APIs unchanged; actual GPU background/foreground run still required')
