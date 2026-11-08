#!/usr/bin/env python3
"""Run both production PE recipes through their real shared overlay wrapper.

CMake compilation is substituted here; allocator behavior and PE package
validation have separate production-source and image fixtures.
"""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fex_stage', ROOT / 'tools/build/stage-fex-compat.py')
stager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stager)

with tempfile.TemporaryDirectory(prefix='madeira-fex-pe-') as temporary:
    root = Path(temporary)
    sources = stager.files_for('both')
    scripts = ('tools/build/stage-fex-compat.py', 'tools/build/build-fex-pe-compat.sh',
               'tools/build/build-fex-wow64-compat.sh', 'tools/build/build-fex-arm64ec-compat.sh',
               'build/fex-wow64/build.sh', 'build/fex-arm64ec/build.sh')
    for relative in (*scripts, *('build/fex-compat/' + name for name in stager.PATCHES)):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, path)
    for relative in sources:
        path = root / 'FEX' / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'FEX' / relative, path)
    source = root / 'FEX'
    subprocess.run(['git', 'init', '-q', str(source)], check=True)
    subprocess.run(['git', '-C', str(source), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'pinned fixture'], check=True)
    originals = {name: (source / name).read_bytes() for name in sources}
    for backend in ('wow64', 'arm64ec'):
        cache = source / ('build-' + backend)
        cache.mkdir()
        (cache / 'CMakeCache.txt').write_text('old cache without owned heap hook\n')
        (root / 'app/Madeira' / ('aarch64-windows' if backend == 'wow64' else 'arm64ec-windows')).mkdir(parents=True)

    commands = root / 'bin'
    commands.mkdir()
    trace = root / 'trace.jsonl'
    cmake = commands / 'cmake'
    cmake.write_text(r'''#!/usr/bin/env python3
import json, os, struct, sys
from pathlib import Path
root=Path(os.environ['ROOT']); args=sys.argv[1:]
with Path(os.environ['PE_TRACE']).open('a') as log:log.write(json.dumps(args)+'\n')
core=root/'FEX/FEXCore/Source/Interface/IR/IREmitter.h'
assert 'TryReownOrClaimBuffer()' in core.read_text()
assert '[fex-ir-pool-v1]' in core.read_text()
wow=(root/'FEX/Source/Windows/WOW64/Module.cpp').read_text()
build_dir=Path(args[1] if args[0]=='--build' else args[args.index('-B')+1])
if build_dir.name=='build-wow64':assert 'MadeiraPrepareFirstDispatch' in wow
else:assert 'MadeiraPrepareFirstDispatch' not in (root/'FEX/Source/Windows/ARM64EC/Module.cpp').read_text()
if args[0]=='--build':
    target=args[args.index('--target')+1]
    if target=='arm64ecfex' and os.environ.get('FAIL_EC')=='1':sys.exit(37)
    output=Path(args[1])/'Bin'/('libwow64fex.dll' if target=='wow64fex' else 'libarm64ecfex.dll')
    output.parent.mkdir(exist_ok=True)
    data=bytearray(0x300);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0';struct.pack_into('<I',data,0x80+24+56,len(data))
    output.write_bytes(data)
''')
    cmake.chmod(0o755)
    (root / 'tools/check-io-abi-package.py').write_text('''
import os
from pathlib import Path
def fex_cpu(data, backend):
    with Path(os.environ['PE_TRACE']).open('a') as trace:trace.write('"checked-'+backend+'"\\n')
''')
    env = dict(os.environ, ROOT=str(root), PE_TRACE=str(trace), PATH=str(commands) + os.pathsep + os.environ['PATH'])
    wrapper = root / 'tools/build/build-fex-pe-compat.sh'

    def run(backend='both', **extra):
        return subprocess.run(['bash', str(wrapper), backend], env=dict(env, **extra), capture_output=True, text=True)

    def restored():
        assert all((source / name).read_bytes() == data for name, data in originals.items())
        assert not (source / '.madeira-pe-overlay.lock').exists()
        assert not subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only'])

    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    restored()
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    calls = [event for event in events if isinstance(event, list)]
    assert [call[0] for call in calls] == ['-S', '--build', '-S', '--build'], calls
    assert [calls[i][calls[i].index('--target') + 1] for i in (1, 3)] == ['wow64fex', 'arm64ecfex']
    for call in (calls[0], calls[2]):
        assert '-DCMAKE_PROJECT_INCLUDE=' + str(root / 'build/fex-compat/owner_allocator.cmake') in call
        assert '-DENABLE_FEX_ALLOCATOR=ON' in call
        assert any(arg.startswith('-DCMAKE_ASM_FLAGS=-DFEX_IOS_HOST') for arg in call)
    assert events[-2:] == ['checked-wow64', 'checked-arm64ec']
    result = run(FAIL_EC='1')
    assert result.returncode == 37, result.stdout + result.stderr
    restored()
    for backend in ('arm64ec', 'wow64'):
        trace.write_text('')
        result = run(backend)
        assert result.returncode == 0, result.stdout + result.stderr
        restored()
        single = [json.loads(line) for line in trace.read_text().splitlines()]
        assert len(single) == 3 and single[0][0] == '-S' and single[1][0] == '--build'
        assert single[2] == 'checked-' + backend
    result = run('arm64ec', FAIL_EC='1')
    assert result.returncode == 37, result.stdout + result.stderr
    restored()
    lock = source / '.madeira-pe-overlay.lock'
    lock.mkdir()
    before = trace.read_bytes()
    result = run()
    assert result.returncode and 'Another FEX PE overlay build' in result.stderr
    assert trace.read_bytes() == before
    lock.rmdir()
    restored()

entry = (ROOT / 'tools/build-ipa.sh').read_text()
assert '"$ROOT/tools/build/build-fex-pe-compat.sh"' in entry
assert '"$ROOT/tools/build/build-fex-wow64-compat.sh"' not in entry
native = (ROOT / 'tools/build/build-fex-ios.sh').read_text()
assert '-DENABLE_FEX_ALLOCATOR=OFF' in native and 'owner_allocator.cmake' not in native
workflow = (ROOT / '.github/workflows/build.yml').read_text()
assert 'fex-pe-${{ steps.pins.outputs.fex }}' in workflow
for name in ('build/fex-compat/**', *scripts):
    assert name in workflow, name
print('PASS cached PE recipes always configure owned hooks and ASM flags; combined/ARM64EC-only/WoW64-only staging restores success and failed ARM64EC builds; concurrent staging refused')
