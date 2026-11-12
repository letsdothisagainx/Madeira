#!/usr/bin/env python3
"""Exercise actual DXMT source staging/restore and the fail-closed build gates.

No fixture in this test claims GPU execution, map loading or a memory reduction.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dxmt_memory_transaction', ROOT / 'tools/build/stage-dxmt-memory-compat.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
spec = importlib.util.spec_from_file_location('dxmt_memory_package', ROOT / 'tools/check-dxmt-memory-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def run(repo, operation, state):
    return subprocess.run(['python3', str(repo / 'tools/build/stage-dxmt-memory-compat.py'),
                           operation, str(state), '--root', str(repo)], capture_output=True, text=True)


with tempfile.TemporaryDirectory(prefix='madeira-dxmt-transaction-') as directory:
    repo = Path(directory) / 'repo'
    inputs = [*('src/dxmt/' + name for name in stage.UPLOAD), *stage.DYNAMIC]
    original = {}
    for name in inputs:
        path = repo / 'dxmt' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / 'dxmt' / name).read_bytes()
        path.write_bytes(data)
        original[name] = data
    scripts = ['stage-dxmt-memory-compat.py', 'stage-dxmt-upload-memory.py', 'stage-dxmt-dynamic-memory.py']
    for name in scripts:
        path = repo / 'tools/build' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'tools/build' / name, path)
    header = repo / 'build/dxmt-ios/memory_pressure.hpp'
    header.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'build/dxmt-ios/memory_pressure.hpp', header)
    unrelated = repo / 'dxmt/unrelated-source.cpp'
    unrelated.write_bytes(b'preserve this unrelated file\n')
    state = Path(directory) / 'state'
    result = run(repo, 'apply', state)
    assert result.returncode == 0, result.stdout + result.stderr
    metadata = json.loads((state / 'state.json').read_text())
    assert len(metadata['records']) == 11 and metadata['applied']
    for name, record in metadata['records'].items():
        assert hashlib.sha256((repo / 'dxmt' / name).read_bytes()).hexdigest() == record['staged']
    # Both PE and native compiler commands compile beside these exact headers.
    assert 'TrimCompletedForQueue' in (repo / 'dxmt/src/dxmt/dxmt_dynamic.hpp').read_text()
    assert '[upload-memory-v1]' in (repo / 'dxmt/src/dxmt/dxmt_resource_initializer.cpp').read_text()
    assert '[dynamic-memory-pressure-v1]' in (repo / 'dxmt/src/dxmt/dxmt_dynamic.cpp').read_text()
    result = run(repo, 'restore', state)
    assert result.returncode == 0, result.stdout + result.stderr
    for name, data in original.items():
        assert (repo / 'dxmt' / name).read_bytes() == data
    assert not (repo / 'dxmt' / stage.HEADER).exists()
    assert unrelated.read_bytes() == b'preserve this unrelated file\n'
    assert run(repo, 'restore', state).returncode == 0, 'restore must be idempotent'
    print('PASS actual production DXMT source staging applies all 11 owned files; restores byte-exact originals/new-header absence, preserves unrelated files and permits repeated cleanup')

    # Emulate interruption halfway through application, before applied=true.
    half = Path(directory) / 'half'
    result = run(repo, 'prepare', half)
    assert result.returncode == 0, result.stdout + result.stderr
    metadata = json.loads((half / 'state.json').read_text())
    for name in list(metadata['records'])[:5]:
        (repo / 'dxmt' / name).write_bytes((half / 'replacement' / name).read_bytes())
    assert run(repo, 'restore', half).returncode == 0
    assert all((repo / 'dxmt' / name).read_bytes() == data for name, data in original.items())
    print('PASS interrupted/partial apply cleanup restores the real production source inputs')

    changed = Path(directory) / 'changed'
    assert run(repo, 'apply', changed).returncode == 0
    edited = repo / 'dxmt/src/dxmt/dxmt_dynamic.hpp'
    edited.write_bytes(edited.read_bytes() + b'\n// unrelated simultaneous developer edit\n')
    result = run(repo, 'restore', changed)
    assert result.returncode != 0 and 'source changed during build' in result.stderr
    assert b'unrelated simultaneous developer edit' in edited.read_bytes()
    # Test owns that edit and can remove it; the production restorer may not.
    edited.write_bytes((changed / 'replacement/src/dxmt/dxmt_dynamic.hpp').read_bytes())
    assert run(repo, 'restore', changed).returncode == 0
    print('PASS concurrent unrelated source changes fail closed rather than being silently discarded')

    native = Path(directory) / 'native.a'
    native.write_bytes(b'archive fixture' + b'\0'.join(package.NATIVE_MARKERS))
    package.markers(native, package.NATIVE_MARKERS)
    native.write_bytes(b'old native archive without the process-budget producer')
    try:
        package.markers(native, package.NATIVE_MARKERS)
    except AssertionError:
        pass
    else:
        raise AssertionError('stale native DXMT image passed marker gate')
    print('PASS compiled native marker gate rejects the old native implementation; fixture supplies no Metal execution result')


# The existing shader-header builder intentionally changes one tracked Metal
# source for Xcode 27. Attribute only its exact known bytes, never a wildcard.
with tempfile.TemporaryDirectory(prefix='madeira-dxmt-shader-proof-') as directory:
    repo = Path(directory)
    shader = repo / 'dxmt' / package.SHADER
    shader.parent.mkdir(parents=True)
    original, canonical = package.shader_bytes(ROOT)
    shader.write_bytes(original)
    unrelated = repo / 'dxmt/unrelated.cpp'
    unrelated.write_text('original tracked source\n')
    recipe = repo / 'tools/build/build-shader-headers.sh'
    recipe.parent.mkdir(parents=True)
    recipe.write_bytes((ROOT / 'tools/build/build-shader-headers.sh').read_bytes())
    subprocess.run(['git', 'init', '-q', str(repo / 'dxmt')], check=True)
    subprocess.run(['git', '-C', str(repo / 'dxmt'), 'add', package.SHADER, 'unrelated.cpp'], check=True)
    subprocess.run(['git', '-C', str(repo / 'dxmt'), '-c', 'user.name=DXMT build fixture',
                    '-c', 'user.email=fixture@invalid', '-c', 'core.hooksPath=/dev/null',
                    'commit', '-qm', 'Pinned shader fixture'], check=True)
    pristine_proof = package.compiled_shader_inputs(repo)
    try:
        package.check_source_tree(repo)
    except AssertionError:
        pass
    else:
        raise AssertionError('build preflight must require the shader bytes actually compiled by the existing builder')
    shader.write_bytes(canonical)
    package.check_source_tree(repo)
    assert package.compiled_shader_inputs(repo, writing=True) == pristine_proof
    shader.write_bytes(canonical + b'\n// unowned source change\n')
    try:
        package.check_source_tree(repo)
    except AssertionError:
        pass
    else:
        raise AssertionError('unattributed shader modification accepted')
    shader.write_bytes(canonical)
    unrelated.write_text('unrecorded tracked source change\n')
    try:
        package.check_source_tree(repo)
    except AssertionError:
        pass
    else:
        raise AssertionError('unrelated source change accepted')
    print('PASS actual build guard accepts only the exact pre-existing Metal atomic patch; modified shader/other tracked files fail; pristine post-IPA checkout derives identical compiled-source provenance')

entry = (ROOT / 'tools/build-ipa.sh').read_text()
recipe = (ROOT / 'tools/build/build-dxmt-memory-compat.sh').read_text()
assert '"$ROOT/tools/build/build-dxmt-memory-compat.sh"' in entry
assert recipe.index('memory-compat.py" apply') < recipe.index('for farm in aarch64-windows arm64ec-windows i386-windows; do')
assert recipe.index('memory-compat.py" restore "$STATE"\npython3') > recipe.index('"$ROOT/tools/build/build-dxmt-ios.sh"')
for target in ('src/d3d11/d3d11.dll.postproc', 'src/dxgi/dxgi.dll.postproc',
               'src/d3d10/d3d10core.dll.postproc', 'src/winemetal/winemetal.dll.postproc'):
    assert target in recipe
native_recipe = (ROOT / 'build/dxmt-ios/build.sh').read_text()
assert 'stage-dxmt-memory-pressure.py' in native_recipe and 'compile_objc "$BUILD_DIR/staged/winemetal_memory.c" winemetal_unix' in native_recipe
print('PASS actual IPA entry point invokes native + real PE builds for all three farms, retains builtin/hybrid postprocessing and compiles the native measured-budget producer')
