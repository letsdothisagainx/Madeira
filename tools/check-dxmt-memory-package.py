#!/usr/bin/env python3
"""Reject stale D3D11 PE/native binaries and prove the packaged memory recipe.

This is binary/source provenance, not an iPhone memory or rendered-pixel test.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import subprocess
import tempfile
import zipfile

FARMS = ('aarch64-windows', 'arm64ec-windows', 'i386-windows')
MODULES = {'d3d11.dll': 'D3D11CreateDevice', 'dxgi.dll': 'CreateDXGIFactory1',
           'd3d10core.dll': 'D3D10CoreCreateDevice', 'winemetal.dll': None}
MANIFEST = 'arm64ec-windows/madeira-dxmt-memory.json'
PE_MARKERS = (b'[dynamic-memory-pressure-v1]', b'policy=bounded-hot-v2', b'storage=owner-heap-v1', b'[upload-memory-v1]')
NATIVE_MARKERS = (*PE_MARKERS, b'[madeira-memory-pressure-v1]')
RECIPES = (
    'tools/build/stage-dxmt-memory-compat.py', 'tools/build/stage-dxmt-upload-memory.py',
    'tools/build/stage-dxmt-dynamic-memory.py', 'tools/build/stage-dxmt-memory-pressure.py',
    'tools/build/build-dxmt-memory-compat.sh', 'tools/build/build-dxmt-ios.sh',
    'tools/build/build-shader-headers.sh',
    'tools/check-dxmt-memory-package.py', 'tools/check-system-programs.py',
    'build/dxmt-ios/build.sh', 'build/dxmt-ios/memory_pressure.hpp',
    'build/dxmt-ios/memory_pressure_native.h', 'build/dxmt-ios/graphics_diagnostics.h',
    'build/dxmt-ios/metal_lifecycle.h', 'build/dxmt-ios/metal_submission_gate.h',
    'tools/build/stage-dxmt-diagnostics.py', 'tools/build/stage-dxmt-lifecycle.py',
)


def sha(path):
    assert path.is_file() and not path.is_symlink(), 'missing or symlinked DXMT build input: ' + str(path)
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def markers(path, required):
    assert path.is_file() and not path.is_symlink() and path.stat().st_size, 'missing compiled DXMT image'
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for marker in required:
            assert data.find(marker) >= 0, 'stale compiled DXMT memory contract: ' + marker.decode()


def sources(repo, transaction=None):
    if transaction is not None:
        data = json.loads((transaction / 'state.json').read_text())
        assert data.get('restored') and not data.get('applied'), 'DXMT source transaction was not restored'
        for name, record in data['records'].items():
            path = repo / 'dxmt' / name
            assert (sha(path) if path.exists() else None) == record['original'], 'DXMT original source differs: ' + name
    else:
        with tempfile.TemporaryDirectory(prefix='madeira-dxmt-verify-') as directory:
            state = Path(directory) / 'transaction'
            subprocess.run(['python3', str(repo / 'tools/build/stage-dxmt-memory-compat.py'),
                            'prepare', str(state), '--root', str(repo)], check=True, stdout=subprocess.DEVNULL)
            data = json.loads((state / 'state.json').read_text())
    return {name: {'original': record['original'], 'staged': record['staged']}
            for name, record in data['records'].items()}


def recipe_inputs(repo):
    return {name: sha(repo / name) for name in RECIPES}


def pin(repo, name):
    return subprocess.check_output(['git', '-C', str(repo / name), 'rev-parse', 'HEAD'], text=True).strip()


SHADER = 'src/airconv/shaders/air_tessellation.metal'


def shader_bytes(repo):
    """Attribute the existing Xcode 27 shader fix without allowing other edits."""
    original = subprocess.check_output(['git', '-C', str(repo / 'dxmt'), 'show', 'HEAD:' + SHADER])
    recipe = (repo / 'tools/build/build-shader-headers.sh').read_text()
    # Read, never execute, the existing owned recipe's Python here-document.
    body = recipe.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
    tree = ast.parse(body)
    assignments = {node.targets[0].id: node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name)}
    old = ast.literal_eval(assignments['old'])
    expected = '  return __metal_atomic_fetch_add_explicit(out_count, 1, int(memory_order_relaxed), __METAL_MEMORY_SCOPE_THREADGROUP__);\n'
    assert old == expected, 'existing Metal atomic compatibility anchor changed'
    expected_new = ast.parse('new = ("#ifdef __METAL_MEMORY_FLAGS_NONE__\\n" + old.replace("__);", "__, __METAL_MEMORY_FLAGS_NONE__);") + "#else\\n" + old + "#endif\\n")').body[0].value
    assert ast.dump(assignments['new']) == ast.dump(expected_new), 'existing Metal atomic compatibility transform changed'
    new = '#ifdef __METAL_MEMORY_FLAGS_NONE__\n' + old.replace('__);', '__, __METAL_MEMORY_FLAGS_NONE__);') + '#else\n' + old + '#endif\n'
    text = original.decode()
    assert text.count(old) == 1 and '__METAL_MEMORY_FLAGS_NONE__' not in text, 'pinned Metal shader compatibility input changed'
    return original, text.replace(old, new, 1).encode()


def compiled_shader_inputs(repo, writing=False):
    original, patched = shader_bytes(repo)
    path = repo / 'dxmt' / SHADER
    assert path.is_file() and not path.is_symlink(), 'missing or symlinked Metal shader input'
    current = path.read_bytes()
    assert current in ((patched,) if writing else (original, patched)), 'unattributed Metal shader source modification'
    return {'path': SHADER, 'original_sha256': hashlib.sha256(original).hexdigest(),
            'compiled_sha256': hashlib.sha256(patched).hexdigest(),
            'recipe_sha256': sha(repo / 'tools/build/build-shader-headers.sh')}


def check_source_tree(repo):
    changed = subprocess.check_output(['git', '-C', str(repo / 'dxmt'), 'diff', '--name-only', 'HEAD', '--'], text=True).splitlines()
    assert set(changed) <= {SHADER}, 'unrecorded modified DXMT source paths: ' + ', '.join(changed)
    compiled_shader_inputs(repo, writing=True)
    print('PASS DXMT preflight: only the exact pre-existing Xcode Metal atomic compatibility transform is present')


def check(root, repo, write=False, transaction=None, app=None, ipa=None):
    spec = importlib.util.spec_from_file_location('dxmt_pe_inspection', repo / 'tools/check-system-programs.py')
    pe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pe)
    binaries = {}
    for farm in FARMS:
        for module, export in MODULES.items():
            name = farm + '/' + module
            image = root / name
            data = pe.read(image)
            binaries[name] = pe.inspect(data, farm, required_export=export)
            if module == 'd3d11.dll':
                for marker in PE_MARKERS:
                    assert marker in data, 'stale real D3D11 implementation: ' + name + ': ' + marker.decode()
    recipe = recipe_inputs(repo)
    shader = compiled_shader_inputs(repo, writing=write)
    staged_sources = sources(repo, transaction if write else None)
    metadata = {'recipe': 1, 'pins': {name: pin(repo, name) for name in ('wine', 'dxmt')},
                'inputs': recipe, 'shader': shader, 'sources': staged_sources, 'binaries': binaries,
                'scope': 'completed-only upload and dynamic backing retirement; measured native process budget',
                'device_acceptance': 'unmeasured'}
    native = root / 'libdxmt_combined.a'
    if write:
        assert transaction is not None, 'build transaction proof required to write DXMT manifest'
        markers(native, NATIVE_MARKERS)
        metadata['native'] = {'sha256': sha(native), 'bytes': native.stat().st_size}
        path = root / MANIFEST
        pending = path.with_suffix('.json.pending')
        assert not path.is_symlink() and not pending.exists() and not pending.is_symlink(), 'unowned DXMT manifest output'
        pending.write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
        pending.replace(path)
    stored = json.loads(pe.read(root / MANIFEST, 1 << 20), object_pairs_hook=pe.unique_object)
    assert set(stored) == set(metadata) | ({'native'} if not write else set()), 'invalid DXMT build manifest shape'
    for field in metadata:
        assert stored.get(field) == metadata[field], 'stale DXMT memory build provenance: ' + field
    assert set(stored['native']) == {'sha256', 'bytes'} and stored['native']['bytes'] > 0, 'missing native DXMT build provenance'
    if native.exists():
        assert sha(native) == stored['native']['sha256'] and native.stat().st_size == stored['native']['bytes'], 'stale native DXMT archive'
        markers(native, NATIVE_MARKERS)
    else:
        assert ipa is not None or app is not None, 'native DXMT archive missing before package'
    paths = [*binaries, MANIFEST]
    if app:
        for name in paths:
            assert pe.read(app / name) == pe.read(root / name), 'stale app DXMT memory binary: ' + name
        markers(app / 'Madeira.debug.dylib', NATIVE_MARKERS)
    if ipa:
        with zipfile.ZipFile(ipa) as archive:
            for name in paths:
                target = 'Payload/Madeira.app/' + name
                entries = [item for item in archive.infolist() if item.filename == target]
                assert len(entries) == 1, 'missing or duplicate IPA DXMT resource: ' + name
                expected = pe.read(root / name)
                assert entries[0].file_size == len(expected), 'stale IPA DXMT resource length: ' + name
                with archive.open(entries[0]) as stream:
                    assert stream.read(len(expected) + 1) == expected, 'stale IPA DXMT resource: ' + name
            # Scan the linked native image in bounded chunks; do not duplicate a
            # large IPA or LLVM-bearing native library in Python's heap.
            matches = {marker: False for marker in NATIVE_MARKERS}
            with archive.open('Payload/Madeira.app/Madeira.debug.dylib') as stream:
                previous = b''
                for block in iter(lambda: stream.read(1 << 20), b''):
                    data = previous + block
                    for marker in matches:
                        matches[marker] |= marker in data
                    previous = data[-128:]
            assert all(matches.values()), 'stale linked IPA DXMT memory implementation'
    print('PASS rebuilt DXMT memory recipe: real D3D11 PE exports and ARM64EC/A64/I386 ABIs, source/staged/native hashes and exact package copies; iPhone map loading remains unmeasured')
    return stored


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--transaction', type=Path)
    parser.add_argument('--write-manifest', action='store_true')
    parser.add_argument('--check-source-tree', action='store_true')
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    if args.check_source_tree:
        check_source_tree(args.repo_root.resolve())
    else:
        check(args.root.resolve(), args.repo_root.resolve(), args.write_manifest,
              args.transaction, args.app, args.ipa)
