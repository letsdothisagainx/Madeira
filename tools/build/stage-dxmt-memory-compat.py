#!/usr/bin/env python3
"""Apply owned DXMT memory changes transactionally without changing its source pin.

Quoted includes in DXMT resolve beside the original .cpp first. Both PE and
native builds must therefore compile the same temporarily staged source tree;
a mere -I overlay silently compiles old production headers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

UPLOAD = ('dxmt_ring_bump_allocator.hpp', 'dxmt_resource_initializer.hpp',
          'dxmt_resource_initializer.cpp', 'dxmt_command_queue.cpp', 'dxmt_command_queue.hpp')
DYNAMIC = ('src/dxmt/dxmt_dynamic.hpp', 'src/dxmt/dxmt_dynamic.cpp',
           'src/d3d11/d3d11_buffer.cpp', 'src/d3d11/d3d11_texture_dynamic.cpp',
           'src/dxmt/dxmt_buffer.cpp')
CENSUS = ('src/dxmt/dxmt_mem_census.hpp', 'src/dxmt/dxmt_mem_census.cpp',
          'src/dxmt/dxmt_dynamic.cpp', 'src/dxmt/dxmt_buffer.cpp')
PERF = ('src/dxmt/dxmt_command_queue.hpp', 'src/dxmt/dxmt_command_queue.cpp',
        'src/d3d11/d3d11_context_impl.cpp', 'src/d3d11/d3d11_context_imm.cpp')
COMMAND_STATE = ('src/d3d11/d3d11_context_impl.cpp', 'src/d3d11/d3d11_swapchain.cpp')
HEADER = 'src/dxmt/memory_pressure.hpp'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    assert path.is_file() and not path.is_symlink(), 'missing or symlinked DXMT source: ' + str(path)
    assert path.stat().st_size < 32 << 20, 'oversized DXMT source'
    return path.read_bytes()


def replace(path, data, mode=0o644):
    pending = path.with_name(path.name + '.madeira-memory-pending')
    assert not pending.exists() and not pending.is_symlink(), 'unowned DXMT pending file: ' + str(pending)
    assert not path.is_symlink(), 'refusing symlinked DXMT destination'
    try:
        pending.write_bytes(data)
        pending.chmod(mode)
        pending.replace(path)
    finally:
        if pending.exists():
            pending.unlink()


def prepare(root, state):
    source = root / 'dxmt'
    assert not state.exists() or not any(state.iterdir()), 'DXMT transaction directory must be empty'
    state.mkdir(parents=True, exist_ok=True)
    generated = state / 'generated'
    upload = generated / 'upload'
    dynamic = generated / 'dynamic'
    subprocess.run([sys.executable, str(root / 'tools/build/stage-dxmt-upload-memory.py'),
                    '--source-dir', str(source / 'src/dxmt'), '--output-dir', str(upload)], check=True)
    subprocess.run([sys.executable, str(root / 'tools/build/stage-dxmt-dynamic-memory.py'),
                    '--source-dir', str(source), '--output-dir', str(dynamic)], check=True)
    outputs = {'src/dxmt/' + name: upload / name for name in UPLOAD}
    outputs.update({name: dynamic / name for name in DYNAMIC})
    # Compose from the already staged upload/cache implementation. These
    # additional passes change storage, not the cache or GPU lifetime policy.
    overlay = generated / 'composed'
    for name, staged in outputs.items():
        target = overlay / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(read(staged))
    for kind, recipe, names in (
        ('census', 'stage-dxmt-census-heap.py', CENSUS),
        ('perf', 'stage-dxmt-perf-heap.py', PERF),
        ('command-state', 'stage-dxmt-command-state.py', COMMAND_STATE),
    ):
        destination = generated / kind
        subprocess.run([sys.executable, str(root / 'tools/build' / recipe),
                        '--source-dir', str(source), '--output-dir', str(destination),
                        '--overlay-dir', str(overlay)], check=True)
        for name in names:
            staged = destination / name
            outputs[name] = staged
            target = overlay / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(read(staged))
    # The existing bounded pressure report also identifies the compiled storage
    # contract. Packaging rejects stale PE/native implementations by this marker.
    path = outputs['src/dxmt/dxmt_dynamic.cpp']
    text = read(path).decode()
    marker = 'storage=owner-heap-v1 cache-detached='
    assert text.count(marker) == 1, 'DXMT counter storage capability anchor changed'
    path.write_text(text.replace(marker, 'storage=owner-heap-v1 counter-storage=census-perf-heap-v1 pe-command-state=dedup-hud-v1 cache-detached=', 1))
    outputs[HEADER] = root / 'build/dxmt-ios/memory_pressure.hpp'
    records = {}
    for name, staged in outputs.items():
        path = source / name
        existed = path.exists()
        assert existed or name == HEADER, 'DXMT source disappeared: ' + name
        assert not (name == HEADER and existed), 'DXMT memory header is already staged'
        old = read(path) if existed else b''
        new = read(staged)
        backup = state / 'original' / name
        backup.parent.mkdir(parents=True, exist_ok=True)
        if existed:
            backup.write_bytes(old)
        materialized = state / 'replacement' / name
        materialized.parent.mkdir(parents=True, exist_ok=True)
        materialized.write_bytes(new)
        records[name] = {'existed': existed, 'original': sha(old) if existed else None,
                         'staged': sha(new), 'mode': path.stat().st_mode & 0o777 if existed else 0o644}
    metadata = {'recipe': 1, 'source': str(source.resolve()), 'records': records, 'applied': False}
    (state / 'state.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    return metadata


def load(state):
    return json.loads((state / 'state.json').read_text())


def restore(state):
    metadata = load(state)
    source = Path(metadata['source'])
    # Preflight every entry before restoring any: never discard an unrelated edit.
    for name, record in metadata['records'].items():
        path = source / name
        current = sha(read(path)) if path.exists() else None
        allowed = {record['staged'], record['original']}
        assert current in allowed, 'DXMT source changed during build; preserve it for review: ' + name
    for name, record in metadata['records'].items():
        path = source / name
        if record['existed']:
            original = read(state / 'original' / name)
            assert sha(original) == record['original'], 'DXMT source backup damaged'
            if sha(read(path)) != record['original']:
                replace(path, original, record['mode'])
        elif path.exists():
            path.unlink()
    for name, record in metadata['records'].items():
        path = source / name
        assert (sha(read(path)) if path.exists() else None) == record['original'], 'DXMT restoration failed'
    metadata['applied'] = False
    metadata['restored'] = True
    (state / 'state.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    print('Restored all pinned DXMT source bytes after memory build')


def apply(root, state):
    metadata = prepare(root, state)
    try:
        for name, record in metadata['records'].items():
            replace(root / 'dxmt' / name, read(state / 'replacement' / name), record['mode'])
        metadata['applied'] = True
        (state / 'state.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    except BaseException:
        restore(state)
        raise
    print('Applied owned DXMT memory sources for native and all three PE ABIs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'apply', 'restore'))
    parser.add_argument('state', type=Path)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    if args.operation == 'restore':
        restore(args.state)
    elif args.operation == 'prepare':
        prepare(args.root.resolve(), args.state.resolve())
    else:
        apply(args.root.resolve(), args.state.resolve())


if __name__ == '__main__':
    main()
