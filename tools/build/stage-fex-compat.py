#!/usr/bin/env python3
"""Apply Madeira's downstream FEX overlay and restore exact pinned inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FILES = ('Source/Windows/WOW64/Module.cpp', 'FEXCore/include/FEXCore/Utils/AllocatorHooks.h',
         'Source/Windows/Common/InvalidationTracker.cpp',
         'FEXCore/include/FEXCore/Utils/ThreadPoolAllocator.h',
         'FEXCore/include/FEXCore/fextl/memory.h',
         'FEXCore/Source/Interface/IR/IntrusiveIRList.h',
         'FEXCore/Source/Interface/IR/IREmitter.h',
         'FEXCore/Source/Interface/Core/Frontend.h',
         'FEXCore/Source/Interface/Core/Frontend.cpp',
         'FEXCore/Source/Interface/Core/Core.cpp',
         'FEXCore/Source/Interface/Core/JIT/JIT.cpp',
         'FEXCore/Source/Interface/Core/LookupCache.cpp',
         'FEXCore/Source/Interface/Core/LookupCache.h',
         'FEXCore/Source/Interface/Context/Context.h',
         'FEXCore/include/FEXCore/Utils/WritePriorityMutex.h',
         'FEXCore/Source/Utils/Allocator.cpp',
         'FEXCore/include/FEXCore/Utils/Telemetry.h',
         'FEXCore/Source/Utils/Telemetry.cpp',
         'FEXCore/Source/Interface/IR/IRTopologyCheck.h',
         'Source/Windows/WOW64/CMakeLists.txt',
         'Source/Windows/WOW64/libwow64fex.def')
PATCH = ROOT / 'build/fex-compat/thread-init.patch'
PATCHES = ('thread-init.patch', 'guest-write.patch', 'compiler-startup.patch', 'ir-pool-failure.patch',
           'arena-exports.patch', 'lookup-blocklist.patch', 'hold-release.patch', 'thread-retire.patch',
           'subfloor-domain.patch', 'native-diagnostics.patch', 'native-tracker-storage.patch')
ARM64EC_FILES = ('Source/Windows/ARM64EC/Module.cpp', 'Source/Windows/ARM64EC/libarm64ecfex_ios.def',
                 'Source/Windows/ARM64EC/IosJitAlias.cpp', 'Source/Windows/ARM64EC/CMakeLists.txt')


def files_for(backend):
    if backend == 'arm64ec':
        return tuple(n for n in FILES if '/WOW64/' not in n) + ARM64EC_FILES
    return FILES + (ARM64EC_FILES if backend == 'both' else ())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(destination, source, backend='wow64'):
    destination = destination.resolve()
    files = files_for(backend)
    for name in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    # Select by source path: ARM64EC shares the core allocator/compiler fixes,
    # but retains its own Module.cpp, TLS/termination ABI and existing DATA exports.
    includes = [f'--include={name}' for name in files]
    for name in PATCHES:
        patch = ROOT / 'build/fex-compat' / name
        # git apply rejects a patch whose every file was intentionally excluded.
        paths = [line[6:] for line in patch.read_text().splitlines() if line.startswith('+++ b/')]
        if not any(path in files for path in paths):
            continue
        # A stage may live inside another Git worktree. Without an explicit
        # work tree, git prefixes --include paths with that outer repository's
        # subdirectory and can silently skip every hunk while returning zero.
        command = ['git', '-C', str(destination), '--work-tree=' + str(destination), 'apply']
        subprocess.run([*command, *includes, '--check', str(patch)], check=True)
        subprocess.run([*command, *includes, str(patch)], check=True)


def apply(state, source, backend='wow64'):
    files = files_for(backend)
    for name in files:
        subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', 'HEAD', '--', name], check=True)
    stage(state / 'staged', source, backend)
    for name in files:
        backup = state / 'originals' / name
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, backup)
    manifest = {'source': str(source), 'backend': backend, 'after': {n: digest(state / 'staged' / n) for n in files}}
    (state / 'manifest.json').write_text(json.dumps(manifest))
    try:
        for name in files:
            shutil.copyfile(state / 'staged' / name, source / name)
    except BaseException:
        for name in files:
            shutil.copyfile(state / 'originals' / name, source / name)
        raise


def restore(state):
    manifest = json.loads((state / 'manifest.json').read_text())
    source = Path(manifest['source'])
    for name, expected in manifest['after'].items():
        if digest(source / name) != expected:
            raise SystemExit(f'Refusing to overwrite build-time edits: {name}; backup: {state}')
    for name in manifest['after']:
        shutil.copyfile(state / 'originals' / name, source / name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'apply', 'restore'))
    parser.add_argument('directory', type=Path)
    parser.add_argument('--source', type=Path, default=ROOT / 'FEX')
    parser.add_argument('--backend', choices=('wow64', 'arm64ec', 'both'), default='wow64')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    if args.operation == 'stage': stage(args.directory, args.source, args.backend)
    elif args.operation == 'apply': apply(args.directory, args.source, args.backend)
    else: restore(args.directory)
