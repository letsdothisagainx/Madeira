#!/usr/bin/env python3
"""Stage the bounded GetMappedFileNameW result/capacity correction.

The ordinary Wine filename query and its errors are unchanged. This stage only
repairs the public output-buffer contract; it does not change image identity,
signature validation, security policy, or any game decision.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path('dlls/kernelbase/debug.c')
PATCH = ROOT / 'build/wine-pe/mapped-filename-contract.patch'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, description):
    if path.is_symlink() or not path.is_file():
        raise ValueError(description + ' must be a regular file')


def stage(destination, source):
    target = destination / SOURCE
    regular(source / SOURCE, 'mapped-filename source')
    regular(PATCH, 'mapped-filename patch')
    if target.exists() or target.is_symlink():
        raise ValueError('refusing an existing mapped-filename staging output')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / SOURCE, target)
    before = target.read_bytes()
    try:
        subprocess.run(['git', '-C', str(destination), 'apply', '--no-index', '--check', str(PATCH)],
                       check=True, capture_output=True, text=True)
        subprocess.run(['git', '-C', str(destination), 'apply', '--no-index', str(PATCH)],
                       check=True, capture_output=True, text=True)
        text = target.read_text()
        start = text.index('DWORD WINAPI DECLSPEC_HOTPATCH GetMappedFileNameW(')
        body = text[start:text.index('\n}', start) + 2]
        if (target.read_bytes() == before or body.count('    if (!size)') != 1 or
                body.count('    return min( len, size );') != 1):
            raise ValueError('mapped-filename patch did not produce the bounded output contract')
    except BaseException:
        target.unlink()
        raise


def apply(state, source):
    if (state / 'manifest.json').exists() or (state / 'manifest.json').is_symlink():
        raise ValueError('refusing an existing mapped-filename transaction')
    stage(state / 'staged', source)
    backup = state / 'original/debug.c'
    backup.parent.mkdir()
    shutil.copyfile(source / SOURCE, backup)
    manifest = {'source': str(source.resolve()), 'before': digest(backup),
                'after': digest(state / 'staged' / SOURCE)}
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')
    try:
        shutil.copyfile(state / 'staged' / SOURCE, source / SOURCE)
    except BaseException:
        shutil.copyfile(backup, source / SOURCE)
        raise


def restore(state):
    regular(state / 'manifest.json', 'mapped-filename transaction')
    manifest = json.loads((state / 'manifest.json').read_text())
    source = Path(manifest['source'])
    regular(source / SOURCE, 'mapped-filename staged source')
    regular(state / 'original/debug.c', 'mapped-filename original source')
    if digest(source / SOURCE) != manifest['after']:
        raise ValueError('refusing to discard build-time mapped-filename source changes')
    if digest(state / 'original/debug.c') != manifest['before']:
        raise ValueError('invalid mapped-filename source backup')
    shutil.copyfile(state / 'original/debug.c', source / SOURCE)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'apply', 'restore'))
    parser.add_argument('directory', type=Path)
    parser.add_argument('--source', type=Path, default=ROOT / 'wine')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    if args.operation == 'stage':
        stage(args.directory, args.source)
    elif args.operation == 'apply':
        apply(args.directory, args.source)
    else:
        restore(args.directory)
