#!/usr/bin/env python3
"""Backport Wine's ordinary PKCS#7 attribute-order verification correction.

The exact upstream change preserves verification inputs; it neither supplies a
trust verdict nor changes signature generation, certificate or file checks.
Only the private-header insertion context differs from the upstream patch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'build/wine-pe/crypt32-authattrs-order.patch'
PROVENANCE = ROOT / 'build/wine-pe/crypt32-authattrs-order.json'
SOURCES = tuple(Path('dlls/crypt32') / name for name in ('crypt32_private.h', 'encode.c', 'msg.c'))


def regular(path, description):
    if path.is_symlink() or not path.is_file():
        raise ValueError(description + ' must be a regular file')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def description():
    regular(PATCH, 'crypt32 compatibility patch')
    regular(PROVENANCE, 'crypt32 compatibility provenance')
    data = json.loads(PROVENANCE.read_text())
    if (data.get('format') != 1 or data.get('upstreamCommit') != 'a358d7ecf13b420d7fa65d54fcad1f96003d7a48' or
            set(data.get('files', {})) != {str(p) for p in SOURCES} or digest(PATCH) != data.get('patchSHA256')):
        raise ValueError('invalid crypt32 compatibility patch provenance')
    return data


def stage(destination, source):
    data = description()
    for name in SOURCES:
        regular(source / name, 'crypt32 compatibility input')
        if digest(source / name) != data['files'][str(name)]['beforeSHA256']:
            raise ValueError('unexpected or already patched crypt32 input: ' + str(name))
        if (destination / name).exists() or (destination / name).is_symlink():
            raise ValueError('refusing an existing crypt32 staging output: ' + str(name))
    # A build state can live inside the repository. Apply in an isolated copy
    # so git's repository-prefix rules cannot silently skip every patch hunk.
    with tempfile.TemporaryDirectory(prefix='madeira-authattrs-source-') as temporary:
        scratch = Path(temporary)
        for name in SOURCES:
            (scratch / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, scratch / name)
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(scratch))
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            env.pop(key, None)
        subprocess.run(['git', 'apply', '--no-index', '--check', str(PATCH)], cwd=scratch, env=env, check=True)
        subprocess.run(['git', 'apply', '--no-index', str(PATCH)], cwd=scratch, env=env, check=True)
        for name in SOURCES:
            if digest(scratch / name) != data['files'][str(name)]['afterSHA256']:
                raise ValueError('crypt32 backport output differs from reviewed upstream change: ' + str(name))
        for name in SOURCES:
            (destination / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(scratch / name, destination / name)


def apply(state, source):
    if (state / 'manifest.json').exists() or (state / 'manifest.json').is_symlink():
        raise ValueError('refusing an existing crypt32 compatibility transaction')
    stage(state / 'staged', source)
    data = description()
    for name in SOURCES:
        (state / 'original' / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, state / 'original' / name)
    manifest = {'source': str(source.resolve()), 'format': 1, 'files': data['files'], 'applied': False}
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')
    try:
        for name in SOURCES:
            shutil.copyfile(state / 'staged' / name, source / name)
        for name in SOURCES:
            if digest(source / name) != data['files'][str(name)]['afterSHA256']:
                raise ValueError('crypt32 compatibility publication failed: ' + str(name))
    except BaseException:
        for name in SOURCES:
            shutil.copyfile(state / 'original' / name, source / name)
        raise
    manifest['applied'] = True
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')


def restore(state):
    regular(state / 'manifest.json', 'crypt32 compatibility transaction')
    manifest = json.loads((state / 'manifest.json').read_text())
    data = description()
    if manifest.get('format') != 1 or manifest.get('files') != data['files']:
        raise ValueError('invalid crypt32 compatibility restoration description')
    source = Path(manifest['source'])
    expected = 'afterSHA256' if manifest['applied'] else 'beforeSHA256'
    for name in SOURCES:
        regular(source / name, 'crypt32 staged source')
        regular(state / 'original' / name, 'crypt32 original source')
        if digest(source / name) != data['files'][str(name)][expected]:
            raise ValueError('refusing to discard build-time crypt32 source changes: ' + str(name))
        if digest(state / 'original' / name) != data['files'][str(name)]['beforeSHA256']:
            raise ValueError('invalid crypt32 source backup: ' + str(name))
    if manifest['applied']:
        for name in SOURCES:
            shutil.copyfile(state / 'original' / name, source / name)
        manifest['applied'] = False
        (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')


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
