#!/usr/bin/env python3
"""Stage real named registry security operations for explicit WOW64 views.

The view selector applies only to RegOpenKeyExW. The resulting handle goes to
the existing registry security implementation, including its access checks and
actual errors. This does not change certificate, signature, or trust policy.
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
SOURCE = Path('dlls/advapi32/security.c')
PATCH = ROOT / 'build/wine-pe/registry-security-views.patch'
PROVENANCE = ROOT / 'build/wine-pe/registry-security-views.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, description):
    if path.is_symlink() or not path.is_file():
        raise ValueError(description + ' must be a regular file')


def description():
    regular(PATCH, 'registry security patch')
    regular(PROVENANCE, 'registry security provenance')
    data = json.loads(PROVENANCE.read_text())
    if (data.get('format') != 1 or set(data.get('files', {})) != {SOURCE.as_posix()} or
            digest(PATCH) != data.get('patchSHA256')):
        raise ValueError('invalid registry security patch provenance')
    return data


def stage(destination, source):
    data = description()['files'][SOURCE.as_posix()]
    regular(source / SOURCE, 'registry security input')
    if digest(source / SOURCE) != data['beforeSHA256']:
        raise ValueError('unexpected or already patched registry security input')
    target = destination / SOURCE
    if target.exists() or target.is_symlink():
        raise ValueError('refusing an existing registry security staging output')
    # Avoid git repository-prefix rules silently skipping an in-repo stage.
    with tempfile.TemporaryDirectory(prefix='madeira-registry-security-') as temporary:
        scratch = Path(temporary)
        (scratch / SOURCE).parent.mkdir(parents=True)
        shutil.copyfile(source / SOURCE, scratch / SOURCE)
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(scratch))
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            env.pop(key, None)
        for options in (['--check'], []):
            subprocess.run(['git', 'apply', '--no-index', *options, str(PATCH)],
                           cwd=scratch, env=env, check=True)
        if digest(scratch / SOURCE) != data['afterSHA256']:
            raise ValueError('registry security output differs from reviewed patch')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(scratch / SOURCE, target)


def apply(state, source):
    if (state / 'manifest.json').exists() or (state / 'manifest.json').is_symlink():
        raise ValueError('refusing an existing registry security transaction')
    stage(state / 'staged', source)
    backup = state / 'original/security.c'
    backup.parent.mkdir()
    shutil.copyfile(source / SOURCE, backup)
    manifest = {'source': str(source.resolve()), 'format': 1,
                'files': description()['files'], 'applied': False}
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')
    try:
        shutil.copyfile(state / 'staged' / SOURCE, source / SOURCE)
        if digest(source / SOURCE) != manifest['files'][SOURCE.as_posix()]['afterSHA256']:
            raise ValueError('registry security publication failed')
    except BaseException:
        shutil.copyfile(backup, source / SOURCE)
        raise
    manifest['applied'] = True
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')


def restore(state):
    regular(state / 'manifest.json', 'registry security transaction')
    manifest = json.loads((state / 'manifest.json').read_text())
    if manifest.get('format') != 1 or manifest.get('files') != description()['files']:
        raise ValueError('invalid registry security restoration description')
    source = Path(manifest['source'])
    backup = state / 'original/security.c'
    regular(source / SOURCE, 'registry security staged source')
    regular(backup, 'registry security original source')
    expected = 'afterSHA256' if manifest['applied'] else 'beforeSHA256'
    data = manifest['files'][SOURCE.as_posix()]
    if digest(source / SOURCE) != data[expected]:
        raise ValueError('refusing to discard build-time registry security changes')
    if digest(backup) != data['beforeSHA256']:
        raise ValueError('invalid registry security source backup')
    if manifest['applied']:
        shutil.copyfile(backup, source / SOURCE)
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
