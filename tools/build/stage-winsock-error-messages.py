#!/usr/bin/env python3
"""Stage ordinary Windows Winsock error message resources.

The real send status and Windows FormatMessage failure semantics are unchanged.
The messages prevent a missing resource from masking an already real socket
error. This does not alter routing, packet delivery, authentication or trust.
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
SOURCE = Path('dlls/kernelbase/winerror.mc')
PATCH = ROOT / 'build/wine-pe/winsock-error-messages.patch'
PROVENANCE = ROOT / 'build/wine-pe/winsock-error-messages.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, description):
    if path.is_symlink() or not path.is_file():
        raise ValueError(description + ' must be a regular file')


def description():
    regular(PATCH, 'Winsock messages patch')
    regular(PROVENANCE, 'Winsock messages provenance')
    data = json.loads(PROVENANCE.read_text())
    if (data.get('format') != 1 or set(data.get('files', {})) != {SOURCE.as_posix()} or
            digest(PATCH) != data.get('patchSHA256')):
        raise ValueError('invalid Winsock messages patch provenance')
    return data


def stage(destination, source):
    data = description()['files'][SOURCE.as_posix()]
    regular(source / SOURCE, 'Winsock messages input')
    if digest(source / SOURCE) != data['beforeSHA256']:
        raise ValueError('unexpected or already patched Winsock messages input')
    target = destination / SOURCE
    if target.exists() or target.is_symlink():
        raise ValueError('refusing an existing Winsock messages staging output')
    # Avoid git repository-prefix rules silently skipping an in-repo stage.
    with tempfile.TemporaryDirectory(prefix='madeira-winsock-messages-') as temporary:
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
            raise ValueError('Winsock messages output differs from reviewed patch')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(scratch / SOURCE, target)


def apply(state, source):
    if (state / 'manifest.json').exists() or (state / 'manifest.json').is_symlink():
        raise ValueError('refusing an existing Winsock messages transaction')
    stage(state / 'staged', source)
    backup = state / 'original/winerror.mc'
    backup.parent.mkdir()
    shutil.copyfile(source / SOURCE, backup)
    manifest = {'source': str(source.resolve()), 'format': 1,
                'files': description()['files'], 'applied': False}
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')
    try:
        shutil.copyfile(state / 'staged' / SOURCE, source / SOURCE)
        if digest(source / SOURCE) != manifest['files'][SOURCE.as_posix()]['afterSHA256']:
            raise ValueError('Winsock messages publication failed')
    except BaseException:
        shutil.copyfile(backup, source / SOURCE)
        raise
    manifest['applied'] = True
    (state / 'manifest.json').write_text(json.dumps(manifest) + '\n')


def restore(state):
    regular(state / 'manifest.json', 'Winsock messages transaction')
    manifest = json.loads((state / 'manifest.json').read_text())
    if manifest.get('format') != 1 or manifest.get('files') != description()['files']:
        raise ValueError('invalid Winsock messages restoration description')
    source = Path(manifest['source'])
    backup = state / 'original/winerror.mc'
    regular(source / SOURCE, 'Winsock messages staged source')
    regular(backup, 'Winsock messages original source')
    expected = 'afterSHA256' if manifest['applied'] else 'beforeSHA256'
    data = manifest['files'][SOURCE.as_posix()]
    if digest(source / SOURCE) != data[expected]:
        raise ValueError('refusing to discard build-time Winsock messages changes')
    if digest(backup) != data['beforeSHA256']:
        raise ValueError('invalid Winsock messages source backup')
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
