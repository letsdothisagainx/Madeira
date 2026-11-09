#!/usr/bin/env python3
"""Stage a bounded observer around the real Wine verifier; restore exact inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path('dlls/wintrust/wintrust_main.c')
HEADER = Path('dlls/wintrust/madeira_trust_diagnostics.h')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(destination, source):
    if (source / SOURCE).is_symlink() or not (source / SOURCE).is_file():
        raise ValueError('trust verifier input must be a regular source file')
    for path in (SOURCE, HEADER):
        if (destination / path).exists() or (destination / path).is_symlink():
            raise ValueError('refusing to overwrite existing staged trust file: ' + str(path))
    text = (source / SOURCE).read_text()
    declaration = 'LONG WINAPI WinVerifyTrust( HWND hwnd, GUID *ActionID, LPVOID ActionData )'
    boundary = '/***********************************************************************\n *\t\tWinVerifyTrustEx (WINTRUST.@)'
    if text.count(declaration) != 1 or text.count(boundary) != 1:
        raise ValueError('WinVerifyTrust boundary changed; refusing stale observer')
    if 'madeira_trust_diagnostics.h' in text:
        raise ValueError('trust observer is already applied')
    text = text.replace(declaration, declaration.replace('LONG WINAPI WinVerifyTrust',
                                                      'static LONG WINAPI madeira_real_WinVerifyTrust'), 1)
    text = text.replace(boundary, '#include "madeira_trust_diagnostics.h"\n\n' + boundary, 1)
    (destination / SOURCE).parent.mkdir(parents=True, exist_ok=True)
    (destination / SOURCE).write_text(text)
    shutil.copyfile(ROOT / 'build/wine-pe/trust_diagnostics.h', destination / HEADER)


def apply(state, source):
    if (source / HEADER).exists() or (source / HEADER).is_symlink():
        raise ValueError('refusing to overwrite existing trust observer header')
    stage(state / 'staged', source)
    (state / 'original').mkdir()
    shutil.copyfile(source / SOURCE, state / 'original/wintrust_main.c')
    manifest = {'source': str(source.resolve()),
                'after': {str(p): digest(state / 'staged' / p) for p in (SOURCE, HEADER)}}
    (state / 'manifest.json').write_text(json.dumps(manifest))
    try:
        for path in (SOURCE, HEADER):
            shutil.copyfile(state / 'staged' / path, source / path)
    except BaseException:
        shutil.copyfile(state / 'original/wintrust_main.c', source / SOURCE)
        (source / HEADER).unlink(missing_ok=True)
        raise


def restore(state):
    manifest = json.loads((state / 'manifest.json').read_text())
    source = Path(manifest['source'])
    for name, expected in manifest['after'].items():
        if (source / name).is_symlink() or not (source / name).is_file() or digest(source / name) != expected:
            raise ValueError('refusing to discard build-time source changes: ' + name)
    shutil.copyfile(state / 'original/wintrust_main.c', source / SOURCE)
    (source / HEADER).unlink()


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
