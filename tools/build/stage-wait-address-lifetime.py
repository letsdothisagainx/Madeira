#!/usr/bin/env python3
"""Keep a PE WaitOnAddress stack node alive until its waker finishes unlinking.

Only an owned build copy is changed. All wake selection, native wait results,
timeout values, comparison sizes and memory-ordering primitives are retained.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

FILE = 'dlls/ntdll/sync.c'
MARKER = '[wait-address-lifetime-v1]'
OLD = '''    if (entry.addr)
    {
        spin_lock( &queue->lock );
        if (entry.addr)
            list_remove( &entry.entry );
        spin_unlock( &queue->lock );
    }'''
NEW = '''    /* A timeout or unrelated thread alert may finish the native wait while
     * a waker holds this queue lock, has cleared entry.addr, and is still
     * unlinking our stack node. Always join that lock before returning:
     * observing NULL alone does not prove the waker has finished using it. */
    spin_lock( &queue->lock );
    if (entry.addr)
        list_remove( &entry.entry );
    spin_unlock( &queue->lock );'''


def stage(source):
    signature = 'NTSTATUS WINAPI RtlWaitOnAddress('
    if source.count(signature) != 1 or MARKER in source:
        raise ValueError('WaitOnAddress lifetime input missing, duplicated or already staged')
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    function = source[start:end]
    if function.count(OLD) != 1:
        raise ValueError('WaitOnAddress stack cleanup contract changed')
    anchor = '    NTSTATUS ret;\n'
    if function.count(anchor) != 1:
        raise ValueError('WaitOnAddress declaration contract changed')
    function = function.replace(anchor, anchor + '''    static const volatile char lifetime_contract[] = "[wait-address-lifetime-v1]";
    (void)lifetime_contract[0];
''', 1).replace(OLD, NEW, 1)
    return source[:start] + function + source[end:]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply(wine, backup):
    if backup.exists() and any(backup.iterdir()):
        raise ValueError('WaitOnAddress backup must be empty')
    path = wine / FILE
    subprocess.run(['git', '-C', str(wine), 'diff', '--quiet', 'HEAD', '--', FILE], check=True)
    original = path.read_bytes()
    generated = stage(original.decode()).encode()
    backup.mkdir(parents=True, exist_ok=True)
    (backup / 'original').write_bytes(original)
    (backup / 'manifest.json').write_text(json.dumps({'original': sha(original), 'staged': sha(generated)}))
    path.write_bytes(generated)


def restore(wine, backup):
    manifest = backup / 'manifest.json'
    if not manifest.exists():
        return
    hashes = json.loads(manifest.read_text())
    original = (backup / 'original').read_bytes()
    path = wine / FILE
    if sha(original) != hashes['original'] or sha(path.read_bytes()) not in hashes.values():
        raise ValueError('Refusing to overwrite unrelated WaitOnAddress source edits')
    path.write_bytes(original)
    manifest.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'restore'))
    parser.add_argument('--wine', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    (apply if args.action == 'apply' else restore)(args.wine, args.backup)
