#!/usr/bin/env python3
"""Verify built observer ABI, restored source provenance, and exact package copies.

This checks build/package evidence only. It does not authenticate a game file,
replace a verifier decision, or claim eligibility for a protected server.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('trust_pe_inspector', ROOT / 'tools/check-system-programs.py')
PE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PE)
FARMS = PE.FARMS
MANIFEST = 'arm64ec-windows/madeira-trust-diagnostics.json'
MARKER = b'[trust-result-v1]'
EXPORT = 'WinVerifyTrust'
OWNED_INPUTS = (
    'build/wine-pe/trust_diagnostics.h',
    'build/wine-pe/build-trust-diagnostics.sh',
    'tools/build/stage-trust-diagnostics.py',
    'tools/check-trust-diagnostics-object.py',
    'tools/check-trust-diagnostics-package.py',
    'tools/check-system-programs.py',
    'tools/check-fex-subfloor-atomics.py',
)
STOCK_HEADERS = (
    'include/wintrust.h', 'include/winbase.h', 'include/winerror.h',
    'include/softpub.h', 'include/mscat.h', 'include/winnt.h',
    'include/wine/exception.h',
)


def read(path, limit=64 << 20):
    path = Path(path)
    assert not path.is_symlink() and path.is_file(), 'missing or symlinked trust provenance file: ' + str(path)
    assert path.stat().st_size <= limit, 'oversized trust provenance file: ' + str(path)
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    assert len(data) <= limit, 'trust provenance file grew while reading'
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'duplicate trust manifest key'
        result[key] = value
    return result


def source_inputs(source, repo=ROOT):
    source, repo = Path(source), Path(repo)
    verifier = read(source / 'dlls/wintrust/wintrust_main.c', 2 << 20)
    assert verifier.count(b'LONG WINAPI WinVerifyTrust( HWND hwnd, GUID *ActionID, LPVOID ActionData )') == 1, 'stock verifier declaration changed'
    assert b'madeira_real_WinVerifyTrust' not in verifier and b'madeira_trust_diagnostics.h' not in verifier, 'trust source restoration is incomplete'
    observer = source / 'dlls/wintrust/madeira_trust_diagnostics.h'
    assert not observer.exists() and not observer.is_symlink(), 'trust observer header was not restored'
    result = {path: digest(read(repo / path, 2 << 20)) for path in OWNED_INPUTS}
    directory = source / 'dlls/wintrust'
    stock = sorted(path for path in directory.iterdir()
                   if path.name == 'Makefile.in' or path.suffix in ('.c', '.h', '.spec', '.rc'))
    assert any(path.name == 'softpub.c' for path in stock), 'stock trust provider source missing'
    for path in stock:
        result['wine/' + path.relative_to(source).as_posix()] = digest(read(path, 2 << 20))
    for path in STOCK_HEADERS:
        result['wine/' + path] = digest(read(source / path, 2 << 20))
    return result


def check(root, source, write=False, app=None, ipa=None, repo=ROOT):
    root, source, repo = Path(root), Path(source), Path(repo)
    records, payload = {}, {}
    for farm in FARMS:
        relative = farm + '/wintrust.dll'
        data = read(root / relative)
        record = PE.inspect(data, farm, required_export=EXPORT)
        assert MARKER in data, 'stale trust observer marker: ' + farm
        records[relative] = record
        payload[relative] = data
    provenance = source_inputs(source, repo)
    expected = {'recipe': 1, 'dlls': records, 'sources': provenance}
    if write:
        path = root / MANIFEST
        assert not path.is_symlink(), 'refusing symlinked trust manifest output'
        temporary = path.with_suffix('.json.pending')
        assert not temporary.exists() and not temporary.is_symlink(), 'refusing existing trust manifest temporary'
        temporary.write_text(json.dumps(expected, sort_keys=True, indent=2) + '\n')
        temporary.replace(path)
    manifest = read(root / MANIFEST, 1 << 20)
    metadata = json.loads(manifest, object_pairs_hook=unique_object)
    assert metadata == expected, 'stale trust observer build/source manifest'
    payload[MANIFEST] = manifest
    if app:
        for relative, data in payload.items():
            assert read(Path(app) / relative) == data, 'stale app trust observer: ' + relative
    if ipa:
        with zipfile.ZipFile(ipa) as archive:
            for relative, data in payload.items():
                name = 'Payload/Madeira.app/' + relative
                entries = [info for info in archive.infolist() if info.filename == name]
                assert len(entries) == 1, 'missing or duplicate IPA trust observer: ' + relative
                assert entries[0].file_size == len(data), 'stale IPA trust observer length: ' + relative
                with archive.open(entries[0]) as stream:
                    assert stream.read(len(data) + 1) == data, 'stale IPA trust observer: ' + relative
    print('PASS trust observer package: A64/ARM64EC/I386 ABI, hybrid RX export, marker, restored source/build hashes, and requested exact package copies; trust verdicts unmeasured')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT / 'wine')
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--write', '--write-manifest', dest='write', action='store_true')
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    try:
        check(args.root, args.source_root, args.write, args.app, args.ipa, args.repo_root)
    except (AssertionError, OSError, ValueError, KeyError, UnicodeError, struct.error, zipfile.BadZipFile) as error:
        parser.error(str(error))
