#!/usr/bin/env python3
"""Bind the WaitOnAddress lifetime fix to real objects and packaged ntdlls.

This checks source/build provenance and machine code in all three Wine ABIs.
It is not proof of Steam/CEF startup or execution on an iPhone.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


native = module('wait_address_native_code', ROOT / 'tools/check-native-srw-code.py')
code = native.code
FUNCTION = 'RtlWaitOnAddress'
MARKER = b'[wait-address-lifetime-v1]'
NATIVE_MARKER = b'[cs2-texture-scope-v1] phase=child-environment-prepared'
MANIFEST = 'arm64ec-windows/madeira-wait-address.json'
FARMS = code.FARMS
MACHINES = {'aarch64-windows': 'aarch64', 'arm64ec-windows': 'arm64ec', 'i386-windows': 'i386'}
STOCK_INPUTS = ('dlls/ntdll/sync.c', 'dlls/ntdll/ntdll.spec', 'dlls/ntdll/Makefile.in',
                'include/winnt.h', 'include/winbase.h', 'include/wine/list.h')
OWNED_INPUTS = ('tools/build/stage-wait-address-lifetime.py',
                'tools/build/stage-native-counter-writes.py',
                'tools/build/stage-native-srw-wake.py',
                'tools/check-native-srw-code.py', 'tools/check-security-compat-package.py',
                'tools/check-winsock-message-resources.py',
                'tools/check-system-programs.py', 'tools/check-wait-address-package.py',
                'build/wine-pe/build-ntdll.sh', 'build/wine-i386/build.sh',
                'tools/build/build-wow64-io.sh',
                'build/ntdll-unix/process_ios.c')


def inputs(repo):
    result = {name: code.digest(code.read(repo / name, 2 << 20)) for name in OWNED_INPUTS}
    for name in STOCK_INPUTS:
        result['wine/' + name] = code.digest(code.read(repo / 'wine' / name, 2 << 20))
    stage = module('wait_address_source_contract', repo / OWNED_INPUTS[0])
    source = code.read(repo / 'wine/dlls/ntdll/sync.c', 2 << 20).decode()
    assert all(hasattr(stage, name) for name in ('MARKER', 'NEW', 'stage')), 'invalid WaitOnAddress source recipe'
    assert stage.MARKER.encode() == MARKER and stage.MARKER not in source, 'WaitOnAddress source was not restored'
    staged = stage.stage(source)
    assert staged.count(stage.MARKER) == 1 and stage.NEW in staged, 'WaitOnAddress lifetime source contract missing'
    assert NATIVE_MARKER in code.read(repo / 'build/ntdll-unix/process_ios.c', 2 << 20), 'CS2 child texture-profile scope source marker missing'
    return result


def native_marker(stream, length):
    assert 0 < length <= 512 << 20, 'invalid native child-profile image size'
    seen, tail, found = 0, b'', False
    while True:
        block = stream.read(min(1 << 20, length + 1 - seen))
        if not block:
            break
        seen += len(block)
        assert seen <= length, 'native child-profile image grew during verification'
        combined = tail + block
        found |= NATIVE_MARKER in combined
        tail = combined[-len(NATIVE_MARKER) + 1:]
    assert seen == length and found, 'linked native image lacks genuine CS2 child-profile scope preparation'


def native_file(path):
    path = Path(path)
    assert path.is_file() and not path.is_symlink(), 'missing or symlinked native child-profile image'
    with path.open('rb') as stream:
        native_marker(stream, path.stat().st_size)


def verify(image, proof, farm):
    assert set(proof) == {'objectSHA256', 'nativeRVA', 'function'}, 'invalid WaitOnAddress compiled proof shape'
    assert re.fullmatch('[0-9a-f]{64}', proof['objectSHA256']), 'invalid WaitOnAddress object hash'
    function = proof['function']
    assert set(function) == {'symbol', 'code', 'mask'}, 'invalid WaitOnAddress function proof shape'
    assert code.canonical(function['symbol']) == FUNCTION, 'wrong WaitOnAddress compiler function'
    wanted, mask = bytes.fromhex(function['code']), bytes.fromhex(function['mask'])
    assert 8 <= len(wanted) <= 65536 and len(mask) == len(wanted), 'invalid WaitOnAddress code extent'
    assert set(mask) <= {0, 255} and sum(bool(x) for x in mask) >= max(8, len(mask) // 4), 'insufficient WaitOnAddress relocation-free code evidence'
    target = image.native_target(MACHINES[farm])
    assert isinstance(proof['nativeRVA'], int) and proof['nativeRVA'] == target, 'WaitOnAddress proof differs from real export/native entry'
    actual = image.read(target, len(wanted), executable=True)
    assert bytes(b & m for b, m in zip(actual, mask)) == wanted, 'WaitOnAddress linked export code differs from actual sync.o'


def build_proof(build_root, farm, image):
    path = Path(build_root) / code.TREES[farm] / 'dlls/ntdll' / farm / 'sync.o'
    raw = code.read(path, 32 << 20)
    obj = code.Code(raw)
    allowed = {0xaa64, 0xa641} if farm == 'arm64ec-windows' else {FARMS[farm]}
    assert not obj.pe and obj.machine in allowed, 'wrong WaitOnAddress compiler object architecture'
    assert MARKER in raw, 'actual sync.o lacks the lifetime source marker'
    result = {'objectSHA256': code.digest(raw), 'nativeRVA': image.native_target(MACHINES[farm]),
              'function': obj.proof(obj.function(FUNCTION))}
    verify(image, result, farm)
    return result


def check(root, repo=ROOT, build_root=None, write=False, app=None, ipa=None, native_image=None):
    root, repo = Path(root), Path(repo)
    provenance, images, records, payload = inputs(repo), {}, {}, {}
    for farm in FARMS:
        assert not (root / farm).is_symlink(), 'symlinked WaitOnAddress architecture farm'
        relative = farm + '/ntdll.dll'
        data = code.read(root / relative)
        assert MARKER in data, 'packaged ntdll lacks the WaitOnAddress lifetime fix marker: ' + farm
        image = native.Image(data, farm, required_export=FUNCTION)
        images[farm], records[relative], payload[relative] = image, image.metadata, data
    path = root / MANIFEST
    if write:
        assert build_root is not None, 'real compiler object tree required to publish WaitOnAddress provenance'
        metadata = {'recipe': 1, 'sources': provenance, 'dlls': records,
                    'compiled': {farm: build_proof(build_root, farm, images[farm]) for farm in FARMS}}
        pending = path.with_suffix('.json.pending')
        assert not path.is_symlink() and not pending.exists() and not pending.is_symlink(), 'unowned WaitOnAddress manifest output'
        created = False
        try:
            with pending.open('x', encoding='utf-8') as stream:
                created = True
                json.dump(metadata, stream, sort_keys=True, indent=2)
                stream.write('\n')
            pending.replace(path)
        finally:
            if created and pending.exists():
                pending.unlink()
    raw = code.read(path, 2 << 20)
    metadata = json.loads(raw, object_pairs_hook=code.unique_object)
    assert set(metadata) == {'recipe', 'sources', 'dlls', 'compiled'} and metadata['recipe'] == 1, 'invalid WaitOnAddress manifest recipe'
    assert metadata['sources'] == provenance and metadata['dlls'] == records, 'stale WaitOnAddress source or ntdll provenance'
    assert set(metadata['compiled']) == set(FARMS), 'missing WaitOnAddress compiler architecture'
    for farm, proof in metadata['compiled'].items():
        verify(images[farm], proof, farm)
        if build_root is not None:
            assert proof == build_proof(build_root, farm, images[farm]), 'stale WaitOnAddress compiler object'
    payload[MANIFEST] = raw
    if app:
        for relative, data in payload.items():
            assert code.read(Path(app) / relative) == data, 'stale app WaitOnAddress component: ' + relative
        native_file(Path(app) / 'Madeira.debug.dylib')
    if native_image:
        native_file(native_image)
    if ipa:
        with zipfile.ZipFile(ipa) as archive:
            for relative, data in payload.items():
                entries = [entry for entry in archive.infolist() if entry.filename == 'Payload/Madeira.app/' + relative]
                assert len(entries) == 1 and entries[0].file_size == len(data), 'missing/duplicate/stale IPA WaitOnAddress component: ' + relative
                with archive.open(entries[0]) as stream:
                    assert stream.read(len(data) + 1) == data, 'substituted IPA WaitOnAddress component: ' + relative
            native_entries = [entry for entry in archive.infolist() if entry.filename == 'Payload/Madeira.app/Madeira.debug.dylib']
            assert len(native_entries) == 1, 'missing or duplicate native CS2 child-profile image'
            with archive.open(native_entries[0]) as stream:
                native_marker(stream, native_entries[0].file_size)
    print('PASS WaitOnAddress package: A64/ARM64EC/I386 actual sync.o-to-RX-export proof, restored source/recipe hashes, requested native child-profile marker and exact app/IPA copies; no Steam/CEF runtime claim')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--build-root', type=Path)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    parser.add_argument('--native', type=Path)
    args = parser.parse_args()
    check(args.root, args.repo_root, args.build_root, args.write, args.app, args.ipa, args.native)
