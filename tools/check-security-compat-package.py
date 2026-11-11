#!/usr/bin/env python3
"""Check compiled Wine API corrections and their exact packaged copies.

This is build provenance, not publisher authentication, a file-trust verdict,
or evidence that a protected multiplayer server accepts the runtime.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('security_pe', ROOT / 'tools/check-system-programs.py')
PE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PE)
FARMS = PE.FARMS
TREES = {'aarch64-windows': 'build-macos', 'arm64ec-windows': 'build-arm64ec', 'i386-windows': 'build-i386'}
MANIFEST = 'arm64ec-windows/madeira-security-compat.json'
HELPER = 'CRYPT_AsnEncodePKCSAttributesUnsorted'
STOCK_INPUTS = (
    'dlls/crypt32/crypt32_private.h', 'dlls/crypt32/encode.c', 'dlls/crypt32/msg.c',
    'dlls/crypt32/Makefile.in', 'dlls/crypt32/crypt32.spec',
    'dlls/kernelbase/debug.c', 'dlls/kernelbase/Makefile.in', 'dlls/kernelbase/kernelbase.spec',
    'include/wincrypt.h', 'include/winbase.h', 'include/winerror.h', 'include/winnt.h',
)
OWNED_INPUTS = (
    'build/wine-pe/crypt32-authattrs-order.patch', 'build/wine-pe/crypt32-authattrs-order.json',
    'build/wine-pe/mapped-filename-contract.patch', 'build/wine-pe/build-security-compat.sh',
    'build/wine-pe/build-system-programs.sh', 'tools/build/stage-process-lookup.py',
    'tools/build/stage-crypt32-authattrs.py', 'tools/build/stage-mapped-filename-contract.py',
    'tools/check-security-compat-package.py',
)


def read(path, limit=64 << 20):
    path = Path(path)
    assert not path.is_symlink() and path.is_file(), 'missing or symlinked security build input: ' + str(path)
    assert path.stat().st_size <= limit, 'oversized security build input'
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    assert len(data) <= limit, 'security build input grew while reading'
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'duplicate security build manifest key'
        result[key] = value
    return result


def canonical(name):
    return re.sub(r'@\d+$', '', name.lstrip('#').removeprefix('_'))


class Code:
    """Read ordinary/big COFF objects and retained final PE function symbols."""
    def __init__(self, data):
        self.data = data
        self.pe = data[:2] == b'MZ'
        start = self.unpack('<I', 0x3c)[0] + 4 if self.pe else 0
        if not self.pe and data[:4] == b'\0\0\xff\xff':
            self.machine = self.unpack('<H', 6)[0]
            assert self.unpack('<H', 4)[0] >= 2, 'unsupported big COFF version'
            assert data[12:28] == bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8'), 'invalid big COFF identity'
            count, symbols, number = self.unpack('<III', 44)
            table, symbol_size = 56, 20
        else:
            self.machine, count, _, symbols, number, optional, _ = self.unpack('<HHIIIHH', start)
            assert self.pe or not optional, 'expected COFF object'
            table, symbol_size = start + 20 + optional, 18
        assert self.machine in (0x14c, 0xaa64, 0xa641, 0x8664), 'unsupported security object machine'
        assert 0 < count <= 8192 and table + count * 40 <= len(data), 'invalid security section table'
        self.sections = []
        for i in range(count):
            entry = table + i * 40
            rva = self.unpack('<I', entry + 12)[0]
            size, raw, reloc = self.unpack('<III', entry + 16)
            reloc_count = self.unpack('<H', entry + 32)[0]
            flags = self.unpack('<I', entry + 36)[0]
            assert raw <= len(data) and size <= len(data) - raw, 'section outside security object'
            assert reloc <= len(data) and reloc_count * 10 <= len(data) - reloc, 'relocations outside security object'
            self.sections.append({'rva': rva, 'size': size, 'raw': raw, 'flags': flags,
                                  'relocs': [self.unpack('<IIH', reloc + j * 10) for j in range(reloc_count)]})
        assert 0 < number <= 1000000 and symbols <= len(data) and number * symbol_size <= len(data) - symbols, 'invalid security symbol table'
        strings = symbols + number * symbol_size
        string_size = self.unpack('<I', strings)[0]
        assert 4 <= string_size <= len(data) - strings, 'invalid security string table'
        self.symbols, self.functions = {}, []
        i = 0
        while i < number:
            entry = symbols + i * symbol_size
            first, offset = self.unpack('<II', entry)
            if first:
                name = data[entry:entry + 8].split(b'\0', 1)[0].decode('ascii')
            else:
                assert 4 <= offset < string_size, 'symbol name outside security string table'
                end = data.find(b'\0', strings + offset, min(strings + string_size, strings + offset + 4096))
                assert end >= 0, 'unterminated security symbol name'
                name = data[strings + offset:end].decode('ascii')
            value = self.unpack('<I', entry + 8)[0]
            section, kind, storage, aux = self.unpack('<hHBB' if symbol_size == 18 else '<iHBB', entry + 12)
            assert aux < number - i, 'security auxiliary symbol overflow'
            self.symbols[i] = name
            if kind & 0x30 == 0x20 and 0 < section <= count:
                sec = self.sections[section - 1]
                if sec['flags'] & 0xe0000020 == 0x60000020:
                    assert value < sec['size'], 'security function outside code section'
                    length = self.unpack('<I', entry + symbol_size + 4)[0] if aux and storage in (2, 3) else 0
                    assert length <= sec['size'] - value, 'security function extent outside code section'
                    self.functions.append({'name': name, 'section': section - 1, 'start': value, 'length': length})
            i += 1 + aux
        for fn in self.functions:
            if not fn['length']:
                fn['length'] = min((x['start'] for x in self.functions if x['section'] == fn['section'] and x['start'] > fn['start']),
                                   default=self.sections[fn['section']]['size']) - fn['start']

    def unpack(self, fmt, offset):
        size = struct.calcsize(fmt)
        assert 0 <= offset <= len(self.data) - size, 'truncated security COFF/PE metadata'
        return struct.unpack_from(fmt, self.data, offset)

    def function(self, name):
        matches = [fn for fn in self.functions if canonical(fn['name']) == canonical(name)]
        assert matches, 'required compiled security function missing: ' + name
        assert len({(f['section'], f['start']) for f in matches}) == 1, 'ambiguous compiled security function: ' + name
        return matches[0]

    def bytes(self, fn):
        section = self.sections[fn['section']]
        start = section['raw'] + fn['start']
        return self.data[start:start + fn['length']]

    def caller(self, name):
        found, references = [], []
        for index, section in enumerate(self.sections):
            for address, symbol, kind in section['relocs']:
                if kind and canonical(self.symbols.get(symbol, '')) == canonical(name):
                    references.append((index, address, kind, self.symbols.get(symbol, '')))
                    # ARM64EC also emits a helper$exit_thunk containing ADRP /
                    # ADD address references to the undecorated helper. Those
                    # are not calls from the message verifier. Select the
                    # actual compiler call relocation, then verify its final
                    # linked instruction and destination below.
                    call_kind = 0x14 if self.machine == 0x14c else 3
                    if kind != call_kind:
                        continue
                    candidates = [fn for fn in self.functions if fn['section'] == index and fn['start'] <= address < fn['start'] + fn['length']]
                    assert candidates, 'new verifier call is not in a real emitted code function'
                    found.append(max(candidates, key=lambda fn: fn['start']))
        assert found, ('compiled message verifier has no direct unsorted-attribute encoder call: '
                       f'machine={self.machine:#06x} references={references!r}')
        # The static updater may be inlined into its real decode caller.
        return min(found, key=lambda fn: (fn['length'], fn['name']))

    def proof(self, fn):
        data = self.bytes(fn)
        assert 8 <= len(data) <= 65536, 'invalid compiled security function length'
        mask = bytearray(b'\xff' * len(data))
        for address, _, kind in self.sections[fn['section']]['relocs']:
            if not kind or not fn['start'] <= address < fn['start'] + len(data):
                continue
            if self.machine == 0x14c:
                widths = {0x6: 4, 0x7: 4, 0xa: 2, 0xb: 4, 0x14: 4}
            elif self.machine == 0x8664:
                widths = {0x1: 8, 0x2: 4, 0x3: 4, **{x: 4 for x in range(0x4, 0xa)}, 0xa: 2, 0xb: 4}
            else:
                widths = {**{x: 4 for x in range(1, 0x12)}, 0xd: 2, 0xe: 8}
            assert kind in widths, 'unknown relocation in compiled security function: ' + hex(kind)
            start, width = address - fn['start'], widths[kind]
            assert start + width <= len(data), 'security function relocation extends past function'
            mask[start:start + width] = bytes(width)
        assert sum(bool(x) for x in mask) >= max(8, len(data) // 4), 'insufficient unrelocated security code evidence'
        return {'symbol': fn['name'], 'code': bytes(b & m for b, m in zip(data, mask)).hex(), 'mask': bytes(mask).hex()}

    def calls(self, fn, target):
        result = []
        for address, symbol, kind in self.sections[fn['section']]['relocs']:
            if fn['start'] <= address < fn['start'] + fn['length'] and canonical(self.symbols.get(symbol, '')) == target:
                if self.machine == 0x14c and kind == 0x14:
                    result.append(['i386-rel32', address - fn['start']])
                elif self.machine in (0xaa64, 0xa641) and kind == 3:
                    result.append(['arm64-branch26', address - fn['start']])
                else:
                    raise ValueError('unexpected relocation for direct attribute-encoder call: '
                                     f'machine={self.machine:#06x} kind={kind:#x} symbol={self.symbols.get(symbol)!r} '
                                     f'function={fn["name"]!r} section={fn["section"]} offset={address - fn["start"]:#x}')
        assert result, 'actual verifier helper call is missing'
        return result


def verify_proof(image, proof):
    assert set(proof) in ({'symbol', 'code', 'mask'}, {'symbol', 'code', 'mask', 'calls'}), 'invalid security code proof fields'
    fn = image.function(proof['symbol'])
    data, wanted, mask = image.bytes(fn), bytes.fromhex(proof['code']), bytes.fromhex(proof['mask'])
    assert 8 <= len(wanted) <= 65536 and len(mask) == len(wanted) <= len(data), 'invalid linked security code extent'
    assert set(mask) <= {0, 255} and sum(bool(x) for x in mask) >= max(8, len(mask) // 4), 'invalid linked security relocation mask'
    assert bytes(b & m for b, m in zip(data, mask)) == wanted, 'linked security code differs from actual compiled object: ' + proof['symbol']
    if 'calls' in proof:
        target = image.function(HELPER)
        target_rva = image.sections[target['section']]['rva'] + target['start']
        function_rva = image.sections[fn['section']]['rva'] + fn['start']
        assert isinstance(proof['calls'], list) and 0 < len(proof['calls']) <= 64, 'invalid helper call proof count'
        for kind, offset in proof['calls']:
            assert isinstance(offset, int) and 0 <= offset <= len(wanted) - 4, 'helper call outside emitted verifier'
            if kind == 'arm64-branch26':
                word, = struct.unpack_from('<I', data, offset)
                assert word & 0x7c000000 == 0x14000000, 'verifier helper call is not an ARM64 direct branch'
                displacement = word & 0x03ffffff
                if displacement & 0x02000000:
                    displacement -= 0x04000000
                actual = function_rva + offset + displacement * 4
            elif kind == 'i386-rel32':
                assert offset and data[offset - 1] in (0xe8, 0xe9), 'verifier helper call is not an I386 direct branch'
                actual = function_rva + offset + 4 + struct.unpack_from('<i', data, offset)[0]
            else:
                raise ValueError('unknown linked verifier helper call architecture')
            assert actual == target_rva, 'linked verifier call does not reach the corrected encoder'


def source_inputs(source, repo):
    result = {name: digest(read(repo / name, 2 << 20)) for name in OWNED_INPUTS}
    for name in STOCK_INPUTS:
        data = read(source / name, 2 << 20)
        if name in ('dlls/crypt32/crypt32_private.h', 'dlls/crypt32/encode.c', 'dlls/crypt32/msg.c'):
            assert HELPER.encode() not in data, 'security source was not restored before package provenance'
        result['wine/' + name] = digest(data)
    reviewed = json.loads(read(repo / 'build/wine-pe/crypt32-authattrs-order.json', 1 << 20), object_pairs_hook=unique_object)
    assert reviewed.get('format') == 1 and reviewed.get('upstreamCommit') == 'a358d7ecf13b420d7fa65d54fcad1f96003d7a48', 'unreviewed crypt32 backport provenance'
    assert reviewed.get('patchSHA256') == result['build/wine-pe/crypt32-authattrs-order.patch'], 'crypt32 backport patch differs from reviewed source'
    assert set(reviewed.get('files', {})) == {'dlls/crypt32/' + name for name in ('crypt32_private.h', 'encode.c', 'msg.c')}, 'crypt32 backport source coverage differs'
    for name, record in reviewed['files'].items():
        assert record['beforeSHA256'] == result['wine/' + name], 'crypt32 stock source differs from reviewed input'
    return result


def build_proofs(build_root, farm, images):
    tree = Path(build_root) / TREES[farm]
    files = {'encode': tree / 'dlls/crypt32' / farm / 'encode.o',
             'msg': tree / 'dlls/crypt32' / farm / 'msg.o',
             'debug': tree / 'dlls/kernelbase' / farm / 'debug.o'}
    objects = {name: read(path, 32 << 20) for name, path in files.items()}
    parsed = {name: Code(data) for name, data in objects.items()}
    allowed = {0xa641, 0xaa64} if farm == 'arm64ec-windows' else {FARMS[farm]}
    assert all(obj.machine in allowed and not obj.pe for obj in parsed.values()), 'wrong architecture or PE substituted for security object'
    caller = parsed['msg'].caller(HELPER)
    call_proof = parsed['msg'].proof(caller)
    call_proof['calls'] = parsed['msg'].calls(caller, HELPER)
    proofs = {'crypt32.dll': [parsed['encode'].proof(parsed['encode'].function(HELPER)), call_proof],
              'kernelbase.dll': [parsed['debug'].proof(parsed['debug'].function('GetMappedFileNameW'))]}
    for dll, records in proofs.items():
        for proof in records:
            verify_proof(images[dll], proof)
    return {'objects': {name: digest(data) for name, data in objects.items()}, 'code': proofs}


def check(root, source, write=False, app=None, ipa=None, repo=ROOT, build_root=None):
    root, source, repo = Path(root), Path(source), Path(repo)
    records, payload, images = {}, {}, {}
    for farm in FARMS:
        assert not (root / farm).is_symlink(), 'symlinked security architecture farm'
        images[farm] = {}
        for dll, export in (('crypt32.dll', 'CryptMsgControl'), ('kernelbase.dll', 'GetMappedFileNameW')):
            relative = farm + '/' + dll
            data = read(root / relative)
            records[relative] = PE.inspect(data, farm, required_export=export)
            images[farm][dll] = Code(data)
            payload[relative] = data
        images[farm]['crypt32.dll'].function(HELPER)
    provenance = source_inputs(source, repo)
    path = root / MANIFEST
    if write:
        assert build_root is not None, 'real object build tree required to publish security provenance'
        proofs = {farm: build_proofs(build_root, farm, images[farm]) for farm in FARMS}
        metadata = {'recipe': 1, 'dlls': records, 'sources': provenance, 'compiled': proofs}
        pending = path.with_suffix('.json.pending')
        assert not path.is_symlink() and not pending.exists() and not pending.is_symlink(), 'refusing unowned security manifest output'
        pending.write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
        pending.replace(path)
    manifest = read(path, 2 << 20)
    metadata = json.loads(manifest, object_pairs_hook=unique_object)
    assert set(metadata) == {'recipe', 'dlls', 'sources', 'compiled'} and metadata['recipe'] == 1, 'invalid security provenance recipe'
    assert metadata['dlls'] == records and metadata['sources'] == provenance, 'stale security DLL/source/recipe provenance'
    assert set(metadata['compiled']) == set(FARMS), 'missing security object farm'
    for farm, proof in metadata['compiled'].items():
        assert set(proof) == {'objects', 'code'} and set(proof['objects']) == {'encode', 'msg', 'debug'}, 'invalid security object proof'
        assert all(re.fullmatch(r'[0-9a-f]{64}', x) for x in proof['objects'].values()), 'invalid security object digest'
        assert set(proof['code']) == {'crypt32.dll', 'kernelbase.dll'}, 'missing security DLL code proof'
        assert len(proof['code']['crypt32.dll']) == 2 and len(proof['code']['kernelbase.dll']) == 1, 'missing security function proof'
        assert canonical(proof['code']['crypt32.dll'][0]['symbol']) == HELPER, 'unsorted-attribute helper proof missing'
        assert 'calls' in proof['code']['crypt32.dll'][1] and canonical(proof['code']['crypt32.dll'][1]['symbol']) != HELPER, 'actual verifier caller proof missing'
        assert canonical(proof['code']['kernelbase.dll'][0]['symbol']) == 'GetMappedFileNameW', 'mapped filename proof missing'
        for dll, proofs in proof['code'].items():
            for record in proofs:
                verify_proof(images[farm][dll], record)
        if build_root is not None:
            assert proof == build_proofs(build_root, farm, images[farm]), 'stale security compiled-object provenance'
    payload[MANIFEST] = manifest
    if app:
        for relative, data in payload.items():
            assert read(Path(app) / relative) == data, 'stale app security DLL: ' + relative
    if ipa:
        with zipfile.ZipFile(ipa) as archive:
            for relative, data in payload.items():
                name = 'Payload/Madeira.app/' + relative
                entries = [entry for entry in archive.infolist() if entry.filename == name]
                assert len(entries) == 1 and entries[0].file_size == len(data), 'missing/duplicate/stale IPA security DLL: ' + relative
                with archive.open(entries[0]) as stream:
                    assert stream.read(len(data) + 1) == data, 'substituted IPA security DLL: ' + relative
    print('PASS security API package: all three ABIs, actual compiler object-to-linked-code proofs, source/recipe hashes and exact requested app/IPA copies; no publisher-trust or secure-play claim')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT / 'wine')
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--build-root', type=Path)
    parser.add_argument('--write', '--write-manifest', dest='write', action='store_true')
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    try:
        check(args.root, args.source_root, args.write, args.app, args.ipa, args.repo_root, args.build_root)
    except (AssertionError, OSError, ValueError, KeyError, UnicodeError, struct.error, zipfile.BadZipFile) as error:
        parser.error(str(error))
