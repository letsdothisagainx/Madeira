#!/usr/bin/env python3
"""Tie the real rebuilt SRW release object to the stripped native ntdll code.

No new PE exports, runtime marker loads or lock operations are introduced.
Final app/IPA gates independently require byte-identical copies of these DLLs.
"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('srw_compiled_code', ROOT / 'tools/check-security-compat-package.py')
code = importlib.util.module_from_spec(spec)
spec.loader.exec_module(code)
FUNCTION = 'RtlReleaseSRWLockShared'


class Image:
    def __init__(self, data, farm):
        self.data = data
        self.metadata = code.PE.inspect(data, farm, required_export=FUNCTION)
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        self.opt = pe + 24
        self.base = struct.unpack_from('<Q', data, self.opt + 24)[0]
        optional = struct.unpack_from('<H', data, pe + 20)[0]
        count = struct.unpack_from('<H', data, pe + 6)[0]
        self.sections = []
        for index in range(count):
            at = self.opt + optional + index * 40
            virtual, rva, size, raw = struct.unpack_from('<IIII', data, at + 8)
            flags = struct.unpack_from('<I', data, at + 36)[0]
            self.sections.append((rva, size, raw, flags))

    def read(self, rva, size, executable=False):
        assert isinstance(rva, int) and isinstance(size, int) and size > 0, 'invalid native SRW code extent'
        for base, length, raw, flags in self.sections:
            if base <= rva and rva - base + size <= length:
                if executable:
                    assert flags & 0xe0000000 == 0x60000000, 'SRW function is not file-backed RX code'
                start = raw + rva - base
                return self.data[start:start + size]
        raise AssertionError('SRW PE metadata/code is outside file-backed sections')

    def unpack(self, fmt, rva):
        return struct.unpack(fmt, self.read(rva, struct.calcsize(fmt)))

    def native_target(self, machine):
        target = self.metadata['export_rva']
        if machine == 'aarch64':
            return target
        directory, length = struct.unpack_from('<II', self.data, self.opt + 112 + 10 * 8)
        assert directory and length >= 208, 'ARM64EC SRW load configuration missing'
        pointer = self.unpack('<Q', directory + 200)[0]
        assert pointer >= self.base, 'ARM64EC SRW metadata below image base'
        metadata = pointer - self.base
        version, ranges, count = self.unpack('<III', metadata)
        assert version in (1, 2) and 0 < count <= 65536, 'invalid SRW hybrid code map'
        redirection = self.unpack('<I', metadata + 16)[0]
        redirects = self.unpack('<I', metadata + 52)[0]
        assert redirects <= 65536 and bool(redirection) == bool(redirects), 'invalid SRW hybrid redirections'
        matches = []
        for index in range(redirects):
            source, destination = self.unpack('<II', redirection + index * 8)
            if source == target:
                matches.append(destination)
        assert len(matches) <= 1, 'ambiguous SRW hybrid export redirection'
        if matches:
            target = matches[0]
        native = False
        for index in range(count):
            start, span = self.unpack('<II', ranges + index * 8)
            if start & 3 == 1 and start & ~3 <= target < (start & ~3) + span:
                native = True
        assert native, 'SRW release export does not resolve to ARM64EC native code'
        return target


def check(image, obj, machine, source=None):
    farm = {'aarch64': 'aarch64-windows', 'arm64ec': 'arm64ec-windows'}[machine]
    data, original = code.read(image), code.read(obj, 32 << 20)
    compiled = code.Code(original)
    assert not compiled.pe and compiled.machine in ({0xaa64} if machine == 'aarch64' else {0xaa64, 0xa641}), 'wrong SRW compiler object architecture'
    proof = compiled.proof(compiled.function(FUNCTION))
    actual = Image(data, farm)
    target = actual.native_target(machine)
    wanted, mask = bytes.fromhex(proof['code']), bytes.fromhex(proof['mask'])
    linked = actual.read(target, len(wanted), executable=True)
    assert bytes(a & b for a, b in zip(linked, mask)) == wanted, 'packaged native SRW code differs from the rebuilt sync.o'
    if source:
        helper_spec = importlib.util.spec_from_file_location('srw_wake_source', ROOT / 'tools/build/stage-native-srw-wake.py')
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        text = code.read(source, 2 << 20).decode()
        start = text.index(helper.SIGNATURE)
        body = text[start:text.index('\n}\n', start) + 3]
        assert body.count(helper.GUARDED) == 1 and helper.ORIGINAL not in body, 'real compiled SRW source lacks the exclusive-waiter wake condition'
    result = {'machine': machine, 'native_rva': target, 'bytes': len(wanted),
              'object_sha256': code.digest(original), 'masked_code_sha256': code.digest(wanted),
              'stage_sha256': code.digest(code.read(ROOT / 'tools/build/stage-native-srw-wake.py', 1 << 20))}
    print('PASS native SRW compiled-object -> stripped PE export/native entry: ' + str(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--machine', choices=('aarch64', 'arm64ec'), required=True)
    parser.add_argument('--source-sync', type=Path)
    args = parser.parse_args()
    check(args.image, args.object, args.machine, args.source_sync)
