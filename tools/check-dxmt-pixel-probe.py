#!/usr/bin/env python3
"""Validate the bundled owned probe's loader contract, never its pixel output."""
import argparse
from pathlib import Path
import struct


def validate(path):
    image = path.read_bytes()
    assert image[:2] == b'MZ', 'probe is not a PE image'
    offset = struct.unpack_from('<I', image, 0x3c)[0]
    assert image[offset:offset + 4] == b'PE\0\0'
    assert struct.unpack_from('<H', image, offset + 4)[0] == 0x8664, 'probe must run as an x64 guest'
    sections = struct.unpack_from('<H', image, offset + 6)[0]
    optional_size = struct.unpack_from('<H', image, offset + 20)[0]
    optional = offset + 24
    assert struct.unpack_from('<H', image, optional)[0] == 0x20b
    assert struct.unpack_from('<H', image, optional + 68)[0] == 3, 'probe must retain console logging'
    section_table = optional + optional_size

    def file_offset(rva):
        for i in range(sections):
            section = section_table + i * 40
            virtual_size, start, raw_size, raw = struct.unpack_from('<IIII', image, section + 8)
            if start <= rva < start + min(virtual_size, raw_size):
                return raw + rva - start
        raise AssertionError('PE RVA outside mapped file data')

    def string(rva):
        start = file_offset(rva)
        return image[start:image.index(b'\0', start)].decode('ascii')

    imports = {}
    directory = struct.unpack_from('<I', image, optional + 112 + 8)[0]
    descriptor = file_offset(directory)
    while any(image[descriptor:descriptor + 20]):
        lookup, _, _, name, thunk = struct.unpack_from('<IIIII', image, descriptor)
        names = []
        cursor = file_offset(lookup or thunk)
        while (entry := struct.unpack_from('<Q', image, cursor)[0]):
            assert not entry >> 63, 'unexpected ordinal-only import'
            names.append(string(entry + 2))
            cursor += 8
        imports[string(name).lower()] = names
        descriptor += 20
    assert imports.get('d3d11.dll') == ['D3D11CreateDevice'], 'must use the shipped D3D11 entry point'
    assert 'wined3d.dll' not in imports and 'd3d12.dll' not in imports
    assert 'd3dcompiler_47.dll' not in imports, 'compiler failure must be logged by the running probe'
    assert b'Wine builtin DLL' not in image[:offset], 'must run through the ordinary x64 guest loader'
    for marker in (b'[d3d11-pixels]', b'DXMT device identity', b'GPU completion exceeded 30 seconds',
                   b'BC3-update-copy-region-tail', b'readbacks=%u failures=%u'):
        assert marker in image, 'probe reporting contract missing: ' + repr(marker)
    print('PASS DXMT probe PE: x64 guest, console, real D3D11 import, explicit DXMT identity, bounded GPU completion; pixel execution not measured')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    validate(args.image)
