#!/usr/bin/env python3
"""Resolve Run14's native read continuations in the exact tested IPA; read only."""
import argparse
import bisect
import hashlib
import plistlib
from pathlib import Path
import struct
import uuid
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipa', type=Path, required=True)
    args = parser.parse_args()
    expected = 'AAABE9A1-D67E-3187-BE74-A1435A5E998A'
    with zipfile.ZipFile(args.ipa) as ipa:
        info = plistlib.loads(ipa.read('Payload/Madeira.app/Info.plist'))
        provenance = info['MadeiraNativeBuildProvenance']
        assert provenance['packageSourceRevision'] == '08c333bae081862256d73d0d4b388ceea9fa1db7'
        assert provenance['nativeImageUUID'] == expected
        member = ipa.getinfo('Payload/Madeira.app/Madeira.debug.dylib')
        assert member.file_size < 512 << 20
        data = ipa.read(member)
    assert struct.unpack_from('<II', data) == (0xfeedfacf, 0x100000c)
    at = 32
    sections, symtab, indirect, image_base, image_uuid = [], None, None, None, None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        assert size >= 8 and at + size <= len(data)
        if command == 0x19:
            name = data[at + 8:at + 24].split(b'\0')[0]
            if name == b'__TEXT':
                image_base = struct.unpack_from('<Q', data, at + 24)[0]
            count = struct.unpack_from('<I', data, at + 64)[0]
            assert 72 + count * 80 <= size
            for i in range(count):
                row = struct.unpack_from('<16s16sQQIIIIIIII', data, at + 72 + i * 80)
                sections.append(dict(name=row[0].split(b'\0')[0], addr=row[2], size=row[3],
                                     offset=row[4], flags=row[8], reserved1=row[9], reserved2=row[10]))
        elif command == 2:
            symtab = struct.unpack_from('<IIII', data, at + 8)
        elif command == 0xb:
            indirect = struct.unpack_from('<II', data, at + 56)
        elif command == 0x1b:
            image_uuid = str(uuid.UUID(bytes=data[at + 8:at + 24])).upper()
        at += size
    assert image_uuid == expected and symtab and indirect and image_base is not None
    offset, count, strings, string_size = symtab
    assert offset + count * 16 <= len(data) and strings + string_size <= len(data)
    symbols, functions = [], {}
    for i in range(count):
        index, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + i * 16)
        assert index < string_size
        end = data.index(b'\0', strings + index, strings + string_size)
        name = data[strings + index:end].decode('utf-8', errors='replace')
        symbols.append(name)
        if kind & 0xe == 0xe and not kind & 0xe0 and section and sections[section - 1]['name'] == b'__text':
            functions[address] = name
    indirect_offset, indirect_count = indirect
    assert indirect_offset + indirect_count * 4 <= len(data)
    stubs = {}
    for section in sections:
        stride = section['reserved2']
        if section['flags'] & 0xff != 8 or not stride:
            continue
        for i in range(section['size'] // stride):
            index = section['reserved1'] + i
            assert index < indirect_count
            symbol = struct.unpack_from('<I', data, indirect_offset + index * 4)[0]
            if symbol < len(symbols):
                stubs[section['addr'] + i * stride] = symbols[symbol]
    positions = sorted(functions)
    print(f'TESTED_NATIVE uuid={image_uuid} sha256={hashlib.sha256(data).hexdigest()} source={provenance["packageSourceRevision"]}')
    # These are observations to resolve, never runtime constants or a fix.
    runtime_base = 0x100710000  # Run14 native line252, not a PE/JIT mapping
    for continuation in (0x101a79018, 0x101a8ab70):
        address = image_base + continuation - runtime_base
        index = bisect.bisect_right(positions, address) - 1
        assert index >= 0
        entry = positions[index]
        print(f'CONTINUATION runtime={continuation:#x} image-offset={address-image_base:#x} '
              f'function={functions[entry]}+{address-entry:#x}')
        section = next(s for s in sections if s['name'] == b'__text' and s['addr'] <= address - 4 < s['addr'] + s['size'])
        word = struct.unpack_from('<I', data, section['offset'] + address - 4 - section['addr'])[0]
        if word & 0xfc000000 == 0x94000000:
            delta = word & 0x3ffffff
            if delta & 0x2000000:
                delta -= 0x4000000
            destination = address - 4 + delta * 4
            print(f'CALL word={word:08x} target={stubs.get(destination, functions.get(destination, hex(destination)))}')
        else:
            print(f'CALL word={word:08x} indirect-or-not-BL; no guessed callee')
    print('LIMIT: call-site identity does not measure request/reply latency, identify the waited object, or attribute the whole loading interval')


if __name__ == '__main__':
    main()
