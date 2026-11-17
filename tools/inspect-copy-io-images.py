#!/usr/bin/env python3
"""Resolve captured native-copy PCs using the exact archived IPA's PE images."""
import argparse
import hashlib
import struct
import uuid
import zipfile


def native_uuid(image):
    assert image[:4] == b'\xcf\xfa\xed\xfe', 'expected ARM64 Mach-O'
    pos = 32
    for _ in range(struct.unpack_from('<I', image, 16)[0]):
        command, size = struct.unpack_from('<II', image, pos)
        assert size >= 8 and pos + size <= len(image)
        if command == 0x1b:
            return str(uuid.UUID(bytes=image[pos + 8:pos + 24])).upper()
        pos += size
    raise AssertionError('missing native UUID')


def inspect(image, name, rva):
    import capstone
    assert image[:2] == b'MZ'
    pe = struct.unpack_from('<I', image, 0x3c)[0]
    assert image[pe:pe + 4] == b'PE\0\0'
    machine, count, stamp, sym, nsym, opt, _ = struct.unpack_from('<HHIIIHH', image, pe + 4)
    assert machine in (0x8664, 0xa641), 'expected ARM64EC PE'
    image_size = struct.unpack_from('<I', image, pe + 24 + 56)[0]
    sections = []
    for i in range(count):
        at = pe + 24 + opt + 40 * i
        section_name = image[at:at + 8].rstrip(b'\0').decode('ascii', 'replace')
        virtual_size, va, raw_size, raw = struct.unpack_from('<IIII', image, at + 8)
        flags = struct.unpack_from('<I', image, at + 36)[0]
        assert raw + raw_size <= len(image)
        sections.append((section_name, va, virtual_size, raw, raw_size, flags))
    rows = []
    if sym and nsym:
        strings = sym + nsym * 18
        length = struct.unpack_from('<I', image, strings)[0]
        assert 4 <= length <= len(image) - strings
        i = 0
        while i < nsym:
            at = sym + i * 18
            raw_name = image[at:at + 8]
            if raw_name[:4] == bytes(4):
                off = struct.unpack_from('<I', raw_name, 4)[0]
                assert 4 <= off < length
                end = image.find(b'\0', strings + off, strings + length)
                assert end >= 0
                symbol = image[strings + off:end].decode('utf8', 'replace')
            else:
                symbol = raw_name.rstrip(b'\0').decode('utf8', 'replace')
            value, section, kind, _, aux = struct.unpack_from('<IhHBB', image, at + 8)
            if 0 < section <= count:
                rows.append((sections[section - 1][1] + value, symbol, kind))
            i += 1 + aux
    rows.sort()
    functions = [row for row in rows if row[2] & 0x20]
    preceding = [row for row in functions if row[0] <= rva]
    following = [row for row in functions if row[0] > rva]
    print(f'IMAGE {name} sha256={hashlib.sha256(image).hexdigest()} machine={machine:04x} '
          f'timestamp={stamp:08x} image-size={image_size:#x} symbols={nsym}')
    print(f'TARGET {name}+{rva:#x} preceding-functions={preceding[-4:]} next-functions={following[:2]}')
    for section_name, va, _, raw, raw_size, flags in sections:
        if va <= rva < va + raw_size:
            assert flags & 0x20000000, 'captured PC is not in executable section'
            print(f'SECTION {section_name} RVA={va:#x} flags={flags:#x}')
            begin = max(va, rva - 0x80) & ~3
            end = min(va + raw_size, rva + 0x180)
            dis = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            dis.skipdata = True
            for insn in dis.disasm(image[raw + begin - va:raw + end - va], begin):
                mark = ' >>' if insn.address == rva else '   '
                print(f'{mark} {insn.address:#x}: {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}')
            return
    raise AssertionError('captured RVA is outside file-backed PE sections')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('ipa')
    p.add_argument('--expected-uuid', required=True)
    p.add_argument('--query', action='append', required=True, metavar='FILE:RVA')
    args = p.parse_args()
    with zipfile.ZipFile(args.ipa) as archive:
        actual = native_uuid(archive.read('Payload/Madeira.app/Madeira.debug.dylib'))
        assert actual == args.expected_uuid.upper(), (actual, args.expected_uuid)
        print('PASS exact archived native UUID=' + actual)
        for query in args.query:
            name, rva = query.rsplit(':', 1)
            assert '/' not in name and '\\' not in name and name.endswith('.dll')
            inspect(archive.read('Payload/Madeira.app/arm64ec-windows/' + name), name, int(rva, 0))


if __name__ == '__main__':
    main()
