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
    def at(address, length):
        for _, va, _, raw, raw_size, _ in sections:
            if va <= address and address - va + length <= raw_size:
                return image[raw + address - va:raw + address - va + length]
        raise AssertionError(f'PE metadata outside file-backed sections: {address:#x}+{length:#x}')

    def value(fmt, address):
        return struct.unpack(fmt, at(address, struct.calcsize(fmt)))

    def string(address):
        for _, va, _, raw, raw_size, _ in sections:
            if va <= address < va + raw_size:
                off = raw + address - va
                stop = image.find(b'\0', off, min(off + 512, raw + raw_size))
                assert stop >= 0, 'unterminated bounded PE name'
                return image[off:stop].decode('ascii', 'replace')
        raise AssertionError('PE name outside sections')

    def directory(index):
        return struct.unpack_from('<II', image, pe + 24 + 112 + index * 8)

    # ARM64EC uses a native 8-byte RUNTIME_FUNCTION table in CHPE metadata;
    # its ordinary exception directory can contain x64 12-byte entries.
    # Never decode the latter as native ARM64 unwind records.
    redirects, metadata = {}, None
    config, config_size = directory(10)
    if config and config_size >= 208:
        preferred = struct.unpack_from('<Q', image, pe + 24 + 24)[0]
        pointer = value('<Q', config + 200)[0]
        if pointer:
            assert pointer >= preferred
            metadata = pointer - preferred
            version, ranges, ranges_count = value('<III', metadata)
            table = value('<I', metadata + 16)[0]
            table_count = value('<I', metadata + 52)[0]
            assert version in (1, 2) and ranges_count <= 65536 and table_count <= 65536
            for i in range(table_count):
                source, dest = value('<II', table + i * 8)
                assert source not in redirects, 'duplicate CHPE redirection'
                redirects[source] = dest
            matched_ranges = []
            for i in range(ranges_count):
                first, length = value('<II', ranges + i * 8)
                if first & ~3 <= rva < (first & ~3) + length:
                    matched_ranges.append((hex(first & ~3), hex(length), first & 3))
            print(f'CHPE target={rva:#x} version={version} code-ranges={matched_ranges}')
            native_table, table_bytes = value('<II', metadata + 64)
            assert table_bytes <= 8 << 20 and table_bytes % 8 == 0
            for i in range(table_bytes // 8):
                begin, unwind = value('<II', native_table + i * 8)
                flag = unwind & 3
                if flag in (1, 2):
                    length = ((unwind >> 2) & 0x7ff) * 4
                    detail = (f'packed flag={flag} frame-bytes={((unwind >> 23) & 0x1ff) * 16} '
                              f'RegF={(unwind >> 13) & 7} RegI={(unwind >> 16) & 15} '
                              f'H={(unwind >> 20) & 1} CR={(unwind >> 21) & 3}')
                elif not flag and unwind:
                    header = value('<I', unwind)[0]
                    length = (header & 0x3ffff) * 4
                    detail = f'xdata={unwind:#x} header={header:#010x} first16={at(unwind, 16).hex()}'
                else:
                    continue
                if begin <= rva < begin + length:
                    print(f'NATIVE_UNWIND entry={native_table + i * 8:#x} begin={begin:#x} '
                          f'end={begin + length:#x} raw={unwind:#x} {detail}')

    export, export_size = directory(0)
    export_rows = []
    if export:
        functions_count, names_count, functions_table, names_table, ordinals = value('<IIIII', export + 20)
        assert functions_count <= 65536 and names_count <= 65536
        for i in range(names_count):
            symbol = string(value('<I', names_table + i * 4)[0])
            ordinal = value('<H', ordinals + i * 2)[0]
            assert ordinal < functions_count
            entry = value('<I', functions_table + ordinal * 4)[0]
            if export <= entry < export + export_size:
                continue
            native = redirects.get(entry, entry)
            if 0 <= rva - native < 128:
                export_rows.append((symbol, hex(entry), hex(native), rva - native))
        print(f'EXPORT_NEAR target={rva:#x} names/export/native/delta={export_rows}')

    imports = {}
    import_table, import_size = directory(1)
    if import_table:
        for i in range(min(import_size // 20, 512)):
            row = value('<IIIII', import_table + i * 20)
            if not any(row):
                break
            original, _, _, dll_name, first = row
            dll = string(dll_name)
            for j in range(8192):
                thunk = value('<Q', (original or first) + j * 8)[0]
                if not thunk:
                    break
                function = '#' + str(thunk & 0xffff) if thunk >> 63 else string(thunk + 2)
                imports[first + j * 8] = dll + '!' + function
            else:
                raise AssertionError('unterminated import thunk table')
        else:
            raise AssertionError('unterminated import descriptor table')
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
    def function_at(address):
        candidates = [row for row in functions if row[0] <= address]
        return candidates[-1] if candidates else None

    def print_callers(target, depth=0):
        if depth >= 2:
            return
        callers = []
        for _, va, _, raw, raw_size, flags in sections:
            if not flags & 0x20000000:
                continue
            for off in range(0, raw_size - 3, 4):
                word = struct.unpack_from('<I', image, raw + off)[0]
                if word & 0xfc000000 != 0x94000000:
                    continue
                delta = word & 0x3ffffff
                if delta & 0x2000000:
                    delta -= 0x4000000
                address = va + off
                if address + delta * 4 == target:
                    callers.append((address, function_at(address)))
        print(f'CALLERS depth={depth} target={target:#x} count={len(callers)} rows={callers[:16]}')
        seen = set()
        for _, function in callers[:16]:
            if function and function[0] not in seen:
                seen.add(function[0])
                print_callers(function[0], depth + 1)

    if preceding:
        print_callers(preceding[-1][0])
    for section_name, va, _, raw, raw_size, flags in sections:
        if va <= rva < va + raw_size:
            assert flags & 0x20000000, 'captured PC is not in executable section'
            print(f'SECTION {section_name} RVA={va:#x} flags={flags:#x}')
            begin = max(va, rva - 0x80) & ~3
            end = min(va + raw_size, rva + 0x180)
            dis = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            dis.skipdata = True
            dis.detail = True
            register_pages = {}
            for insn in dis.disasm(image[raw + begin - va:raw + end - va], begin):
                mark = ' >>' if insn.address == rva else '   '
                print(f'{mark} {insn.address:#x}: {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}')
                ops = insn.operands if insn.id else []
                if insn.mnemonic == 'adrp' and len(ops) == 2:
                    register_pages[ops[0].reg] = ops[1].imm
                elif insn.mnemonic == 'ldr' and len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_MEM:
                    address = register_pages.get(ops[1].mem.base)
                    if address is not None and address + ops[1].mem.disp in imports:
                        slot = address + ops[1].mem.disp
                        print(f'       IAT_REFERENCE instruction={insn.address:#x} slot={slot:#x} import={imports[slot]}')
                    register_pages.pop(ops[0].reg, None)
                if insn.mnemonic in ('b', 'bl', 'blr', 'br', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz'):
                    register_pages.clear()
                elif insn.id and insn.mnemonic != 'adrp':
                    for reg in insn.regs_access()[1]:
                        register_pages.pop(reg, None)
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
