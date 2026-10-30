#!/usr/bin/env python3
"""Locate an APC fault in an exact arm64 Mach-O image, without running it."""
import argparse
import hashlib
from pathlib import Path
import struct
import uuid


def inspect(path, offset):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    data = Path(path).read_bytes()
    magic, cpu, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x0100000c:
        raise ValueError('expected a thin, little-endian arm64 Mach-O image')
    pos = 32
    segments, symbols, image_uuid = [], None, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, pos)
        if size < 8 or pos + size > len(data):
            raise ValueError('invalid Mach-O load command')
        if cmd == 0x19:  # LC_SEGMENT_64
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', data, pos + 24)
            segments.append((vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x1b:  # LC_UUID
            image_uuid = str(uuid.UUID(bytes=data[pos + 8:pos + 24])).upper()
        elif cmd == 2:  # LC_SYMTAB
            symbols = struct.unpack_from('<4I', data, pos + 8)
        pos += size
    if not symbols or not image_uuid:
        raise ValueError('image needs its UUID and native symbol table')
    symoff, count, stroff, strsize = symbols
    names = {}
    for i in range(count):
        index, kind, _, _, address = struct.unpack_from('<IBBHQ', data, symoff + i * 16)
        if not index or index >= strsize or kind & 0xe0:
            continue
        end = data.find(b'\0', stroff + index, stroff + strsize)
        if end < 0:
            raise ValueError('unterminated native symbol')
        name = data[stroff + index:end].decode('utf-8', 'replace')
        names[name] = address
    address = names.get('_invoke_system_apc')
    if address is None:
        raise ValueError('invoke_system_apc symbol not present')
    target = address + offset
    start, end = max(address, target - 48), target + 52
    for vmaddr, _, fileoff, filesize in segments:
        if vmaddr <= start and end <= vmaddr + filesize:
            raw = data[fileoff + start - vmaddr:fileoff + end - vmaddr]
            break
    else:
        raise ValueError('APC instruction range is not file-backed')
    lines = [f'UUID={image_uuid}', f'SHA256={hashlib.sha256(data).hexdigest()}',
             f'invoke_system_apc={address:#x} target=+{offset:#x} ({target:#x})']
    for insn in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(raw, start):
        mark = 'FAULT-OFFSET' if insn.address == target else ''
        lines.append(f'+{insn.address - address:04x} {insn.bytes.hex()} '
                     f'{insn.mnemonic} {insn.op_str} {mark}'.rstrip())
    return image_uuid, lines


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--offset', type=lambda s: int(s, 0), default=0x578)
    parser.add_argument('--expected-uuid')
    parser.add_argument('--annotations', action='store_true')
    args = parser.parse_args()
    image_uuid, lines = inspect(args.image, args.offset)
    for line in lines:
        print(line)
        if args.annotations:
            print('::notice title=Native APC image::' + line.replace('%', '%25'))
    if args.expected_uuid and image_uuid != args.expected_uuid.upper():
        raise SystemExit('UUID does not match the device report; do not attribute this disassembly to it')
