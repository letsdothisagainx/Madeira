"""Owned PE resource bytes for package-parser negative tests, not an OS emulator."""
import struct


def resource(values, rva=0x2900, language=0x409):
    payload = bytearray(struct.pack('<I', len(values)) + bytes(12 * len(values)))
    for index, (value, text) in enumerate(sorted(values.items())):
        struct.pack_into('<III', payload, 4 + 12 * index, value, value, len(payload))
        encoded = (text + '\r\n\0').encode('utf-16-le')
        encoded += bytes((-len(encoded)) % 4)
        payload += struct.pack('<HH', 4 + len(encoded), 1) + encoded
    tree = bytearray(88)
    for at in (0, 24, 48):
        struct.pack_into('<HH', tree, at + 12, 0, 1)
    struct.pack_into('<II', tree, 16, 11, 0x80000018)
    struct.pack_into('<II', tree, 40, 1, 0x80000030)
    struct.pack_into('<II', tree, 64, language, 72)
    struct.pack_into('<IIII', tree, 72, rva + 88, len(payload), 0, 0)
    return tree + payload


def add_to_owned_pe(data, values):
    data = bytearray(data)
    pe, = struct.unpack_from('<I', data, 60)
    opt = pe + 24
    magic, = struct.unpack_from('<H', data, opt)
    dirs = opt + (96 if magic == 0x10b else 112)
    body = resource(values)
    assert len(body) <= 0x700
    struct.pack_into('<II', data, dirs + 16, 0x2900, len(body))
    data[0xf00:0xf00 + len(body)] = body
    return data
