#!/usr/bin/env python3
"""Read actual PE message resources; do not infer success from source strings.

These entries describe genuine failures. Their presence does not establish
packet delivery, authentication, a publisher identity or a secure-play result.
"""
import argparse
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    10051: 'A socket operation was attempted to an unreachable network.',
    10060: 'A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.',
    10065: 'A socket operation was attempted to an unreachable host.',
}


def messages(data, language=0x409):
    def unpack(fmt, at):
        size = struct.calcsize(fmt)
        assert 0 <= at <= len(data) and size <= len(data) - at, 'truncated PE resource'
        return struct.unpack_from(fmt, data, at)
    assert data[:2] == b'MZ', 'invalid PE DOS signature'
    pe, = unpack('<I', 60)
    assert data[pe:pe + 4] == b'PE\0\0', 'invalid PE signature'
    _, sections, _, _, _, optional_size, _ = unpack('<HHIIIHH', pe + 4)
    opt = pe + 24
    magic, = unpack('<H', opt)
    assert magic in (0x10b, 0x20b), 'invalid PE optional header'
    dirs = opt + (96 if magic == 0x10b else 112)
    count, = unpack('<I', dirs - 4)
    assert count >= 3 and dirs + 24 <= opt + optional_size, 'missing resource directory'
    resource_rva, resource_size = unpack('<II', dirs + 16)
    assert resource_rva and 16 <= resource_size <= len(data), 'missing message resources'
    table = opt + optional_size
    assert 0 < sections <= 96, 'invalid PE section count'
    ranges = []
    for index in range(sections):
        length, rva, raw_size, raw = unpack('<IIII', table + 40 * index + 8)
        assert raw <= len(data) and raw_size <= len(data) - raw, 'truncated PE section'
        ranges.append((rva, raw_size, raw))
    def offset(rva, size):
        for base, extent, raw in ranges:
            if rva >= base and rva - base <= extent and size <= extent - (rva - base):
                return raw + rva - base
        raise AssertionError('resource is not file-backed')
    resource_at = offset(resource_rva, resource_size)
    def within(at, size):
        assert at <= resource_size and size <= resource_size - at, 'resource tree outside directory'
        return resource_at + at
    def child(at, wanted, directory):
        named, numbered = unpack('<HH', within(at, 16) + 12)
        assert named + numbered <= 4096, 'oversized resource directory'
        within(at + 16, 8 * (named + numbered))
        found = None
        for index in range(named + numbered):
            key, value = unpack('<II', resource_at + at + 16 + 8 * index)
            if key != wanted:
                continue
            assert found is None, 'ambiguous resource entry'
            assert bool(value & 0x80000000) == directory, 'wrong resource tree entry type'
            found = value & 0x7fffffff
        assert found is not None, 'required message-table resource absent'
        return found
    type_at = child(0, 11, True)  # RT_MESSAGETABLE
    name_at = child(type_at, 1, True)
    leaf = child(name_at, language, False)
    rva, size, _, _ = unpack('<IIII', within(leaf, 16))
    payload = data[offset(rva, size):offset(rva, size) + size]
    assert len(payload) >= 4, 'truncated message-table data'
    count, = struct.unpack_from('<I', payload)
    assert 0 < count <= 65536 and 4 + count * 12 <= len(payload), 'invalid message blocks'
    result = {}
    previous = -1
    for index in range(count):
        low, high, at = struct.unpack_from('<III', payload, 4 + 12 * index)
        assert previous < low <= high and high - low <= 65536, 'unordered message block'
        assert 4 + count * 12 <= at <= len(payload), 'message entry overlaps block headers'
        previous = high
        for value in range(low, high + 1):
            assert at + 4 <= len(payload), 'truncated message entry'
            length, flags = struct.unpack_from('<HH', payload, at)
            assert 4 <= length <= len(payload) - at and flags in (0, 1), 'invalid message entry'
            raw = payload[at + 4:at + length]
            if flags:
                assert len(raw) % 2 == 0, 'unaligned Unicode message'
            text = raw.decode('utf-16-le' if flags else 'cp1252').rstrip('\0\r\n')
            assert value not in result, 'duplicate message identifier'
            result[value] = text
            at += length
    return result


def check(data):
    found = messages(data)
    for value, text in EXPECTED.items():
        assert found.get(value) == text, f'missing or stale Windows socket message {value}'
    return {str(value): found[value] for value in EXPECTED}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('images', nargs='+', type=Path)
    args = parser.parse_args()
    for image in args.images:
        assert image.is_file() and not image.is_symlink() and image.stat().st_size <= 64 << 20
        check(image.read_bytes())
        print('PASS compiled PE Winsock message resources 10051/10060/10065: ' + str(image))


if __name__ == '__main__':
    main()
