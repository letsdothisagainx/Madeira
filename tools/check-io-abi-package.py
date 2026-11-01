#!/usr/bin/env python3
"""Require the matching native IOSB consumer and rebuilt ARM64 WoW64 producer."""
import argparse
from pathlib import Path
import struct
import zipfile

PRODUCER = b'madeira-io-abi-v1'
CONSUMER = b'[io-abi] v1 per-request IOSB layout active'


def producer(data):
    assert data[:2] == b'MZ', 'WoW64 producer is not a PE image'
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe + 4] == b'PE\0\0', 'invalid WoW64 PE signature'
    assert struct.unpack_from('<H', data, pe + 4)[0] == 0xaa64, 'WoW64 producer must be native ARM64'
    assert PRODUCER in data, 'stale WoW64 IOSB producer'


def check(staged, app, ipa):
    expected = staged.read_bytes()
    producer(expected)
    assert (app / 'aarch64-windows/wow64.dll').read_bytes() == expected, 'Xcode packaged a stale WoW64 producer'
    native = (app / 'Madeira.debug.dylib').read_bytes()
    assert CONSUMER in native, 'native IOSB consumer missing from linked image'
    with zipfile.ZipFile(ipa) as archive:
        assert archive.read('Payload/Madeira.app/aarch64-windows/wow64.dll') == expected, 'ZIP producer differs'
        assert archive.read('Payload/Madeira.app/Madeira.debug.dylib') == native, 'ZIP native consumer differs'
    print('PASS final IPA contains matching native IOSB consumer and byte-identical rebuilt ARM64 WoW64 producer')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', type=Path, required=True)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--ipa', type=Path, required=True)
    args = parser.parse_args()
    check(args.staged, args.app, args.ipa)
