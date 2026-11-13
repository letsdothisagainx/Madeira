#!/usr/bin/env python3
"""Reject stale native networking features in the app and exact IPA copy.

Presence/packaging proof only: this does not establish on-device relay access.
"""
import argparse
import hashlib
import mmap
from pathlib import Path
import struct
import zipfile

MARKERS = (b'[udp-send-failure-v1]', b'[udp-recv-failure-v1]',
           b'[udp-native-progress-v1]', b'MadeiraSocketControl:traffic-class-bounds-v1',
           b'[nsi-ipv4-route-v1]')
ENTRY = 'Payload/Madeira.app/Madeira.debug.dylib'


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1 << 20), b''):
        result.update(chunk)
    return result.digest()


def check(native, ipa=None):
    assert native.is_file() and not native.is_symlink(), 'native network image is missing or symlinked'
    assert 8 <= native.stat().st_size <= 2 << 30, 'native network image has invalid size'
    with native.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        assert struct.unpack_from('<II', data) == (0xfeedfacf, 0x100000c), 'expected native ARM64 Mach-O'
        for marker in MARKERS:
            assert data.find(marker) >= 0, 'stale native networking contract: ' + marker.decode()
    if ipa is not None:
        with native.open('rb') as stream:
            expected = digest(stream)
        with zipfile.ZipFile(ipa) as archive:
            entries = [entry for entry in archive.infolist() if entry.filename == ENTRY]
            assert len(entries) == 1 and entries[0].file_size == native.stat().st_size, 'IPA native networking entry missing, duplicated or wrong size'
            with archive.open(entries[0]) as stream:
                assert digest(stream) == expected, 'IPA contains a different native networking image'
    print('PASS compiled native receive/control/route contracts and exact IPA bytes; official relay connectivity requires iPhone validation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    check(args.native, args.ipa)
