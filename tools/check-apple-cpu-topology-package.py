#!/usr/bin/env python3
"""Reject an IPA missing the rebuilt Apple CPU-topology producer.

This verifies the compiled contract marker and exact native app/IPA bytes.
Topology semantics are covered by check-apple-cpu-topology.py; this gate does
not establish the cause of CS2 dispatch or an on-device gameplay result.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import zipfile

MARKERS = (b'[apple-cpu-topology-v1]',)
ENTRY = 'Payload/Madeira.app/Madeira.debug.dylib'
BLOCK = 1 << 20
MAX_IMAGE = 2 << 30


def scan(stream):
    """Read bounded chunks, including markers straddling a chunk boundary."""
    digest = hashlib.sha256()
    found = {marker: False for marker in MARKERS}
    overlap = max(map(len, MARKERS)) - 1
    previous = b''
    size = 0
    for chunk in iter(lambda: stream.read(BLOCK), b''):
        if not size:
            assert len(chunk) >= 8 and struct.unpack_from('<II', chunk) == (0xfeedfacf, 0x100000c), \
                'Apple CPU-topology image must be native ARM64 Mach-O'
        size += len(chunk)
        assert size <= MAX_IMAGE, 'Apple CPU-topology native image exceeds size bound'
        digest.update(chunk)
        data = previous + chunk
        for marker in found:
            found[marker] |= marker in data
        previous = data[-overlap:]
    assert size >= 8, 'Apple CPU-topology native image is empty or truncated'
    missing = [marker.decode() for marker, present in found.items() if not present]
    assert not missing, 'stale Apple CPU-topology native contract: ' + ', '.join(missing)
    return size, digest.digest()


def check(native=None, ipa=None):
    assert native is not None or ipa is not None, 'provide a native image or IPA'
    expected = None
    if native is not None:
        native = Path(native)
        assert native.is_file() and not native.is_symlink(), 'native Apple CPU-topology image missing or symlinked'
        assert 8 <= native.stat().st_size <= MAX_IMAGE, 'native Apple CPU-topology image has invalid size'
        with native.open('rb') as stream:
            expected = scan(stream)
        assert expected[0] == native.stat().st_size, 'native image changed during validation'
    if ipa is not None:
        try:
            with zipfile.ZipFile(ipa) as archive:
                entries = [item for item in archive.infolist() if item.filename == ENTRY]
                assert len(entries) == 1, 'IPA Apple CPU-topology image missing or duplicated'
                entry = entries[0]
                assert not entry.is_dir() and 8 <= entry.file_size <= MAX_IMAGE, 'IPA Apple CPU-topology image has invalid size'
                with archive.open(entry) as stream:
                    actual = scan(stream)
                assert actual[0] == entry.file_size, 'IPA Apple CPU-topology image is truncated'
                if expected is not None:
                    assert actual == expected, 'app and IPA Apple CPU-topology images differ'
        except (zipfile.BadZipFile, EOFError) as error:
            raise AssertionError('invalid or truncated IPA: ' + str(error)) from error
    print('PASS rebuilt Apple CPU-topology native contract and exact app/IPA copy; '
          'CS2 dispatch and iPhone gameplay remain unverified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    if args.native is None and args.ipa is None:
        parser.error('provide --native and/or --ipa')
    check(args.native, args.ipa)
