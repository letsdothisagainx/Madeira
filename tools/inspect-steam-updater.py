#!/usr/bin/env python3
"""Inspect Valve's public Windows bootstrap packages; never install or run them."""
import hashlib
import io
import re
import struct
import urllib.request
import zipfile
from pathlib import Path

ORIGIN = 'https://client-update.akamai.steamstatic.com/'


def fetch(name, limit):
    with urllib.request.urlopen(ORIGIN + name, timeout=120) as response:
        if response.status != 200 or response.url != ORIGIN + name:
            raise ValueError('unexpected CDN response')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('oversized response')
    return data


def main():
    # The manifest is retrieved from Valve over HTTPS. The package is then
    # independently checked against its SHA-256 before parsing any ZIP entry.
    manifest = fetch('steam_client_win64', 1 << 20).decode()
    print('manifest-sha256=' + hashlib.sha256(manifest.encode()).hexdigest())
    print('version=' + re.search(r'"version"\s+"([0-9]+)"', manifest)[1])
    packages = re.findall(r'"file"\s+"(steam_win64(?:_steamrow)?\.zip\.[0-9a-f]{40})"\s+"size"\s+"([0-9]+)"\s+"sha2"\s+"([0-9a-f]{64})"', manifest)
    name, size, expected = next(p for p in packages if p[0].startswith('steam_win64.zip.'))
    candidate = Path(__file__).resolve().parents[1] / 'app/Madeira/SteamClientUpdate.swift'
    image_hash = None
    if candidate.exists():
        source = candidate.read_text()
        name = re.search(r'static let package = "([^"]+)"', source)[1]
        size = re.search(r'static let packageBytes = ([0-9_]+)', source)[1].replace('_', '')
        expected = re.search(r'static let packageSHA256 = "([0-9a-f]{64})"', source)[1]
        image_hash = re.search(r'static let imageSHA256 = "([0-9a-f]{64})"', source)[1]
        assert re.fullmatch(r'steam_win64\.zip\.[0-9a-f]{40}', name)
        print(f'candidate-matches-current-manifest={int((name, size, expected) in packages)}')
    data = fetch(name, 16 << 20)
    assert len(data) == int(size) and hashlib.sha256(data).hexdigest() == expected
    print(f'package={name} bytes={size} sha256={expected}')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert sum(i.file_size for i in archive.infolist()) < 64 << 20
        for entry in archive.infolist():
            print(f'entry={entry.filename} bytes={entry.file_size}')
            if entry.filename.lower() != 'steam.exe':
                continue
            image = archive.read(entry)
            assert image[:2] == b'MZ'
            pe = struct.unpack_from('<I', image, 0x3c)[0]
            assert image[pe:pe+4] == b'PE\0\0'
            machine = struct.unpack_from('<H', image, pe+4)[0]
            print(f'steam.exe machine={machine:04x} sha256={hashlib.sha256(image).hexdigest()}')
            assert machine == 0x8664
            if image_hash:
                assert hashlib.sha256(image).hexdigest() == image_hash
            shown = 0
            for text in re.findall(rb'[ -~]{6,}', image):
                if shown < 32 and b'\\' not in text and any(key in text.lower() for key in (b'win64', b'32-bit', b'64-bit', b'forcewin')):
                    print('bootstrap-string=' + text[:240].decode())
                    shown += 1


if __name__ == '__main__':
    main()
