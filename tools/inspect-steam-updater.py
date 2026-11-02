#!/usr/bin/env python3
"""Inspect Valve's public Windows bootstrap packages; never install or run them."""
import hashlib
import io
import re
import struct
import urllib.request
import zipfile

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
            for text in re.findall(rb'[ -~]{6,}', image):
                if any(key in text.lower() for key in (b'win64', b'win32', b'32-bit', b'64-bit', b'forcewin', b'migrate')):
                    print('bootstrap-string=' + text[:240].decode())


if __name__ == '__main__':
    main()
