#!/usr/bin/env python3
"""Verify exact-build evidence separating dormant registration from Library routing.

Read-only static proof, not a claim of renderer or screensaver compatibility.
No Steam/account installation is accessed or executed. The literal occurrence
count applies to these shipped resources, not arbitrary dynamically built calls.
Inspection: https://github.com/letsdothisagainx/Madeira/actions/runs/41799828099
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import struct
import urllib.request
import zipfile

PACKAGES = (
    ('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8', 64_309_479,
     'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236'),
    ('steamui_websrc_all.zip.24dd80531ce5c8cf19b5bfdd2e580ab55ebf8365', 35_647_879,
     '275f353463226631c3a43e90994f65a64262c30a961dccd257ccfc4b08f2f1a1'),
)
CORE_SHA256 = 'cd9226db4e6c28942df70c22c0475d91fdd62cba5f100baae2d65af57cabb610'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official', action='store_true', help='Permit the two exact public Valve archive downloads')
parser.add_argument('--cache', type=Path, default=Path(os.environ.get('MADEIRA_VALVE_ARCHIVE_CACHE', '.official-browser-archives')))
args = parser.parse_args()
if not args.download_official:
    parser.error('--download-official is required; network access is never implicit')
args.cache.mkdir(parents=True, exist_ok=True)
archives = []
for name, size, digest in PACKAGES:
    file = args.cache / name
    if file.is_file():
        data = file.read_bytes()
    else:
        url = 'https://client-update.akamai.steamstatic.com/' + name
        with urllib.request.urlopen(url, timeout=60) as response:
            assert response.status == 200 and response.url == url
            data = response.read(size + 1)
        assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
        file.write_bytes(data)
    assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
    archives.append(data)
with zipfile.ZipFile(io.BytesIO(archives[0])) as archive:
    names = [name for name in archive.namelist() if name.lower().endswith('steamui.dll')]
    assert len(names) == 1
    image = archive.read(names[0])
assert hashlib.sha256(image).hexdigest() == CORE_SHA256
nt, = struct.unpack_from('<I', image, 0x3c)
assert image[nt:nt + 4] == b'PE\0\0' and struct.unpack_from('<H', image, nt + 4)[0] == 0x8664
count, optional_bytes = struct.unpack_from('<H', image, nt + 6)[0], struct.unpack_from('<H', image, nt + 20)[0]
sections = nt + 24 + optional_bytes

def at(rva, size):
    for index in range(count):
        section = sections + 40 * index
        va, raw, offset = struct.unpack_from('<III', image, section + 12)
        if va <= rva and rva - va + size <= raw:
            return image[offset + rva - va:offset + rva - va + size]
    raise AssertionError('RVA is not backed by the exact image')

def relative(rva, prefix, length):
    assert at(rva, len(prefix)) == prefix
    return rva + length + struct.unpack('<i', at(rva + length - 4, 4))[0]

assert relative(0x663721, b'\xe8', 5) == 0x66aa30
assert relative(0x66ab8d, b'\x48\x8d\x15', 7) == 0xda11d0
domain_format = b'%s.steamscreensavers.host\0'
assert at(0xda11d0, len(domain_format)) == domain_format
assert at(0x66abaf, 7) == b'\x48\x8b\xb8\x30\x01\x00\x00'  # controller slot 38
assert at(0x66abc5, 2) == b'\xff\xd7'  # call the retrieved registration method
assert at(0x66ab71, 2) == b'\x74\x6e'  # empty enumeration skips to cleanup66abe1
assert at(0x663b12, 7) == b'\x48\x8b\xb8\x38\x01\x00\x00'  # separate per-browser local mapping
assert at(0x663b37, 2) == b'\xff\xd7'
hits = []
with zipfile.ZipFile(io.BytesIO(archives[1])) as archive:
    members = [entry for entry in archive.infolist() if entry.filename.endswith(('.js', '.json'))]
    assert len(members) < 10_000 and sum(entry.file_size for entry in members) < 256 * 1024 * 1024
    for entry in members:
        assert entry.file_size < 64 * 1024 * 1024
        data = archive.read(entry)
        offset = 0
        while (offset := data.find(b'bBrowserViewDomainMapping', offset)) >= 0:
            hits.append((entry.filename, offset, data[max(0, offset - 700):offset + 400]))
            offset += 1
assert len(hits) == 1
name, _, context = hits[0]
assert name == 'steamui/sp.js'
assert b'CreateBrowserView("Screensaver",$r)' in context and b'bBrowserViewDomainMapping:!0' in context
assert b'screensaver_current_id' in context and b'Xt.strID==Xu.HW?' in context and b'Xt.strURL?' in context
print('PASS exact SteamUI/native and web-resource pins: startup registers enumerated *.steamscreensavers.host mappings before shared browser; ordinary shared UI independently uses local mapping; only literal activation is the custom-screensaver branch. No activation, policy equivalence or rendered UI is claimed.')
