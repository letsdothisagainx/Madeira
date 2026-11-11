#!/usr/bin/env python3
"""Read public Valve packages; never install, load, execute or alter their PEs.

This disposable CI inspection deliberately makes no HTMLIPC ABI or runtime
readiness claim. In particular an iOS mapped-image size may include Madeira's
alignment padding: compare actual PE headers, not only a runtime log extent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import urllib.request
import zipfile

ORIGIN = 'https://client-update.akamai.steamstatic.com/'
OLD = ('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8', 64309479,
       'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236')
OLD_CORE_SHA = '37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
OLD_METHODS = [0x58bf0, 0x59100, 0x590e0, 0x593f0, 0x58fa0, 0x58e60, 0x58dc0]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fetch(name, destination, maximum, expected_size=None, expected_sha=None):
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None, 'unsafe package name')
    url = ORIGIN + name
    digest, total = hashlib.sha256(), 0
    with urllib.request.urlopen(urllib.request.Request(url, headers={'Accept-Encoding': 'identity'}), timeout=90) as response:
        require(response.status == 200 and response.url == url, 'unexpected Valve CDN response')
        with destination.open('wb') as output:
            while chunk := response.read(1 << 20):
                total += len(chunk)
                require(total <= maximum, 'download exceeds bound')
                digest.update(chunk)
                output.write(chunk)
    actual = digest.hexdigest()
    require(expected_size is None or total == expected_size, 'package size mismatch')
    require(expected_sha is None or actual == expected_sha, 'package SHA-256 mismatch')
    return {'file': name, 'bytes': total, 'sha256': actual, 'source': ORIGIN}


class PE:
    def __init__(self, data):
        self.data = data
        require(64 <= len(data) <= 64 << 20 and data[:2] == b'MZ', 'invalid PE size/header')
        nt = self.unpack('<I', 60)[0]
        require(self.read(nt, 4) == b'PE\0\0', 'missing PE signature')
        self.machine, count = self.unpack('<HH', nt + 4)
        self.timestamp = self.unpack('<I', nt + 8)[0]
        optional_size = self.unpack('<H', nt + 20)[0]
        self.characteristics = self.unpack('<H', nt + 22)[0]
        optional = nt + 24
        magic = self.unpack('<H', optional)[0]
        require(magic in (0x10b, 0x20b) and 96 <= optional_size <= 4096 and 0 < count <= 96, 'unsupported PE headers')
        self.bits = 64 if magic == 0x20b else 32
        self.base = self.unpack('<Q' if self.bits == 64 else '<I', optional + (24 if self.bits == 64 else 28))[0]
        self.image_size, self.headers = self.unpack('<II', optional + 56)
        require(4096 <= self.image_size <= 256 << 20 and self.headers <= len(data), 'invalid PE image bounds')
        self.checksum_offset = optional + 64
        self.sections = []
        for index in range(count):
            row = optional + optional_size + index * 40
            name = self.read(row, 8).split(b'\0', 1)[0].decode('ascii', errors='replace')
            virtual, rva, size, raw = self.unpack('<IIII', row + 8)
            flags = self.unpack('<I', row + 36)[0]
            require(raw <= len(data) and size <= len(data) - raw and rva <= self.image_size and max(virtual, size) <= self.image_size - rva, 'invalid PE section')
            self.sections.append({'name': name, 'rva': rva, 'virtual': virtual, 'raw': raw, 'bytes': size, 'flags': flags,
                                  'raw_sha256': hashlib.sha256(self.read(raw, size)).hexdigest()})
        directory = optional + (112 if self.bits == 64 else 96)
        directory_count = self.unpack('<I', directory - 4)[0]
        require(directory_count <= 16 and directory + directory_count * 8 <= optional + optional_size, 'invalid PE directories')
        self.directories = [self.unpack('<II', directory + i * 8) for i in range(directory_count)]
        self.security_directory_offset = directory + 4 * 8 if directory_count > 4 else None

    def read(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset, 'truncated PE bytes')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))

    def offset(self, rva, size):
        if rva < self.headers and size <= self.headers - rva:
            return rva
        for section in self.sections:
            delta = rva - section['rva']
            if 0 <= delta <= section['bytes'] and size <= section['bytes'] - delta:
                return section['raw'] + delta
        raise ValueError('RVA is not file backed')

    def at(self, rva, size):
        return self.read(self.offset(rva, size), size)

    def rva_of(self, offset):
        for section in self.sections:
            if section['raw'] <= offset < section['raw'] + section['bytes']:
                return section['rva'] + offset - section['raw']
        return offset if offset < self.headers else None

    def string(self, rva):
        offset = self.offset(rva, 1)
        end = self.data.find(b'\0', offset, min(offset + 256, len(self.data)))
        require(end >= 0, 'unterminated PE name')
        name = self.data[offset:end].decode('ascii')
        require(all(32 <= ord(c) < 127 for c in name), 'nonprintable PE name')
        return name

    def imports(self):
        if len(self.directories) < 2 or not self.directories[1][0]:
            return []
        rva, size = self.directories[1]
        names = []
        for index in range(min(size // 20, 512)):
            row = self.at(rva + index * 20, 20)
            if not any(row):
                return names
            names.append(self.string(struct.unpack_from('<I', row, 12)[0]))
        raise ValueError('unterminated/excessive PE imports')

    def describe(self):
        certificate_offset, certificate_bytes = self.directories[4] if len(self.directories) > 4 else (0, 0)
        certificate_at_eof = bool(certificate_offset and certificate_bytes and certificate_offset % 8 == 0 and
                                  certificate_offset <= len(self.data) and certificate_bytes == len(self.data) - certificate_offset and
                                  all(s['raw'] + s['bytes'] <= certificate_offset for s in self.sections))
        canonical = bytearray(self.data[:certificate_offset] if certificate_at_eof else self.data)
        canonical[self.checksum_offset:self.checksum_offset + 4] = bytes(4)
        if self.security_directory_offset is not None:
            canonical[self.security_directory_offset:self.security_directory_offset + 8] = bytes(8)
        return {'bytes': len(self.data), 'sha256': hashlib.sha256(self.data).hexdigest(),
                'machine': f'{self.machine:04x}', 'pointer_bits': self.bits,
                'timestamp': f'0x{self.timestamp:x}', 'preferred_base': hex(self.base),
                'size_of_image': hex(self.image_size), 'sections': self.sections,
                'imports': self.imports(), 'certificate_file_offset': hex(certificate_offset),
                'certificate_bytes': certificate_bytes, 'certificate_is_bounded_eof_overlay': certificate_at_eof,
                'canonical_comparison_sha256': hashlib.sha256(canonical).hexdigest(),
                'canonical_comparison_scope': 'Checksum and security-directory bytes zeroed; certificate removed only when bounded at EOF outside every section. This is a byte-comparison aid, not Authenticode or trust verification.'}


def select(archive, wanted):
    with zipfile.ZipFile(archive) as z:
        require(len(z.infolist()) < 10000, 'archive entry bound exceeded')
        found = {}
        for item in z.infolist():
            name = item.filename.replace('\\', '/')
            require(item.orig_filename == item.filename, 'ambiguous archive member')
            if name.casefold() not in wanted:
                continue
            require(name.casefold() not in found and not item.flag_bits & 1 and item.file_size <= 64 << 20, 'invalid selected archive member')
            require(all(part not in ('', '.', '..') for part in name.split('/')), 'unsafe selected member')
            data = z.read(item)
            require(len(data) == item.file_size, 'truncated archive member')
            found[name.casefold()] = data
        return found


def occurrences(image, needle, limit=16):
    found, start = [], 0
    while (offset := image.data.find(needle, start)) >= 0:
        require(len(found) < limit, 'ambiguous/excessive ABI pattern matches')
        found.append({'file_offset': hex(offset), 'rva': hex(image.rva_of(offset)) if image.rva_of(offset) is not None else None})
        start = offset + 1
    return found


def compare(old, current):
    methods = []
    for rva in OLD_METHODS:
        prefix = old.at(rva, 48)
        methods.append({'old_rva': hex(rva), 'old_prefix_48': prefix.hex(),
                        'current_exact_prefix_locations': occurrences(current, prefix)})
    needles = [b'.?AVCSharedMemStream@@\0', b'.?AVIMemStream@@\0',
               b'ChromeHTML_Controller_003\0', b'bin/cef/cef.win64/steamwebhelper.exe\0',
               b'SteamChrome_MasterStream_spid%u\0']
    fields = {}
    for rva, size in [(0x132338, 64), (0x15c550, 24), (0x121cd8, 48), (0x123688, 42 * 8), (0x1806b0, 8)]:
        try:
            new_bytes = current.at(rva, size).hex()
        except ValueError:
            new_bytes = None
        try:
            old_bytes = old.at(rva, size).hex()
        except ValueError:
            old_bytes = None  # Mutable BSS/controller state has no disk bytes.
        fields[hex(rva)] = {'old': old_bytes, 'current_at_old_rva': new_bytes}
    return {'identical_file_bytes': old.data == current.data, 'old_profile_fields': fields,
            'method_prefixes': methods,
            'named_ABI_patterns': {needle.decode('ascii').rstrip('\0'): {'old': occurrences(old, needle), 'current': occurrences(current, needle)} for needle in needles},
            'warning': 'Prefix/string matches alone do not establish stream ABI or wire-command compatibility.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'format': 1, 'mode': 'read-only-public-file-inspection',
              'runtime_readiness': 'unmeasured', 'trust_scope': 'HTTPS Valve manifest plus package SHA-256; no VAC verdict'}
    with tempfile.TemporaryDirectory(prefix='madeira-steam-browser-inspection-') as name:
        temporary = Path(name)
        manifest_file = temporary / 'manifest'
        report['manifest'] = fetch('steam_client_win64', manifest_file, 1 << 20)
        manifest = manifest_file.read_text()
        version = re.search(r'"version"\s+"([0-9]+)"', manifest)
        require(version is not None, 'manifest has no version')
        report['manifest']['version'] = version[1]
        packages = {}
        for package in ('bins_win64', 'bins_webhelpers_win64', 'bins_cef_win64'):
            block = re.search(r'"' + package + r'"\s*\{([^{}]+)\}', manifest)
            require(block is not None, 'missing manifest package ' + package)
            values = dict(re.findall(r'"([A-Za-z0-9_]+)"\s+"([^"\r\n]+)"', block[1]))
            require(re.fullmatch(package + r'\.zip\.[0-9a-f]{40}', values.get('file', '')) is not None, 'unsupported package container')
            require(re.fullmatch(r'[0-9a-f]{64}', values.get('sha2', '')) is not None, 'missing authenticated package digest')
            packages[package] = (values['file'], int(values['size']), values['sha2'])
        report['manifest']['packages'] = packages
        old_path = temporary / 'old-core.zip'
        report['old_package'] = fetch(OLD[0], old_path, 128 << 20, OLD[1], OLD[2])
        old_bytes = select(old_path, {'bin/chromehtml.dll'})['bin/chromehtml.dll']
        require(hashlib.sha256(old_bytes).hexdigest() == OLD_CORE_SHA, 'old core provenance mismatch')
        old = PE(old_bytes)
        report['old_core'] = old.describe()
        report['current_packages'] = []
        selected = {}
        for package in ('bins_win64', 'bins_webhelpers_win64'):
            file, size, sha = packages[package]
            path = temporary / (package + '.zip')
            report['current_packages'].append(fetch(file, path, 128 << 20, size, sha))
            wanted = {'bin/chromehtml.dll', 'bin/steamservice.dll', 'bin/steamservice.exe',
                      'bin/cef/cef.win64/steamwebhelper.exe', 'steamclient64.dll', 'steamclient.dll'}
            for member, data in select(path, wanted).items():
                require(member not in selected, 'duplicate selected component')
                selected[member] = data
        require('bin/chromehtml.dll' in selected and 'bin/cef/cef.win64/steamwebhelper.exe' in selected, 'required current components absent')
        report['current_components'] = {member: PE(data).describe() for member, data in selected.items()}
        report['core_comparison'] = compare(old, PE(selected['bin/chromehtml.dll']))
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    require(len(text) < 256 << 10, 'inspection report exceeds bound')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
