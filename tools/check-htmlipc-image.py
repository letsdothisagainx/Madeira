#!/usr/bin/env python3
"""Validate source-built AMD64 HTMLIPC DATA and exact bundle/IPA resources.

This reads PE bytes. It never loads a DLL, executes guest code, or claims that
runtime readiness/Steam UI has been reached. Native-owner provenance is supplied
by the hash-bound build report; the PE has no immutable compile-mode export.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

RESOURCE = 'arm64ec-windows/madeira-htmlipc-bridge.dll'
MANIFEST_RESOURCE = 'arm64ec-windows/madeira-htmlipc-bridge.manifest.json'
FILENAME = 'madeira-htmlipc-bridge.dll'
CORE_SHA256 = '37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
READY_MAGIC = 0x314452504948444d
READY_SIZE = 80
READY_VERSION = 1
EXPORTS = {'MadeiraArmStreamInstaller', 'MadeiraStreamInstallerStatus',
           'MadeiraResolveCurrentController', 'MadeiraRuntimeGetStatus', 'MadeiraRuntimeReady'}
MAX_IMAGE = 32 << 20

class InvalidImage(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise InvalidImage(message)

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None

class PE:
    def __init__(self, data):
        self.data = data
        require(64 <= len(data) <= MAX_IMAGE, 'invalid DLL file size')
        require(data[:2] == b'MZ', 'missing DOS header')
        self.pe = self.unpack('<I', 60)[0]
        require(64 <= self.pe <= len(data) - 24, 'invalid PE header offset')
        require(self.read(self.pe, 4) == b'PE\0\0', 'missing PE signature')
        self.machine, count = self.unpack('<HH', self.pe + 4)
        require(self.machine == 0x8664, 'source bridge must be genuine AMD64 (8664)')
        flags = self.unpack('<H', self.pe + 22)[0]
        require(flags & 0x2000, 'source bridge must be a DLL')
        self.optional = self.pe + 24
        optional_size = self.unpack('<H', self.pe + 20)[0]
        require(120 <= optional_size <= 4096, 'invalid optional header size')
        require(self.unpack('<H', self.optional)[0] == 0x20b, 'source bridge must be PE32+')
        self.entry = self.unpack('<I', self.optional + 16)[0]
        self.image_size, self.headers_size = self.unpack('<II', self.optional + 56)
        require(4096 <= self.image_size <= MAX_IMAGE, 'invalid mapped image size')
        require(0 < self.headers_size <= min(self.image_size, len(data)), 'invalid PE header extent')
        directories = self.unpack('<I', self.optional + 108)[0]
        require(2 <= directories <= 16 and 112 + directories * 8 <= optional_size,
                'invalid data directory count/extent')
        self.directories = [self.unpack('<II', self.optional + 112 + i * 8) for i in range(directories)]
        require(1 <= count <= 96, 'invalid section count')
        section_table = self.optional + optional_size
        require(section_table + count * 40 <= self.headers_size, 'section table exceeds headers')
        self.sections = []
        raw_ranges = []
        for i in range(count):
            at = section_table + 40 * i
            name = self.read(at, 8).split(b'\0', 1)[0]
            virtual, rva, raw_size, raw = self.unpack('<IIII', at + 8)
            characteristics = self.unpack('<I', at + 36)[0]
            extent = max(virtual, raw_size)
            require(rva <= self.image_size and extent <= self.image_size - rva,
                    'section exceeds mapped image')
            require(not extent or rva >= self.headers_size, 'section overlaps headers')
            require(raw <= len(data) and raw_size <= len(data) - raw, 'section raw data exceeds file')
            require(not raw_size or raw >= self.headers_size, 'raw section overlaps headers')
            for other in self.sections:
                require(not extent or not other['extent'] or
                        rva + extent <= other['rva'] or other['rva'] + other['extent'] <= rva,
                        'overlapping mapped sections')
            for a, b in raw_ranges:
                require(not raw_size or raw + raw_size <= a or b <= raw, 'overlapping raw sections')
            if raw_size:
                raw_ranges.append((raw, raw + raw_size))
            require(not (characteristics & 0x20000000 and characteristics & 0x80000000),
                    'writable executable section')
            require(not extent or name not in (b'.CRT', b'.ctors', b'.init_array', b'.hexpthk', b'.wowthk', b'.a64xrm'),
                    'constructor/hybrid architecture section')
            self.sections.append(dict(name=name, rva=rva, extent=extent, virtual=virtual,
                                      raw=raw, raw_size=raw_size, flags=characteristics, table=at))
        require(self.entry and self.section(self.entry, 1)['flags'] & 0x20000000,
                'missing executable DllMain entry')
        if len(self.directories) > 10:
            load_rva, load_size = self.directories[10]
            if load_rva or load_size:
                require(load_rva and load_size >= 4, 'invalid load configuration')
                declared = self.rva_unpack('<I', load_rva)[0]
                require(4 <= declared <= load_size, 'invalid load configuration extent')
                if declared >= 0xd0:
                    require(self.rva_unpack('<Q', load_rva + 0xc8)[0] == 0,
                            'ARM64EC/CHPE metadata in AMD64 source bridge')

    def read(self, offset, size):
        require(isinstance(offset, int) and 0 <= offset <= len(self.data) and
                0 <= size <= len(self.data) - offset, 'truncated PE data')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))

    def section(self, rva, size):
        require(0 <= rva <= self.image_size and 0 <= size <= self.image_size - rva,
                'RVA exceeds mapped image')
        matches = [s for s in self.sections if s['rva'] <= rva and
                   size <= s['extent'] - (rva - s['rva'])]
        require(len(matches) == 1, 'ambiguous/unmapped RVA')
        return matches[0]

    def offset(self, rva, size):
        if 0 <= rva < self.headers_size and size <= self.headers_size - rva:
            return rva
        section = self.section(rva, size)
        delta = rva - section['rva']
        require(delta <= section['raw_size'] and size <= section['raw_size'] - delta,
                'RVA has no initialized file bytes')
        return section['raw'] + delta

    def rva_read(self, rva, size):
        return self.read(self.offset(rva, size), size)

    def rva_unpack(self, fmt, rva):
        return struct.unpack(fmt, self.rva_read(rva, struct.calcsize(fmt)))

    def string(self, rva, maximum=128):
        value = bytearray()
        for i in range(maximum):
            b = self.rva_read(rva + i, 1)[0]
            if not b:
                try:
                    return value.decode('ascii')
                except UnicodeDecodeError as error:
                    raise InvalidImage('non-ASCII PE name') from error
            value.append(b)
        raise InvalidImage('unterminated/oversized PE name')

    def exports(self):
        rva, size = self.directories[0]
        require(rva and 40 <= size <= self.image_size - rva, 'missing/invalid export directory')
        fields = self.rva_unpack('<IIHHIIIIIII', rva)
        functions, names, function_rva, name_rva, ordinal_rva = fields[6:]
        require(1 <= functions <= 4096 and 1 <= names <= 4096, 'invalid export counts')
        self.rva_read(function_rva, functions * 4)
        self.rva_read(name_rva, names * 4)
        self.rva_read(ordinal_rva, names * 2)
        result = {}
        for i in range(names):
            name = self.string(self.rva_unpack('<I', name_rva + i * 4)[0], 64)
            ordinal = self.rva_unpack('<H', ordinal_rva + i * 2)[0]
            require(ordinal < functions and name not in result, 'invalid/duplicate named export')
            target = self.rva_unpack('<I', function_rva + ordinal * 4)[0]
            require(target and not rva <= target < rva + size, 'native bridge has export forwarder')
            result[name] = target
        require(set(result) == EXPORTS and functions == len(EXPORTS), 'unexpected/missing source bridge export')
        return result

    def imports(self):
        rva, size = self.directories[1]
        require(rva and 20 <= size <= self.image_size - rva, 'missing/invalid import directory')
        result = {}
        terminated = False
        for i in range(min(size // 20, 128)):
            lookup, timestamp, forwarder, name, iat = self.rva_unpack('<5I', rva + i * 20)
            if not any((lookup, timestamp, forwarder, name, iat)):
                terminated = True
                break
            dll = self.string(name, 64).lower()
            require(dll not in result and dll in ('kernel32.dll', 'ntdll.dll'), 'unexpected/duplicate imported DLL')
            require(lookup or iat, 'missing import lookup table')
            symbols = []
            for j in range(512):
                entry = self.rva_unpack('<Q', (lookup or iat) + j * 8)[0]
                if not entry:
                    break
                require(not entry >> 63 and entry <= 0xffffffff, 'unexpected ordinal/VA import')
                symbol = self.string(entry + 2)
                require(symbol not in symbols, 'duplicate import')
                symbols.append(symbol)
            else:
                raise InvalidImage('unterminated import table')
            result[dll] = symbols
        require(terminated and set(result) == {'kernel32.dll', 'ntdll.dll'}, 'unterminated/missing import descriptor')
        require('NtQueryInformationProcess' in result['ntdll.dll'], 'missing native owner lease query import')
        for index in (9, 13):
            if len(self.directories) > index:
                require(self.directories[index] == (0, 0), 'unexpected TLS/delay import directory')
        return result

    def mapped_image(self):
        result = bytearray(self.image_size)
        result[:self.headers_size] = self.data[:self.headers_size]
        for section in self.sections:
            at, raw, size = section['rva'], section['raw'], section['raw_size']
            result[at:at + size] = self.data[raw:raw + size]
        return result

def inspect_image(data):
    pe = PE(data)
    exports = pe.exports()
    imports = pe.imports()
    ready_rva = exports['MadeiraRuntimeReady']
    ready = pe.section(ready_rva, READY_SIZE)
    require(ready['flags'] & 0x40000000 and ready['flags'] & 0x80000000 and
            ready['flags'] & 0xc0 and not ready['flags'] & 0x32000020,
            'MadeiraRuntimeReady must be private readable/writable nonexecutable DATA')
    fields = pe.rva_unpack('<Q8I5Q', ready_rva)
    require(fields[:3] == (READY_MAGIC, READY_SIZE, READY_VERSION), 'wrong Ready DATA ABI')
    require(fields[3] and not fields[3] & 1 and not any(fields[4:]), 'Ready DATA must start unpublished/zero')
    for name, rva in exports.items():
        if name != 'MadeiraRuntimeReady':
            require(pe.section(rva, 1)['flags'] & 0x20000000, 'function export is not executable code')
    return dict(machine='8664', pe='PE32+', sha256=sha256(data), bytes=len(data),
                ready_rva=ready_rva, image_size=pe.image_size, imports=imports, exports=exports)

# Reusable build-hook API. Both names inspect file bytes only.
parse_pe = inspect_image

def make_manifest(data, abi_header, core_hash=CORE_SHA256, build_report=None, cache_marker=None):
    result = dict(format=1, mode='native-owner', filename=FILENAME, bytes=len(data), sha256=sha256(data),
                  coreSHA256=core_hash,
                  readinessABI=dict(version=READY_VERSION, size=READY_SIZE,
                                    sha256=sha256(Path(abi_header).read_bytes())))
    if build_report is not None:
        result['sourceSHA256'] = sha256(json.dumps(build_report['sources'], sort_keys=True,
                                                separators=(',', ':')).encode())
    if cache_marker is not None:
        result['cacheMarkerSHA256'] = sha256(Path(cache_marker).read_bytes())
    validate_manifest(data, result, result['readinessABI']['sha256'], core_hash)
    return result

def validate_manifest(data, manifest, abi_hash=None, core_hash=CORE_SHA256):
    require(isinstance(manifest, dict), 'manifest must be an object')
    require(type(manifest.get('format')) is int and manifest['format'] == 1, 'unsupported source manifest format')
    require(manifest.get('mode') == 'native-owner' and manifest.get('filename') == FILENAME,
            'manifest must select named native-owner source bridge')
    require(type(manifest.get('bytes')) is int and manifest['bytes'] == len(data), 'manifest byte count mismatch')
    require(manifest.get('sha256') == sha256(data), 'manifest DLL hash mismatch')
    require(digest(manifest.get('coreSHA256')) and manifest['coreSHA256'] == core_hash, 'manifest current core hash mismatch')
    abi = manifest.get('readinessABI')
    require(isinstance(abi, dict) and type(abi.get('version')) is int and abi['version'] == READY_VERSION and
            type(abi.get('size')) is int and abi['size'] == READY_SIZE and
            digest(abi.get('sha256')), 'manifest readiness ABI mismatch')
    if abi_hash is not None:
        require(abi['sha256'] == abi_hash, 'manifest readiness header hash mismatch')
    for key in ('sourceSHA256', 'cacheMarkerSHA256'):
        if key in manifest:
            require(digest(manifest[key]), 'invalid manifest ' + key)

def validate_build_report(data, manifest, report, source_root=None):
    require(isinstance(report, dict), 'build report must be an object')
    require(report.get('native_owner') is True and report.get('stock_wine_test') is False and
            report.get('experimental_auto_arm') is True, 'report is not an active native-owner build')
    require(report.get('compiler_target') == 'x86_64-windows-msvc', 'incorrect source compiler target')
    require(report.get('sha256') == sha256(data) and report.get('size') == len(data), 'build report DLL hash/size mismatch')
    require(report.get('owner_query_class') == '0x4d480001' and report.get('cache_environment') == 'MADEIRA_HTMLIPC_CACHE_DIR',
            'incorrect native-owner/cache build contract')
    require(report.get('writable_executable_sections') is False and report.get('static_constructor_sections') is False,
            'unsafe source build section report')
    abi = report.get('ready_data')
    require(isinstance(abi, dict) and abi.get('name') == 'MadeiraRuntimeReady' and abi.get('size') == READY_SIZE and
            abi.get('version') == READY_VERSION and abi.get('abi_sha256') == manifest['readinessABI']['sha256'] and
            abi.get('forwarder') is False and abi.get('executable') is False and abi.get('shared_section') is False,
            'build report readiness ABI mismatch')
    if 'diagnostics_merged' in report:
        require(report['diagnostics_merged'] is True, 'source diagnostics build mode mismatch')
    if 'core_sha256' in report:
        require(report['core_sha256'] == manifest['coreSHA256'], 'build/manifest current core mismatch')
    if 'cache_marker_sha256' in report:
        require(digest(report['cache_marker_sha256']), 'invalid build cache marker hash')
        if 'cacheMarkerSHA256' in manifest:
            require(report['cache_marker_sha256'] == manifest['cacheMarkerSHA256'], 'build/manifest cache marker mismatch')
    sources = report.get('sources')
    require(isinstance(sources, dict) and len(sources) >= 7 and all(isinstance(k, str) and digest(v) for k, v in sources.items()),
            'missing/invalid source closure hashes')
    closure = sha256(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())
    if 'sourceSHA256' in manifest:
        require(manifest['sourceSHA256'] == closure, 'manifest source closure hash mismatch')
    if source_root is not None:
        root = Path(source_root).resolve()
        for name, expected in sources.items():
            path = Path(name)
            require(not path.is_absolute() and '..' not in path.parts, 'unsafe source report path')
            path = (root / path).resolve()
            require(path.is_relative_to(root) and path.is_file() and sha256(path.read_bytes()) == expected,
                    'source closure file hash mismatch: ' + name)

def validate_packages(data, manifest_bytes, app=None, ipa=None):
    if app is not None:
        for name, expected in ((RESOURCE, data), (MANIFEST_RESOURCE, manifest_bytes)):
            path = Path(app) / name
            require(path.is_file() and not path.is_symlink(), 'missing/symlinked app resource: ' + name)
            require(path.read_bytes() == expected, 'app resource differs from staged: ' + name)
    if ipa is not None:
        with zipfile.ZipFile(ipa) as archive:
            for name, expected in ((RESOURCE, data), (MANIFEST_RESOURCE, manifest_bytes)):
                entry = 'Payload/Madeira.app/' + name
                require(archive.namelist().count(entry) == 1, 'missing/duplicate IPA resource: ' + name)
                info = archive.getinfo(entry)
                require((info.external_attr >> 16) & 0o170000 != 0o120000, 'symlinked IPA resource: ' + name)
                require(info.file_size == len(expected) and archive.read(info) == expected,
                        'IPA resource differs from staged: ' + name)

def check(staged, manifest_path, abi_header=None, build_report=None, source_root=None, app=None, ipa=None,
          core_hash=CORE_SHA256):
    require(Path(staged).is_file() and not Path(staged).is_symlink(), 'missing/symlinked staged DLL')
    require(Path(staged).stat().st_size <= MAX_IMAGE, 'oversized staged DLL')
    require(Path(manifest_path).stat().st_size <= 65536, 'oversized source manifest')
    data = Path(staged).read_bytes()
    manifest_bytes = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_bytes)
    result = inspect_image(data)
    validate_manifest(data, manifest, sha256(Path(abi_header).read_bytes()) if abi_header else None, core_hash)
    if build_report is not None:
        validate_build_report(data, manifest, json.loads(Path(build_report).read_bytes()), source_root)
    require(source_root is None or build_report is not None, '--source-root requires --build-report')
    validate_packages(data, manifest_bytes, app, ipa)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--abi-header', type=Path, required=True)
    parser.add_argument('--build-report', type=Path)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--core-sha256', default=CORE_SHA256)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path)
    args = parser.parse_args()
    try:
        result = check(args.staged, args.manifest, args.abi_header, args.build_report,
                       args.source_root, args.app, args.ipa, args.core_sha256)
    except (InvalidImage, OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile) as error:
        parser.exit(1, 'FAIL: HTMLIPC source image/package: ' + str(error) + '\n')
    print('PASS HTMLIPC AMD64 PE32+ DLL: private Ready DATA80, owner query import, native manifest/hash and exact package bytes; runtime readiness unclaimed')
    return result

if __name__ == '__main__':
    main()
