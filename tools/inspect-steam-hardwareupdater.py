#!/usr/bin/env python3
"""Inspect an authentic Steam hardware updater without executing its code.

HTTPS manifest/package SHA-256 establishes source provenance, not Authenticode,
runtime readiness, hardware compatibility, or VAC acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


public = load('hardware_public_pe', ROOT / 'tools/inspect-steam-browser-update.py')
service = load('hardware_manifest', ROOT / 'tools/inspect-steam-service-loader.py')
require = public.require


def pe_summary(raw):
    pe = public.PE(raw)
    return {key: value for key, value in pe.describe().items()
            if key in ('bytes', 'sha256', 'machine', 'pointer_bits', 'timestamp',
                       'preferred_base', 'size_of_image', 'imports',
                       'certificate_file_offset', 'certificate_bytes')}


def carchive(raw):
    magic = b'MEI\x0c\x0b\x0a\x0b\x0e'
    cookie = raw.rfind(magic)
    require(cookie >= 0 and cookie + 88 <= len(raw), 'no bounded modern PyInstaller cookie')
    _, package_size, toc_offset, toc_size, version, dll_name = struct.unpack_from('!8sIIII64s', raw, cookie)
    dll_name = dll_name.split(b'\0', 1)[0].decode('ascii')
    require(re.fullmatch(r'python[0-9]+\.dll', dll_name, re.I) is not None, 'unexpected Python runtime name')
    start = cookie + 88 - package_size
    require(0 <= start < cookie and toc_offset <= package_size and toc_size <= package_size - toc_offset,
            'PyInstaller package or table outside executable')
    cursor, end = start + toc_offset, start + toc_offset + toc_size
    require(end <= cookie, 'PyInstaller table overlaps cookie')
    entries, native, unpacked = [], {}, 0
    while cursor < end:
        require(len(entries) < 4096 and end - cursor >= 18, 'PyInstaller entry bound exceeded')
        size, offset, compressed, expanded, flag, kind = struct.unpack_from('!iIIIBc', raw, cursor)
        require(18 <= size <= end - cursor and flag in (0, 1), 'invalid PyInstaller entry header')
        name_raw = raw[cursor + 18:cursor + size]
        require(b'\0' in name_raw, 'unterminated PyInstaller entry')
        name = name_raw.split(b'\0', 1)[0].decode('utf-8')
        require(name and len(name) < 1024 and offset <= toc_offset and compressed <= toc_offset - offset,
                'PyInstaller payload outside package data')
        entry = {'name': name, 'kind': kind.decode('ascii'), 'compressed_bytes': compressed,
                 'expanded_bytes': expanded, 'compressed': bool(flag)}
        entries.append(entry)
        if name.lower().endswith(('.dll', '.pyd')):
            require(expanded <= 32 << 20 and unpacked + expanded <= 128 << 20, 'native payload bound exceeded')
            payload = raw[start + offset:start + offset + compressed]
            if flag:
                decoder = zlib.decompressobj()
                body = decoder.decompress(payload, expanded + 1)
                require(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
                        'incomplete or concatenated native payload')
            else:
                body = payload
            require(len(body) == expanded, 'native payload size differs from archive table')
            unpacked += expanded
            require(name not in native, 'duplicate native payload')
            native[name] = pe_summary(body)
        cursor += size
    require(cursor == end, 'misaligned PyInstaller table end')
    return {'cookie_file_offset': hex(cookie), 'package_file_offset': hex(start),
            'package_bytes': package_size, 'toc_relative_offset': hex(toc_offset),
            'toc_bytes': toc_size, 'python_version_code': version, 'python_dll': dll_name,
            'entries': entries, 'native_components': native,
            'scope': 'Read-only table/decompression/PE inspection; Python bytecode and native code never executed.'}


def bootloader(raw):
    """Record the actual bootloader's ordinary process-creation evidence."""
    inspector = service.Inspector(raw)
    names = ('_PYI_PARENT_PROCESS_LEVEL', '_PYI_APPLICATION_HOME_DIR', '_PYI_ARCHIVE_FILE',
             'Failed to create child process!', 'CreateProcessW', 'GetCommandLineW')
    strings = []
    for name in names:
        for encoding, value in (('ascii', name.encode()), ('utf16le', name.encode('utf-16le'))):
            offset = raw.find(value)
            if offset < 0:
                continue
            rva = inspector.pe.rva_of(offset)
            strings.append({'name': name, 'encoding': encoding, 'file_offset': hex(offset),
                            'rva': hex(rva) if rva is not None else None,
                            'references': [hex(x) for x in inspector.string_refs(rva)] if rva is not None else []})
    slots = {rva: name for rva, name in inspector.imports.items()
             if name.rsplit('!', 1)[-1] in ('CreateProcessW', 'CreateProcessA', 'GetCommandLineW',
                                          'GetModuleFileNameW', 'SetEnvironmentVariableW')}
    calls, bodies = [], {}
    for section in inspector.code:
        body = inspector.pe.at(section['rva'], section['bytes'])
        for match in re.finditer(b'\xff\x15....', body, re.S):
            rva = section['rva'] + match.start()
            ins = next(inspector.md.disasm(body[match.start():match.start() + 15], rva, count=1), None)
            if ins is None:
                continue
            row = inspector.row(ins)
            if not any(ref.get('import', '').rsplit('!', 1)[-1] in ('CreateProcessW', 'CreateProcessA')
                       for ref in row.get('references', [])):
                continue
            require(len(calls) < 8, 'process-creation callsite bound exceeded')
            calls.append(row)
            function = inspector.body(rva)
            bodies[function['start_rva']] = function
    return {'strings': strings, 'imports': {hex(rva): name for rva, name in slots.items()},
            'process_creation_calls': calls, 'process_creation_functions': list(bodies.values()),
            'scope': 'Actual PE bytes and ordinary process APIs; no code executed. The upstream PyInstaller algorithm is a separate reference, not a runtime result.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inspect-file', type=Path)
    args = parser.parse_args()
    report = {'format': 1, 'mode': 'read-only-public-binary-inspection',
              'runtime_readiness': 'unmeasured', 'vac_verdict': 'unmeasured'}
    if args.inspect_file:
        raw = args.inspect_file.read_bytes()
        report['helper'] = pe_summary(raw)
        report['pyinstaller'] = carchive(raw)
        report['bootloader'] = bootloader(raw)
    else:
        with tempfile.TemporaryDirectory(prefix='madeira-official-hardware-') as name:
            temporary = Path(name)
            manifest = temporary / 'manifest'
            report['manifest'] = public.fetch('steam_client_win64', manifest, 1 << 20)
            values = service.manifest_blocks(manifest.read_text())
            report['manifest']['version'] = values.get('version')
            packages = {key: value for key, value in values.items() if isinstance(value, dict)
                        and all(field in value for field in ('file', 'size', 'sha2'))}
            report['manifest']['package_inventory'] = {key: {'file': value['file'], 'bytes': int(value['size'])}
                                                       for key, value in packages.items()}
            order = sorted(packages, key=lambda key: (0 if re.search('hardware|hwupdate', key, re.I) else
                                                     1 if 'misc' in key else 2 if key == 'bins_win64' else 3, key))
            report['searched_packages'] = []
            total = 0
            for key in order:
                value = packages[key]
                size, sha, file = int(value['size']), value['sha2'], value['file']
                if size > 128 << 20 or any(word in key for word in ('cef', 'localization', 'fonts', 'webhelper', 'vr')):
                    continue
                require(0 < size <= 128 << 20 and total + size <= 512 << 20,
                        'official package search download budget exceeded before finding helper')
                require(re.fullmatch('[0-9a-f]{64}', sha) is not None, 'manifest package SHA missing')
                archive = temporary / 'current.zip'
                downloaded = public.fetch(file, archive, 128 << 20, size, sha)
                total += size
                report['searched_packages'].append({'name': key, **downloaded})
                with zipfile.ZipFile(archive) as z:
                    require(len(z.infolist()) < 10000, 'package entry bound exceeded')
                    selected = [entry for entry in z.infolist()
                                if entry.filename.replace('\\', '/').lower() == 'bin/hardwareupdater/hardwareupdater.exe']
                    if not selected:
                        continue
                    require(len(selected) == 1 and not selected[0].flag_bits & 1 and selected[0].file_size <= 128 << 20,
                            'invalid official helper member')
                    raw = z.read(selected[0])
                    report['helper_package'] = {'name': key, **downloaded}
                    report['helper'] = {'member': selected[0].filename, **pe_summary(raw)}
                    report['pyinstaller'] = carchive(raw)
                    report['bootloader'] = bootloader(raw)
                    break
            require('helper' in report, 'official current packages did not provide the requested helper')
    encoded = json.dumps(report, indent=2).encode() + b'\n'
    require(len(encoded) <= 2 << 20, 'inspection report bound exceeded')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    # Keep useful public evidence available in logs when artifact redirects cannot be read.
    for key in ('manifest', 'helper_package', 'helper'):
        if key in report:
            value = {k: v for k, v in report[key].items() if k != 'package_inventory'}
            print(json.dumps({'record': key, **value}, separators=(',', ':')))
    py = report['pyinstaller']
    print(json.dumps({'record': 'pyinstaller', **{key: value for key, value in py.items()
                                               if key not in ('entries', 'native_components')}}))
    for name, data in py['native_components'].items():
        print(json.dumps({'record': 'native-component', 'name': name, **data}, separators=(',', ':')))
    bl = report['bootloader']
    print(json.dumps({'record': 'bootloader', **{key: value for key, value in bl.items()
                                               if key != 'process_creation_functions'}}, separators=(',', ':')))
    for function in bl['process_creation_functions']:
        print(json.dumps({'record': 'process-creation-function', **{key: value for key, value in function.items()
                                                                  if key != 'instructions'}}, separators=(',', ':')))
        rows = function['instructions']
        selected = set()
        for index, row in enumerate(rows):
            if any(ref.get('import', '').rsplit('!', 1)[-1] in ('CreateProcessW', 'CreateProcessA', 'GetCommandLineW')
                   for ref in row.get('references', [])):
                selected.update(range(max(0, index - 64), min(len(rows), index + 25)))
        require(len(selected) <= 512, 'process creation stdout bound exceeded')
        for index in sorted(selected):
            print(json.dumps({'record': 'process-creation-instruction', **rows[index]}, separators=(',', ':')))
    print(f'PASS public helper inspection report-bytes={len(encoded)} executed=0 runtime=unmeasured VAC=unmeasured')


if __name__ == '__main__':
    main()
