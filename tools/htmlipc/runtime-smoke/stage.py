#!/usr/bin/env python3
"""Stage an official-component interoperability experiment in an empty directory.

Never run against an installed Steam directory. No version receipts, steam.cfg,
update switches, account data, or binary patches are created.
"""
import argparse
import os
import hashlib
import io
import json
import re
import struct
import urllib.request
import urllib.error
import time
import zipfile
from pathlib import Path, PurePosixPath

ORIGIN = 'https://client-update.akamai.steamstatic.com/'
CURRENT_VERSION = '1792618285'
CURRENT_CORE = ('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8',
                'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236')
LEGACY_CORE = ('bins_win64.zip.60eb5927dc89e3352bfabaf26ffa7b94d5f67604', 62591361,
               '117d666a5a06474260bf0407e21ac52ebecbdbca55bb85ad7807bcf09757f293')
I386_CEF = ('bins_cef_win32.zip.1c1d9dc1d899e7c8d1cff9cb0fcc11b89e412b98',
            'fee14790d59463f31693ef95e10327824f5bdd95baf0aa8fae3b81aea98e794f')
I386_HELPER = ('bins_webhelpers_win32.zip.8a153ec2ee2090c19b25204806ffca2a7ba15bf2',
               '1ab3b3834172a644759860f65d853970ba1d8b65f30190aae774395d69136307')
MAX_DOWNLOAD = 600 * 1024**2
MAX_UNPACKED = 2500 * 1024**2


def digest(data):
    return hashlib.sha256(data).hexdigest()


def vdf(text):
    tokens = [a if a else b for a, b in re.findall(r'"([^"\r\n]*)"|([{}])', text)]
    cursor = 0

    def parse(nested=False):
        nonlocal cursor
        result = {}
        while cursor < len(tokens):
            key = tokens[cursor]
            cursor += 1
            if key == '}':
                assert nested, 'unexpected closing brace'
                return result
            assert key != '{' and cursor < len(tokens)
            value = tokens[cursor]
            cursor += 1
            assert key not in result, f'duplicate key: {key}'
            result[key] = parse(True) if value == '{' else value
        assert not nested, 'missing closing brace'
        return result

    return parse()


def package(manifest, architecture, key):
    # Use ONLY the default node, never its win7-64/SteamChina alternatives.
    node = manifest[architecture][key]
    assert isinstance(node, dict) and all(k in node for k in ('file', 'size', 'sha2'))
    assert re.fullmatch(r'[A-Za-z0-9_.-]+\.zip\.[0-9a-f]{40}', node['file'])
    assert re.fullmatch(r'[0-9a-f]{64}', node['sha2'])
    size = int(node['size'])
    assert 0 < size <= 200 * 1024**2
    return node['file'], size, node['sha2']


def safe_name(name):
    assert '\\' not in name and ':' not in name
    path = PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts
    assert path.parts and path.parts[0] != '.'
    return path


def machine(data):
    assert data[:2] == b'MZ' and len(data) >= 0x40
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[offset:offset + 4] == b'PE\0\0'
    return struct.unpack_from('<H', data, offset + 4)[0]


def open_official(url):
    for attempt in range(3):
        try:
            return urllib.request.urlopen(url, timeout=30)
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            print('OFFICIAL_CDN_RETRY', attempt + 1, error.code, flush=True)
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2: raise
            print('OFFICIAL_CDN_RETRY', attempt + 1, 'connection', flush=True)
        time.sleep(attempt + 1)
    raise AssertionError('bounded retry fell through')


def fetch(name, size=None):
    cache = Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE']) if os.environ.get('MADEIRA_VALVE_ARCHIVE_CACHE') else None
    cached = cache / name if cache else None
    if size is not None and cached and cached.is_file():
        existing = cached.read_bytes()
        assert len(existing) == size
        return existing
    # Redirects remain HTTPS and at an official steamstatic.com CDN host.
    with open_official(ORIGIN + name) as response:
        from urllib.parse import urlparse
        url = urlparse(response.url)
        assert url.scheme == 'https' and url.hostname.endswith('.steamstatic.com')
        limit = size if size is not None else 2 * 1024**2
        blob = response.read(limit + 1)
    assert len(blob) <= limit
    if size is not None:
        assert len(blob) == size
    return blob


def stage(root, current_manifest_path, current_manifest_sha, mode, bridge_dll=None):
    root = root.resolve()
    assert not root.exists(), 'scratch destination must not exist'
    expected_manifest = current_manifest_path.read_bytes()
    assert digest(expected_manifest) == current_manifest_sha
    # Abort on a newly published client. This is not a request to pin updates.
    live = fetch('steam_client_win64')
    assert live == expected_manifest, 'official current manifest changed; refresh inspection inputs'
    current = vdf(live.decode())
    assert current['win64']['version'] == CURRENT_VERSION
    win32_bytes = fetch('steam_client_win32')
    assert digest(win32_bytes) == '4b8aa78d95dd7a1475c7849c3e783b136452d34be67342b53728799d697c4823'
    win32 = vdf(win32_bytes.decode())
    assert win32['win32']['version'] == '1769731672'
    assert package(current, 'win64', 'bins_win64')[::2] == CURRENT_CORE
    cef = package(win32, 'win32', 'bins_cef_win32')
    helper = package(win32, 'win32', 'bins_webhelpers_win32')
    assert cef[::2] == I386_CEF and helper[::2] == I386_HELPER
    selected = [(key, package(current, 'win64', key)) for key, value in current['win64'].items()
                if isinstance(value, dict) and key not in ('bins_cef_win64', 'bins_webhelpers_win64')]
    selected += [(key, package(current, 'win64', key)) for key in ('bins_cef_win64','bins_webhelpers_win64')]
    if mode == 'bridge':
        selected += [('coherent-i386-cef', cef), ('coherent-i386-helper', helper)]
    total = sum(item[1][1] for item in selected)
    assert total <= MAX_DOWNLOAD
    steam = root / 'steam'
    steam.mkdir(parents=True)
    report = {'experiment': 'current-amd64-core/current-controller/'+mode,
              'current_version': CURRENT_VERSION, 'legacy_controller_version': None,
              'browser_version': '1769731672' if mode == 'bridge' else CURRENT_VERSION, 'download_bytes': total, 'archives': [], 'files': {},
              'user_installation_accessed': False, 'auth_data_present': False,
              'update_bypass_flags': [], 'version_receipts_created': False}
    unpacked = 0
    browser_files = {}
    for label, (name, size, sha) in selected:
        print('PINNED_ARCHIVE', label, name, flush=True)
        blob = fetch(name, size)
        assert digest(blob) == sha
        if os.environ.get('MADEIRA_VALVE_ARCHIVE_CACHE'):
            cache = Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE'])
            cache.mkdir(parents=True, exist_ok=True)
            (cache / name).write_bytes(blob)
        report['archives'].append({'label': label, 'file': name, 'size': size, 'sha256': sha})
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                path = safe_name(member.filename)
                assert (member.external_attr >> 16) & 0o170000 != 0o120000, 'symlink refused'
                if label == 'legacy-controller-only' and str(path).lower() != 'bin/chromehtml.dll':
                    continue
                unpacked += member.file_size
                assert unpacked <= MAX_UNPACKED
                data = archive.read(member)
                if label.startswith('coherent-i386-'):
                    assert str(path) not in browser_files or browser_files[str(path)] == data, 'conflicting browser archive members'
                    browser_files[str(path)] = data
                    continue
                destination = steam.joinpath(*path.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
    # Move the complete verified browser tree, not individual/mixed DLLs.
    parents = {str(PurePosixPath(name).parent) for name in browser_files
               if PurePosixPath(name).name.lower() in ('libcef.dll', 'steamwebhelper.exe')}
    assert len(parents) == (1 if mode == 'bridge' else 0), 'browser archives do not share one coherent directory'
    parent = next(iter(parents)) if parents else ''
    browser_root = steam / 'bin/cef/cef.win32'
    if mode == 'baseline':
        assert not browser_files
    assert not browser_root.exists()
    assert (steam / 'bin/cef/cef.win64').is_dir(), 'official current CEF must remain installed'
    for name, data in browser_files.items():
        path = PurePosixPath(name)
        assert path.is_relative_to(parent), 'official browser archive has files outside its runtime tree'
        relative = path.relative_to(parent)
        destination = browser_root.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    for path, expected_machine in (
        ('steam.exe', 0x8664), ('SteamUI.dll', 0x8664), ('steamclient64.dll', 0x8664),
        ('bin/chromehtml.dll', 0x8664), ('bin/cef/cef.win64/steamwebhelper.exe', 0x8664),
        ('bin/cef/cef.win64/libcef.dll', 0x8664), ('bin/cef/cef.win64/chrome_elf.dll', 0x8664)):
        data = (steam / path).read_bytes()
        assert machine(data) == expected_machine, path
        report['files'][path] = {'sha256': digest(data), 'machine': f'{expected_machine:04x}'}
    assert report['files']['bin/chromehtml.dll']['sha256'] == '37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
    if mode == 'bridge':
        assert bridge_dll and bridge_dll.is_file(), 'compiled real source provider required'
        native = bridge_dll.read_bytes()
        assert machine(native) == 0x8664
        assert not (steam / 'version.dll').exists(), 'official current package contains version.dll; refuse replacement'
        (steam / 'version.dll').write_bytes(native)
        report['files']['version.dll'] = {'sha256': digest(native), 'machine': '8664'}
        for name in ('steamwebhelper.exe', 'libcef.dll', 'chrome_elf.dll'):
            relative = 'bin/cef/cef.win32/' + name
            data = (steam / relative).read_bytes()
            assert machine(data) == 0x14c
            report['files'][relative] = {'sha256': digest(data), 'machine': '014c'}
        # Verify the architecture of the genuine current core's actual 32-bit
        # SteamClient dependency; do not substitute an unrelated DLL.
        dependency = steam / 'steamclient.dll'
        report['steamclient_i386_present'] = dependency.is_file()
        if dependency.is_file():
            data = dependency.read_bytes()
            report['steamclient_i386_machine'] = hex(machine(data))
            report['steamclient_i386_sha256'] = digest(data)
            assert machine(data) == 0x14c
    assert (steam / 'steamui').is_dir(), 'current Steam web UI resources missing'
    assert not list(steam.glob('**/steam.cfg'))
    assert not list(steam.glob('**/*loginusers*'))
    report['unpacked_bytes'] = unpacked
    (root / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'staged': True, 'download_bytes': total, 'unpacked_bytes': unpacked,
                      'browser_files': len(browser_files), 'identity_count': len(report['files'])}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['baseline','bridge'], required=True)
    parser.add_argument('--bridge-dll', type=Path)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--current-manifest', type=Path, required=True)
    parser.add_argument('--current-manifest-sha256', required=True)
    args = parser.parse_args()
    stage(args.root, args.current_manifest, args.current_manifest_sha256, args.mode, args.bridge_dll)
