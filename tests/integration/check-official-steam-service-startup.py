#!/usr/bin/env python3
"""Run the genuine pinned Valve service through production preparation and SCM.

This is a Linux-Wine control, not an iOS/FEX runtime claim. It creates its own
prefix, obtains only the immutable official packages already pinned by Madeira,
and runs Valve's own /install and /RunAsService paths. The control executable
only holds the test session and queries SCM; it never substitutes for the
service or supplies status/pipe replies. No account or installed game is used.
"""
from pathlib import Path
import argparse
import hashlib
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official', action='store_true', help='Allow the immutable official Valve packages pinned in production SteamRuntime.swift')
args = parser.parse_args()
if not args.download_official:
    parser.error('--download-official is required; no network access is implicit')
for tool in ['wine', 'wineserver', 'i686-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc']:
    assert shutil.which(tool), 'required integration tool unavailable: ' + tool
WINE64 = shutil.which('wine64') or next((str(p) for p in [Path('/usr/lib/wine/wine64'), Path('/usr/lib64/wine/wine64')] if p.is_file()), None)
assert WINE64, 'explicit AMD64 Wine loader unavailable'
runtime = (ROOT / 'app/Madeira/SteamRuntime.swift').read_text()
origin = re.search(r'static let origin = "(https://[^"\n]+/)"', runtime).group(1)
assert origin == 'https://client-update.akamai.steamstatic.com/'
recipe = re.search(r'static let packages = \[(.*?)\n    \]', runtime, re.S).group(1)
packages = re.findall(r'Package\(file: "([^"\n]+)", bytes: ([0-9_]+),\s*sha256: "([0-9a-f]{64})"\)', recipe)
assert len(packages) == 3, 'production official package recipe changed; review the genuine service control'
MAX_OUTPUT = 8 * 1024 * 1024

with tempfile.TemporaryDirectory(prefix='madeira-genuine-service-') as directory:
    temporary = Path(directory)
    prefix = temporary / 'prefix'
    env = {**os.environ, 'WINEPREFIX': str(prefix), 'WINEARCH': 'win64',
           'WINEDEBUG': '-all,trace+service,err+service,err+module', 'WINEDLLOVERRIDES': 'mscoree,mshtml='}
    for key in list(env):
        if any(word in key.upper() for word in ['TOKEN', 'PASSWORD', 'SECRET', 'CREDENTIAL']):
            env.pop(key)
    def safe_lines(output):
        lines = []
        for line in output.decode(errors='replace').splitlines():
            if not any(word in line.lower() for word in ['[steam-service]', '[service-fixture]', 'service', 'error', 'failed', 'wine:']):
                continue
            line = re.sub(r'https?://[^\s]+', '<url>', line)
            line = line.replace(str(ROOT), '<repo>').replace(str(temporary), '<isolated-prefix>')
            line = re.sub(r'(?:[A-Za-z]:[\\/]|/)[^\s"\']+', '<path>', line)
            lines.append(line[:360])
        return lines[-32:]
    def run(argv, *, phase, expected=0, timeout=90):
        try:
            result = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(f'genuine service phase={phase} timeout={timeout}; bounded={safe_lines((error.stdout or b"")[:MAX_OUTPUT])!r}') from None
        assert len(result.stdout) <= MAX_OUTPUT, phase + ': diagnostic bound exceeded'
        if expected is not None and result.returncode != expected:
            raise AssertionError(f'genuine service phase={phase} exit={result.returncode}; bounded={safe_lines(result.stdout)!r}')
        return result.returncode, result.stdout
    def compile_pe(compiler, destination, source):
        run([compiler, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-municode', '-static',
             '-Wl,--no-insert-timestamp', str(source), '-ladvapi32', '-o', str(destination)], phase='compile')
    helper = temporary / 'madeira-steam-service.exe'
    control = temporary / 'scm-query32.exe'
    compile_pe('x86_64-w64-mingw32-gcc', helper, ROOT / 'build/steam-service/main.c')
    compile_pe('i686-w64-mingw32-gcc', control, ROOT / 'tests/integration/steam-service/fixture.c')
    anchor = None
    try:
        run([WINE64, 'wineboot.exe', '--init'], phase='wineboot', timeout=120)
        drive = prefix / 'drive_c'
        steam = drive / 'Program Files (x86)/Steam'
        steam.mkdir(parents=True, exist_ok=True)
        seen = {}
        total = 0
        for index, (name, size_text, digest) in enumerate(packages, 1):
            assert re.fullmatch(r'[A-Za-z0-9_.-]+', name)
            expected_size = int(size_text.replace('_', ''))
            request = urllib.request.Request(origin + name, headers={'Accept-Encoding': 'identity'})
            with urllib.request.urlopen(request, timeout=90) as response:
                assert response.status == 200 and response.url == origin + name, 'official package transport identity changed'
                data = response.read(expected_size + 1)
            assert len(data) == expected_size and hashlib.sha256(data).hexdigest() == digest, 'official package size/SHA256 mismatch'
            package = temporary / f'official-{index}.zip'
            package.write_bytes(data)
            with zipfile.ZipFile(package) as archive:
                members = archive.infolist()
                assert len(members) <= 256
                for member in members:
                    relative = member.filename.replace('\\', '/')
                    if member.is_dir() or relative.endswith('/'):
                        continue
                    parts = relative.split('/')
                    assert relative and len(relative) < 240 and all(p not in ['', '.', '..'] for p in parts)
                    assert not any(':' in p or p.endswith(('.', ' ')) or any(ord(c) < 32 for c in p) for p in parts)
                    assert not stat.S_ISLNK(member.external_attr >> 16) and not member.flag_bits & 1
                    assert member.compress_type in [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED] and member.file_size <= 64 * 1024 * 1024
                    body = archive.read(member)
                    assert len(body) == member.file_size
                    key = relative.lower()
                    if key in seen:
                        assert seen[key] == (relative, hashlib.sha256(body).hexdigest()), 'conflicting official package member'
                        continue
                    seen[key] = (relative, hashlib.sha256(body).hexdigest())
                    total += len(body)
                    assert total <= 256 * 1024 * 1024
                    destination = steam.joinpath(*parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(body)
            print(f'PASS genuine service source package={index} size={expected_size} sha256={digest} verified=1', flush=True)
        relative, service_digest = seen['bin/steamservice.exe']
        service = steam / relative
        image = service.read_bytes()
        pe = struct.unpack_from('<I', image, 0x3c)[0]
        assert image[:2] == b'MZ' and image[pe:pe + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', image, pe + 4)[0] == 0x014c, 'genuine service source must exercise the captured I386 path'
        timestamp = struct.unpack_from('<I', image, pe + 8)[0]
        image_size = struct.unpack_from('<I', image, pe + 24 + 56)[0]
        # FEX's ImageTracker ID is filename/PE metadata, NOT a content hash.
        # This constant is XXH3_64bits("steamservice.exe"); SHA256 above remains
        # the actual authenticity check. Report whether the control matches
        # the captured Oct-21 service metadata instead of assuming it does.
        tracker_id = 0xe5719cc502173c9e ^ ((image_size << 32) | timestamp)
        capture_match = int(tracker_id == 0xe5440cc568ce1694)
        print(f'PASS genuine SteamService source machine=I386 size={len(image)} sha256={service_digest} image-size={image_size:#x} timestamp={timestamp:#x} captured-build-metadata-match={capture_match}; Valve bytes unmodified', flush=True)
        fixture = drive / 'Fixture'
        fixture.mkdir()
        installed_control = fixture / 'scm-query32.exe'
        shutil.copyfile(control, installed_control)
        anchor = subprocess.Popen(['wine', str(installed_control), '--anchor'], env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 20
        while not (fixture / 'anchor-ready.fixture').exists():
            assert anchor.poll() is None and time.monotonic() < deadline, 'isolated service session anchor failed'
            time.sleep(.05)
        protected = {steam / 'config/loginusers.vdf': b'isolated-login-sentinel-no-account\n',
                     steam / 'steamapps/appmanifest_730.acf': b'isolated-existing-appmanifest-sentinel\n',
                     steam / 'steamapps/common/CS2/game/bin/win64/cs2.exe': b'isolated-existing-game-sentinel\n'}
        for path, body in protected.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        # No --setup fixture call: registration, executable copying and service
        # initialization are all performed by Valve's genuine /install path.
        begin = time.monotonic()
        _, output = run([WINE64, str(helper), r'C:\Program Files (x86)\Steam'], phase='genuine-install-and-start', timeout=105)
        elapsed = time.monotonic() - begin
        assert b'[steam-service] installer-attempt=1' in output and b'[steam-service] installer-exit=0' in output
        assert b'[steam-service] service-state=4' in output and b'[steam-service] result=0' in output
        _, status = run(['wine', str(installed_control), '--query'], phase='genuine-running-status')
        assert b'query-state=4' in status
        match = re.search(rb'query-state=4 pid=(\d+)', status)
        assert match and int(match.group(1)) != 0, 'SCM running state lacks a real service process'
        _, status = run(['wine', str(installed_control), '--query-image'], phase='genuine-running-image')
        image_line = next(line for line in status.decode(errors='strict').splitlines() if line.startswith('[service-fixture] query-image='))
        windows_image = image_line.split('query-image=', 1)[1]
        assert windows_image[:3].upper() == 'C:\\' and '/' not in windows_image
        image_parts = windows_image[3:].split('\\')
        assert all(part not in ['', '.', '..'] and ':' not in part for part in image_parts)
        assert image_parts[-1].lower() == 'steamservice.exe'
        installed_service = drive
        for part in image_parts:
            matches = [entry for entry in installed_service.iterdir() if entry.name.lower() == part.lower()]
            assert len(matches) == 1, 'SCM process image path is missing or case-ambiguous inside the isolated prefix'
            installed_service = matches[0]
        assert hashlib.sha256(installed_service.read_bytes()).hexdigest() == service_digest, 'SCM process image is not the exact pinned genuine service source'
        print(f'PASS genuine Valve /install -> production helper -> actual SCM SERVICE_RUNNING pid={match.group(1).decode()} elapsed-ms={int(elapsed * 1000)}; Linux-Wine control, not iOS timing proof', flush=True)
        _, output = run([WINE64, str(helper), r'C:\Program Files (x86)\Steam'], phase='genuine-running-reuse', timeout=40)
        assert b'[steam-service] result=0' in output
        assert b'[steam-service] installer-attempt=1' not in output
        assert hashlib.sha256(service.read_bytes()).hexdigest() == service_digest, 'genuine source executable changed'
        assert all(path.read_bytes() == body for path, body in protected.items())
        print('PASS genuine service reuse without reinstallation; authenticated-session/game sentinels and official source bytes unchanged', flush=True)
    finally:
        if anchor is not None:
            try:
                run(['wine', str(installed_control), '--anchor-stop'], phase='anchor-stop', expected=None, timeout=10)
                anchor.wait(timeout=10)
            except (AssertionError, subprocess.TimeoutExpired):
                pass
        subprocess.run(['wineserver', '-k'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=20, check=False)
