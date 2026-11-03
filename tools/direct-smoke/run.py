#!/usr/bin/env python3
"""Bounded no-account Wine/Xvfb smoke test; never reports full compatibility."""
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

MAX_SECONDS = 180
MAX_RSS_KIB = 5 * 1024**2
MAX_TREE_BYTES = 8 * 1024**3
MAX_LOG_BYTES = 32 * 1024**2


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_identities(steam, identities):
    changed = []
    for name, expected in identities.items():
        path = steam / name
        if not path.is_file() or sha(path) != expected['sha256']:
            changed.append(name)
    return changed


def used_bytes(root):
    return sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())


def process_census(prefix, watched):
    rss, evidence = 0, set()
    prefix_bytes = ('WINEPREFIX=' + str(prefix)).encode() + b'\0'
    for process in Path('/proc').glob('[0-9]*'):
        try:
            if prefix_bytes not in (process / 'environ').read_bytes():
                continue
            status = (process / 'status').read_text()
            found = re.search(r'^VmRSS:\s+(\d+)', status, re.M)
            rss += int(found[1]) if found else 0
            mappings = (process / 'maps').read_text(errors='replace').lower()
            for name, path in watched.items():
                if str(path).lower() in mappings:
                    evidence.add(name)
        except (OSError, ProcessLookupError):
            pass
    return rss, evidence


def capture(display, raw_path, output_path):
    import cv2
    subprocess.run(['scrot', '--silent', str(raw_path)],
                   env={**os.environ, 'DISPLAY': display}, check=True, timeout=8,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    image = cv2.imread(str(raw_path))
    assert image is not None
    # Detection only: never decode, log, or retain an authentication QR token.
    qr = cv2.QRCodeDetector()
    found, polygons = qr.detectMulti(image)
    if found:
        for polygon in polygons:
            x, y, w, h = cv2.boundingRect(polygon.astype('int32'))
            cv2.rectangle(image, (max(0, x - 24), max(0, y - 24)),
                          (x + w + 24, y + h + 24), (0, 0, 0), -1)
    cv2.imwrite(str(raw_path), image)
    result = subprocess.run(['tesseract', str(raw_path), 'stdout', '--psm', '11', 'tsv'],
                            capture_output=True, text=True, timeout=12, check=False)
    # Export pixels ONLY for predefined static labels. QR detector failure
    # must never expose even a newly issued anonymous login QR token.
    approved = {'steam', 'sign', 'in', 'account', 'name', 'password'}
    redacted = image.copy()
    redacted[:] = 0
    words = []
    for row in result.stdout.splitlines()[1:]:
        fields = row.split('\t', 11)
        if len(fields) != 12:
            continue
        word = fields[11].strip().lower()
        if word in approved and float(fields[10]) >= 60:
            x, y, w, h = (int(v) for v in fields[6:10])
            redacted[y:y+h, x:x+w] = image[y:y+h, x:x+w]
        words.append(word)
    cv2.imwrite(str(output_path), redacted)
    raw_path.unlink(missing_ok=True)
    # Keep only predicates over a fresh no-account login page, not OCR text.
    text = ' '.join(words)
    probes = {
        'sign_in_label': 'sign in' in text,
        'account_name_label': 'account name' in text,
        'password_label': 'password' in text,
        'update_label': 'updating steam' in text or 'checking for available updates' in text,
        'nonuniform_frame': float(image.std()) > 3,
        'qr_regions_redacted': len(polygons) if found else 0,
    }
    return probes


def main(root, artifacts):
    root, artifacts = root.resolve(), artifacts.resolve()
    provenance = json.loads((root / 'provenance.json').read_text())
    steam = root / 'steam'
    prefix = root / 'wine-prefix'
    assert not prefix.exists(), 'a fresh prefix is required; never reuse account data'
    assert not check_identities(steam, provenance['files'])
    artifacts.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(root / 'provenance.json', artifacts / 'provenance.json')
    # Never pass Actions service/artifact tokens or unrelated credentials to
    # the Windows applications under test.
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LOGNAME') if key in os.environ}
    env.update({'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'WINEPREFIX': str(prefix), 'WINEARCH': 'win64',
           'WINEDEBUG': '+loaddll,err+all', 'DISPLAY': ':109',
           'WINEDLLOVERRIDES': 'mscoree,mshtml='})
    # Mono/Gecko are optional Wine components, not Steam authentication APIs.
    # No Steam/Chromium sandbox, update, version, or certificate flags are set.
    log_path = root / 'private-wine.log'
    report = {'result': 'inconclusive', 'max_seconds': MAX_SECONDS,
              'login_frame_observed': False, 'loaded': [], 'samples': [],
              'updater_replaced_component': [], 'scope': 'unauthenticated login rendering only',
              'authentication_attempted': False, 'library_or_game_launch_validated': False, 'controller': 'genuine-current-unchanged'}
    xvfb = subprocess.Popen(['Xvfb', ':109', '-screen', '0', '1280x800x24', '-nolisten', 'tcp'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes = [xvfb]
    try:
        time.sleep(1)
        subprocess.run(['wineboot', '-u'], env=env, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(['winecfg', '-v', 'win10'], env=env, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        processes.append(subprocess.Popen(['openbox', '--sm-disable'], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        with log_path.open('wb') as log:
            processes.append(subprocess.Popen(['wine', str(steam / 'steam.exe')], env=env,
                             cwd=steam, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True))
            watched = {name: steam / name for name in provenance['files']}
            started = time.monotonic()
            next_frame = 10
            all_loaded = set()
            screenshot_count = 0
            while time.monotonic() - started < MAX_SECONDS:
                elapsed = time.monotonic() - started
                changed = check_identities(steam, provenance['files'])
                if changed:
                    report['updater_replaced_component'] = changed
                    report['result'] = 'inconclusive-official-updater-replaced-test-component'
                    break
                rss, loaded = process_census(prefix, watched)
                all_loaded.update(loaded)
                if rss > MAX_RSS_KIB or used_bytes(root) > MAX_TREE_BYTES or log_path.stat().st_size > MAX_LOG_BYTES:
                    report['result'] = 'inconclusive-resource-budget'
                    break
                if elapsed >= next_frame:
                    next_frame += 20
                    screenshot_count += 1
                    name = f'frame-{screenshot_count:02d}.png'
                    probes = capture(env['DISPLAY'], root / 'private-frame.png', artifacts / name)
                    report['samples'].append({'seconds': round(elapsed), 'rss_kib': rss, **probes})
                    # Require actual current core, selected controller and I386 CEF
                    # mappings plus a rendered login form. Process creation alone fails.
                    required = {'steam.exe', 'SteamUI.dll', 'steamclient64.dll', 'bin/chromehtml.dll',
                                'bin/cef/cef.win64/steamwebhelper.exe', 'bin/cef/cef.win64/libcef.dll'}
                    if required <= all_loaded and all(probes[k] for k in
                        ('sign_in_label', 'account_name_label', 'password_label', 'nonuniform_frame')):
                        report['login_frame_observed'] = True
                        report['result'] = 'unauthenticated-login-rendered'
                        break
                time.sleep(2)
            report['loaded'] = sorted(all_loaded)
            report['elapsed_seconds'] = round(time.monotonic() - started)
        # Preserve no raw Wine/CEF logs, account store, screenshots or QR payloads.
        # Exact bounded module load counts help distinguish a loader failure.
        raw = log_path.read_bytes()[:MAX_LOG_BYTES].decode(errors='replace')
        report['loader_error_counts'] = {key: raw.lower().count(key) for key in
            ('chrome_elf', 'libcef', 'steamwebhelper.exe', 'protocol', 'assertion', 'err:module:import_dll', 'err:module:loader_init', 'unimplemented function',
             'c0000135', 'c0000005', '80000003')}
    finally:
        subprocess.run(['wineserver', '-k'], env=env, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        (root / 'private-frame.png').unlink(missing_ok=True)
        (artifacts / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
    return 0 if report['login_frame_observed'] else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(main(args.root, args.artifacts))
