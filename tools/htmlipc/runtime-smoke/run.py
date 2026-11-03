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
IDENTITY_TOKENS = {}
CLIENT_ARGUMENTS = ['-no-cef-sandbox', '-cef-disable-gpu', '-console', '-nocrashmonitor', '-cef-disable-features=SegmentationPlatform,OptimizationTargetPrediction,OptimizationHints']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_identities(steam, identities):
    changed = []
    for name, expected in identities.items():
        path = steam / name
        if not path.is_file():
            changed.append(name)
            continue
        stat = path.stat()
        token = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        if IDENTITY_TOKENS.get(str(path)) != token:
            if sha(path) != expected['sha256']:
                changed.append(name)
            else:
                IDENTITY_TOKENS[str(path)] = token
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
    image = cv2.resize(image, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    # Validate only a known Steam login URI prefix in memory, then discard the
    # decoded anonymous challenge. Never log/retain it or attempt authentication.
    qr = cv2.QRCodeDetector()
    found, polygons = qr.detectMulti(image)
    steam_login_qr = False
    if found:
        try:
            decoded, values, _ = qr.decodeMulti(image, polygons)
            if decoded:
                steam_login_qr = any(re.fullmatch(r'https://s\.team/q/[A-Za-z0-9_/-]{1,512}', value) for value in values)
            del values
        except cv2.error:
            pass
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
    text = re.sub(r'[^a-z0-9 ]+', ' ', ' '.join(words))
    probes = {
        'sign_in_label': bool(re.search(r'\bsign\s*in(?:\b|to)', text)),
        'account_name_label': bool(re.search(r'\baccount\s*name\b', text)),
        'password_label': bool(re.search(r'\bpass\s*word\b', text)),
        'update_label': 'updating steam' in text or 'checking for available updates' in text,
        'nonuniform_frame': float(image.std()) > 3,
        'qr_regions_redacted': len(polygons) if found else 0,
        'steam_login_qr_validated': bool(steam_login_qr),
        'not_responding_dialog': 'steamwebhelper' in text and 'responding' in text,
        'approved_words': sorted(set(words) & (approved | {'error','failed','connect','network','welcome','create','join','username','loading','continue'})),
    }
    return probes


def main(root, artifacts):
    root, artifacts = root.resolve(), artifacts.resolve()
    provenance = json.loads((root / 'provenance.json').read_text())
    bridge_mode = provenance['experiment'].endswith('/bridge')
    needs_native_args = provenance.get('require_native_cef_args',False)
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
           'WINEDEBUG': '+pid,+loaddll,+debugstr,err+all', 'DISPLAY': ':109',
           'WINEDLLOVERRIDES': 'mscoree,mshtml='})
    if needs_native_args:
        token=os.environ.get('MADEIRA_CEF_ARGS_TEST_TOKEN','')
        assert re.fullmatch(r'[0-9a-fA-F]{32,96}',token)
        env['MADEIRA_CEF_ARGS_TEST_TOKEN']=token
    # Mono/Gecko are optional Wine components, not Steam authentication APIs.
    # Use Madeira's existing client arguments exactly. No additional sandbox,
    # update, version or certificate policy is introduced by this probe.
    log_path = root / 'private-wine.log'
    report = {'result': 'inconclusive', 'max_seconds': MAX_SECONDS,
              'login_frame_observed': False, 'loaded': [], 'samples': [],
              'updater_replaced_component': [], 'scope': 'unauthenticated login rendering only',
              'authentication_attempted': False, 'library_or_game_launch_validated': False,
              'client_arguments': CLIENT_ARGUMENTS, 'graphics_control': False, 'bridge_installed': False,
              'bridge_connected': False, 'bridge_failure': [], 'missing_dlls': [],
              'bridge_loader_entry': False, 'version_load_events': [],
              'image_mismatch': [], 'bridge_hook_reached': False, 'stream_probes': [],
              'cef_args_installed':False,'cef_args_applied':False,
              'i386_client_dependency': {k: provenance[k] for k in
                  ('steamclient_i386_present','steamclient_i386_machine','steamclient_i386_sha256') if k in provenance}}
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
        # Prove the actual Wine GDI/X11 test setup before attributing a black
        # frame to Steam. No account or Steam process exists during this probe.
        control = subprocess.Popen(['wine', 'notepad.exe'], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(control)
        for _ in range(12):
            windows = subprocess.run(['xwininfo', '-root', '-tree'], env=env,
                                     capture_output=True, text=True, timeout=5, check=False).stdout
            if 'notepad.exe' in windows.lower() or 'notepad' in windows.lower():
                report['graphics_control'] = True
                break
            time.sleep(1)
        subprocess.run(['wine', 'taskkill.exe', '/IM', 'notepad.exe', '/F'], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        if not report['graphics_control']:
            report['result'] = 'inconclusive-wine-graphics-control-failed'
            return 2
        if 'version.dll' in provenance['files']:
            # App-specific only: the I386 helper must retain its own genuine
            # builtin VERSION implementation, rather than inherit an AMD64 override.
            subprocess.run(['wine', 'reg.exe', 'add',
                r'HKCU\Software\Wine\AppDefaults\steam.exe\DllOverrides',
                '/v', 'version', '/t', 'REG_SZ', '/d', 'native,builtin', '/f'], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
        if 'version.dll' in provenance['files']:
            env['WINEDLLOVERRIDES'] = 'version=n,b;mscoree,mshtml='
        with log_path.open('wb') as log:
            processes.append(subprocess.Popen(['wine', str(steam / 'steam.exe'), *CLIENT_ARGUMENTS], env=env,
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
                raw_now = log_path.read_bytes()[:MAX_LOG_BYTES].decode(errors='replace')
                report['bridge_loader_entry'] |= 'MADEIRA_HTMLIPC loader-entry' in raw_now
                report['bridge_installed'] |= 'MADEIRA_HTMLIPC installed pid=' in raw_now
                report['bridge_connected'] |= 'MADEIRA_HTMLIPC connected pid=' in raw_now
                report['bridge_hook_reached'] |= 'MADEIRA_HTMLIPC hook-reached pid=' in raw_now
                report['cef_args_installed'] |= 'MADEIRA_CEF_ARGS exact tier0 CreateProcessW IAT installed R-RW-R' in raw_now
                report['cef_args_applied'] |= 'MADEIRA_CEF_ARGS browser-native-flags applied; BRP unchanged' in raw_now
                report['stream_probes'] = re.findall(
                    r'MADEIRA_HTMLIPC stream-probe pid=(\d+) operation=(\d+) stream=(\d+) to=(\d+) from=(\d+)', raw_now)[:8]
                install_failures = re.findall(r'MADEIRA_HTMLIPC install-error pid=(\d+) code=(\d+)', raw_now)
                if install_failures:
                    report['image_mismatch'] = re.findall(
                        r'MADEIRA_HTMLIPC image-mismatch stage=(\d+) rva=(\d+) expected=(\d+) actual=(\d+) bytes=(\d+) expected-protection=(\d+) actual-protection=(\d+) image-size=(\d+) query-flags=(\d+)', raw_now)[:1]
                    report['bridge_failure'] = ['install', *install_failures[0]]
                    report['result'] = 'failed-source-bridge-installation'
                    break
                failures = re.findall(r'MADEIRA_HTMLIPC error=(\d+) pid=(\d+) generation=(\d+) direction=(\d+) command=(\d+) wire=(\d+)', raw_now)
                failures = [x for x in failures if x[0] != '1'] # scoped provider ignores other executable names
                if failures:
                    report['bridge_failure'] = list(failures[0])
                    report['result'] = 'failed-source-bridge-operation'
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
                    if bridge_mode:
                        required = {'steam.exe','SteamUI.dll','steamclient64.dll','bin/chromehtml.dll',
                                    'version.dll','bin/cef/cef.win7/steamwebhelper.exe','bin/cef/cef.win7/libcef.dll'}
                        eligible = report['bridge_installed'] and report['bridge_connected']
                        eligible &= 'bin/cef/cef.win64/steamwebhelper.exe' not in loaded
                        eligible &= 'bin/cef/cef.win64/libcef.dll' not in loaded
                    else:
                        required = {'steam.exe','SteamUI.dll','steamclient64.dll','bin/chromehtml.dll',
                                    'bin/cef/cef.win64/steamwebhelper.exe','bin/cef/cef.win64/libcef.dll'}
                        eligible = True
                        if 'version.dll' in provenance['files']:required.add('version.dll')
                    if needs_native_args:eligible &= report['cef_args_installed'] and report['cef_args_applied']
                    form = all(probes[k] for k in ('sign_in_label','account_name_label','password_label'))
                    login_content = form or probes['steam_login_qr_validated']
                    if eligible and required <= loaded and login_content and probes['nonuniform_frame'] and not probes['not_responding_dialog']:
                        report['login_frame_observed'] = True
                        report['result'] = 'unauthenticated-login-rendered'
                        break
                time.sleep(2)
            report['loaded'] = sorted(all_loaded)
            report['elapsed_seconds'] = round(time.monotonic() - started)
        IDENTITY_TOKENS.clear()
        final_changes = check_identities(steam, provenance['files'])
        if final_changes:
            report['updater_replaced_component'] = final_changes
            report['login_frame_observed'] = False
            report['result'] = 'inconclusive-official-updater-replaced-test-component'
        # Preserve no raw Wine/CEF logs, account store, screenshots or QR payloads.
        # Exact bounded module load counts help distinguish a loader failure.
        raw = log_path.read_bytes()[:MAX_LOG_BYTES].decode(errors='replace')
        report['version_load_events'] = [
            {'native': 'native' in line.lower(), 'builtin': 'builtin' in line.lower(),
             'candidate_path': str(steam / 'version.dll').lower() in line.lower()}
            for line in raw.splitlines() if 'loaddll' in line.lower() and 'version.dll' in line.lower()][:24]
        report['bridge_loader_entry'] |= 'MADEIRA_HTMLIPC loader-entry' in raw
        report['bridge_hook_reached'] |= 'MADEIRA_HTMLIPC hook-reached pid=' in raw
        report['cef_source_counts'] = {}
        report['cef_internal_messages'] = []
        for file in sorted((steam / 'logs').glob('*'))[:32]:
            if not file.is_file() or file.stat().st_size > 2 * 1024**2:
                continue
            content = file.read_bytes().decode(errors='replace')
            # Only known CEF internal source locations in a fresh no-account
            # fixture. Drop credential-related lines; never export URLs or long
            # opaque values. Console/JavaScript/network transcripts stay private.
            for line in content.splitlines():
                if len(report['cef_internal_messages']) >= 12: break
                if not re.search(r'(?:chrome_main_delegate\.cc\(748\)|child_thread_impl\.cc\(942\)|crash_reporting\.cc\(271\))', line): continue
                if re.search(r'password|authorization|cookie|ticket|token|secret|session|steamid', line, re.I): continue
                safe = re.sub(r'(?:https?|wss?)://\S+', '[url-redacted]', line)
                safe = re.sub(r'[A-Za-z0-9_+/=-]{24,}', '[opaque-redacted]', safe)
                report['cef_internal_messages'].append(safe[:320])
            for tag in re.findall(r'\b([A-Za-z0-9_]{1,80}\.(?:cc|cpp)\(\d{1,6}\))', content):
                if tag in report['cef_source_counts'] or len(report['cef_source_counts']) < 64:
                    report['cef_source_counts'][tag] = report['cef_source_counts'].get(tag, 0) + 1
            for tag in ('SteamAPI_Init failed','Could not load steamclient','Unable to load steamclient',
                        'Failed to connect','Check failed: false'):
                count = content.count(tag)
                if count: report['cef_source_counts'][tag] = report['cef_source_counts'].get(tag, 0) + count
        report['missing_dlls'] = sorted(set(re.findall(r'Library ([A-Za-z0-9_.-]{1,128}\.dll) .*?not found', raw, re.I)))[:16]
        report['loader_error_counts'] = {key: raw.lower().count(key.lower()) for key in
            ('nodrv_CreateWindow', 'Make sure that your X server is running', 'err:module:import_dll', 'err:module:loader_init', 'unimplemented function',
             'c0000135', 'c0000005', '80000003')}
        report['client_registry'] = []
        for view in ('32','64'):
            for value in ('SteamClientDll','SteamClientDll64'):
                try:
                    queried = subprocess.run(['wine','reg.exe','query',r'HKCU\Software\Valve\Steam\ActiveProcess',
                        '/v',value,'/reg:'+view],env=env,capture_output=True,text=True,timeout=8,check=False)
                except subprocess.TimeoutExpired:
                    report['client_registry'].append({'view':view,'value':value,'query_timeout':True})
                    continue
                found = re.search(r'\b'+value+r'\s+REG_SZ\s+([^\r\n]+)',queried.stdout)
                row = {'view':view,'value':value,'present':bool(found)}
                if found:
                    value_path = found[1].strip().replace('\\','/')
                    target = Path('/'+value_path[3:]) if value_path.lower().startswith('z:/') else prefix/'drive_c'/value_path[3:] if value_path.lower().startswith('c:/') else None
                    row['matches_current_i386'] = bool(target and target.resolve() == (steam/'steamclient.dll').resolve())
                    row['matches_current_amd64'] = bool(target and target.resolve() == (steam/'steamclient64.dll').resolve())
                    row['file_present'] = bool(target and target.is_file())
                report['client_registry'].append(row)
    finally:
        subprocess.run(['wineserver', '-k'], env=env, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=5)
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
