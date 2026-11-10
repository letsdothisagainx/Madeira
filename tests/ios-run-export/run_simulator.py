#!/usr/bin/env python3
"""Run actual native share UI on an owned iOS simulator host, collect tiny fixtures."""
from pathlib import Path
import json
import os
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
BUNDLE = 'com.madeira.tests.RunExportUIHost'
EVIDENCE = HERE / 'simulator-evidence'
RUN_STARTED_AT = time.time()
PAYLOAD = b'Owned run export UI fixture\n'


def call(*args):
    return subprocess.check_output(args, text=True, timeout=60)


def run_logged(stage, command, timeout):
    """End stalled simulator tools before Actions kills evidence upload.

    The first native run reached the job's 25-minute timeout and then its
    five-minute cancellation grace, leaving neither an xcresult artifact nor
    a readable job-log blob. Preserve each stage's output while it runs and
    terminate the complete owned subprocess group within the job budget.
    """
    EVIDENCE.mkdir(exist_ok=True)
    output_path = EVIDENCE / (stage + '.log')
    started = time.monotonic()
    print('UI stage started:', stage, 'timeout-seconds=' + str(timeout), flush=True)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)

    def copy_output():
        remaining = 8 * 1024 * 1024
        with output_path.open('wb') as output:
            for line in iter(process.stdout.readline, b''):
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
                if remaining:
                    chunk = line[:remaining]
                    output.write(chunk)
                    output.flush()
                    remaining -= len(chunk)

    pump = threading.Thread(target=copy_output, daemon=True)
    pump.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        print('UI stage timed out:', stage, '; terminating owned process group', flush=True)
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
    pump.join(timeout=5)
    elapsed = round(time.monotonic() - started, 3)
    (EVIDENCE / (stage + '-status.json')).write_text(json.dumps({
        'stage': stage, 'elapsedSeconds': elapsed, 'timeoutSeconds': timeout,
        'timedOut': timed_out, 'returnCode': process.returncode,
    }, indent=2) + '\n')
    print('UI stage finished:', stage, 'elapsed-seconds=' + str(elapsed),
          'return-code=' + str(process.returncode), 'timed-out=' + str(timed_out), flush=True)
    return 124 if timed_out else process.returncode


def owned_container_from_metadata(device, data_path=None):
    # Post-Xcode simctl IPC timed out after the genuine native Save test passed.
    # Read CoreSimulator's actual, exact-bundle container ownership metadata;
    # never guess a directory from its contents or accept an ambiguous owner.
    if not data_path and not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', device):
        raise ValueError('The default device-set lookup requires the selected simulator UUID')
    data = Path(data_path) if data_path else Path.home() / 'Library/Developer/CoreSimulator/Devices' / device / 'data'
    applications = data / 'Containers/Data/Application'
    if data.is_symlink() or applications.is_symlink(): return None
    matches = []
    for index, candidate in enumerate(applications.glob('*')):
        if index >= 4096: raise RuntimeError('Unexpectedly large simulator container catalog')
        metadata = candidate / '.com.apple.mobile_container_manager.metadata.plist'
        if candidate.is_symlink() or not candidate.is_dir() or metadata.is_symlink() or not metadata.is_file():
            continue
        if candidate.stat().st_uid != os.getuid() or metadata.stat().st_uid != os.getuid(): continue
        if metadata.stat().st_size > 65536: continue
        try:
            identity = plistlib.loads(metadata.read_bytes())
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
        if isinstance(identity, dict) and identity.get('MCMMetadataIdentifier') == BUNDLE:
            matches.append(candidate.resolve())
    print('OWNED_EXPORT_CONTAINER_METADATA exact-bundle-matches=' + str(len(matches)), flush=True)
    return matches[0] if len(matches) == 1 else None


def native_saved_archive(documents):
    """Find the actual native filename, including Files' allowed renaming.

    The producer never writes Documents. Only a fresh, uniquely identifiable
    native copy beneath this exact owned container can satisfy the CRC gate.
    """
    if documents.is_symlink() or not documents.is_dir() or documents.stat().st_uid != os.getuid():
        raise RuntimeError('The owned Documents root must be a regular owned directory')
    pending = [(documents, 0)]
    inspected = 0
    valid = []
    while pending:
        directory, depth = pending.pop()
        for candidate in directory.iterdir():
            inspected += 1
            if inspected > 128: raise RuntimeError('Owned Documents catalog exceeds the bounded fixture limit')
            attributes = candidate.lstat()
            relative = str(candidate.relative_to(documents))
            regular = stat.S_ISREG(attributes.st_mode)
            owned = attributes.st_uid == os.getuid()
            fresh = attributes.st_ctime >= RUN_STARTED_AT - 2
            record = {'relative': relative, 'bytes': attributes.st_size,
                      'regular': regular, 'owned': owned, 'fresh': fresh}
            if stat.S_ISDIR(attributes.st_mode) and owned and depth < 2:
                pending.append((candidate, depth + 1))
            if candidate.name.startswith('RunExportFixture'):
                acceptable = False
                if regular and owned and fresh and attributes.st_size < 4096:
                    try:
                        with zipfile.ZipFile(candidate) as contents:
                            info = contents.infolist()
                            acceptable = (len(info) == 1 and info[0].filename == 'run.txt' and
                                          info[0].file_size == len(PAYLOAD) and
                                          contents.testzip() is None and contents.read('run.txt') == PAYLOAD)
                    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
                        acceptable = False
                record['crcAndPayloadValid'] = acceptable
                if acceptable: valid.append(candidate)
            print('OWNED_EXPORT_DOCUMENTS_ENTRY ' + json.dumps(record), flush=True)
    if len(valid) > 1: raise RuntimeError('Ambiguous multiple fresh native Files fixture copies')
    return valid[0] if valid else None


def collect(device, verify, selected_test='', data_path=None):
    evidence = EVIDENCE
    evidence.mkdir(exist_ok=True)
    container = owned_container_from_metadata(device, data_path)
    if container is None:
        result = subprocess.run(['xcrun', 'simctl', 'get_app_container', device, BUNDLE, 'data'],
                                text=True, capture_output=True, timeout=60)
        if result.returncode:
            if verify: raise RuntimeError('Owned UI host container unavailable after successful tests')
            print('Owned host was not installed; preserve xcresult build failure evidence')
            return
        container = Path(result.stdout.strip()).resolve()
    records = []
    for file in sorted((container / 'Documents').glob('run-export-events-*.txt')):
        assert not file.is_symlink() and file.is_file() and file.stat().st_size <= 65536
        text = file.read_text()
        assert len(records) < 32
        records.append(text)
        shutil.copyfile(file, evidence / file.name)
    # These records originate only from this isolated test host. Keep a tiny
    # textual copy even if a subsequent file/CRC assertion fails or the artifact
    # download service is unavailable. No game or account logs are read here.
    remaining = 16384
    for index, record in enumerate(records):
        if remaining <= 0: break
        excerpt = record[:remaining]
        print('OWNED_EXPORT_FIXTURE_EVENTS ' + str(index) + '\n' + excerpt, flush=True)
        remaining -= len(excerpt)
    archive = container / 'tmp/RunExportUI/RunExportFixture.zip'
    if archive.is_file() and not archive.is_symlink():
        assert archive.stat().st_size < 4096
        with zipfile.ZipFile(archive) as contents:
            assert contents.testzip() is None and contents.namelist() == ['run.txt']
            assert contents.read('run.txt') == b'Owned run export UI fixture\n'
        shutil.copyfile(archive, evidence / archive.name)
    elif verify:
        raise AssertionError('Actual file supplied to UIKit was not retained or was unavailable')
    # Only the native Save to Files extension can create this destination.
    # Host.swift's producer writes its separate tmp file, never Documents.
    saved_archive = native_saved_archive(container / 'Documents')
    native_saved = saved_archive is not None
    print('OWNED_EXPORT_NATIVE_FILES_DESTINATION exists=' + str(native_saved) +
          ' bytes=' + str(saved_archive.stat().st_size if native_saved else 0), flush=True)
    if native_saved:
        assert saved_archive.stat().st_size < 4096
        shutil.copyfile(saved_archive, evidence / 'native-files-saved.zip')
    elif verify:
        raise AssertionError('Native Save to Files did not create the CRC-openable owned Documents archive')
    if verify:
        assert len(records) >= (1 if selected_test else 5), 'Every actual test launch must preserve its bounded event trail'
        modern = [r for r in records if 'baseline=0' in r]
        assert any('event=share-presented' in r and 'event=share-finished' in r for r in modern)
        assert any('event=share-finished request=1 completed=1' in r for r in modern)
        if not selected_test:
            assert any('event=failed' in r and 'stage=archive' in r for r in modern)
            assert any('baseline=1' in r and 'event=factory-created' in r and 'event=share-presented' not in r for r in records)
        print('PASS real UIKit event trails and CRC-openable archive supplied to native sharing; fixture-only evidence')
    summary = {
        'schema': 'madeira-export-ui-simulator-v1', 'hostBundle': BUNDLE,
        'nativeUITestsPassed': verify, 'eventFiles': len(records),
        'nativeFilesSavedAndCRCVerified': native_saved,
        'selectedTest': selected_test or 'full-suite',
        'scope': ('stock UIKit primary normal-window control + same production operation/owned archive producer'
                  if selected_test.endswith('testStockPrimaryWindowFilesSaveControl') else
                  'production coordinator/UIKit + owned host and archive-production boundary; no game or account data'),
        'deviceAcceptance': 'unverified; simulator does not establish operation on the user iPhone',
    }
    (evidence / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('OWNED_EXPORT_FIXTURE_SUMMARY ' + json.dumps(summary), flush=True)


def main():
    subprocess.run([sys.executable, str(HERE / 'generate_project.py')], check=True, timeout=60)
    data = json.loads(call('xcrun', 'simctl', 'list', 'devices', 'available', '--json'))
    choices = []
    for runtime, devices in data['devices'].items():
        if '.iOS-' not in runtime: continue
        version = tuple(map(int, re.findall(r'\d+', runtime.split('.iOS-')[-1])))
        for device in devices:
            if device.get('isAvailable', True) and device['name'].startswith('iPhone'):
                choices.append((version, device['state'] == 'Booted', device['name'], device))
    assert choices, 'An installed available iPhone simulator is required; UI tests must not silently skip'
    # Keep a conventional, numbered iPhone model reproducible across runner
    # images. The prior iPhone Duo timeout is not evidence of a device defect.
    conventional = [item for item in choices if re.fullmatch(r'iPhone \d+(?: (?:Pro|Pro Max|Plus))?', item[2])]
    selected = sorted(conventional or choices, key=lambda item: item[:3], reverse=True)[0][3]
    device = selected['udid']
    print('Using owned UI test simulator:', selected['name'], device, flush=True)
    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / 'simulator.json').write_text(json.dumps({
        'device': selected, 'scope': 'owned integration test host only',
    }, indent=2) + '\n')
    result = 1
    verify = False
    test_case = os.environ.get('MADEIRA_UI_TEST_CASE', 'all')
    selectors = {
        'all': '',
        'landscape': 'RunExportUITests/ExportRunUITests/testActiveLandscapeExportSurvivesOriginDestructionAndOpensFiles',
        'stock': 'RunExportUITests/ExportRunUITests/testStockPrimaryWindowFilesSaveControl',
    }
    if test_case not in selectors:
        raise ValueError('Only the all, landscape or stock owned UI test selection is permitted')
    selected_test = selectors[test_case]
    try:
        if selected['state'] != 'Booted':
            result = run_logged('simulator-boot', ['xcrun', 'simctl', 'boot', device], 60)
            if result: return result
        result = run_logged('simulator-bootstatus', ['xcrun', 'simctl', 'bootstatus', device, '-b'], 300)
        if result: return result
        result_path = HERE / ('Result-' + uuid.uuid4().hex + '.xcresult')
        command = ['xcodebuild', 'test', '-project', str(HERE / 'RunExportUI.xcodeproj'),
                   '-scheme', 'RunExportUI', '-configuration', 'Debug', '-sdk', 'iphonesimulator',
                   '-destination', 'id=' + device, '-derivedDataPath', str(HERE / 'DerivedData'),
                   '-resultBundlePath', str(result_path), '-parallel-testing-enabled', 'NO',
                   '-maximum-concurrent-test-simulator-destinations', '1',
                   '-test-timeouts-enabled', 'YES', '-maximum-test-execution-time-allowance', '180',
                   'CODE_SIGNING_ALLOWED=NO', 'CODE_SIGNING_REQUIRED=NO', "CODE_SIGN_IDENTITY="]
        if selected_test:
            command.append('-only-testing:' + selected_test)
        result = run_logged('xcodebuild', command, 720)
        verify = result == 0
        return result
    finally:
        try:
            collect(device, verify=verify, selected_test=selected_test, data_path=selected.get('dataPath'))
        except Exception as error:
            (EVIDENCE / 'collection-failure.txt').write_text(type(error).__name__ + ': ' + str(error) + '\n')
            if verify: raise
            print('Owned fixture collection failed after unsuccessful simulator stage:', type(error).__name__, flush=True)


if __name__ == '__main__': raise SystemExit(main())
