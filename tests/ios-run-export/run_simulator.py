#!/usr/bin/env python3
"""Run actual native share UI on an owned iOS simulator host, collect tiny fixtures."""
from pathlib import Path
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
BUNDLE = 'com.madeira.tests.RunExportUIHost'
EVIDENCE = HERE / 'simulator-evidence'


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


def collect(device, verify, selected_test=''):
    evidence = EVIDENCE
    evidence.mkdir(exist_ok=True)
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
    saved_archive = container / 'Documents/RunExportFixture.zip'
    native_saved = saved_archive.is_file() and not saved_archive.is_symlink()
    if native_saved:
        assert saved_archive.stat().st_size < 4096
        with zipfile.ZipFile(saved_archive) as contents:
            assert contents.testzip() is None and contents.namelist() == ['run.txt']
            assert contents.read('run.txt') == b'Owned run export UI fixture\n'
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
    (evidence / 'summary.json').write_text(json.dumps({
        'schema': 'madeira-export-ui-simulator-v1', 'hostBundle': BUNDLE,
        'nativeUITestsPassed': verify, 'eventFiles': len(records),
        'nativeFilesSavedAndCRCVerified': native_saved,
        'selectedTest': selected_test or 'full-suite',
        'scope': 'production coordinator/UIKit + owned host and archive-production boundary; no game or account data',
        'deviceAcceptance': 'unverified; simulator does not establish operation on the user iPhone',
    }, indent=2) + '\n')


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
    }
    if test_case not in selectors:
        raise ValueError('Only the all or landscape owned UI test selection is permitted')
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
            collect(device, verify=verify, selected_test=selected_test)
        except Exception as error:
            (EVIDENCE / 'collection-failure.txt').write_text(type(error).__name__ + ': ' + str(error) + '\n')
            if verify: raise
            print('Owned fixture collection failed after unsuccessful simulator stage:', type(error).__name__, flush=True)


if __name__ == '__main__': raise SystemExit(main())
