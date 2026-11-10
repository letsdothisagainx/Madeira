#!/usr/bin/env python3
"""Run actual native share UI on an owned iOS simulator host, collect tiny fixtures."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import sys
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
BUNDLE = 'com.madeira.tests.RunExportUIHost'


def call(*args):
    return subprocess.check_output(args, text=True)


def collect(device, verify):
    evidence = HERE / 'simulator-evidence'
    evidence.mkdir(exist_ok=True)
    result = subprocess.run(['xcrun', 'simctl', 'get_app_container', device, BUNDLE, 'data'],
                            text=True, capture_output=True)
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
    if verify:
        assert len(records) >= 5, 'Every actual test launch must preserve its bounded event trail'
        modern = [r for r in records if 'baseline=0' in r]
        assert any('event=share-presented' in r and 'event=share-finished' in r for r in modern)
        assert any('event=failed' in r and 'stage=archive' in r for r in modern)
        assert any('baseline=1' in r and 'event=factory-created' in r and 'event=share-presented' not in r for r in records)
        print('PASS real UIKit event trails and CRC-openable archive supplied to native sharing; fixture-only evidence')
    (evidence / 'summary.json').write_text(json.dumps({
        'schema': 'madeira-export-ui-simulator-v1', 'hostBundle': BUNDLE,
        'nativeUITestsPassed': verify, 'eventFiles': len(records),
        'scope': 'production coordinator/UIKit + owned host and archive-production boundary; no game or account data',
        'deviceAcceptance': 'unverified; simulator does not establish operation on the user iPhone',
    }, indent=2) + '\n')


def main():
    subprocess.run([sys.executable, str(HERE / 'generate_project.py')], check=True)
    data = json.loads(call('xcrun', 'simctl', 'list', 'devices', 'available', '--json'))
    choices = []
    for runtime, devices in data['devices'].items():
        if '.iOS-' not in runtime: continue
        version = tuple(map(int, re.findall(r'\d+', runtime.split('.iOS-')[-1])))
        for device in devices:
            if device.get('isAvailable', True) and device['name'].startswith('iPhone'):
                choices.append((version, device['state'] == 'Booted', device['name'], device))
    assert choices, 'An installed available iPhone simulator is required; UI tests must not silently skip'
    selected = sorted(choices, key=lambda item: item[:3], reverse=True)[0][3]
    device = selected['udid']
    print('Using owned UI test simulator:', selected['name'], device, flush=True)
    if selected['state'] != 'Booted':
        subprocess.run(['xcrun', 'simctl', 'boot', device], check=True)
    subprocess.run(['xcrun', 'simctl', 'bootstatus', device, '-b'], check=True)
    result_path = HERE / ('Result-' + uuid.uuid4().hex + '.xcresult')
    command = ['xcodebuild', 'test', '-project', str(HERE / 'RunExportUI.xcodeproj'),
               '-scheme', 'RunExportUI', '-configuration', 'Debug', '-sdk', 'iphonesimulator',
               '-destination', 'id=' + device, '-derivedDataPath', str(HERE / 'DerivedData'),
               '-resultBundlePath', str(result_path), '-parallel-testing-enabled', 'NO',
               '-maximum-concurrent-test-simulator-destinations', '1',
               '-test-timeouts-enabled', 'YES', '-maximum-test-execution-time-allowance', '180',
               'CODE_SIGNING_ALLOWED=NO', 'CODE_SIGNING_REQUIRED=NO', "CODE_SIGN_IDENTITY="]
    result = subprocess.run(command)
    collect(device, verify=result.returncode == 0)
    raise SystemExit(result.returncode)


if __name__ == '__main__': main()
