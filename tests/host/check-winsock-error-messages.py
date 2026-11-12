#!/usr/bin/env python3
"""Verify real MC staging/restoration and actual PE message-resource parsing.

Actual old bundled DLLs demonstrate absence. Owned PE fixtures exercise parser
bounds only; post-build package validation checks the real compiled DLLs.
This supplies no game-server connectivity result.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


stage = module('wsa_stage', ROOT / 'tools/build/stage-winsock-error-messages.py')
resource = module('wsa_resources', ROOT / 'tools/check-winsock-message-resources.py')
fixture = module('owned_pe', ROOT / 'tests/host/check-native-registration-tools.py')
owned = module('owned_messages', ROOT / 'tests/host/fixtures/winsock_message_resource.py')
source = ROOT / 'wine' / stage.SOURCE
before = source.read_bytes()
assert b'MessageId=10061\n' in before
for value in resource.EXPECTED:
    assert f'MessageId={value}\n'.encode() not in before
with tempfile.TemporaryDirectory(prefix='madeira-wsa-messages-') as temporary:
    base = Path(temporary)
    wine = base / 'wine'
    (wine / stage.SOURCE).parent.mkdir(parents=True)
    shutil.copyfile(source, wine / stage.SOURCE)
    stage.apply(base / 'state', wine)
    patched = (wine / stage.SOURCE).read_text()
    expected = json.loads(stage.PROVENANCE.read_text())['messages']
    for value, text in resource.EXPECTED.items():
        entry = f"MessageId={value}\nSymbolicName={expected[str(value)]['symbol']}\nLanguage=ENU\n{text}\n.\n"
        assert patched.count(entry) == 1
    try:
        stage.apply(base / 'again', wine)
    except ValueError:
        pass
    else:
        raise AssertionError('already patched input accepted')
    stage.restore(base / 'state')
    assert (wine / stage.SOURCE).read_bytes() == before
    stage.restore(base / 'state')
    assert (wine / stage.SOURCE).read_bytes() == before
print('PASS exact production MC stage, three standard error messages, unchanged formatter, source ownership and restoration')

old = 0
for farm in ('aarch64-windows', 'arm64ec-windows', 'i386-windows'):
    path = ROOT / 'app/Madeira' / farm / 'kernelbase.dll'
    if not path.exists():
        continue  # CI supplies the full I386 farm; local checkout need not.
    found = resource.messages(path.read_bytes())
    assert found.get(10061), 'real PE message directory was not read'
    if all(value not in found for value in resource.EXPECTED):
        old += 1
        try:
            resource.check(path.read_bytes())
        except AssertionError:
            pass
        else:
            raise AssertionError('old compiled DLL unexpectedly accepted')
        print('PASS before actual compiled ' + farm + ': 10061 exists; network/timeout/host messages absent')
    else:
        resource.check(path.read_bytes())
        print('PASS after actual compiled ' + farm + ': all standard messages present')
assert old or all((ROOT / 'app/Madeira' / farm / 'kernelbase.dll').exists() for farm in ('aarch64-windows', 'arm64ec-windows', 'i386-windows'))

for farm in ('aarch64-windows', 'arm64ec-windows', 'i386-windows'):
    data = owned.add_to_owned_pe(fixture.fixture(farm), resource.EXPECTED)
    assert resource.check(data) == {str(key): text for key, text in resource.EXPECTED.items()}
    cases = []
    for value in resource.EXPECTED:
        wrong = dict(resource.EXPECTED)
        wrong[value] = 'incorrect owned fixture'
        cases.append(owned.add_to_owned_pe(fixture.fixture(farm), wrong))
    cases += [data[:0xf20], data[:-1]]
    wrong = bytearray(data)
    struct.pack_into('<I', wrong, 0xf00 + 64, 0x40c)
    cases.append(wrong)
    wrong = bytearray(data)
    struct.pack_into('<I', wrong, 0xf00 + 20, 0xffffffff)
    cases.append(wrong)
    for malformed in cases:
        try:
            resource.check(malformed)
        except (AssertionError, UnicodeError, struct.error):
            pass
        else:
            raise AssertionError('missing/stale/truncated message fixture accepted')
print('PASS actual PE parser: all three machine layouts; missing/stale messages, wrong language and malformed resource bounds rejected')
