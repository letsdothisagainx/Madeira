#!/usr/bin/env python3
"""Test the actual registry-security package gate with owned COFF/PE bytes.

This validates the gate, not Windows execution, Steam IPC or VAC acceptance.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CHECK = module('registry_security_package', ROOT / 'tools/check-registry-security-package.py')
FIXTURE = module('registry_security_pe', ROOT / 'tests/host/check-native-registration-tools.py')
FUNCTIONS = CHECK.FUNCTIONS
BYTES = {name: bytes((seed + i) % 256 for i in range(48)) for name, seed in zip(FUNCTIONS, (0x20, 0x80))}


def symbols():
    entries, strings = bytearray(), bytearray(4)
    for index, name in enumerate(FUNCTIONS):
        entries += struct.pack('<IIIhHBB', 0, len(strings), index * 0x80, 1, 0x20, 2, 0)
        strings += name.encode() + b'\0'
    struct.pack_into('<I', strings, 0, len(strings))
    return bytes(entries + strings)


def object_bytes(farm):
    machine = 0xa641 if farm == 'arm64ec-windows' else CHECK.code.FARMS[farm]
    body = bytearray(0x80 + 48)
    for index, name in enumerate(FUNCTIONS):
        body[index * 0x80:index * 0x80 + 48] = BYTES[name]
    header = struct.pack('<HHIIIHH', machine, 1, 0, 60 + len(body), 2, 0, 0)
    section = bytearray(40)
    section[:5] = b'.text'
    struct.pack_into('<III', section, 16, len(body), 60, 0)
    struct.pack_into('<I', section, 36, 0x60000020)
    return header + section + body + symbols()


def dll_bytes(farm):
    data = bytearray(FIXTURE.fixture(farm))
    # The first COFF function extends to the next symbol, so include the same
    # zero-filled alignment gap in its linked counterpart.
    data[0x400:0x400 + 0x80 + 48] = bytes(0x80 + 48)
    for index, name in enumerate(FUNCTIONS):
        data[0x400 + index * 0x80:0x400 + index * 0x80 + 48] = BYTES[name]
    dirs = 0x98 + (96 if farm == 'i386-windows' else 112)
    struct.pack_into('<II', data, dirs, 0x2800, 0x100)
    data[0xe00:0xf00] = bytes(0x100)
    struct.pack_into('<IIHHIIIIIII', data, 0xe00, 0, 0, 0, 0, 0x2880,
                     1, 1, 1, 0x2840, 0x2844, 0x2848)
    struct.pack_into('<I', data, 0xe40, 0x1000)
    struct.pack_into('<I', data, 0xe44, 0x2890)
    struct.pack_into('<H', data, 0xe48, 0)
    data[0xe80:0xe80 + 13] = b'advapi32.dll\0'
    export = FUNCTIONS[0].encode() + b'\0'
    data[0xe90:0xe90 + len(export)] = export
    struct.pack_into('<II', data, 0x80 + 12, len(data), 2)
    return bytes(data) + symbols()


def archive(stage, destination, omit=None, duplicate=None):
    with zipfile.ZipFile(destination, 'w') as output:
        for file in sorted(stage.rglob('*')):
            if not file.is_file():
                continue
            relative = file.relative_to(stage).as_posix()
            if relative == omit:
                continue
            name = 'Payload/Madeira.app/' + relative
            output.writestr(name, file.read_bytes())
            if relative == duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    output.writestr(name, file.read_bytes())


def run(stage, source, repo, app=None, ipa=None, write=False, objects=True):
    with contextlib.redirect_stdout(io.StringIO()):
        return CHECK.check(stage, source, repo, source if objects else None, write, app, ipa)


def setup(directory):
    base = Path(directory)
    stage, source, repo = base / 'stage', base / 'wine', base / 'recipes'
    for name in ('dlls/advapi32/security.c', 'dlls/advapi32/advapi32.spec', 'dlls/advapi32/Makefile.in',
                 'include/accctrl.h', 'include/winnt.h'):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'wine' / name, path)
    for name in CHECK.SOURCES:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
    for farm in CHECK.code.FARMS:
        path = stage / farm
        path.mkdir(parents=True)
        (path / 'advapi32.dll').write_bytes(dll_bytes(farm))
        obj = source / CHECK.code.TREES[farm] / 'dlls/advapi32' / farm / 'security.o'
        obj.parent.mkdir(parents=True)
        obj.write_bytes(object_bytes(farm))
    run(stage, source, repo, write=True)
    app, ipa = base / 'app', base / 'fixture.ipa'
    shutil.copytree(stage, app)
    archive(stage, ipa)
    return stage, source, repo, app, ipa


def change(path, offset, value):
    data = bytearray(path.read_bytes())
    data[offset:offset + len(value)] = value
    path.write_bytes(data)


def metadata(stage, mutation):
    path = stage / CHECK.MANIFEST
    value = json.loads(path.read_text())
    mutation(value)
    path.write_text(json.dumps(value))


def reject(label, mutation, writing=False, objects=True):
    global rejected
    with tempfile.TemporaryDirectory(prefix='madeira-registry-package-negative-') as directory:
        stage, source, repo, app, ipa = setup(directory)
        mutation(stage, source, repo, app, ipa)
        try:
            run(stage, source, repo, None if writing else app, None if writing else ipa, writing, objects)
        except (AssertionError, ValueError, OSError, KeyError, UnicodeError, struct.error, zipfile.BadZipFile):
            rejected += 1
            return
        raise AssertionError('incorrectly accepted: ' + label)


rejected = 0
with tempfile.TemporaryDirectory(prefix='madeira-registry-package-valid-') as directory:
    stage, source, repo, app, ipa = setup(directory)
    run(stage, source, repo, app, ipa)
    run(stage, source, repo, app, ipa, objects=False)

for farm in CHECK.code.FARMS:
    reject('wrong DLL architecture ' + farm, lambda stage, *_, f=farm:
           change(stage / f / 'advapi32.dll', 0x84, b'\0\0'), writing=True)
    reject('substituted linked set code ' + farm, lambda stage, *_, f=farm:
           change(stage / f / 'advapi32.dll', 0x400, b'X'), writing=True)
    reject('substituted linked get code ' + farm, lambda stage, *_, f=farm:
           change(stage / f / 'advapi32.dll', 0x480, b'X'), writing=True)
    reject('substituted object ' + farm, lambda stage, source, *_, f=farm:
           change(source / CHECK.code.TREES[f] / 'dlls/advapi32' / f / 'security.o', 60, b'X'), writing=True)
    reject('wrong object architecture ' + farm, lambda stage, source, *_, f=farm:
           change(source / CHECK.code.TREES[f] / 'dlls/advapi32' / f / 'security.o', 0, b'\0\0'), writing=True)
    reject('stale app ' + farm, lambda stage, source, repo, app, ipa, f=farm:
           change(app / f / 'advapi32.dll', 0x400, b'X'))
    reject('missing IPA ' + farm, lambda stage, source, repo, app, ipa, f=farm:
           archive(stage, ipa, omit=f + '/advapi32.dll'))
    reject('duplicate IPA ' + farm, lambda stage, source, repo, app, ipa, f=farm:
           archive(stage, ipa, duplicate=f + '/advapi32.dll'))

reject('no real object at publication', lambda *args: None, writing=True, objects=False)
reject('stale reviewed patch', lambda stage, source, repo, *_:
       (repo / CHECK.SOURCES[0]).write_text('stale patch'))
reject('changed source', lambda stage, source, *_:
       (source / 'dlls/advapi32/security.c').write_text('stale source'))
reject('missing architecture proof', lambda stage, *_:
       metadata(stage, lambda value: value['compiled'].pop('i386-windows')))
reject('missing get function proof', lambda stage, *_:
       metadata(stage, lambda value: value['compiled']['aarch64-windows']['code'].pop()), objects=False)
reject('zero proof mask', lambda stage, *_:
       metadata(stage, lambda value: value['compiled']['aarch64-windows']['code'][0].update(mask='00' * 128)), objects=False)
reject('unowned pending manifest', lambda stage, *_:
       (stage / CHECK.MANIFEST).with_suffix('.json.pending').write_text('unowned'), writing=True)
reject('duplicate metadata key', lambda stage, *_:
       (stage / CHECK.MANIFEST).write_text('{"recipe":1,' + (stage / CHECK.MANIFEST).read_text()[1:]))

print('PASS actual registry security package gate: both functions/all 3 ABIs, compiler-to-linked proofs, restored source/recipe hashes, exact app/IPA copies; rejected', rejected, 'negative fixtures; no Windows/Steam/VAC claim')
