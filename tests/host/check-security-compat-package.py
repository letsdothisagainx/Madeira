#!/usr/bin/env python3
"""Exercise the actual security-correction package checker with owned byte fixtures.

These are COFF/PE-shaped compiler/link fixtures, not working Wine DLLs. Real
crypto and Windows API conformance are tested separately. No trust or gameplay
result is inferred from acceptance of package metadata.
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
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CHECKER = module('security_package', ROOT / 'tools/check-security-compat-package.py')
FIXTURE = module('security_owned_pe', ROOT / 'tests/host/check-native-registration-tools.py')
MESSAGES = module('owned_message_resource', ROOT / 'tests/host/fixtures/winsock_message_resource.py')
CALLER = 'CSignedMsgData_UpdateAuthenticatedAttributes'
CODE = {name: bytes((seed + i) % 256 for i in range(48)) for name, seed in
        ((CHECKER.HELPER, 0x20), (CALLER, 0x60), ('GetMappedFileNameW', 0xa0))}


def symbol_table(symbols, big=False):
    entries, strings = bytearray(), bytearray(b'\0\0\0\0')
    for name, value, section, kind in symbols:
        encoded = name.encode() + b'\0'
        entries += struct.pack('<II', 0, len(strings)) + struct.pack('<IiHBB' if big else '<IhHBB', value, section, kind, 2, 0)
        strings += encoded
    struct.pack_into('<I', strings, 0, len(strings))
    return bytes(entries + strings)


def object_bytes(farm, name, reference=None, big=False):
    machine = 0xa641 if farm == 'arm64ec-windows' else CHECKER.FARMS[farm]
    body = bytearray(CODE[name])
    if reference:
        if machine == 0x14c:
            body[7] = 0xe8
        else:
            struct.pack_into('<I', body, 8, 0x94000000)
    relocs = struct.pack('<IIH', 8, 1, 0x14 if machine == 0x14c else 3) if reference else b''
    symbols = [(name, 0, 1, 0x20)] + ([(reference, 0, 0, 0)] if reference else [])
    if reference and farm == 'arm64ec-windows':
        # Real clang ARM64EC also emits a shorter exit thunk. Its ADRP/ADD
        # references address the undecorated helper; they are not the call in
        # the real verifier. The previous shortest-reference search selected
        # this thunk and rejected a correctly compiled DLL.
        start = len(body)
        body += struct.pack('<IIII', 0x9000000b, 0x9100016b, 0xd61f0200, 0xd65f03c0)
        relocs += struct.pack('<IIH', start, 1, 4) + struct.pack('<IIH', start + 4, 1, 6)
        symbols += [('#' + reference + '$exit_thunk', start, 1, 0x20)]
    code_start = 96 if big else 60
    offset = code_start + len(body) + len(relocs)
    if big:
        header = bytearray(56)
        struct.pack_into('<HHHH', header, 0, 0, 0xffff, 2, machine)
        header[12:28] = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
        struct.pack_into('<III', header, 44, 1, offset, len(symbols))
    else:
        header = struct.pack('<HHIIIHH', machine, 1, 0, offset, len(symbols), 0, 0)
    section = bytearray(40)
    section[:5] = b'.text'
    struct.pack_into('<III', section, 16, len(body), code_start, code_start + len(body) if reference else 0)
    struct.pack_into('<H', section, 32, len(relocs) // 10)
    struct.pack_into('<I', section, 36, 0x60000020)
    return header + section + body + relocs + symbol_table(symbols, big)


def dll_bytes(farm, dll):
    data = bytearray(FIXTURE.fixture(farm))
    crypto = dll == 'crypt32.dll'
    export, at = ('CryptMsgControl', 0x1080) if crypto else ('GetMappedFileNameW', 0x1000)
    names = [(CHECKER.HELPER, 0, 1, 0x20), (CALLER, 0x80, 1, 0x20),
             (export, 0x80, 1, 0x20)] if crypto else [(export, 0, 1, 0x20)]
    for name, offset, _, _ in names:
        if name in CODE:
            data[0x400 + offset:0x400 + offset + len(CODE[name])] = CODE[name]
    # A real linker changes relocation operands. The surrounding code must
    # match, while those compiler-declared relocation slots may differ.
    if crypto:
        if farm == 'i386-windows':
            data[0x487] = 0xe8
            struct.pack_into('<i', data, 0x488, 0x1000 - (0x1080 + 8 + 4))
        else:
            struct.pack_into('<I', data, 0x488, 0x94000000 | (((0x1000 - (0x1080 + 8)) // 4) & 0x03ffffff))
    dirs = 0x98 + (96 if farm == 'i386-windows' else 112)
    struct.pack_into('<II', data, dirs, 0x2800, 0x100)
    data[0xe00:0xf00] = bytes(0x100)
    struct.pack_into('<IIHHIIIIIII', data, 0xe00, 0, 0, 0, 0, 0x2880,
                     1, 1, 1, 0x2840, 0x2844, 0x2848)
    struct.pack_into('<I', data, 0xe40, at)
    struct.pack_into('<I', data, 0xe44, 0x2890)
    struct.pack_into('<H', data, 0xe48, 0)
    text = dll.encode() + b'\0'
    data[0xe80:0xe80 + len(text)] = text
    text = export.encode() + b'\0'
    data[0xe90:0xe90 + len(text)] = text
    if not crypto:
        data = MESSAGES.add_to_owned_pe(data, CHECKER.WSA_MESSAGES.EXPECTED)
    struct.pack_into('<II', data, 0x80 + 12, len(data), len(names))
    data += symbol_table(names)
    return bytes(data)


def ipa(stage, path, omit=None, duplicate=None, mutate=None):
    with zipfile.ZipFile(path, 'w') as out:
        for file in sorted(stage.rglob('*')):
            if not file.is_file():
                continue
            relative = file.relative_to(stage).as_posix()
            if relative == omit:
                continue
            data = file.read_bytes()
            if mutate:
                data = mutate(relative, data)
            name = 'Payload/Madeira.app/' + relative
            out.writestr(name, data)
            if relative == duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    out.writestr(name, data)


def check(stage, source, repo, app=None, archive=None, writing=False, objects=None):
    with contextlib.redirect_stdout(io.StringIO()):
        return CHECKER.check(stage, source, write=writing, app=app, ipa=archive, repo=repo, build_root=objects)


def setup(directory):
    base = Path(directory)
    stage, source, repo = base / 'stage', base / 'wine', base / 'recipes'
    for name in CHECKER.STOCK_INPUTS:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'wine' / name, target)
    for name in CHECKER.OWNED_INPUTS:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    for farm in CHECKER.FARMS:
        (stage / farm).mkdir(parents=True)
        for name in ('crypt32.dll', 'kernelbase.dll'):
            (stage / farm / name).write_bytes(dll_bytes(farm, name))
        tree = source / CHECKER.TREES[farm]
        for dll, file, name, reference in (
                ('crypt32', 'encode.o', CHECKER.HELPER, None),
                ('crypt32', 'msg.o', CALLER, CHECKER.HELPER),
                ('kernelbase', 'debug.o', 'GetMappedFileNameW', None)):
            path = tree / 'dlls' / dll / farm / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(object_bytes(farm, name, reference))
    check(stage, source, repo, writing=True, objects=source)
    app, archive = base / 'app', base / 'owned.ipa'
    shutil.copytree(stage, app)
    ipa(stage, archive)
    return stage, source, repo, app, archive


def reject(label, mutation, *, writing=False, objects=True):
    global rejected
    with tempfile.TemporaryDirectory(prefix='madeira-security-package-') as tmp:
        stage, source, repo, app, archive = setup(tmp)
        mutation(stage, source, repo, app, archive)
        try:
            check(stage, source, repo, None if writing else app, None if writing else archive,
                  writing=writing, objects=source if objects else None)
        except (AssertionError, OSError, ValueError, KeyError, UnicodeError, struct.error, zipfile.BadZipFile):
            rejected += 1
            return
        raise AssertionError('actual security package checker accepted ' + label)


def change(path, offset, data):
    value = bytearray(path.read_bytes())
    value[offset:offset + len(data)] = data
    path.write_bytes(value)


def object_path(source, name, farm='aarch64-windows'):
    return source / CHECKER.TREES[farm] / 'dlls' / ('kernelbase' if name == 'debug.o' else 'crypt32') / farm / name


def manifest_change(stage, edit):
    file = stage / CHECKER.MANIFEST
    metadata = json.loads(file.read_text())
    edit(metadata)
    file.write_text(json.dumps(metadata))


rejected = 0
with tempfile.TemporaryDirectory(prefix='madeira-security-package-valid-') as tmp:
    stage, source, repo, app, archive = setup(tmp)
    proof = check(stage, source, repo, app, archive, objects=source)
    assert len(proof['dlls']) == 6 and len(proof['compiled']) == 3
    ec = CHECKER.Code(object_path(source, 'msg.o', 'arm64ec-windows').read_bytes())
    assert ec.caller(CHECKER.HELPER)['name'] == CALLER
    # Establish the actual old selection failure instead of making the
    # compiler-created thunk disappear from the regression fixture.
    old_choice = min(ec.functions, key=lambda fn: (fn['length'], fn['name']))
    assert old_choice['name'].endswith('$exit_thunk')
    try:
        ec.calls(old_choice, CHECKER.HELPER)
    except ValueError as error:
        assert 'machine=0xa641 kind=0x4' in str(error)
    else:
        raise AssertionError('address-loading exit thunk was accepted as a verifier call')
    check(stage, source, repo, app, archive)  # Artifact-only consumer need not possess build objects.

with tempfile.TemporaryDirectory(prefix='madeira-security-package-bigobj-') as tmp:
    stage, source, repo, _, _ = setup(tmp)
    for name, symbol, reference in (('encode.o', CHECKER.HELPER, None), ('msg.o', CALLER, CHECKER.HELPER), ('debug.o', 'GetMappedFileNameW', None)):
        object_path(source, name).write_bytes(object_bytes('aarch64-windows', symbol, reference, big=True))
    check(stage, source, repo, writing=True, objects=source)

reject('missing real object evidence at publication', lambda *args: None, writing=True, objects=False)
for farm in CHECKER.FARMS:
    reject('wrong DLL machine ' + farm, lambda stage, *_, f=farm:
           change(stage / f / 'crypt32.dll', 0x84, b'\0\0'), writing=True)
    reject('substituted compiled message object ' + farm, lambda stage, source, *_, f=farm:
           change(object_path(source, 'msg.o', f), 60, b'X'), writing=True)
    reject('linked caller differs from compiled object ' + farm, lambda stage, *_, f=farm:
           change(stage / f / 'crypt32.dll', 0x480, b'X'), writing=True)
    reject('linked mapped filename code differs ' + farm, lambda stage, *_, f=farm:
           change(stage / f / 'kernelbase.dll', 0x400, b'X'), writing=True)
    reject('stale app farm ' + farm, lambda stage, source, repo, app, archive, f=farm:
           change(app / f / 'crypt32.dll', 0x400, b'X'))
    reject('missing IPA farm ' + farm, lambda stage, source, repo, app, archive, f=farm:
           ipa(stage, archive, omit=f + '/crypt32.dll'))
    reject('duplicate IPA farm ' + farm, lambda stage, source, repo, app, archive, f=farm:
           ipa(stage, archive, duplicate=f + '/kernelbase.dll'))
    reject('wrong object machine ' + farm, lambda stage, source, *_, f=farm:
           change(object_path(source, 'encode.o', f), 0, b'\0\0'), writing=True)

reject('removed actual verifier helper reference', lambda stage, source, *_:
       change(object_path(source, 'msg.o'), 60 + 48 + 4, struct.pack('<I', 0)), writing=True)
reject('ARM64EC exit-thunk address references cannot replace the real verifier call', lambda stage, source, *_:
       change(object_path(source, 'msg.o', 'arm64ec-windows'), 60 + 64 + 4, struct.pack('<I', 0)), writing=True)
reject('linked relocation points at the old verifier instead of corrected helper', lambda stage, *_:
       change(stage / 'aarch64-windows/crypt32.dll', 0x488, struct.pack('<I', 0x94000000)), writing=True)
reject('missing helper symbol', lambda stage, *_:
       change(stage / 'aarch64-windows/crypt32.dll', 0x1800 + 3 * 18 + 4,
              b'X' * len(CHECKER.HELPER)), writing=True)
reject('compiler relocation has unsupported width', lambda stage, source, *_:
       change(object_path(source, 'msg.o'), 60 + 48 + 8, b'\xff\xff'), writing=True)
reject('a stale crypt32 source input', lambda stage, source, *_:
       (source / 'dlls/crypt32/msg.c').write_text('stale'))
reject('already patched input was not restored', lambda stage, source, *_:
       (source / 'dlls/crypt32/msg.c').write_text(CHECKER.HELPER))
reject('changed owned build recipe', lambda stage, source, repo, *_:
       (repo / 'build/wine-pe/build-security-compat.sh').write_text('stale'))
reject('missing architecture proof', lambda stage, *_:
       manifest_change(stage, lambda meta: meta['compiled'].pop('i386-windows')))
reject('zeroed relocation mask cannot stand in for code', lambda stage, *_:
       manifest_change(stage, lambda meta: meta['compiled']['aarch64-windows']['code']['crypt32.dll'][0].update(mask='00' * 48)), objects=False)
reject('malformed manifest', lambda stage, *_: (stage / CHECKER.MANIFEST).write_text('{'))
reject('duplicate manifest keys', lambda stage, *_:
       (stage / CHECKER.MANIFEST).write_text('{"recipe":1,' + (stage / CHECKER.MANIFEST).read_text()[1:]))
reject('existing unowned pending output', lambda stage, *_:
       (stage / CHECKER.MANIFEST).with_suffix('.json.pending').write_text('unowned'), writing=True)
reject('symlinked farm', lambda stage, *_:
       ((stage / 'aarch64-windows').rename(stage / 'outside'),
        (stage / 'aarch64-windows').symlink_to(stage / 'outside')), writing=True)
reject('changed linked byte with merely refreshed self-hash', lambda stage, *_:
       (change(stage / 'aarch64-windows/crypt32.dll', 0x480, b'X'),
        manifest_change(stage, lambda meta: meta['dlls'].__setitem__('aarch64-windows/crypt32.dll',
            CHECKER.PE.inspect((stage / 'aarch64-windows/crypt32.dll').read_bytes(), 'aarch64-windows', required_export='CryptMsgControl')))), objects=False)

print('PASS actual security package checker: six DLLs/all ABIs, object/helper/caller/linked-code proof, preserved relocation differences, source/build hashes and exact app/IPA copies; rejected', rejected, 'owned negative cases; no Windows trust/gameplay execution claim')
