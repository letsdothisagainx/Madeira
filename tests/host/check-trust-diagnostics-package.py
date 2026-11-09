#!/usr/bin/env python3
"""Test the actual trust-observer package verifier with owned PE byte fixtures.

The fixtures exercise ABI/export/provenance/package checks. They are not compiled
Wine DLLs and do not run WinVerifyTrust, DirectX, Steam, or an iPhone.
"""
from pathlib import Path
import contextlib
import importlib.util
import io
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


PE_FIXTURES = module('trust_owned_pe_fixtures', ROOT/'tests/host/check-native-registration-tools.py')
CHECKER = module('trust_package_checker', ROOT/'tools/check-trust-diagnostics-package.py')


def fixture(farm):
    data = bytearray(PE_FIXTURES.fixture(farm))
    dirs = 0x98 + (96 if farm == 'i386-windows' else 112)
    struct.pack_into('<II', data, dirs, 0x2800, 0x100)
    data[0xe00:0xf00] = bytes(0x100)
    struct.pack_into('<IIHHIIIIIII', data, 0xe00,
                     0, 0, 0, 0, 0x2880, 1, 1, 1, 0x2840, 0x2844, 0x2848)
    struct.pack_into('<I', data, 0xe40, 0x1000)
    struct.pack_into('<I', data, 0xe44, 0x2890)
    struct.pack_into('<H', data, 0xe48, 0)
    data[0xe80:0xe80+13] = b'wintrust.dll\0'
    name = CHECKER.EXPORT.encode() + b'\0'
    data[0xe90:0xe90+len(name)] = name
    data[0x1100:0x1100+len(CHECKER.MARKER)] = CHECKER.MARKER
    return bytes(data)


def write_ipa(stage, destination, mutate=None, omit=None, duplicate=None):
    with zipfile.ZipFile(destination, 'w') as archive:
        for path in sorted(stage.rglob('*')):
            if not path.is_file():
                continue
            relative = path.relative_to(stage).as_posix()
            if relative == omit:
                continue
            data = path.read_bytes()
            if mutate:
                data = mutate(relative, data)
            name = 'Payload/Madeira.app/'+relative
            archive.writestr(name, data)
            if relative == duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr(name, data)


def check(stage, source, repo, app=None, ipa=None, write=False):
    with contextlib.redirect_stdout(io.StringIO()):
        return CHECKER.check(stage, source, write=write, app=app, ipa=ipa, repo=repo)


def fixture_tree(directory):
    folder = Path(directory)
    stage, source, repo = folder/'stage', folder/'wine', folder/'recipes'
    shutil.copytree(ROOT/'wine/dlls/wintrust', source/'dlls/wintrust')
    for name in CHECKER.STOCK_HEADERS:
        destination = source/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/'wine'/name, destination)
    for name in CHECKER.OWNED_INPUTS:
        destination = repo/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/name, destination)
    for farm in CHECKER.FARMS:
        (stage/farm).mkdir(parents=True)
        (stage/farm/'wintrust.dll').write_bytes(fixture(farm))
    check(stage, source, repo, write=True)
    app, ipa = folder/'app', folder/'owned.ipa'
    shutil.copytree(stage, app)
    write_ipa(stage, ipa)
    return stage, source, repo, app, ipa


def edit(path, offset, value, fmt='<I'):
    data = bytearray(path.read_bytes())
    struct.pack_into(fmt, data, offset, value)
    path.write_bytes(data)


def rejected(label, mutate, *, writing=False):
    with tempfile.TemporaryDirectory(prefix='madeira-trust-package-') as directory:
        stage, source, repo, app, ipa = fixture_tree(directory)
        mutate(stage, source, repo, app, ipa)
        try:
            # A fresh proof must reject malformed bytes on their own. Stale
            # prior hashes or app/IPA copies must not mask a relaxed PE gate.
            check(stage, source, repo, None if writing else app, None if writing else ipa, write=writing)
        except (AssertionError, OSError, ValueError, KeyError, UnicodeError, struct.error,
                zipfile.BadZipFile):
            return
        raise AssertionError('production verifier accepted '+label)


def malformed(label, mutate):
    rejected(label, mutate, writing=True)


def dll(stage, farm='aarch64-windows'):
    return stage/farm/'wintrust.dll'


def invalidate_export_name(stage, *_):
    path = dll(stage)
    data = bytearray(path.read_bytes())
    data[0xe90:0xe90+len(CHECKER.EXPORT)] = b'X'*len(CHECKER.EXPORT)
    path.write_bytes(data)


def remove_marker(stage, *_):
    path = dll(stage)
    path.write_bytes(path.read_bytes().replace(CHECKER.MARKER, b'x'*len(CHECKER.MARKER)))


def forwarded_export(stage, *_):
    path = dll(stage)
    edit(path, 0xe40, 0x28c0)
    data = bytearray(path.read_bytes())
    forwarder = b'kernelbase.SomeFunction\0'
    data[0xec0:0xec0+len(forwarder)] = forwarder
    path.write_bytes(data)


def oversized_payload(stage, *_):
    with dll(stage).open('wb') as output:
        output.truncate((64 << 20)+1)


def symlinked_payload(stage, *_):
    path = dll(stage)
    target = stage.parent/'outside-fixture.dll'
    path.replace(target)
    path.symlink_to(target)


def dangling_manifest(stage, *_):
    path = stage/CHECKER.MANIFEST
    path.unlink()
    path.symlink_to(stage.parent/'must-not-be-created')


def pending_manifest(stage, *_):
    (stage/CHECKER.MANIFEST).with_suffix('.json.pending').write_text('unowned pending content')


def malformed_manifest(stage, *_):
    (stage/CHECKER.MANIFEST).write_text('{')


def duplicate_manifest_key(stage, *_):
    path = stage/CHECKER.MANIFEST
    value = path.read_text()
    path.write_text('{"recipe":1,'+value[1:])


def symlinked_stock_source(stage, source, *_):
    path = source/'dlls/wintrust/wintrust_main.c'
    target = source.parent/'outside-fixture-source.c'
    path.replace(target)
    path.symlink_to(target)


def sparse_manifest(stage, *_):
    with (stage/CHECKER.MANIFEST).open('wb') as output:
        output.truncate((1 << 20)+1)


def stale_ipa(stage, source, repo, app, ipa):
    def changed(relative, data):
        if relative == 'aarch64-windows/wintrust.dll':
            data = bytearray(data)
            data[0x410] ^= 1
        return data
    write_ipa(stage, ipa, mutate=changed)


def main():
    with tempfile.TemporaryDirectory(prefix='madeira-trust-valid-') as directory:
        stage, source, repo, app, ipa = fixture_tree(directory)
        result = check(stage, source, repo, app, ipa)
        assert result['recipe'] == 1 and len(result['dlls']) == 3
        assert set(result['dlls']) == {farm+'/wintrust.dll' for farm in CHECKER.FARMS}
        for record in result['dlls'].values():
            assert record['export_name'] == CHECKER.EXPORT and record['export_rva'] == 0x1000
        assert result['sources'], 'source manifest must not be empty'
    # Real ARM64EC Wine DLLs can export an RX compatibility thunk outside the
    # native ARM64EC intervals. Whole-image CHPE/native code is still required;
    # the public export must be checked as RX, not assumed to be its native body.
    with tempfile.TemporaryDirectory(prefix='madeira-trust-ec-thunk-') as directory:
        stage, source, repo, app, ipa = fixture_tree(directory)
        path = dll(stage, 'arm64ec-windows')
        edit(path, 0xe40, 0x1100)
        data = bytearray(path.read_bytes())
        data[0x500:0x504] = b'\xc3\x90\x90\x90'
        path.write_bytes(data)
        metadata = check(stage, source, repo, write=True)
        assert metadata['dlls']['arm64ec-windows/wintrust.dll']['export_rva'] == 0x1100
        shutil.copyfile(path, dll(app, 'arm64ec-windows'))
        shutil.copyfile(stage/CHECKER.MANIFEST, app/CHECKER.MANIFEST)
        write_ipa(stage, ipa)
        check(stage, source, repo, app, ipa)

    malformed('missing native DLL', lambda s,w,r,a,z: dll(s).unlink())
    malformed('empty image', lambda s,w,r,a,z: dll(s).write_bytes(b''))
    malformed('truncated headers', lambda s,w,r,a,z: dll(s).write_bytes(fixture('aarch64-windows')[:90]))
    malformed('oversized DLL before reading it', oversized_payload)
    malformed('symlinked DLL', symlinked_payload)
    malformed('wrong architecture', lambda s,w,r,a,z: edit(dll(s), 0x84, 0x14c, '<H'))
    malformed('wrong optional header', lambda s,w,r,a,z: edit(dll(s, 'i386-windows'), 0x98, 0x20b, '<H'))
    malformed('EXE masquerading as trust DLL', lambda s,w,r,a,z: edit(dll(s), 0x96, 2, '<H'))
    malformed('unmapped PE header offset', lambda s,w,r,a,z: edit(dll(s), 0x3c, 0xfffffff0))
    malformed('section outside image', lambda s,w,r,a,z: edit(dll(s), 0x98+240+12, 0xfffff000))
    malformed('plain AMD64 without native EC code', lambda s,w,r,a,z: edit(dll(s, 'arm64ec-windows'), 0x98+112+10*8, 0))
    malformed('hybrid map has no native range', lambda s,w,r,a,z: edit(dll(s, 'arm64ec-windows'), 0xd40, 0x1000))
    malformed('hybrid native code lies in data', lambda s,w,r,a,z: edit(dll(s, 'arm64ec-windows'), 0xd40, 0x3001))
    malformed('missing export directory', lambda s,w,r,a,z: edit(dll(s), 0x98+112, 0))
    malformed('missing WinVerifyTrust name', invalidate_export_name)
    malformed('export forwarded to another DLL', forwarded_export)
    malformed('export to writable data', lambda s,w,r,a,z: edit(dll(s), 0xe40, 0x3000))
    malformed('export to unbacked memory', lambda s,w,r,a,z: edit(dll(s), 0xe40, 0x3f00))
    malformed('export outside own image', lambda s,w,r,a,z: edit(dll(s), 0xe40, 0x5000))
    malformed('malformed export ordinal', lambda s,w,r,a,z: edit(dll(s), 0xe48, 9, '<H'))
    malformed('oversized export name count', lambda s,w,r,a,z: edit(dll(s), 0xe00+24, 0xffffffff))
    malformed('unbacked export-name table', lambda s,w,r,a,z: edit(dll(s), 0xe00+32, 0x4000))
    malformed('stale observer marker', remove_marker)
    rejected('changed real DLL bytes', lambda s,w,r,a,z: edit(dll(s), 0x410, 0x12345678))
    rejected('changed stock verifier source', lambda s,w,r,a,z: (w/'dlls/wintrust/wintrust_main.c').write_text('invalid source'))
    rejected('symlinked stock verifier source', symlinked_stock_source)
    rejected('changed stock trust header', lambda s,w,r,a,z: (w/'include/wintrust.h').write_text('changed source header'))
    rejected('changed owned observer header', lambda s,w,r,a,z: (r/'build/wine-pe/trust_diagnostics.h').write_text('changed observer'))
    rejected('changed owned staging recipe', lambda s,w,r,a,z: (r/'tools/build/stage-trust-diagnostics.py').write_text('changed stager'))
    malformed('unrestored injected header', lambda s,w,r,a,z: (w/'dlls/wintrust/madeira_trust_diagnostics.h').write_text('staged content'))
    rejected('missing completion manifest', lambda s,w,r,a,z: (s/CHECKER.MANIFEST).unlink())
    rejected('invalid completion JSON', malformed_manifest)
    rejected('duplicate completion JSON key', duplicate_manifest_key)
    rejected('stale completion recipe', lambda s,w,r,a,z: (s/CHECKER.MANIFEST).write_text('{}'))
    rejected('oversized completion file', sparse_manifest)
    rejected('symlinked output manifest', dangling_manifest, writing=True)
    rejected('unowned pending output manifest', pending_manifest, writing=True)
    rejected('stale app DLL', lambda s,w,r,a,z: edit(dll(a), 0x410, 0x87654321))
    rejected('stale app manifest', lambda s,w,r,a,z: (a/CHECKER.MANIFEST).write_text('{}'))
    rejected('missing app I386 DLL', lambda s,w,r,a,z: dll(a, 'i386-windows').unlink())
    rejected('stale IPA DLL', stale_ipa)
    rejected('missing IPA DLL', lambda s,w,r,a,z: write_ipa(s,z,omit='i386-windows/wintrust.dll'))
    rejected('duplicate IPA DLL', lambda s,w,r,a,z: write_ipa(s,z,duplicate='aarch64-windows/wintrust.dll'))
    rejected('duplicate IPA manifest', lambda s,w,r,a,z: write_ipa(s,z,duplicate=CHECKER.MANIFEST))
    rejected('stale IPA manifest', lambda s,w,r,a,z: write_ipa(
        s,z,mutate=lambda relative,data: b'{}' if relative==CHECKER.MANIFEST else data))
    print('PASS actual trust package verifier: three owned ABI/RX-export/marker/source/app/IPA fixtures accepted; malformed, missing, forwarded, foreign, stale, symlinked and duplicate cases rejected')
    print('Package byte contracts only: real trust decisions, official installer completion and iPhone execution remain unmeasured')


if __name__ == '__main__':
    main()
