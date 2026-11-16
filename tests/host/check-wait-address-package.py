#!/usr/bin/env python3
"""Exercise the real WaitOnAddress object/export/package gate with owned bytes.

These are structural COFF/stripped-PE fixtures, not executable Wine binaries.
Production publishing requires the actual rebuilt sync.o for every ABI.
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


CHECK = module('wait_address_package', ROOT / 'tools/check-wait-address-package.py')
FIXTURE = module('wait_address_pe_fixture', ROOT / 'tests/host/check-native-registration-tools.py')
BODY = bytes(range(0x20, 0x60))


def symbols(farm):
    function = ('_RtlWaitOnAddress@16' if farm == 'i386-windows' else
                '#RtlWaitOnAddress' if farm == 'arm64ec-windows' else 'RtlWaitOnAddress')
    rows = ((function, 0, 1, 0x20, 2), ('lifetime_contract', 0, 2, 0, 3))
    entries, strings = bytearray(), bytearray(4)
    for name, value, section, kind, storage in rows:
        entries += struct.pack('<IIIhHBB', 0, len(strings), value, section, kind, storage, 0)
        strings += name.encode() + b'\0'
    struct.pack_into('<I', strings, 0, len(strings))
    return bytes(entries + strings)


def object_bytes(farm):
    machine = 0xa641 if farm == 'arm64ec-windows' else CHECK.FARMS[farm]
    body = bytearray(BODY)
    body[8:12] = bytes(4)  # Only this compiler-declared relocation may differ.
    marker = CHECK.MARKER + b'\0'
    start, marker_start = 100, 100 + len(body)
    reloc_start = marker_start + len(marker)
    reloc = struct.pack('<IIH', 8, 1, 0x6 if machine == 0x14c else 4)
    header = struct.pack('<HHIIIHH', machine, 2, 0, reloc_start + len(reloc), 2, 0, 0)
    sections = bytearray(80)
    sections[:5] = b'.text'
    struct.pack_into('<III', sections, 16, len(body), start, reloc_start)
    struct.pack_into('<H', sections, 32, 1)
    struct.pack_into('<I', sections, 36, 0x60000020)
    sections[40:46] = b'.rdata'
    struct.pack_into('<III', sections, 56, len(marker), marker_start, 0)
    struct.pack_into('<I', sections, 76, 0x40000040)
    return header + sections + body + marker + reloc + symbols(farm)


def dll_bytes(farm):
    data = bytearray(FIXTURE.fixture(farm))
    native = 0x1080 if farm == 'arm64ec-windows' else 0x1000
    raw = 0x400 + native - 0x1000
    data[raw:raw + len(BODY)] = BODY
    data[raw + 8:raw + 12] = b'\xde\xad\xbe\xef'
    dirs = 0x98 + (96 if farm == 'i386-windows' else 112)
    struct.pack_into('<II', data, dirs, 0x2800, 0x100)
    data[0xe00:0xf00] = bytes(0x100)
    struct.pack_into('<IIHHIIIIIII', data, 0xe00, 0, 0, 0, 0, 0x2880,
                     1, 1, 1, 0x2840, 0x2844, 0x2848)
    struct.pack_into('<I', data, 0xe40, 0x1000)
    struct.pack_into('<I', data, 0xe44, 0x2890)
    struct.pack_into('<H', data, 0xe48, 0)
    data[0xe80:0xe80 + 10] = b'ntdll.dll\0'
    name = CHECK.FUNCTION.encode() + b'\0'
    data[0xe90:0xe90 + len(name)] = name
    data[0x1100:0x1100 + len(CHECK.MARKER)] = CHECK.MARKER
    if farm == 'arm64ec-windows':
        # Public AMD64 export thunk redirects to a distinct native RX entry.
        struct.pack_into('<I', data, 0xd00 + 16, 0x2760)
        struct.pack_into('<I', data, 0xd00 + 52, 1)
        struct.pack_into('<II', data, 0xd60, 0x1000, native)
        struct.pack_into('<II', data, 0xd40, native | 1, 0x80)
    return bytes(data)


def augment_base_ntdll(data, farm):
    """Append a Wait export to the owned native-counter ntdll fixture.

    Existing DATA exports and backing ranges stay untouched. This helper is
    solely for composed package tests; it is never a production DLL updater.
    I386 has no native-counter fixture and uses the complete PE32 byte fixture.
    """
    if farm == 'i386-windows':
        return dll_bytes(farm)
    data = bytearray(data)
    assert struct.unpack_from('<H', data, 0x98)[0] == 0x20b

    def raw(rva):
        for begin, offset, size in ((0x1000,0x400,0x1000), (0x2000,0x1400,0x1000),
                                    (0x4000,0x2400,0x9000), (0xe000,0xb400,0x1000)):
            if begin <= rva < begin + size:
                return offset + rva - begin
        raise AssertionError('not an owned counter ntdll fixture')

    assert struct.unpack_from('<II', data, raw(0x1000)+20) == (5,5)
    struct.pack_into('<II', data, raw(0x1000)+20, 6, 6)
    struct.pack_into('<I', data, raw(0x1100)+5*4, 0x2000)
    struct.pack_into('<I', data, raw(0x1120)+5*4, 0x1260)
    struct.pack_into('<H', data, raw(0x1140)+5*2, 5)
    name = CHECK.FUNCTION.encode()+b'\0'
    data[raw(0x1260):raw(0x1260)+len(name)] = name
    data[raw(0x2000):raw(0x2000)+len(BODY)] = BODY
    data[raw(0x2008):raw(0x200c)] = b'\xde\xad\xbe\xef'
    data[raw(0xc300):raw(0xc300)+len(CHECK.MARKER)] = CHECK.MARKER
    if farm == 'arm64ec-windows':
        base = struct.unpack_from('<Q', data, 0x98+24)[0]
        struct.pack_into('<II', data, 0x98+112+10*8, 0xc400, 208)
        struct.pack_into('<I', data, raw(0xc400), 208)
        struct.pack_into('<Q', data, raw(0xc400)+200, base+0xc500)
        struct.pack_into('<III', data, raw(0xc500), 1, 0xc600, 1)
        struct.pack_into('<II', data, raw(0xc600), 0x2001, 0x1000)
    return bytes(data)


def archive(stage, destination, omit=None, duplicate=None, mutate=None):
    with zipfile.ZipFile(destination, 'w') as output:
        for file in sorted(stage.rglob('*')):
            if not file.is_file():
                continue
            relative = file.relative_to(stage).as_posix()
            if relative == omit:
                continue
            name = 'Payload/Madeira.app/' + relative
            data = file.read_bytes()
            if mutate:
                data = mutate(relative, data)
            output.writestr(name, data)
            if relative == duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    output.writestr(name, data)


def check(stage, repo, *, writing=False, objects=True, app=None, ipa=None):
    with contextlib.redirect_stdout(io.StringIO()):
        return CHECK.check(stage, repo, repo / 'wine' if objects else None,
                           writing, app, ipa)


def setup(folder):
    base = Path(folder)
    stage, repo = base / 'stage', base / 'repo'
    for name in CHECK.OWNED_INPUTS:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    for name in CHECK.STOCK_INPUTS:
        target = repo / 'wine' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'wine' / name, target)
    for farm in CHECK.FARMS:
        (stage / farm).mkdir(parents=True)
        (stage / farm / 'ntdll.dll').write_bytes(dll_bytes(farm))
        obj = repo / 'wine' / CHECK.code.TREES[farm] / 'dlls/ntdll' / farm / 'sync.o'
        obj.parent.mkdir(parents=True, exist_ok=True)
        obj.write_bytes(object_bytes(farm))
    (stage / 'Madeira.debug.dylib').write_bytes(b'owned structural native image\0' + CHECK.NATIVE_MARKER)
    value = check(stage, repo, writing=True)
    assert set(value['compiled']) == set(CHECK.FARMS)
    app, ipa = base / 'app', base / 'owned.ipa'
    shutil.copytree(stage, app)
    archive(stage, ipa)
    check(stage, repo, app=app, ipa=ipa)
    check(stage, repo, objects=False, app=app, ipa=ipa)
    return stage, repo, app, ipa


def change(path, offset, data):
    value = bytearray(path.read_bytes())
    value[offset:offset + len(data)] = data
    path.write_bytes(value)


def manifest_change(stage, edit):
    path = stage / CHECK.MANIFEST
    value = json.loads(path.read_text())
    edit(value)
    path.write_text(json.dumps(value))


def main():
    count = 0

    def reject(label, mutation, writing=False, objects=True):
        nonlocal count
        with tempfile.TemporaryDirectory(prefix='madeira-wait-package-') as folder:
            stage, repo, app, ipa = setup(folder)
            mutation(stage, repo, app, ipa)
            try:
                check(stage, repo, writing=writing, objects=objects,
                      app=None if writing else app, ipa=None if writing else ipa)
            except (AssertionError, OSError, ValueError, KeyError, TypeError, struct.error, zipfile.BadZipFile):
                count += 1
                return
            raise AssertionError('WaitOnAddress package gate accepted ' + label)

    for farm in CHECK.FARMS:
        rel = farm + '/ntdll.dll'
        obj = lambda repo, f=farm: repo / 'wine' / CHECK.code.TREES[f] / 'dlls/ntdll' / f / 'sync.o'
        raw = 0x480 if farm == 'arm64ec-windows' else 0x400
        reject('missing farm ' + farm, lambda s,r,a,z,p=rel: (s/p).unlink())
        reject('unmarked ntdll ' + farm, lambda s,r,a,z,p=rel: change(s/p, 0x1100, b'old!'))
        reject('different machine ' + farm, lambda s,r,a,z,p=rel: change(s/p, 0x84, b'\0\0'), writing=True)
        reject('non-RX code ' + farm, lambda s,r,a,z,p=rel,f=farm: change(s/p, 0x98+(224 if f=='i386-windows' else 240)+36, struct.pack('<I',0xe0000020)), writing=True)
        reject('object nonrelocation corruption ' + farm, lambda s,r,a,z,o=obj: change(o(r), 100, b'\xff'), writing=True)
        reject('object marker absent ' + farm, lambda s,r,a,z,o=obj: change(o(r), 164, b'old!'), writing=True)
        reject('DLL code with rehashed metadata ' + farm,
               lambda s,r,a,z,p=rel,b=raw: (change(s/p,b,b'\xff'), manifest_change(s,lambda v:v['dlls'].__setitem__(p,CHECK.code.PE.inspect((s/p).read_bytes(),p.split('/')[0],required_export=CHECK.FUNCTION)))), objects=False)
        reject('omitted IPA farm ' + farm, lambda s,r,a,z,p=rel: archive(s,z,omit=p))
        reject('duplicate IPA farm ' + farm, lambda s,r,a,z,p=rel: archive(s,z,duplicate=p))
        reject('different app bytes ' + farm, lambda s,r,a,z,p=rel: change(a/p, 0x420, b'\xff'))
    reject('restored source changed', lambda s,r,a,z: (r/'wine/dlls/ntdll/sync.c').write_text('not the pinned source'))
    reject('owned recipe changed', lambda s,r,a,z: (r/CHECK.OWNED_INPUTS[0]).write_text('# altered stage'))
    reject('missing object architecture proof', lambda s,r,a,z: manifest_change(s,lambda v:v['compiled'].pop('i386-windows')), objects=False)
    reject('all code evidence masked', lambda s,r,a,z: manifest_change(s,lambda v:v['compiled']['i386-windows']['function'].__setitem__('mask','00'*len(BODY))), objects=False)
    reject('wrong proof symbol', lambda s,r,a,z: manifest_change(s,lambda v:v['compiled']['i386-windows']['function'].__setitem__('symbol','DifferentFunction')), objects=False)
    reject('non-export proof entry', lambda s,r,a,z: manifest_change(s,lambda v:v['compiled']['arm64ec-windows'].__setitem__('nativeRVA',0x1000)), objects=False)
    reject('forwarded export', lambda s,r,a,z: change(s/'i386-windows/ntdll.dll',0xe40,struct.pack('<I',0x2880)), writing=True)
    reject('hybrid redirection leaves native code', lambda s,r,a,z: change(s/'arm64ec-windows/ntdll.dll',0xd64,struct.pack('<I',0x1000)), writing=True)
    reject('substituted IPA manifest', lambda s,r,a,z: archive(s,z,mutate=lambda p,d:b'{}' if p==CHECK.MANIFEST else d))
    reject('duplicate IPA manifest', lambda s,r,a,z: archive(s,z,duplicate=CHECK.MANIFEST))
    reject('missing compiler object', lambda s,r,a,z: (r/'wine/build-i386/dlls/ntdll/i386-windows/sync.o').unlink(), writing=True)
    reject('missing native child-scope marker', lambda s,r,a,z: (a/'Madeira.debug.dylib').write_bytes(b'old native image'))
    reject('missing IPA native image', lambda s,r,a,z: archive(s,z,omit='Madeira.debug.dylib'))
    reject('duplicate IPA native image', lambda s,r,a,z: archive(s,z,duplicate='Madeira.debug.dylib'))
    reject('native marker substring boundary', lambda s,r,a,z: archive(s,z,mutate=lambda p,d:b'old native image' if p=='Madeira.debug.dylib' else d))
    # Stream through the actual bounded scanner with a marker crossing its
    # chunk boundary; do not require a full native image allocation in memory.
    boundary = b'x' * ((1 << 20) - 7) + CHECK.NATIVE_MARKER + b'owned tail'
    CHECK.native_marker(io.BytesIO(boundary), len(boundary))
    # Existing native-counter contracts survive augmentation for the composed
    # Dock packaging test; native entry proofs still use the actual COFF reader.
    subfloor = module('wait_address_counter_fixture', ROOT/'tests/host/check-fex-subfloor-package.py')
    for farm in ('aarch64-windows', 'arm64ec-windows'):
        data, raw = subfloor.ntdll_fixture(CHECK.FARMS[farm])
        augmented = augment_base_ntdll(data, farm)
        for rva, size in ((0x4000,24712),(0xa100,24),(0xa200,8192),(0xc240,4),(0xc280,32)):
            assert augmented[raw(rva):raw(rva)+size] == data[raw(rva):raw(rva)+size]
        image = CHECK.native.Image(augmented, farm, required_export=CHECK.FUNCTION)
        assert image.native_target(CHECK.MACHINES[farm]) == 0x2000
        obj = CHECK.code.Code(object_bytes(farm))
        proof = {'objectSHA256': CHECK.code.digest(object_bytes(farm)), 'nativeRVA': 0x2000,
                 'function': obj.proof(obj.function(CHECK.FUNCTION))}
        CHECK.verify(image, proof, farm)
    print('PASS actual WaitOnAddress package gate: all 3 COFF objects, stripped RX exports, ARM64EC native redirection, relocation masking, restored sources and exact app/IPA bytes; rejected %d owned negative fixtures; no Windows/CEF runtime claim' % count)


if __name__ == '__main__':
    main()
