#!/usr/bin/env python3
"""Exercise the production registration-program PE/package verifier.

Fixtures have real-shaped PE headers, descriptors, hybrid metadata and import
thunks. They are owned byte fixtures, not working Wine programs. Their success
only verifies the checker; no Windows, iOS or installer execution is claimed.
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
spec = importlib.util.spec_from_file_location(
    'madeira_system_program_checker', ROOT / 'tools/check-system-programs.py')
CHECKER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECKER)


def fixture(farm, program=None):
    """Return an owned PE32/A64/ARM64EC-shaped image for the actual checker."""
    machine = CHECKER.FARMS[farm]
    pe32 = machine == 0x14c
    optional_size, magic = (224, 0x10b) if pe32 else (240, 0x20b)
    data = bytearray(0x1800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    pe, opt = 0x80, 0x98
    data[pe:pe+4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, pe+4, machine, 3, 0, 0, 0,
                     optional_size, 2 | (0 if program else 0x2000))
    struct.pack_into('<H', data, opt, magic)
    struct.pack_into('<I', data, opt+16, 0x1000)
    if pe32:
        struct.pack_into('<I', data, opt+28, 0x400000)
        base = 0x400000
    else:
        struct.pack_into('<Q', data, opt+24, 0x140000000)
        base = 0x140000000
    struct.pack_into('<II', data, opt+32, 0x1000, 0x200)
    struct.pack_into('<II', data, opt+56, 0x4000, 0x400)
    struct.pack_into('<H', data, opt+68, 2)
    dirs = opt + (96 if pe32 else 112)
    struct.pack_into('<I', data, dirs-4, 16)
    for i, (name, rva, size, raw, flags) in enumerate((
            (b'.text', 0x1000, 0x200, 0x400, 0x60000020),
            (b'.rdata', 0x2000, 0x1000, 0x600, 0x40000040),
            (b'.data', 0x3000, 0x200, 0x1600, 0xc0000040))):
        at = opt + optional_size + i*40
        data[at:at+len(name)] = name
        struct.pack_into('<IIII', data, at+8, size, rva, size, raw)
        struct.pack_into('<I', data, at+36, flags)
    data[0x400:0x404] = b'\xc3\x90\x90\x90' if pe32 else b'\xc0\x03\x5f\xd6'
    imports = [] if not program else ['kernelbase.dll', 'user32.dll']
    if program == 'regsvr32':
        imports.append('ole32.dll')
    if imports:
        struct.pack_into('<II', data, dirs+8, 0x2000, (len(imports)+1)*20)
        for i, name in enumerate(imports):
            struct.pack_into('<IIIII', data, 0x600+i*20,
                             0x2300+i*0x20, 0, 0, 0x2100+i*0x30, 0x2400+i*0x20)
            data[0x700+i*0x30:0x700+i*0x30+len(name)+1] = name.encode()+b'\0'
            thunk = 0x2500+i*0x40
            fmt = '<I' if pe32 else '<Q'
            struct.pack_into(fmt, data, 0x900+i*0x20, thunk)
            struct.pack_into(fmt, data, 0xa00+i*0x20, thunk)
            function = b'FixtureExport\0'
            data[0xb02+i*0x40:0xb02+i*0x40+len(function)] = function
    if farm == 'arm64ec-windows':
        struct.pack_into('<II', data, dirs+10*8, 0x2600, 208)
        struct.pack_into('<I', data, 0xc00, 208)
        struct.pack_into('<Q', data, 0xc00+200, base+0x2700)
        struct.pack_into('<III', data, 0xd00, 1, 0x2740, 1)
        struct.pack_into('<II', data, 0xd40, 0x1001, 0x100)
    if not program:
        data[0xe00:0xe00+len(CHECKER.MARKER)] = CHECKER.MARKER
    return bytes(data)


def fixture_tree(folder):
    """Create staged/app/IPA/source fixtures without touching project outputs."""
    folder = Path(folder)
    stage, source = folder/'staged', folder/'wine'
    for program in CHECKER.PROGRAMS:
        shutil.copytree(ROOT/'wine/programs'/program, source/'programs'/program)
    for farm in CHECKER.FARMS:
        (stage/farm).mkdir(parents=True)
        for program in CHECKER.PROGRAMS:
            (stage/farm/(program+'.exe')).write_bytes(fixture(farm, program))
        for name in ('kernelbase.dll', 'user32.dll', 'ole32.dll', 'ntdll.dll'):
            (stage/farm/name).write_bytes(fixture(farm))
    with contextlib.redirect_stdout(io.StringIO()):
        CHECKER.check(stage, source, write=True)
    app = folder/'app'
    shutil.copytree(stage, app)
    ipa = folder/'fixture.ipa'
    write_ipa(stage, ipa)
    return stage, source, app, ipa


def write_ipa(stage, destination):
    with zipfile.ZipFile(destination, 'w') as archive:
        for path in sorted(stage.rglob('*')):
            if path.is_file():
                archive.write(path, 'Payload/Madeira.app/'+path.relative_to(stage).as_posix())


def check(stage, source, app=None, ipa=None, write=False):
    with contextlib.redirect_stdout(io.StringIO()):
        return CHECKER.check(stage, source, write=write, app=app, ipa=ipa)


def rejected(label, mutate, message=None):
    with tempfile.TemporaryDirectory(prefix='madeira-registration-pe-') as directory:
        stage, source, app, ipa = fixture_tree(directory)
        mutate(stage, source, app, ipa)
        try:
            check(stage, source, app, ipa)
        except (AssertionError, FileNotFoundError, KeyError, ValueError, struct.error) as error:
            if message:
                assert message in str(error), (label, type(error).__name__, str(error))
        else:
            raise AssertionError('production checker accepted '+label)


def edit(path, offset, value, fmt='<I'):
    data = bytearray(path.read_bytes())
    struct.pack_into(fmt, data, offset, value)
    path.write_bytes(data)


def main():
    # The original farms lacked native utilities. This is genuine checker
    # rejection of absence, not a simulated successful registration result.
    with tempfile.TemporaryDirectory(prefix='madeira-registration-absent-') as directory:
        stage = Path(directory)
        for farm in CHECKER.FARMS:
            (stage/farm).mkdir()
            (stage/farm/'kernelbase.dll').write_bytes(fixture(farm))
        try:
            check(stage, None)
        except AssertionError as error:
            assert 'missing system program:' in str(error)
        else:
            raise AssertionError('absent native regsvr32 accepted')
    with tempfile.TemporaryDirectory(prefix='madeira-registration-valid-') as directory:
        stage, source, app, ipa = fixture_tree(directory)
        metadata = check(stage, source, app, ipa)
        assert metadata['recipe'] == 1 and len(metadata['programs']) == 6
        for farm in CHECKER.FARMS:
            for program in CHECKER.PROGRAMS:
                record = metadata['programs'][farm+'/'+program+'.exe']
                assert record['machine'] == CHECKER.FARMS[farm]
                assert set(record['imports']) >= {'kernelbase.dll', 'user32.dll'}
    rejected('missing I386 utility',
             lambda s,w,a,z: (s/'i386-windows/regsvr32.exe').unlink(), 'missing system program:')
    rejected('wrong native machine',
             lambda s,w,a,z: edit(s/'aarch64-windows/regsvr32.exe', 0x84, 0x8664, '<H'), 'machine mismatch')
    rejected('DLL masquerading as executable',
             lambda s,w,a,z: edit(s/'aarch64-windows/regsvr32.exe', 0x96, 0x2002, '<H'), 'genuine executable')
    rejected('non GUI subsystem',
             lambda s,w,a,z: edit(s/'aarch64-windows/regsvr32.exe', 0x98+68, 3, '<H'), 'GUI subsystem')
    rejected('I386 wrong optional header',
             lambda s,w,a,z: edit(s/'i386-windows/regsvr32.exe', 0x98, 0x20b, '<H'), 'optional-header ABI')
    rejected('entry in writable data',
             lambda s,w,a,z: edit(s/'aarch64-windows/regsvr32.exe', 0x98+16, 0x3000), 'entry is not file-backed RX')
    rejected('missing registration import',
             lambda s,w,a,z: (s/'aarch64-windows/ole32.dll').unlink(), 'missing')
    rejected('dependency with foreign ABI',
             lambda s,w,a,z: (s/'aarch64-windows/ole32.dll').write_bytes(fixture('i386-windows')), 'machine mismatch')
    rejected('required import replaced by unknown DLL',
             lambda s,w,a,z: rename_import(s/'aarch64-windows/regsvr32.exe', b'user32.dll', b'unknown.dll'), 'stock system program imports missing')
    rejected('unknown additional DLL',
             lambda s,w,a,z: additional_import(s/'aarch64-windows/regsvr32.exe', b'missing.dll'), 'missing')
    rejected('unknown API-looking additional DLL',
             lambda s,w,a,z: additional_import(s/'aarch64-windows/regsvr32.exe', b'api-ms-madeira-unknown.dll'), 'missing')
    rejected('unknown API-set-shaped additional DLL',
             lambda s,w,a,z: additional_import(s/'aarch64-windows/regsvr32.exe', b'api-ms-madeira-unknown.dll'), 'missing')
    rejected('AMD64-only image in EC farm',
             lambda s,w,a,z: edit(s/'arm64ec-windows/regsvr32.exe', 0x98+112+10*8, 0), 'hybrid load configuration')
    rejected('wrong hybrid metadata version',
             lambda s,w,a,z: edit(s/'arm64ec-windows/regsvr32.exe', 0xd00, 9), 'invalid hybrid code map')
    rejected('hybrid code map is AMD64 only',
             lambda s,w,a,z: edit(s/'arm64ec-windows/regsvr32.exe', 0xd40, 0x1000), 'AMD64-only')
    rejected('hybrid native code points into data',
             lambda s,w,a,z: edit(s/'arm64ec-windows/regsvr32.exe', 0xd40, 0x3001), 'hybrid native range')
    rejected('hybrid dependency is plain AMD64',
             lambda s,w,a,z: edit(s/'arm64ec-windows/ole32.dll', 0x98+112+10*8, 0), 'hybrid load configuration')
    rejected('stale staged byte digest',
             lambda s,w,a,z: edit(s/'aarch64-windows/regsvr32.exe', 0x410, 0x12345678), 'stale system program build manifest')
    rejected('stale lookup marker',
             lambda s,w,a,z: (s/'i386-windows/kernelbase.dll').write_bytes(
                 fixture('i386-windows').replace(CHECKER.MARKER, b'x'*len(CHECKER.MARKER))),
             'failed-image attribution')
    rejected('stale app utility',
             lambda s,w,a,z: edit(a/'aarch64-windows/regsvr32.exe', 0x410, 0x12345678), 'stale app')
    rejected('missing app manifest',
             lambda s,w,a,z: (a/CHECKER.MANIFEST).unlink())
    rejected('stale IPA utility',
             lambda s,w,a,z: stale_ipa(s,z), 'stale IPA')
    rejected('missing IPA utility',
             lambda s,w,a,z: missing_ipa(s,z))
    rejected('changed stock program source',
             lambda s,w,a,z: (w/'programs/regsvr32/regsvr32.c').write_text('changed fixture source'),
             'source provenance changed')
    rejected('changed stock build recipe',
             lambda s,w,a,z: (w/'programs/rundll32/Makefile.in').write_text('changed fixture recipe'),
             'source provenance changed')
    rejected('changed completion manifest',
             lambda s,w,a,z: (s/CHECKER.MANIFEST).write_text('{}'), 'stale system program build manifest')
    rejected('symlinked system utility',
             lambda s,w,a,z: symlink_file(s/'aarch64-windows/regsvr32.exe'), 'symlinked')
    rejected('symlinked source',
             lambda s,w,a,z: symlink_file(w/'programs/regsvr32/regsvr32.c'), 'symlinked')
    rejected('symlinked manifest',
             lambda s,w,a,z: symlink_file(s/CHECKER.MANIFEST), 'symlinked')
    rejected('duplicate manifest key',
             lambda s,w,a,z: duplicate_manifest(s/CHECKER.MANIFEST), 'duplicate system program manifest key')
    rejected('duplicate IPA utility',
             lambda s,w,a,z: duplicate_ipa(s,z), 'duplicate IPA system program')
    print('PASS actual system-program checker: absent native utilities rejected; all six A64/EC/I386 PE/import/hybrid/source/app/IPA fixtures accepted; wrong/missing/stale architectures, metadata, RX entries, imports and copies rejected')
    print('Owned PE byte fixtures verify packaging contracts only; no executable, official DirectX or iOS success is claimed')


def rename_import(path, previous, replacement):
    data = bytearray(path.read_bytes())
    at = data.index(previous+b'\0')
    assert len(replacement)<48
    data[at:at+len(replacement)+1] = replacement+b'\0'
    path.write_bytes(data)


def symlink_file(path):
    target=path.with_name(path.name+'.owned-target');target.write_bytes(path.read_bytes());path.unlink();path.symlink_to(target)


def duplicate_manifest(path):
    text=path.read_text();assert text.lstrip().startswith('{')
    path.write_text('{"recipe":1,'+text.lstrip()[1:])


def duplicate_ipa(stage,ipa):
    relative='aarch64-windows/regsvr32.exe'
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',UserWarning)
        with zipfile.ZipFile(ipa,'a') as archive:archive.writestr('Payload/Madeira.app/'+relative,(stage/relative).read_bytes())


def additional_import(path, name):
    data = bytearray(path.read_bytes())
    assert len(name)<48
    dirs = 0x98 + (96 if struct.unpack_from('<H', data, 0x98)[0] == 0x10b else 112)
    struct.pack_into('<II', data, dirs+8, 0x2000, 100)
    struct.pack_into('<IIIII', data, 0x600+3*20, 0x2360, 0, 0, 0x2190, 0x2460)
    data[0x790:0x790+len(name)+1] = name+b'\0'
    path.write_bytes(data)


def stale_ipa(stage, ipa):
    with zipfile.ZipFile(ipa, 'w') as archive:
        for path in sorted(stage.rglob('*')):
            if path.is_file():
                data = path.read_bytes()
                if path.relative_to(stage).as_posix() == 'aarch64-windows/regsvr32.exe':
                    data = bytearray(data)
                    data[0x410] ^= 1
                archive.writestr('Payload/Madeira.app/'+path.relative_to(stage).as_posix(), data)


def missing_ipa(stage, ipa):
    with zipfile.ZipFile(ipa, 'w') as archive:
        for path in sorted(stage.rglob('*')):
            if path.is_file() and path.relative_to(stage).as_posix() != 'i386-windows/rundll32.exe':
                archive.write(path, 'Payload/Madeira.app/'+path.relative_to(stage).as_posix())


if __name__ == '__main__':
    main()
