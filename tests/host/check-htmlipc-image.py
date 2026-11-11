#!/usr/bin/env python3
"""Self-contained PE/package failures plus an optional actual source-built DLL.

Synthetic fixtures test the parser's contracts; they do not stand in for a real
source build or Steam runtime. If work/runtime-production's native build exists,
its actual AMD64 bytes are also validated and read with the exact bounded C
DATA reader. This test never loads or executes the guest DLL.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VALIDATOR = HERE / 'check_htmlipc_image.py'
if not VALIDATOR.exists():
    VALIDATOR = ROOT / 'tools/check-htmlipc-image.py'
spec = importlib.util.spec_from_file_location('htmlipc_image', VALIDATOR)
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)
ABI = HERE / 'htmlipc_ready_abi.h'
if not ABI.exists():
    ABI = ROOT / 'build/scm-rpc/htmlipc_ready_abi.h'
READER = ABI.with_name('htmlipc_ready_reader.h')

def put(data, at, fmt, *values):
    struct.pack_into(fmt, data, at, *values)

def fixture():
    data = bytearray(0x1400)
    data[:2] = b'MZ'; put(data, 60, '<I', 0x80)
    data[0x80:0x84] = b'PE\0\0'
    put(data, 0x84, '<HH', 0x8664, 3)
    put(data, 0x94, '<HH', 240, 0x2022)
    opt = 0x98
    put(data, opt, '<H', 0x20b)
    put(data, opt + 16, '<I', 0x1000)
    put(data, opt + 24, '<Q', 0x180000000)
    put(data, opt + 56, '<II', 0x5000, 0x400)
    put(data, opt + 108, '<I', 16)
    put(data, opt + 112, '<II', 0x2000, 0x200)
    put(data, opt + 120, '<II', 0x2400, 60)
    for index, (name, rva, raw, size, flags) in enumerate([
            (b'.text', 0x1000, 0x400, 0x400, 0x60000020),
            (b'.rdata', 0x2000, 0x800, 0x800, 0x40000040),
            (b'.data', 0x3000, 0x1000, 0x400, 0xc0000040)]):
        at = 0x188 + index * 40
        data[at:at + len(name)] = name
        put(data, at + 8, '<IIII', 0x1000, rva, size, raw)
        put(data, at + 36, '<I', flags)
    data[0x400:0x450] = b'\xc3' * 0x50
    # Synthetic export table with exactly the five source bridge exports.
    put(data, 0x800, '<IIHHIIIIIII', 0, 0, 0, 0, 0x22e0, 1, 5, 5, 0x2100, 0x2120, 0x2140)
    names = sorted(image.EXPORTS)
    text = 0x2160
    for index, name in enumerate(names):
        encoded = name.encode() + b'\0'
        target = 0x3000 if name == 'MadeiraRuntimeReady' else 0x1000 + index * 16
        put(data, 0x900 + index * 4, '<I', target)
        put(data, 0x920 + index * 4, '<I', text)
        put(data, 0x940 + index * 2, '<H', index)
        data[0x800 + text - 0x2000:0x800 + text - 0x2000 + len(encoded)] = encoded
        text += len(encoded)
    dll_name = b'madeira-htmlipc-bridge.dll\0'
    data[0xae0:0xae0 + len(dll_name)] = dll_name
    # Two real-shape imports; query is ordinary NT dispatch, never a callback.
    put(data, 0xc00, '<5I', 0x2500, 0, 0, 0x2480, 0x2500)
    put(data, 0xc14, '<5I', 0x2520, 0, 0, 0x2490, 0x2520)
    data[0xc80:0xc80 + 13] = b'KERNEL32.dll\0'
    data[0xc90:0xc90 + 10] = b'NTDLL.dll\0'
    put(data, 0xd00, '<QQ', 0x2580, 0)
    put(data, 0xd20, '<QQ', 0x25b0, 0)
    symbol = b'GetCurrentProcessId\0'; data[0xd82:0xd82 + len(symbol)] = symbol
    symbol = b'NtQueryInformationProcess\0'; data[0xdb2:0xdb2 + len(symbol)] = symbol
    put(data, 0x1000, '<Q8I5Q', image.READY_MAGIC, 80, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return bytes(data)

def manifest(data):
    return dict(format=1, mode='native-owner', filename=image.FILENAME, bytes=len(data), sha256=image.sha256(data),
                coreSHA256=image.CORE_SHA256, compatibleCoreSHA256=list(image.COMPATIBLE_CORE_SHA256),
                readinessABI=dict(version=1, size=80, sha256=image.sha256(ABI.read_bytes())))

def report(data, source_hashes):
    return dict(native_owner=True, stock_wine_test=False, experimental_auto_arm=True,
                compiler_target='x86_64-windows-msvc', sha256=image.sha256(data), size=len(data),
                compatible_core_sha256=list(image.COMPATIBLE_CORE_SHA256),
                owner_query_class='0x4d480001', cache_environment='MADEIRA_HTMLIPC_CACHE_DIR',
                writable_executable_sections=False, static_constructor_sections=False,
                ready_data=dict(name='MadeiraRuntimeReady', size=80, version=1,
                                abi_sha256=image.sha256(ABI.read_bytes()), forwarder=False,
                                executable=False, shared_section=False), sources=source_hashes)

def rejects(function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except (image.InvalidImage, ValueError, KeyError, struct.error):
        return
    raise AssertionError('invalid image/package accepted')

PROBE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htmlipc_ready_reader.h"
struct mapped { unsigned char *bytes; size_t size; };
static int read_bytes(void *context,uint64_t at,void *out,size_t size){
 struct mapped *m=context;uint64_t base=UINT64_C(0x7100000000);
 if(at<base||at-base>m->size||size>m->size-(size_t)(at-base))return 0;
 memcpy(out,m->bytes+(size_t)(at-base),size);return 1;
}
int main(int argc,char **argv){
 struct mapped m={0};uint64_t address=0;FILE *file;long length;
 if(argc!=3||(file=fopen(argv[1],"rb"))==NULL)return 2;
 if(fseek(file,0,SEEK_END)||(length=ftell(file))<=0||length>32*1024*1024)return 3;
 rewind(file);m.size=(size_t)length;m.bytes=malloc(m.size);if(!m.bytes)return 4;
 if(fread(m.bytes,1,m.size,file)!=m.size)return 5;
 fclose(file);
 if(!madeira_htmlipc_find_ready_export(read_bytes,&m,UINT64_C(0x7100000000),(uint32_t)m.size,&address))return 6;
 if(address!=UINT64_C(0x7100000000)+strtoull(argv[2],NULL,0))return 7;
 free(m.bytes);return 0;
}
'''

def main():
    data = fixture()
    result = image.inspect_image(data)
    assert result['ready_rva'] == 0x3000
    # Linked-profile publication is a production build gate, separate from
    # the generic PE parser used by these deliberately minimal fixtures.
    rejects(image.validate_compiled_profiles, data)
    for omitted in image.COMPATIBLE_CORE_SHA256:
        partial=data+b''.join(bytes.fromhex(value) for value in image.COMPATIBLE_CORE_SHA256 if value!=omitted)
        rejects(image.validate_compiled_profiles, partial)
    image.validate_compiled_profiles(data+b''.join(bytes.fromhex(value) for value in image.COMPATIBLE_CORE_SHA256))
    generated=image.make_manifest(data, ABI)
    assert generated['compatibleCoreSHA256']==list(image.COMPATIBLE_CORE_SHA256)
    with tempfile.TemporaryDirectory(prefix='madeira-htmlipc-image-') as directory:
        temporary = Path(directory)
        staged, selected = temporary / image.FILENAME, temporary / 'bridge.manifest.json'
        build_report = temporary / 'bridge.build.json'
        staged.write_bytes(data)
        sources = {}
        for i in range(7):
            name = 'source/' + str(i) + '.cpp'
            path = temporary / name; path.parent.mkdir(exist_ok=True); path.write_text('source fixture ' + str(i))
            sources[name] = image.sha256(path.read_bytes())
        metadata = manifest(data)
        metadata['sourceSHA256'] = image.sha256(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())
        selected.write_text(json.dumps(metadata))
        native_report = report(data, sources); build_report.write_text(json.dumps(native_report))
        legacy_manifest=copy.deepcopy(metadata);legacy_manifest.pop('compatibleCoreSHA256')
        legacy_report=copy.deepcopy(native_report);legacy_report.pop('compatible_core_sha256')
        image.validate_manifest(data,legacy_manifest,image.sha256(ABI.read_bytes()))
        image.validate_build_report(data,legacy_manifest,legacy_report,temporary)
        rejects(image.validate_build_report,data,metadata,legacy_report,temporary)
        rejects(image.validate_build_report,data,legacy_manifest,native_report,temporary)
        for bad in ([],[image.CORE_SHA256],[image.NEW_CORE_SHA256],
                    [image.CORE_SHA256,'0'*64],list(reversed(image.COMPATIBLE_CORE_SHA256)),
                    list(image.COMPATIBLE_CORE_SHA256)+[image.NEW_CORE_SHA256],None):
            altered_manifest=copy.deepcopy(metadata);altered_manifest['compatibleCoreSHA256']=bad
            rejects(image.validate_manifest,data,altered_manifest,image.sha256(ABI.read_bytes()))
            altered_report=copy.deepcopy(native_report);altered_report['compatible_core_sha256']=bad
            rejects(image.validate_build_report,data,metadata,altered_report,temporary)

        image.check(staged, selected, ABI, build_report, temporary)
        # Same exact copied resources must occur in both .app and IPA.
        app = temporary / 'Madeira.app'
        for name, raw in ((image.RESOURCE, data), (image.MANIFEST_RESOURCE, selected.read_bytes())):
            path = app / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        ipa = temporary / 'Madeira.ipa'
        def archive(override=None, duplicate=False):
            with zipfile.ZipFile(ipa, 'w') as zip_file:
                for name, raw in ((image.RESOURCE, data), (image.MANIFEST_RESOURCE, selected.read_bytes())):
                    zip_file.writestr('Payload/Madeira.app/' + name, override if override is not None and name == image.RESOURCE else raw)
                if duplicate:
                    # Deliberately duplicate an entry to prove package ambiguity closes.
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', UserWarning)
                        zip_file.writestr('Payload/Madeira.app/' + image.RESOURCE, data)
        archive(); image.check(staged, selected, ABI, build_report, temporary, app, ipa)
        archive(b'changed'); rejects(image.check, staged, selected, ABI, build_report, temporary, app, ipa)
        archive(duplicate=True); rejects(image.check, staged, selected, ABI, build_report, temporary, app, ipa)
        archive()
        (app / image.RESOURCE).write_bytes(b'changed')
        rejects(image.check, staged, selected, ABI, build_report, temporary, app, ipa)
        (app / image.RESOURCE).write_bytes(data)
        (app / image.MANIFEST_RESOURCE).unlink(); (app / image.MANIFEST_RESOURCE).symlink_to(selected)
        rejects(image.check, staged, selected, ABI, build_report, temporary, app)
        # Compile the actual bounded Native DATA reader and feed it mapped PE
        # bytes. No PE import is resolved, no AMD64 address is ever called.
        probe = temporary / 'reader.c'; probe.write_text(PROBE)
        executable = temporary / 'reader'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I' + str(READER.parent),
                        str(probe), '-o', str(executable)], check=True)
        def probe_image(raw):
            pe = image.PE(raw); mapped = temporary / 'mapped.pe'; mapped.write_bytes(pe.mapped_image())
            expected = pe.exports()['MadeiraRuntimeReady']
            subprocess.run([str(executable), str(mapped), hex(expected)], check=True)
        probe_image(data)
        # Real prototype native DLL is an additional local positive when present.
        actual = ROOT / 'work/runtime-production/MadeiraHtmlIPCBridge-native.dll'
        if actual.exists():
            actual_bytes = actual.read_bytes(); image.inspect_image(actual_bytes); probe_image(actual_bytes)
            actual_report = json.loads(actual.with_suffix('.build.json').read_bytes())
            actual_manifest=manifest(actual_bytes)
            if 'compatible_core_sha256' not in actual_report:
                actual_manifest.pop('compatibleCoreSHA256')
            image.validate_build_report(actual_bytes, actual_manifest, actual_report)
            print('PASS optional actual source-built AMD64 DLL: bounded C DATA reader and hash-bound native build report')
        for name in ('MadeiraHtmlIPCBridge-disarmed.dll', 'version-stock.dll'):
            other = actual.with_name(name)
            if other.exists():
                raw = other.read_bytes()
                other_report = json.loads(other.with_suffix('.build.json').read_bytes())
                rejects(image.validate_build_report, raw, manifest(raw), other_report)
        for key, value in [('mode', 'stock-wine-test'), ('mode', 'disarmed'), ('filename', 'version.dll'),
                           ('format', 2), ('bytes', len(data) + 1), ('sha256', '0' * 64), ('coreSHA256', '0' * 64)]:
            changed = copy.deepcopy(metadata); changed[key] = value
            rejects(image.validate_manifest, data, changed, image.sha256(ABI.read_bytes()))
        for key, value in [('native_owner', False), ('stock_wine_test', True), ('experimental_auto_arm', False),
                           ('compiler_target', 'arm64ec-windows-msvc'), ('sha256', '0' * 64),
                           ('owner_query_class', '0'), ('cache_environment', 'OTHER')]:
            changed = copy.deepcopy(native_report); changed[key] = value
            rejects(image.validate_build_report, data, metadata, changed, temporary)
        (temporary / 'source/0.cpp').write_text('changed')
        rejects(image.validate_build_report, data, metadata, native_report, temporary)
        # Mutations isolate PE structure/data checks from provenance hash checks.
        for at, fmt, values in [(0x84, '<H', (0x14c,)), (0x98, '<H', (0x10b,)),
                                (0x96, '<H', (0x22,)), (0xa8, '<I', (0,)),
                                (0x188 + 36, '<I', (0xe0000020,)),
                                (0x1d8 + 36, '<I', (0xe0000040,)),
                                (0x1d8 + 36, '<I', (0xd0000040,)),
                                (0x1000, '<Q', (0,)), (0x1008, '<I', (72,)),
                                (0x100c, '<I', (2,)), (0x1010, '<I', (3,)),
                                (0x1014, '<I', (7,)), (0x1028, '<Q', (17,)),
                                (60, '<I', (0xffffffff,)), (0x98 + 108, '<I', (0xffffffff,))]:
            changed = bytearray(data); put(changed, at, fmt, *values); rejects(image.inspect_image, bytes(changed))
        changed = bytearray(data); changed[0x188:0x190] = b'.CRT\0\0\0\0'; rejects(image.inspect_image, bytes(changed))
        changed = bytearray(data)
        put(changed, 0x98 + 112 + 10 * 8, '<II', 0x2600, 0xd0)
        put(changed, 0xe00, '<I', 0xd0); put(changed, 0xec8, '<Q', 0x180002780)
        rejects(image.inspect_image, bytes(changed))
        changed = bytearray(data); changed[0xdb2:0xdb2 + 25] = b'OtherQueryInformationProc\0'; rejects(image.inspect_image, bytes(changed))
        ready_index = sorted(image.EXPORTS).index('MadeiraRuntimeReady')
        changed = bytearray(data); put(changed, 0x900 + ready_index * 4, '<I', 0x2100); rejects(image.inspect_image, bytes(changed))
        for length in (0, 63, 0x94, 0x190, 0x1001):
            rejects(image.inspect_image, data[:length])
    print('PASS self-contained AMD64 PE/package gate: malformed headers/sections/exports/imports/DATA, native provenance, exact app/IPA bytes and zero guest execution')

if __name__ == '__main__':
    main()
