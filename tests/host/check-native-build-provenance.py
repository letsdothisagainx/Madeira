#!/usr/bin/env python3
"""Compile real diagnostic accessors and test package/source/UUID validation."""
import importlib.util
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_provenance', ROOT / 'tools/build/native-provenance.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
virtual = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
allocator = (ROOT / 'app/Madeira/JITAllocator.c').read_text()
bridge = (ROOT / 'app/Madeira/WineProcessBridge.m').read_text()


def function(source, name):
    found = re.search(r'(?:__attribute__\(\(visibility\("default"\)\)\)\s*)?(?:const char \*|uint64_t\s+)' +
                      re.escape(name) + r'\(void\)\s*\{[^}]*\}', source)
    assert found, name
    return found[0]


def refuses(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError('invalid native/package provenance accepted')


def uuid_reader():
    start = bridge.index('static int madeira_read_image_uuid(')
    opening = bridge.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (bridge[end] == '{') - (bridge[end] == '}')
        end += 1
    return bridge[start:end]


with tempfile.TemporaryDirectory(prefix='madeira-native-provenance-') as temporary:
    temp = Path(temporary)
    old_revision, package_revision = 'a' * 40, 'b' * 40
    for component, name, revision in [('virtual', 'virtual.h', old_revision),
                                     ('jitallocator', 'jit.h', package_revision)]:
        tool.write_header(ROOT, component, temp / name, revision)
    expected = tool.expectations(ROOT, package_revision)
    source = r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "virtual.h"
#include "jit.h"
#include "native_build_provenance.h"
/* Run the actual runtime Mach-O decoder with a controlled dladdr image. */
#define MH_MAGIC_64 0xfeedfacf
#define LC_UUID 0x1b
struct mach_header_64 {uint32_t magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved;};
struct load_command {uint32_t cmd,cmdsize;};
struct uuid_command {uint32_t cmd,cmdsize;uint8_t uuid[16];};
typedef struct {const void *dli_fbase;} Dl_info;
static const void *mock_image;
static int dladdr(const void *address,Dl_info *info) {(void)address;info->dli_fbase=mock_image;return mock_image!=NULL;}
'''
    source += function(virtual, 'ios_virtual_build_provenance') + '\n'
    source += function(allocator, 'jit_allocator_build_provenance') + '\n'
    source += function(allocator, 'jit_cs2_code_tail_limit_mb') + '\n'
    source += function(allocator, 'jit_cs2_image_arena_mb') + '\n'
    source += uuid_reader() + '\n'
    source += r'''
int main(void) {
    struct {struct mach_header_64 header;struct uuid_command commands[2];} mapped={0};
    mapped.header.magic=MH_MAGIC_64;mapped.header.ncmds=1;mapped.header.sizeofcmds=24;
    mapped.commands[0].cmd=LC_UUID;mapped.commands[0].cmdsize=24;
    for(unsigned i=0;i<16;++i)mapped.commands[0].uuid[i]=(uint8_t)i;
    mock_image=&mapped;char actual_uuid[33];
    setenv("MADEIRA_APP_IMAGE_UUID","spoofed-environment-uuid",1);
    assert(madeira_read_image_uuid(actual_uuid) && !strcmp(actual_uuid,"000102030405060708090a0b0c0d0e0f"));
    mapped.commands[0].cmdsize=0;assert(!madeira_read_image_uuid(actual_uuid));
    mapped.commands[0].cmdsize=25;assert(!madeira_read_image_uuid(actual_uuid));
    mapped.commands[0].cmdsize=24;mapped.header.sizeofcmds=23;assert(!madeira_read_image_uuid(actual_uuid));
    mapped.header.sizeofcmds=48;mapped.header.ncmds=2;mapped.commands[1]=mapped.commands[0];
    assert(!madeira_read_image_uuid(actual_uuid));
    mapped.header.magic=0;assert(!madeira_read_image_uuid(actual_uuid));
    mock_image=NULL;assert(!madeira_read_image_uuid(actual_uuid));
    struct madeira_build_component component;
    assert(madeira_build_component_read(ios_virtual_build_provenance(),"MadeiraNativeVirtual:v1:",&component));
    assert(!strcmp(component.source,MADEIRA_NATIVE_VIRTUAL_SOURCE_SHA256));
    assert(!strcmp(component.revision,MADEIRA_NATIVE_BUILD_REVISION));
    assert(!madeira_build_component_read(NULL,"MadeiraNativeVirtual:v1:",&component));
    assert(!madeira_build_component_read("MadeiraNativeVirtual:v1:unknown:unknown","MadeiraNativeVirtual:v1:",&component));
    assert(!madeira_build_component_read(jit_allocator_build_provenance(),"MadeiraNativeVirtual:v1:",&component));
    char changed[256];snprintf(changed,sizeof(changed),"%sX",ios_virtual_build_provenance());
    assert(!madeira_build_component_read(changed,"MadeiraNativeVirtual:v1:",&component));
    snprintf(changed,sizeof(changed),"%s",ios_virtual_build_provenance());changed[24]='G';
    assert(!madeira_build_component_read(changed,"MadeiraNativeVirtual:v1:",&component));
    uint64_t number=7;errno=EAGAIN;
    assert(madeira_build_env_number(NULL,&number)==0 && number==7);
    assert(madeira_build_env_number("512",&number)==1 && number==512 && errno==EAGAIN);
    assert(madeira_build_env_number("0x200",&number)==1 && number==512 && errno==EAGAIN);
    const char *invalid[]={"","-1","+1"," 512","512 tail","private-token","999999999999999999999999999999999"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
        number=7;assert(madeira_build_env_number(invalid[i],&number)==-1 && number==7 && errno==EAGAIN);
    }
    puts(ios_virtual_build_provenance());puts(jit_allocator_build_provenance());
    printf("%llu\n",(unsigned long long)jit_cs2_code_tail_limit_mb());
    printf("%llu\n",(unsigned long long)jit_cs2_image_arena_mb());
}
'''
    (temp / 'fixture.c').write_text(source)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                    '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-I' + str(ROOT / 'build'), '-I' + str(temp), str(temp / 'fixture.c'),
                    '-o', str(temp / 'fixture')], check=True)
    records = subprocess.check_output([str(temp / 'fixture')], text=True).splitlines()
    assert int(records[2]) == expected['expectedJITCodeTailLimitMB']
    assert int(records[3]) == expected['expectedJITImageArenaMB']
    assert int(records[2]) == 384 and int(records[3]) == 768
    identity = uuid.UUID('12345678-1234-5678-90ab-123456789abc')
    image = (struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 1, 24, 0, 0) +
             struct.pack('<II', 0x1b, 24) + identity.bytes +
             records[0].encode() + b'\0' + records[1].encode() + b'\0')
    manifest = tool.verified_manifest(ROOT, package_revision, image)
    # A correct cached component's original build commit remains visible and
    # is allowed to differ from the package commit when its actual source fits.
    assert manifest['virtualBuildRevision'] == old_revision
    assert manifest['packageSourceRevision'] == package_revision
    assert manifest['nativeImageUUID'] == str(identity).upper()
    app = temp / 'Madeira.app'; app.mkdir()
    info = dict(CFBundleIdentifier='org.test.Madeira', MadeiraBuild='v0.1.3 source=' + package_revision)
    (app / 'Info.plist').write_bytes(plistlib.dumps(info))
    (app / 'Madeira.debug.dylib').write_bytes(image)
    command = ['python3', str(ROOT / 'tools/build/native-provenance.py'), 'stamp', '--root', str(ROOT),
               '--revision', package_revision, '--app', str(app)]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    stamped = (app / 'Info.plist').read_bytes()
    assert tool.check(ROOT, package_revision, stamped, image) == manifest
    ipa = temp / 'Madeira.ipa'
    with zipfile.ZipFile(ipa, 'w') as archive:
        archive.writestr('Payload/Madeira.app/Info.plist', stamped)
        archive.writestr('Payload/Madeira.app/Madeira.debug.dylib', image)
    subprocess.run(command[:2] + ['check'] + command[3:] + ['--ipa', str(ipa)], check=True, stdout=subprocess.DEVNULL)
    altered = image.replace(records[0].encode(), records[0].replace(expected['expectedVirtualSourceSHA256'], '0' * 64).encode())
    refuses(lambda: tool.verified_manifest(ROOT, package_revision, altered))
    refuses(lambda: tool.verified_manifest(ROOT, package_revision, image.replace(records[1].encode(), b'unknown')))
    refuses(lambda: tool.verified_manifest(ROOT, package_revision, image + altered[56:] ))
    refuses(lambda: tool.image_uuid(image[:40]))
    edited_info = plistlib.loads(stamped)
    edited_info[tool.KEY]['nativeImageUUID'] = str(uuid.uuid4()).upper()
    refuses(lambda: tool.check(ROOT, package_revision, plistlib.dumps(edited_info), image))
    edited_info = plistlib.loads(stamped); edited_info['MadeiraBuild'] = 'source=' + old_revision
    refuses(lambda: tool.check(ROOT, package_revision, plistlib.dumps(edited_info), image))
    copy = temp / 'changed-root'
    for relative, *_ in tool.COMPONENTS.values():
        target = copy / relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for relatives in tool.EXTRA_SOURCES.values():
        for relative in relatives:
            target = copy / relative; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
    header = copy / tool.EXTRA_SOURCES['virtual'][0]
    original_header = header.read_bytes()
    header.write_bytes(original_header + b'\n/* changed header after compile */\n')
    refuses(lambda: tool.verified_manifest(copy, package_revision, image))
    header.write_bytes(original_header)
    with (copy / tool.COMPONENTS['virtual'][0]).open('a') as file:
        file.write('\n/* changed after compile */\n')
    refuses(lambda: tool.verified_manifest(copy, package_revision, image))

build = (ROOT / 'build/ntdll-unix/build.sh').read_text()
packaging = (ROOT / 'tools/build/package-ipa.sh').read_text()
assert '--component virtual --output "$OBJ_DIR/native-provenance.generated.h"' in build
assert '"virtual" -include "$OBJ_DIR/native-provenance.generated.h"' in build
assert packaging.index('--component jitallocator') < packaging.index('\nxcodebuild ')
assert packaging.index('native-provenance.py" stamp') < packaging.index('\ncodesign ')
assert 'native-provenance.py" check' in packaging and '--ipa "$DIST/Madeira.ipa"' in packaging
assert bridge.index('madeira_log_native_build_provenance();') < bridge.index('__wine_main(argc, argv)')
assert 'meaning=input-not-native-effective-policy' in bridge
assert 'const char *image_uuid = madeira_read_image_uuid(actual_uuid)' in bridge
assert '[pool-policy-runtime-v1]' in virtual
print('PASS actual compiled native/JIT accessors and policy, bounded runtime parsing, legitimate older component revisions, source/UUID/package mismatch refusal, app/IPA staging, post-compile changed source refusal')
