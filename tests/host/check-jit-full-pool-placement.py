#!/usr/bin/env python3
"""Exercise real early-pool placement/ownership code, including the iOS 27 control.

The supplied log contains a hole census, not a full Mach region inventory. Its
integer-MiB lengths replay the old refusal; additional VM layouts are explicitly
controlled kernel fixtures. Darwin additionally runs real Mach reservations and
shared aliases. None of these results asserts a successful StikDebug/iPhone run.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/host/fixtures'
CAPTURE = json.loads((FIXTURES / 'jit-placement-140401.json').read_text())
MB = 1 << 20


def run(command, **kw):
    return subprocess.run(command, check=True, timeout=120, **kw)


def before_control(directory, swiftc):
    """Compile literal 5b code; only its Mach OS boundary is supplied."""
    for name, digest in CAPTURE['baselineFixtureSHA256'].items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == digest, name
    old = (FIXTURES / 'jit-placement-early-5b.c').read_text()
    source = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MB ((uint64_t)1 << 20)
#define CHECK(c) do {if(!(c)){fprintf(stderr,"line%d: %s\n",__LINE__,#c);exit(1);}} while(0)
#define __attribute__(a)
typedef uint64_t vm_address_t,vm_size_t;
typedef unsigned natural_t,mach_msg_type_number_t;
typedef int* vm_region_recurse_info_t;
struct region {uint64_t base,size;unsigned tag,prot,owned;};
static struct region regions[8];static unsigned count;
static unsigned calls;
struct region_info {unsigned user_tag,protection;};
typedef struct region_info vm_region_submap_info_data_64_t;
#define VM_REGION_SUBMAP_INFO_COUNT_64 2
#define KERN_SUCCESS 0
#define VM_FLAGS_FIXED 0
#define VM_PROT_NONE 0
static int mach_task_self(void){return 1;}
static int vm_allocate(int task,vm_address_t* p,vm_size_t n,int flags){
 CHECK(task==1&&flags==VM_FLAGS_FIXED&&n&&!(n&0x3fff));calls++;
 for(unsigned i=0;i<count;i++)if(*p<regions[i].base+regions[i].size&&regions[i].base<*p+n)return 3;
 CHECK(count<8);regions[count++]=(struct region){*p,n,0,3,1};return 0;
}
static int vm_protect(int task,vm_address_t p,vm_size_t n,int maximum,int prot){
 CHECK(task==1&&!maximum&&prot==0);
 for(unsigned i=0;i<count;i++)if(regions[i].base==p&&regions[i].size==n&&regions[i].owned){regions[i].prot=0;return 0;}
 CHECK(0);return 1;
}
static int vm_region_recurse_64(int task,vm_address_t* p,vm_size_t* n,natural_t* depth,
                               vm_region_recurse_info_t info,mach_msg_type_number_t* cnt){
 CHECK(task==1&&!*depth&&*cnt==2);unsigned selected=99;
 for(unsigned i=0;i<count;i++)if(regions[i].base+regions[i].size>*p&&(selected==99||regions[i].base<regions[selected].base))selected=i;
 if(selected==99)return 1;
 *p=regions[selected].base;*n=regions[selected].size;
 *(struct region_info*)info=(struct region_info){regions[selected].tag,regions[selected].prot};return 0;
}
unsigned long madeira_early_window_base,madeira_early_window_size;
unsigned long madeira_early_pool_base,madeira_early_pool_size;
unsigned long madeira_early_intruder_base,madeira_early_intruder_size;
unsigned madeira_early_intruder_tag,madeira_early_intruder_prot;
''' + old + r'''
int main(int argc,char** argv){
 (void)argv;
 /* Only the captured blocker start/tag are exact. One page is a controlled
  * representative size consistent with the log's zero-MiB floor. */
 regions[count++]=(struct region){0x16f248000ULL,0x4000,30,0,0};
 madeira_early_va_claim();
 CHECK(madeira_early_window_base==0x140000000ULL&&madeira_early_window_size==128*MB);
 CHECK(madeira_early_pool_base==0x148000000ULL&&madeira_early_pool_size==624*MB);
 CHECK(madeira_early_intruder_base==0x16f248000ULL&&madeira_early_intruder_tag==30);
 CHECK(count==3&&regions[0].base==0x16f248000ULL&&regions[0].size==0x4000&&!regions[0].owned);
 printf("BEFORE literal5b early placeholder=%luMiB requested=1152MiB; no-overwrite attempts=%u\n",madeira_early_pool_size>>20,calls);
 if(argc>1&&madeira_early_pool_size!=1152*MB)return 23;
 return 0;
}
'''
    cfile = directory / 'before.c'; binary = directory / 'before'
    cfile.write_text(source)
    run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
         '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(cfile), '-o', str(binary)])
    run([str(binary)])
    failed = subprocess.run([str(binary), '--expect-full'], capture_output=True, text=True, timeout=20)
    assert failed.returncode == 23 and 'placeholder=624MiB requested=1152MiB' in failed.stdout, failed
    if not swiftc:
        return
    # The log gives floor MiB lengths. The fourth hole's upper boundary is
    # additionally fixed by the captured next-mapping address.
    holes = [(int(h['base'], 16), h['sizeMiBFloor'] * MB) for h in CAPTURE['census']['holes']]
    holes[3] = (holes[3][0], int(CAPTURE['intruder']['base'], 16) - holes[3][0])
    lo, hi = int(CAPTURE['census']['min'], 16), int(CAPTURE['census']['max'], 16)
    regions, cursor = [], lo
    for base, size in holes:
        if base > cursor: regions.append((cursor, base - cursor))
        cursor = base + size
    regions.append((cursor, hi - cursor))
    records = ','.join(f'({base},{size})' for base,size in regions)
    swift = r'''
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
typealias vm_address_t = UInt
typealias vm_size_t = UInt
typealias mach_msg_type_number_t = UInt32
typealias mach_port_t = UInt32
struct vm_region_basic_info_data_64_t {var x:Int32=0}
let mach_task_self_:UInt32=1
let VM_REGION_BASIC_INFO_64:Int32=9
let KERN_SUCCESS:Int32=0
let records:[(UInt,UInt)] = [@RECORDS@]
func vm_region_64(_ task:UInt32,_ address:inout UInt,_ size:inout UInt,_ flavor:Int32,
                  _ info:UnsafeMutablePointer<Int32>,_ count:inout UInt32,_ object:inout UInt32)->Int32 {
 precondition(task==1&&flavor==9)
 for (start,length) in records where start+length>address {
  address=start;size=length;return 0
 }
 return 1
}
final class LogStore {
 static let shared=LogStore()
 func log(_ text:String){print(text)}
}
''' .replace('@RECORDS@', records) + (FIXTURES / 'jit-placement-census-5b.swift').read_text() + r'''
let result=BeforePlacement.fit(wanted:1152<<20)
precondition(result==624<<20)
print("BEFORE literal5b census selected=624MiB requested=1152MiB; debugger request refused")
if CommandLine.arguments.count>1 {exit(23)}
'''
    file = directory / 'before.swift'; executable = directory / 'before-swift'
    file.write_text(swift)
    run([swiftc, str(file), '-o', str(executable)])
    run([str(executable)])
    failed = subprocess.run([str(executable), '--expect-full'], capture_output=True, text=True, timeout=20)
    assert failed.returncode == 23 and 'selected=624MiB requested=1152MiB' in failed.stdout, failed



def production_control(directory):
    source = (ROOT / 'app/Madeira/JITAllocator.c').read_text()
    start = source.index('/* BEGIN REQUIRED POOL PLACEMENT */')
    end = source.index('/* END REQUIRED POOL PLACEMENT */', start)
    block = source[start:end]
    legacy_start = source.index('/* BEGIN LEGACY POOL OWNERSHIP */')
    legacy_end = source.index('/* END LEGACY POOL OWNERSHIP */', legacy_start)
    support = '\nunsigned long madeira_early_pool_base, madeira_early_pool_size;\n' + source[legacy_start:legacy_end]
    fixture = (ROOT / 'tests/host/jit_full_pool_fixture.c').read_text()
    fixture = fixture.replace('/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */', block + support)
    cfile, binary = directory / 'production.c', directory / 'production'
    cfile.write_text(fixture)
    extra = []
    if platform.system() == 'Darwin':
        shim = directory / 'darwin-reserve.c'
        shim.write_text(r'''#include <stdint.h>
#include <mach/mach.h>
int test_darwin_fixed_reserve(uint64_t base,uint64_t size) {
 vm_address_t address=(vm_address_t)base;
 kern_return_t kr=vm_allocate(mach_task_self(),&address,(vm_size_t)size,VM_FLAGS_FIXED);
 if(kr!=KERN_SUCCESS)return -1;
 if(address!=base){vm_deallocate(mach_task_self(),address,(vm_size_t)size);return -1;}
 return 0;
}
''')
        extra.append(str(shim))
    # A 496 GiB fixture address lies in Linux ASan's reserved shadow gap. Keep
    # UBSan for this literal production transaction; the old control uses both.
    run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
         '-Wno-misleading-indentation','-fsanitize=undefined','-fno-sanitize-recover=all',
         '-pthread',str(cfile),*extra,'-o',str(binary)])
    run([str(binary)])
    # Mutation control for the bad API contract caught during review: allocate
    # accepts VM_MAKE_TAG, whereas user remap rejects alias-mask bits. The same
    # production transaction must fail if those bits are reintroduced.
    forbidden = block.replace('VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,',
        'VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(251u),')
    assert block.count('VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,') == 2
    bad = directory / 'unsupported-remap.c'; bad_binary = directory / 'unsupported-remap'
    bad.write_text((ROOT / 'tests/host/jit_full_pool_fixture.c').read_text().replace(
        '/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */', forbidden + support))
    run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
         '-Wno-misleading-indentation','-fsanitize=undefined','-fno-sanitize-recover=all',
         '-pthread',str(bad),*extra,'-o',str(bad_binary)])
    refusal = subprocess.run([str(bad_binary)], capture_output=True, text=True, timeout=30)
    assert refusal.returncode == 1 and 'KERNEL_CONTROL rejected VM_FLAGS_ALIAS_MASK' in refusal.stdout, refusal
    print('PASS mutation control: reintroducing unsupported tagged-remap flags makes the actual transaction fail honestly')



def source_function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


def native_mach(directory, required):
    if platform.system() != 'Darwin':
        if required: raise RuntimeError('Real Mach execution requires Darwin')
        print('UNMEASURED locally: real Darwin Mach/ARM64 callback-boundary integration; Apple CI requires it')
        return
    if platform.machine() not in ('arm64', 'aarch64'):
        raise RuntimeError('Actual guarded ARM64 execution requires an ARM64 Apple runner')
    source = (ROOT / 'app/Madeira/JITAllocator.c').read_text()
    def block(name):
        start = source.index('/* BEGIN ' + name + ' */')
        return source[start:source.index('/* END ' + name + ' */', start)]
    fixture = (ROOT / 'tests/host/jit_full_pool_mach.c').read_text()
    fixture = fixture.replace('/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */', block('REQUIRED POOL PLACEMENT'))
    fixture = fixture.replace('/* ACTUAL EXECUTION PROBE INSERTED HERE */', block('REQUIRED POOL EXECUTION PROBE'))
    fixture = fixture.replace('/* ACTUAL TASK MAP QUERY INSERTED HERE */', source_function(source, 'bool jit_task_map_range('))
    fixture = fixture.replace('/* ACTUAL POLICY GETTERS INSERTED HERE */', ''.join(
        source_function(source, name) for name in ('uint64_t jit_cs2_image_arena_mb(', 'uint64_t jit_cs2_code_tail_limit_mb(')))
    cfile, binary = directory / 'real-mach.c', directory / 'real-mach'
    cfile.write_text(fixture)
    run([os.environ.get('CC','cc'),'-std=c11','-D_DARWIN_C_SOURCE','-Wall','-Wextra','-Werror',
         '-Wno-misleading-indentation','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread',
         str(cfile),'-o',str(binary)])
    run([str(binary)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-swift', action='store_true')
    parser.add_argument('--before-only', action='store_true')
    parser.add_argument('--require-native-mach', action='store_true')
    args = parser.parse_args()
    swiftc = os.environ.get('SWIFTC') or shutil.which('swiftc')
    if args.require_swift and not swiftc: raise RuntimeError('Swift is required')
    if args.require_native_mach and platform.system() != 'Darwin': raise RuntimeError('Real Mach execution requires Darwin')
    with tempfile.TemporaryDirectory(prefix='madeira-full-jit-placement-') as tmp:
        before_control(Path(tmp), swiftc)
        if args.before_only: return
        if platform.system() == 'Darwin':
            # Captured/synthetic virtual addresses are logical fixture input,
            # not a promise that this Mac has those particular addresses free.
            # On Apple we MUST run the unchanged transaction against its real
            # Mach inventory, not overwrite an unrelated native mapping merely
            # to make a controlled address model pass.
            native_mach(Path(tmp), True)
            print('CONTROLLED GEOMETRY: Linux CI exercises the captured-layout/mock-Mach replay; Darwin uses required real Mach above')
        else:
            production_control(Path(tmp))
            native_mach(Path(tmp), args.require_native_mach)


if __name__ == '__main__': main()
