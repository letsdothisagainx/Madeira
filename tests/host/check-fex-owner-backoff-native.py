#!/usr/bin/env python3
"""Cross-compile the complete production rpmalloc copy and prove alias plans.

Requires LLVM_MINGW (its root or bin directory). No FEX vendor input is edited.
The real native planners inspect linked ARM64EC and AArch64 PE instructions.
"""
from pathlib import Path
import ctypes
import argparse
import os
import runpy
import shlex
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
args = argparse.ArgumentParser()
args.add_argument('--wow64', type=Path)
args.add_argument('--arm64ec', type=Path)
args = args.parse_args()
assert bool(args.wow64) == bool(args.arm64ec), 'Supply both final PE images'
tool = Path(os.environ.get('LLVM_MINGW', ''))
if (tool / 'bin').is_dir(): tool /= 'bin'
if not args.wow64:
    assert (tool / 'arm64ec-w64-mingw32-clang').is_file(), 'Set LLVM_MINGW to the LLVM MinGW toolchain'
ns = None if args.wow64 else runpy.run_path(str(ROOT / 'tests/host/check-fex-owner-allocator-config.py'))

WRAPPER = r'''
#include "native_atomic_image.h"
size_t lower(unsigned char* image,size_t size,uintptr_t base) {
 return ios_native_atomic_image_lower(image,size,base,base,0x48000000).planned;
}
struct bounds { uintptr_t lo,hi;intptr_t delta; };
static int allowed(void* context,uintptr_t from,uintptr_t to,size_t width) {
 struct bounds* b=context;return from>=b->lo&&from<b->hi&&width<=b->hi-from&&to==from+b->delta;
}
int plan(const uint32_t* words,size_t count,uintptr_t rx,intptr_t delta,size_t at,
         uintptr_t low,uintptr_t high,uintptr_t* target) {
 struct madeira_native_atomic_alias_plan a;
 struct madeira_native_data_alias_plan d;
 struct bounds b={low,high,delta};
 if(madeira_native_atomic_alias_plan(words,count,rx,delta,at,allowed,&b,&a)){*target=a.target_rx;return 1;}
 if(madeira_native_data_alias_plan(words,count,rx,delta,at,allowed,&b,&d)){*target=d.target_rx;return 1;}
 return 0;
}
/* Independently identify a producer's writes, even if it uses a callee-saved
 * register unsupported by the planner. Read-only references may stay RX: both
 * aliases share storage. A mutable write may never silently lose lowering. */
unsigned writes(const uint32_t* words,size_t count,uintptr_t rx,size_t at,const uintptr_t* fields) {
 uint32_t op=words[at];unsigned base=op&31,mask=0;
 int64_t pages=madeira_na_sext(((op>>29)&3)|(((op>>5)&0x7ffff)<<2),21);
 uintptr_t address=((rx+at*4)&~(uintptr_t)4095)+(intptr_t)(pages*4096);
 for(size_t i=at+1;i<count&&i<at+128;i++) {
  op=words[i];struct madeira_nd_memory m;
  if((op&0xfffffc1f)==0xd65f0000)continue; /* another forward branch may pass this return */
  if((op&0xff800000)==0x91000000|| (op&0xff800000)==0xd1000000) {
   if(((op>>5)&31)==base) {
    if((op&31)!=base)break;
    intptr_t n=(intptr_t)((op>>10)&4095)<<((op>>22)&1?12:0);
    address+=(op&0x40000000)?-n:n;continue;
   }
  }
  if(madeira_nd_memory(op,&m)) {
   if(m.base==base) {
    uintptr_t target=address+m.offset;
    if(m.store)for(unsigned f=0;f<4;f++)if(target==fields[f])mask|=1u<<f;
    if(m.has_writeback)address+=m.writeback;
   }
   if(m.writes&madeira_na_bit(base))break;
  } else {
   uint32_t read,write;
   if(madeira_na_operands(op,&read,&write)&&(write&madeira_na_bit(base)))break;
   if((op&0xfc000000)==0x94000000||(op&0xfffffc1f)==0xd63f0000)break;
  }
 }
 return mask;
}
'''

def pe(path):
    data = path.read_bytes()
    pe_at, = struct.unpack_from('<I', data, 0x3c)
    _, count, _, sym, n, opt_size, _ = struct.unpack_from('<HHIIIHH', data, pe_at + 4)
    opt = pe_at + 24
    base, = struct.unpack_from('<Q', data, opt + 24)
    sections = []
    for i in range(count):
        at = opt + opt_size + i * 40
        size, rva, raw_size, raw = struct.unpack_from('<IIII', data, at + 8)
        sections.append((rva, size, data[raw:raw + raw_size]))
    strings = sym + n * 18
    symbols = {}
    i = 0
    while i < n:
        at = sym + i * 18
        name = data[at:at + 8]
        if name[:4] == bytes(4):
            offset, = struct.unpack_from('<I', name, 4)
            name = data[strings + offset:data.index(b'\0', strings + offset)]
        else: name = name.rstrip(b'\0')
        value, section, _, _, aux = struct.unpack_from('<IhHBB', data, at + 8)
        if 0 < section <= len(sections): symbols[name.decode()] = base + sections[section - 1][0] + value
        i += aux + 1
    return base, sections, symbols

with tempfile.TemporaryDirectory(prefix='madeira-owner-native-') as tmp:
    d = Path(tmp)
    if not args.wow64:
        src = ns['fixture'](d / 'production')
        build = d / 'production/build'
        ns['configure'](src, build)
        staged = build / 'madeira-fex-compat/rpmalloc-checked.c'
    (d / 'stub.c').write_text('volatile int FEX_AllocWatch_Armed;\nvoid FEX_AllocWatch_Event(const void* p,unsigned n) {}\n')
    (d / 'planner.c').write_text(WRAPPER)
    library = d / ('planner.dylib' if os.uname().sysname == 'Darwin' else 'planner.so')
    cc = shlex.split(os.environ.get('CC', 'cc'))
    subprocess.run(cc + ['-std=c11', '-O2', '-shared', '-fPIC', '-I' + str(ROOT / 'build/ntdll-unix'),
                        str(d / 'planner.c'), '-o', str(library)], check=True)
    planner = ctypes.CDLL(str(library)).plan
    planner.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_size_t, ctypes.c_size_t,
                        ctypes.c_ssize_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_size_t)]
    writer = ctypes.CDLL(str(library)).writes
    writer.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_size_t, ctypes.c_size_t,
                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    lower = ctypes.CDLL(str(library)).lower
    lower.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.c_size_t]
    lower.restype = ctypes.c_size_t
    for abi in ('arm64ec', 'aarch64'):
        image = (args.arm64ec if abi == 'arm64ec' else args.wow64) if args.wow64 else d / (abi + '.dll')
        if not args.wow64: subprocess.run([str(tool / (abi + '-w64-mingw32-clang')), '-O3', '-shared',
                        '-DFEX_IOS_HOST', '-DRPMALLOC_FIRST_CLASS_HEAPS=1', '-DDYNAMIC_TLS_NO_FLS=1',
                        '-DENABLE_DECOMMIT=1', '-DENABLE_OVERRIDE=0',
                        '-I' + str(ROOT / 'FEX/External/rpmalloc/rpmalloc'),
                        '-I' + str(ROOT / 'build/fex-compat'), str(staged), str(d / 'stub.c'),
                        '-lntdll', '-o', str(image)], check=True)
        base, sections, symbols = pe(image)
        raw = image.read_bytes()
        pe_at, = struct.unpack_from('<I', raw, 0x3c)
        image_size, header_size = struct.unpack_from('<II', raw, pe_at + 24 + 56)
        mapped = ctypes.create_string_buffer(image_size)
        ctypes.memmove(mapped, raw, header_size)
        for rva, _, content in sections:
            ctypes.memmove(ctypes.addressof(mapped) + rva, content, len(content))
        assert lower(mapped, image_size, base), (abi, 'actual whole-image lowerer did not run')
        owner = symbols['fex_ios_rpm_owner']
        data_section = next(s for s in sections if base + s[0] <= owner < base + s[0] + s[1])
        low, high = base + data_section[0], base + data_section[0] + data_section[1]
        targets = {symbols[x]: x for x in ('fex_ios_rpm_owner', 'fex_ios_rpm_depth',
                                         'fex_ios_rpm_enabled', 'madeira_fex_rpm_backoff_ready')}
        coverage = {name: 0 for name in targets.values()}
        fields = (ctypes.c_size_t * 4)(*targets)
        for name in ('fex_ios_rpm_lock', 'fex_ios_rpm_unlock', 'fex_ios_rpm_enable_backoff',
                     'madeira_fex_rpm_try_owner', 'madeira_fex_rpm_publish_depth', 'madeira_fex_rpm_backoff'):
            address = symbols[name]
            following = min(v for v in symbols.values() if v > address)
            section = next(s for s in sections if base + s[0] <= address < base + s[0] + len(s[2]))
            words = (ctypes.c_uint32 * (len(section[2]) // 4)).from_buffer_copy(section[2][:len(section[2]) // 4 * 4])
            start = (address - base - section[0]) // 4
            stop = min((following - base - section[0]) // 4, len(words))
            for at in range(start, stop):
                if words[at] & 0x9f000000 != 0x90000000: continue
                target = ctypes.c_size_t()
                required = writer(words, stop, base + section[0], at, fields)
                accepted = planner(words, len(words), base + section[0], 0x48000000, at, low, high, ctypes.byref(target))
                if os.environ.get('MADEIRA_BACKOFF_NATIVE_VERBOSE'):
                    print(abi, name, hex(base + section[0] + at * 4), 'writes', required,
                          'planned', accepted, 'first-target', targets.get(target.value, hex(target.value)))
                assert not required or accepted, (abi, name, hex(base + section[0] + at * 4), required)
                if required:
                    lowered = struct.unpack_from('<I', mapped, section[0] + at * 4)[0]
                    assert lowered != words[at], (abi, name, 'production image pass missed write producer')
                for i, label in enumerate(targets.values()):
                    if required & (1 << i): coverage[label] += 1
        assert coverage['fex_ios_rpm_owner'] == 2, (abi, coverage)
        assert coverage['fex_ios_rpm_depth'] == 3, (abi, coverage)
        assert coverage['fex_ios_rpm_enabled'] >= 1, (abi, coverage)
        assert coverage['madeira_fex_rpm_backoff_ready'] == 1, (abi, coverage)
        print('PASS full production ' + abi + ' rpmalloc PE native alias coverage: ' + str(coverage))
