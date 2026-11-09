#!/usr/bin/env python3
"""Execute the actual staged SRW history producer through owned RX/RW data.

The portable test proves the original producer really faults on RX, while the
new source-bound private writer preserves every index/event without making RX
writable. The companion Darwin benchmark measures real Mach emulation cost.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def captured_producer_proof():
    capture = json.loads((ROOT / 'tests/host/fixtures/native-srw-history-9d44.json').read_text())
    assert capture['pe_sha256'] == '975db861e62e49c254fedf87ba93dd8822f4f3e6d8f61cbec95f95e973062655'
    assert capture['ring_entries'] == 512 and capture['ring_stride'] == 16
    first, second = capture['native_blocks']
    a, b = [[int(value, 16) for value in entry['words']] for entry in (first, second)]
    # Exact complete native increments and the two event stores recorded in
    # the packaged PE. These are diagnostic bookkeeping, not the user's lock.
    assert a[5:9] == [0x885ffd09, 0x11000529, 0x880afd09, 0x35ffffaa]
    assert b[7:11] == [0x885ffd2a, 0x1100054a, 0x880bfd2a, 0x35ffffab]
    assert (a[9], a[12], a[14], a[17]) == (0x12002128, 0x8b285128, 0xf9000113, 0xb9000909)
    assert (b[11], b[14], b[17], b[20]) == (0x12002149, 0x8b295149, 0xf9000120, 0xb900092a)
    def address(entry, index):
        words = [int(value, 16) for value in entry['words']]
        word, add = words[index:index+2]
        assert word & 0x9f000000 == 0x90000000 and add & 0xffc00000 == 0x91000000
        immediate = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
        if immediate & (1 << 20):
            immediate -= 1 << 21
        pc = int(entry['rva'], 16) + index * 4
        return (pc & ~4095) + immediate * 4096 + ((add >> 10) & 4095)
    assert address(first, 3) == address(second, 5) == int(capture['index_rva'], 16)
    assert address(first, 10) == address(second, 12) == int(capture['ring_rva'], 16)
    return capture


def staged_source():
    spec = importlib.util.spec_from_file_location('native_counter_stage', ROOT / 'tools/build/stage-native-counter-writes.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    original = {name: (ROOT / 'wine' / name).read_text() for name in stage.FILES}
    return original[stage.FILES[1]], stage.stage(original)[stage.FILES[1]]


def function(source, name):
    import re
    match = re.search(r'(?m)^static (?:inline )?(?:void|LONG \*|struct ios_srw_ring_ent \*)\s*' + name + r'\(', source)
    assert match, name
    return source[match.start():source.index('\n}', match.start()) + 2]


def producer_header():
    captured_producer_proof()
    original, staged = staged_source()
    # Changes to Windows locking bodies are outside this optimization. Preserve
    # every call site and all synchronization arithmetic/control flow exactly.
    start, end = original.index('void WINAPI RtlAcquireSRWLockExclusive'), original.index('/* RtlWaitOnAddress()')
    assert staged[staged.index('void WINAPI RtlAcquireSRWLockExclusive'):staged.index('/* RtlWaitOnAddress()')] == original[start:end]
    struct = original[original.index('struct ios_srw_ring_ent {'):original.index('\n', original.index('struct ios_srw_ring_ent {'))]
    contract_start = staged.index('struct ios_srw_history_write_contract\n')
    contract = staged[contract_start:staged.index('\n};', contract_start) + 3]
    header = r'''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint64_t ULONGLONG;
typedef int BOOL;
struct fake_teb { struct { void *UniqueThread; } ClientId; };
static _Thread_local struct fake_teb srw_teb;
static struct fake_teb *NtCurrentTeb(void) { return &srw_teb; }
#define HandleToULong(value) ((ULONG)(uintptr_t)(value))
#define InterlockedIncrement(value) __atomic_add_fetch((value),1,__ATOMIC_SEQ_CST)
#define ERR(...) ((void)0)
static BOOL ios_sync_lean;
''' + struct + '\n' + contract + r'''
#define SRW_RING_OFFSET 0xa100u
#define SRW_INDEX_OFFSET 0xc120u
#define SRW_CONTRACT_OFFSET 0xc140u
static unsigned char *srw_source_rx;
#define ios_srw_ring (*(struct ios_srw_ring_ent (*)[512])(srw_source_rx+SRW_RING_OFFSET))
#define ios_srw_ring_idx (*(LONG *)(srw_source_rx+SRW_INDEX_OFFSET))
#define ios_srw_history_write_contract (*(struct ios_srw_history_write_contract *)(srw_source_rx+SRW_CONTRACT_OFFSET))
'''
    header += function(staged, 'ios_srw_ring_writer') + '\n' + function(staged, 'ios_srw_index_writer') + '\n'
    header += function(original, 'ios_srw_note').replace('static void ios_srw_note(', 'static __attribute__((noinline)) void srw_note_original(') + '\n'
    header += function(staged, 'ios_srw_note').replace('static void ios_srw_note(', 'static __attribute__((noinline)) void srw_note_bound(') + '\n'
    # The real dump reader must use the same pointer choice; compile it with a
    # bounded native SRW-lock descriptor and a diagnostic sink.
    header += 'struct srw_lock { uint16_t exclusive_waiters, owners; };\n'
    header += function(staged, 'ios_srw_dump_park').replace('static void ios_srw_dump_park(', 'static __attribute__((unused)) void ios_srw_dump_park(') + '\n'
    return header


def pe_fixture_header():
    return r'''
#include "native_srw_alias.h"
enum { SRW_IMAGE_SIZE=0x10000,SRW_EXPORT=0x2000,SRW_TABLE=0x188 };
static void srw_w16(unsigned char *p,size_t at,uint16_t value){memcpy(p+at,&value,2);}
static void srw_w32(unsigned char *p,size_t at,uint32_t value){memcpy(p+at,&value,4);}
static void srw_w64(unsigned char *p,size_t at,uint64_t value){memcpy(p+at,&value,8);}
static void srw_pe_fixture(unsigned char *p) {
    memset(p,0,SRW_IMAGE_SIZE);p[0]='M';p[1]='Z';srw_w32(p,60,0x80);memcpy(p+0x80,"PE\0\0",4);
    srw_w16(p,0x84,0xaa64);srw_w16(p,0x86,3);srw_w16(p,0x94,0xf0);srw_w16(p,0x98,0x20b);
    srw_w64(p,0xb0,0x180000000ULL);srw_w32(p,0xd0,SRW_IMAGE_SIZE);srw_w32(p,0x104,16);
    srw_w32(p,0x108,SRW_EXPORT);srw_w32(p,0x10c,0x700);
    const uint32_t starts[]={0x1000,0x2000,0x4000},lengths[]={0x1000,0x1000,0x9000},flags[]={0x60000020,0x40000040,0xc0000040};
    for(unsigned i=0;i<3;i++) {
        size_t at=SRW_TABLE+i*40;srw_w32(p,at+8,lengths[i]);srw_w32(p,at+12,starts[i]);srw_w32(p,at+16,lengths[i]);srw_w32(p,at+36,flags[i]);
    }
    const char *names[]={"ios_xp_nt","ios_xp_nt_write_contract","ios_srw_ring","ios_srw_ring_idx","ios_srw_history_write_contract"};
    const uint32_t values[]={0x4000,0xa0c0,SRW_RING_OFFSET,SRW_INDEX_OFFSET,SRW_CONTRACT_OFFSET};
    srw_w32(p,SRW_EXPORT+20,5);srw_w32(p,SRW_EXPORT+24,5);srw_w32(p,SRW_EXPORT+28,0x2100);
    srw_w32(p,SRW_EXPORT+32,0x2140);srw_w32(p,SRW_EXPORT+36,0x2180);
    size_t text=0x2200;
    for(unsigned i=0;i<5;i++) {
        srw_w32(p,0x2100+i*4,values[i]);srw_w32(p,0x2140+i*4,(uint32_t)text);srw_w16(p,0x2180+i*2,(uint16_t)i);
        strcpy((char *)p+text,names[i]);text+=strlen(names[i])+1;
    }
    srw_w64(p,0xa0c0,MADEIRA_NATIVE_COUNTER_ABI_V1);srw_w32(p,0xa0c8,MADEIRA_NATIVE_COUNTER_BYTES);
    srw_w64(p,SRW_CONTRACT_OFFSET,MADEIRA_NATIVE_SRW_ABI_V1);srw_w32(p,SRW_CONTRACT_OFFSET+8,MADEIRA_NATIVE_SRW_RING_BYTES);
    srw_w32(p,SRW_CONTRACT_OFFSET+12,MADEIRA_NATIVE_SRW_ENTRY_BYTES);
}
'''


def write_headers(path):
    (path / 'production-srw-producer.h').write_text(producer_header())
    (path / 'production-srw-fixture.h').write_text(pe_fixture_header())


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='madeira-native-srw-source-') as folder:
        work = Path(folder)
        write_headers(work)
        binary = work / 'srw-producer'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                        '-I', str(work), '-I', str(ROOT / 'build/ntdll-unix'),
                        str(ROOT / 'tests/host/native-srw-history-test.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=40)
