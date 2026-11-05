#!/usr/bin/env python3
"""Execute the sampler's real bounded native chain and saved ARM64EC reader."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/server_ios.c').read_text()


def function(name):
    start = source.index(name)
    brace = source.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[start:brace + token.end()]
    raise AssertionError(name)


struct_start = source.index('struct ios_ts_hot_context\n')
context_struct = source[struct_start:source.index('\n};', struct_start) + 3]
helpers = '\n'.join(function(name) for name in (
    'static int ios_ts_read(', 'static unsigned ios_ts_host_chain(',
    'static void ios_ts_saved_guest64('))
sampler = function('static void ios_thread_sampler_pass(')
assert 'burst == 1 && running && bi.cpu_usage >= 900 && x18 && hot_captures < 2' in sampler
assert sampler.index('ios_ts_saved_guest64(x18, &hot)') < sampler.index('\n        thread_resume(tlist[k]);')
assert sampler.index('\n        thread_resume(tlist[k]);') < sampler.index('ios_ts_print_hot_context(&hot, pc, mp)')
assert 'sampled-host-pc=' in source and 'saved-guest-rip=' in source and 'current=false' in source
for forbidden in ('malloc(', 'dladdr(', 'wine_log_write(', 'NtQueryInformationThread(', 'pthread_mutex_lock(', 'ios_call_fex'):
    assert forbidden not in helpers

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "windef.h"
#include "winternl.h"
typedef uint64_t vm_size_t, vm_address_t;
#define KERN_SUCCESS 0
static int mach_task_self(void) { return 1; }
static TEB teb;
static CHPE_V2_CPU_AREA_INFO area;
static ARM64EC_NT_CONTEXT ec;
static uint64_t thread_frame, frame_header, guest_stack[16], host_stack[64];
static const uint64_t teb_at=0xfbfe20000ull, area_at=0x12f7c0000ull;
static const uint64_t frame_at=0xc2c001140ull, thread_at=0xc2c001000ull;
static const uint64_t ec_at=0x12f7c0050ull, rsp_at=0x180000000ull, host_at=0x12f7bf300ull;
static uint64_t deny;
static unsigned reads, tid_reads, recycle;
static int vm_read_overwrite(int task, uint64_t address, uint64_t size, uint64_t dst, uint64_t *got)
{
    struct { uint64_t at; void *data; size_t size; } regions[] = {
        {teb_at,&teb,sizeof(teb)}, {area_at,&area,sizeof(area)},
        {thread_at,&thread_frame,sizeof(thread_frame)}, {frame_at,&frame_header,sizeof(frame_header)}, {ec_at,&ec,sizeof(ec)},
        {rsp_at,guest_stack,sizeof(guest_stack)}, {host_at,host_stack,sizeof(host_stack)}
    };
    assert(task==1); reads++; *got=0;
    if (address==teb_at+offsetof(TEB,ClientId.UniqueThread) && ++tid_reads==2 && recycle==1)
        teb.ClientId.UniqueThread=(HANDLE)(uintptr_t)0x220;
    if (recycle==2 && address==area_at+offsetof(CHPE_V2_CPU_AREA_INFO,ContextAmd64))
        area.ContextAmd64=(void*)(uintptr_t)(ec_at+16);
    if (recycle==3 && address==area_at+offsetof(CHPE_V2_CPU_AREA_INFO,EmulatorData[1]))
        area.EmulatorData[1]=(void*)(uintptr_t)(thread_at+16);
    if (deny && address==deny) return 1;
    /* ec_at lies inside the area object's trailing address range: model the
     * two allocation objects by request size, without overlapping C objects. */
    for (unsigned i=0;i<sizeof(regions)/sizeof(regions[0]);i++)
        if (address>=regions[i].at && size<=regions[i].size &&
            address-regions[i].at<=regions[i].size-size)
        {
            memcpy((void*)(uintptr_t)dst,(char*)regions[i].data+address-regions[i].at,size);
            *got=size; return 0;
        }
    return 1;
}
@STRUCT@
@HELPERS@
static void reset(void)
{
    memset(&teb,0,sizeof(teb)); memset(&area,0,sizeof(area)); memset(&ec,0,sizeof(ec));
    memset(host_stack,0,sizeof(host_stack)); reads=tid_reads=recycle=0; deny=0;
    teb.Tib.Self=(void*)(uintptr_t)teb_at;
    teb.ClientId.UniqueProcess=(HANDLE)(uintptr_t)0x68;
    teb.ClientId.UniqueThread=(HANDLE)(uintptr_t)0x19c;
    teb.Peb=(void*)(uintptr_t)0x111bcc000;
    teb.ChpeV2CpuAreaInfo=(void*)(uintptr_t)area_at;
    area.ContextAmd64=(void*)(uintptr_t)ec_at;
    area.EmulatorData[0]=(void*)(uintptr_t)frame_at;
    area.EmulatorData[1]=(void*)(uintptr_t)thread_at;
    thread_frame=frame_at; ec.Pc=0x3f9b40e1e; ec.Sp=rsp_at;
    guest_stack[0]=0x3f9b283e0;
}
static struct ios_ts_hot_context capture(void)
{
    struct ios_ts_hot_context result={0}; ios_ts_saved_guest64(teb_at,&result); return result;
}
int main(void)
{
    struct ios_ts_hot_context result;
    reset(); result=capture(); assert(result.have_guest && result.have_stack);
    assert(result.teb==teb_at && result.pid==0x68 && result.tid==0x19c && result.owner==0x111bcc000);
    assert(result.frame==frame_at && result.thread==thread_at && result.rip==ec.Pc && result.rsp==ec.Sp && result.stack[0]==guest_stack[0]);
    assert(reads<24);
    reset(); teb.Tib.Self=NULL; assert(!capture().have_guest);
    reset(); teb.Peb=NULL; assert(!capture().have_guest);
    reset(); teb.ClientId.UniqueThread=NULL; assert(!capture().have_guest);
    reset(); thread_frame++; assert(!capture().have_guest);
    reset(); area.EmulatorData[0]=(void*)(uintptr_t)(frame_at+1); assert(!capture().have_guest);
    reset(); area.ContextAmd64=NULL; assert(!capture().have_guest);
    reset(); deny=ec_at; assert(!capture().have_guest);
    reset(); deny=frame_at; assert(!capture().have_guest);
    reset(); ec.Pc=0; assert(!capture().have_guest);
    reset(); ec.Sp=UINT64_MAX; assert(!capture().have_guest);
    reset(); deny=rsp_at; result=capture(); assert(result.have_guest && !result.have_stack);
    reset(); recycle=1; assert(!capture().have_guest);
    reset(); recycle=2; assert(!capture().have_guest);
    reset(); recycle=3; assert(!capture().have_guest);
    /* Same TEB reused by a successor: no old TID, owner or RIP is cached. */
    reset(); (void)capture(); teb.ClientId.UniqueThread=(HANDLE)(uintptr_t)0x220;
    teb.Peb=(void*)(uintptr_t)0x222000000; ec.Pc=0x3f1001000; result=capture();
    assert(result.have_guest && result.tid==0x220 && result.owner==0x222000000 && result.rip==0x3f1001000);
    {
        uint64_t out[10]; unsigned n;
        reset();
        for(unsigned i=0;i<20;i++) {host_stack[2*i]=host_at+16*(i+1);host_stack[2*i+1]=0xabcd000200010000ull+i*4;}
        n=ios_ts_host_chain(host_at-0x80,host_at,0x200000000ull,out);
        assert(n==10 && reads==9 && out[1]==0x200010000ull);
        host_stack[0]=host_at; reads=0;
        assert(ios_ts_host_chain(host_at-0x80,host_at,0,out)==1 && reads==1);
        reads=0;assert(ios_ts_host_chain(host_at,host_at-16,0,out)==0 && reads==0);
        assert(ios_ts_host_chain(host_at,host_at+1,0,out)==0);
        assert(ios_ts_host_chain(host_at-0x200000,host_at,0,out)==0);
        deny=host_at;assert(ios_ts_host_chain(host_at-0x80,host_at,0,out)==0);
        reads=0;assert(!ios_ts_read(UINT64_MAX-7,out,16) && reads==0);
    }
    puts("PASS actual sampler helpers: saved guest exit distinct from host PC, native FP/PAC bounds, unreadable state, recycled TEB identity, fixed read/capture budgets");
}
'''.replace('@STRUCT@', context_struct).replace('@HELPERS@', helpers)

with tempfile.TemporaryDirectory(prefix='madeira-native-context-') as directory:
    test = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    test.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I' + str(root / 'wine/include'), str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=20)
