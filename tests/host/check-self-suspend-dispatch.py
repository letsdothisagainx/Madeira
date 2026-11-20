#!/usr/bin/env python3
"""Exercise the actual Run 11 dispatch observer with sparse, checked OS reads.

The fixture tests observation and refusal only. Its PE/object/stack bytes and
dispatch state are controlled inputs, not a reproduction of the phone's
unmeasured pool state or an assertion that remote gameplay is repaired.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'build/ntdll-unix/self_suspend_dispatch.h'
TRACE = ROOT / 'build/ntdll-unix/self_suspend_trace.h'


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


trace = TRACE.read_text()
observer = HEADER.read_text()
assert trace.count('ios_self_suspend_dispatch_observe( snapshot,') == 1
begin = function(trace, 'static unsigned ios_self_suspend_client_begin(')
assert begin.index('if (!ios_self_suspend_take( &w->caller_reported, 1 )) goto done;') < begin.index('ios_self_suspend_dispatch_observe(')
assert begin.index('if (!snapshot->valid) goto done;') < begin.index('ios_self_suspend_dispatch_observe(')
assert not re.search(r'\b(?:malloc|calloc|realloc|free|NtSuspendThread|SuspendThread|NtResumeThread|ResumeThread|GetThreadContext|SetThreadContext|mach_vm_write|mach_vm_deallocate)\s*\(', observer)

FIXTURE = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t mach_vm_size_t;
typedef uintptr_t mach_vm_address_t;
#define KERN_SUCCESS 0
struct ios_self_suspend_snapshot { uint64_t pc, lr, sp, fp; unsigned valid; };

#define CLIENT UINT64_C(0x71bcad0000)
#define TIER0 UINT64_C(0x71d4e80000)
#define KERNEL UINT64_C(0x71d5d00000)
#define CLIENT_RX UINT64_C(0x7c08000000)
#define TIER0_RX UINT64_C(0x7c0c000000)
#define KERNEL_RX UINT64_C(0x7c0d000000)
#define STACK UINT64_C(0x70db3394f0)
#define JOB UINT64_C(0x7100010000)
#define POOL UINT64_C(0x7100020000)
#define PID 0x3c0
#define TID 0x3c4

struct region { uintptr_t base; size_t bytes; unsigned char data[0x1100]; };
static struct region regions[20], preserved[20];
static unsigned region_count, reads, maps, logs, read_failure, short_read, racy_reads;
static uintptr_t racy_address;
static uintptr_t read_addresses[40];
static size_t read_sizes[40];
static char output[8192];
static size_t output_used;
static unsigned observer_calls;
static struct ios_self_suspend_snapshot snapshot;
static uintptr_t stack_limit, stack_base;
static uint64_t selected_pool_vt;

static uint64_t canonical(uint64_t address)
{
    if (address >= CLIENT_RX && address - CLIENT_RX < 0x298e000) return CLIENT + address - CLIENT_RX;
    if (address >= TIER0_RX && address - TIER0_RX < 0x401000) return TIER0 + address - TIER0_RX;
    if (address >= KERNEL_RX && address - KERNEL_RX < 0x100000) return KERNEL + address - KERNEL_RX;
    return address;
}
static uint64_t rx(uint64_t address)
{
    if (address >= CLIENT && address - CLIENT < 0x298e000) return CLIENT_RX + address - CLIENT;
    if (address >= TIER0 && address - TIER0 < 0x401000) return TIER0_RX + address - TIER0;
    if (address >= KERNEL && address - KERNEL < 0x100000) return KERNEL_RX + address - KERNEL;
    assert(!"only image addresses have a fixture RX alias"); return 0;
}
static struct region *find(uint64_t address, size_t bytes)
{
    address = canonical(address);
    for (unsigned i = 0; i < region_count; ++i)
        if (address >= regions[i].base && bytes <= regions[i].bytes &&
            address - regions[i].base <= regions[i].bytes - bytes) return &regions[i];
    return NULL;
}
static void add(uintptr_t address, const void *data, size_t bytes)
{
    assert(region_count < sizeof(regions) / sizeof(regions[0]) && bytes <= sizeof(regions[0].data));
    struct region *r = &regions[region_count++];
    r->base = address; r->bytes = bytes;
    if (data) memcpy(r->data, data, bytes);
}
static void put(uint64_t address, const void *data, size_t bytes)
{
    struct region *r = find(address, bytes); assert(r);
    memcpy(r->data + canonical(address) - r->base, data, bytes);
}
static void u64(uint64_t address, uint64_t value) { put(address, &value, 8); }
static void u32(uint64_t address, uint32_t value) { put(address, &value, 4); }
static void u16(uint64_t address, uint16_t value) { put(address, &value, 2); }
static void u8(uint64_t address, unsigned char value) { put(address, &value, 1); }

static int mach_task_self(void) { return 7; }
static int mach_vm_read_overwrite(int task, mach_vm_address_t address, size_t bytes,
                                 mach_vm_address_t out, mach_vm_size_t *got)
{
    assert(task == 7 && reads < 40);
    read_addresses[reads] = address; read_sizes[reads] = bytes; ++reads;
    *got = 0; errno = EFAULT;
    if (read_failure == reads) return 1;
    struct region *r = find(address, bytes);
    if (!r) return 1;
    size_t copied = short_read == reads && bytes ? bytes - 1 : bytes;
    memcpy((void *)out, r->data + canonical(address) - r->base, copied);
    *got = copied;
    /* Return changed bytes without changing the registered source, modelling
     * object reuse between the initial check and the validation re-read. */
    if (racy_address && canonical(address) == racy_address && ++racy_reads == 2 && copied == 8)
        *(uint64_t *)(uintptr_t)out ^= 8;
    return KERN_SUCCESS;
}
uint64_t ios_jit_reverse_translate(uint64_t address, uint64_t *base)
{
    assert(++maps < 40); errno = ERANGE;
    uint64_t pe = canonical(address);
    if (pe != address) {
        if (base) *base = pe >= CLIENT && pe - CLIENT < 0x298e000 ? CLIENT :
                         pe >= TIER0 && pe - TIER0 < 0x401000 ? TIER0 : KERNEL;
        return pe;
    }
    if (base) *base = 0;
    return 0;
}
unsigned long long ios_jit_module_base_for_va(unsigned long long address, unsigned long long *size)
{
    assert(++maps < 40); errno = ENOENT;
    uint64_t base = 0, bytes = 0;
    if (address >= CLIENT && address - CLIENT < 0x298e000) { base = CLIENT; bytes = 0x298e000; }
    else if (address >= TIER0 && address - TIER0 < 0x401000) { base = TIER0; bytes = 0x401000; }
    else if (address >= KERNEL && address - KERNEL < 0x100000) { base = KERNEL; bytes = 0x100000; }
    if (size) *size = bytes;
    return base;
}
static int fixture_dprintf(int fd, const char *format, ...)
{
    assert(fd == 2 && ++logs <= 2);
    va_list ap; va_start(ap, format);
    int n = vsnprintf(output + output_used, sizeof(output) - output_used, format, ap);
    va_end(ap);
    assert(n > 0 && (size_t)n < sizeof(output) - output_used);
    output_used += (size_t)n; errno = EBADF; return n;
}
static void *forbidden(const char *operation) __attribute__((unused));
static void *forbidden(const char *operation)
{
    fprintf(stderr, "forbidden observer operation: %s\n", operation);
    abort(); return NULL;
}
'''
FIXTURE += function(trace, 'static int ios_self_suspend_read(') + '\n'
FIXTURE += r'''
#define dprintf fixture_dprintf
#define malloc(...) forbidden("malloc")
#define calloc(...) forbidden("calloc")
#define realloc(...) forbidden("realloc")
#define free(...) forbidden("free")
#define SuspendThread(...) forbidden("SuspendThread")
#define ResumeThread(...) forbidden("ResumeThread")
#define GetThreadContext(...) forbidden("GetThreadContext")
#define SetThreadContext(...) forbidden("SetThreadContext")
#define mach_vm_write(...) forbidden("mach_vm_write")
#include "self_suspend_dispatch.h"
#undef mach_vm_write
#undef SetThreadContext
#undef GetThreadContext
#undef ResumeThread
#undef SuspendThread
#undef free
#undef realloc
#undef calloc
#undef malloc
#undef dprintf

static void image(uint64_t base, uint32_t stamp, uint32_t image_size)
{
    add(base, NULL, 64); add(base + 0x80, NULL, 84);
    u16(base, 0x5a4d); u32(base + 60, 0x80);
    u32(base + 0x80, 0x4550); u16(base + 0x84, 0x8664);
    u32(base + 0x88, stamp); u16(base + 0x98, 0x20b); u32(base + 0xd0, image_size);
}
static void reset(unsigned alternate_pool)
{
    static const unsigned char capture[] = {0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,
        0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20,0x41,0x56,0x48,0x81,0xec,0xf0,0x04,0x00,0x00};
    static const unsigned char caller[] = {0x89,0x54,0x24,0x10,0x53,0x56,0x57,0x41,0x54,0x41,
        0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xec,0xe0,0x09,0x00,0x00};
    static const unsigned char callback[] = {0x48,0x83,0xc1,0x50,0x8b,0x51,0x60,0xe9,0x74,0x89,0xeb,0xff};
    static const unsigned char gate[] = {0x83,0xb9,0x30,0x01,0x00,0x00,0x00};
    static const unsigned char invoke[] = {0xff,0x50,0x28};
    memset(regions, 0, sizeof(regions));
    region_count = reads = maps = logs = output_used = read_failure = short_read = racy_reads = 0;
    racy_address = 0; output[0] = 0;
    snapshot = (struct ios_self_suspend_snapshot){KERNEL + 0x5a698, KERNEL + 0x6dee4, STACK, STACK + 0xe0, 1};
    stack_limit = STACK - 0x1000; stack_base = STACK + 0x1100;
    selected_pool_vt = TIER0 + (alternate_pool ? 0x316358 : 0x316540);
    add(STACK, NULL, 0x1100); add(JOB, NULL, 0xc0); add(POOL, NULL, 0x170);
    image(CLIENT, 0x6aff8722, 0x298e000); image(TIER0, 0x6af4a3e4, 0x401000);
    add(CLIENT + 0x4520, capture, sizeof(capture)); add(CLIENT + 0x3140, caller, sizeof(caller));
    add(CLIENT + 0x14a7c0, callback, sizeof(callback)); add(TIER0 + 0xa5525, gate, sizeof(gate));
    add(TIER0 + 0xa55a7, invoke, sizeof(invoke));
    add(CLIENT + 0x1abc488, NULL, 0x30); add(selected_pool_vt, NULL, 0x88);
    u64(STACK + 56, KERNEL + 0x78f4c); u64(STACK + 232, CLIENT + 0x457b);
    u64(STACK + 256, UINT64_C(0x71ce94bed0));
    u64(STACK + 0x5e8, CLIENT + 0x4331); u64(STACK + 0x728, JOB + 0x50);
    u64(STACK + 0x1008, TIER0 + 0xa55aa); u32(STACK + 0x1018, TID);
    u64(STACK + 0x1038, CLIENT + 0x53dc); u64(STACK + 0xfd8, POOL); u64(STACK + 0xff0, JOB);
    u64(JOB, CLIENT + 0x1abc488); u64(CLIENT + 0x1abc488 + 0x28, CLIENT + 0x14a7c0);
    u8(JOB + 0x15, 2); u64(JOB + 0x18, POOL); u32(JOB + 0xb0, TID);
    u64(POOL, selected_pool_vt); u64(selected_pool_vt + 0x80, TIER0 + 0xa5500);
    u32(POOL + 0x130, 7); u64(POOL + 0x138, 0x7100030000); u64(POOL + 0x140, 0x7100030040);
    u8(POOL + 0x159, 1); u8(POOL + 0x15a, 2);
}
static void observe(const char *expected)
{
    struct ios_self_suspend_snapshot saved = snapshot;
    memcpy(preserved, regions, sizeof(regions));
    errno = 113; ++observer_calls;
    ios_self_suspend_dispatch_observe(&snapshot, stack_limit, stack_base, PID, TID);
    assert(errno == 113 && !memcmp(&saved, &snapshot, sizeof(saved)));
    assert(!memcmp(preserved, regions, sizeof(regions)) && reads <= 32 && maps <= 39 && logs <= 2);
    assert(strstr(output, expected));
    if (strstr(output, "result=unavailable")) assert(logs == 1 && !strstr(output, "result=captured"));
    else assert(logs == 2 && !strstr(output, "result=unavailable"));
}
static void matched_frames_and_aliases(void)
{
    for (unsigned variant = 0; variant < 2; ++variant) {
        for (unsigned mask = 0; mask < 1024; ++mask) {
            reset(variant);
            const uint64_t slots[] = {56, 232, 0x5e8, 0x1008, 0x1038};
            const uint64_t values[] = {KERNEL + 0x78f4c, CLIENT + 0x457b, CLIENT + 0x4331,
                                       TIER0 + 0xa55aa, CLIENT + 0x53dc};
            for (unsigned i = 0; i < 5; ++i) if (mask & (1u << i)) u64(STACK + slots[i], rx(values[i]));
            if (mask & 32) snapshot.lr = rx(snapshot.lr);
            if (mask & 64) u64(JOB, rx(CLIENT + 0x1abc488));
            if (mask & 128) u64(CLIENT + 0x1abc488 + 0x28, rx(CLIENT + 0x14a7c0));
            if (mask & 256) u64(POOL, rx(selected_pool_vt));
            if (mask & 512) u64(selected_pool_vt + 0x80, rx(TIER0 + 0xa5500));
            observe("dispatch=inline-submit-validated");
            assert(reads == 27 && strstr(output, "creator-tid=03c4 creator-is-current=1"));
            assert(strstr(output, "job-u8-15=2 pool-u32-130=7 pool-u8-159=1 pool-u8-15a=2"));
            const size_t derived[] = {0x5e8, 0x728, 0x1008, 0x1018, 0x1038, 0xfd8, 0xff0};
            for (unsigned j = 0; j < sizeof(derived) / sizeof(derived[0]); ++j) {
                unsigned found = 0;
                for (unsigned i = 0; i < reads; ++i) found |= read_addresses[i] == STACK + derived[j];
                assert(found);
            }
        }
    }
    reset(0); u32(JOB + 0xb0, TID + 4); u32(STACK + 0x1018, TID + 4);
    observe("dispatch=inline-submit-validated"); assert(strstr(output, "creator-is-current=0"));
    for (unsigned which = 0; which < 5; ++which) {
        reset(0);
        if (which == 0) u64(STACK + 0x1008, TIER0 + 0xa5780);
        if (which == 1) u64(STACK + 0x1038, CLIENT + 0x53e0);
        if (which == 2) u64(STACK + 0xfd8, POOL + 8);
        if (which == 3) u64(STACK + 0xff0, JOB + 8);
        if (which == 4) u32(STACK + 0x1018, TID + 4);
        observe("dispatch=other-path"); assert(strstr(output, "result=captured"));
    }
}
static void invalid_boundaries_and_contracts(void)
{
    for (unsigned which = 0; which < 8; ++which) {
        reset(0);
        if (which == 0) snapshot.valid = 0;
        if (which == 1) stack_limit = 0;
        if (which == 2) stack_base = stack_limit;
        if (which == 3) stack_limit = STACK + 16;
        if (which == 4) stack_base = STACK;
        if (which == 5) stack_base = STACK + 0x103f;
        if (which == 6) snapshot.sp++;
        if (which == 7) { snapshot.sp = UINTPTR_MAX - 15; stack_limit = snapshot.sp - 16; stack_base = UINTPTR_MAX; }
        observe("reason=stack-bounds"); assert(!reads);
    }
    unsigned char target[40] = {0}; reset(0);
    assert(!ios_dispatch_read(UINTPTR_MAX - 2, 4, target, 8));
    assert(!ios_dispatch_read(1, SIZE_MAX, target, 8));
    assert(!ios_dispatch_read(1, 0, target, SIZE_MAX));
    assert(!ios_dispatch_bytes(CLIENT, 0, target, 33) && !reads);

    for (unsigned which = 0; which < 24; ++which) {
        reset(0);
        switch (which) {
        case 0: snapshot.lr = KERNEL + 0x6dee5; break;
        case 1: u64(STACK + 56, KERNEL + 0x78f50); break;
        case 2: u64(STACK + 232, CLIENT + 0x457c); break;
        case 3: u16(CLIENT, 0); break;
        case 4: u32(CLIENT + 60, 63); break;
        case 5: u32(CLIENT + 60, 4097); break;
        case 6: u32(CLIENT + 0x80, 0); break;
        case 7: u16(CLIENT + 0x84, 0x14c); break;
        case 8: u32(CLIENT + 0x88, 0x6afd14c1); break; /* previous manifest */
        case 9: u16(CLIENT + 0x98, 0x10b); break;
        case 10: u32(CLIENT + 0xd0, 0x298d000); break;
        case 11: u8(CLIENT + 0x4520, 0x49); break;
        case 12: u8(CLIENT + 0x3140, 0x90); break;
        case 13: u8(CLIENT + 0x14a7c0, 0x90); break;
        case 14: u64(STACK + 0x5e8, CLIENT + 0x432c); break;
        case 15: u64(STACK + 0x728, 0x4f); break;
        case 16: u64(JOB, CLIENT + 0x1abc480); break;
        case 17: u64(CLIENT + 0x1abc488 + 0x28, CLIENT + 0x14a7c1); break;
        case 18: u64(JOB + 0x18, 0); break;
        case 19: u64(POOL, selected_pool_vt + 8); break;
        case 20: u64(selected_pool_vt + 0x80, TIER0 + 0xa5508); break;
        case 21: u32(TIER0 + 0x88, 0); break;
        case 22: u8(TIER0 + 0xa5525, 0x90); break;
        case 23: u8(TIER0 + 0xa55a7, 0x90); break;
        }
        observe("result=unavailable"); assert(strstr(output, "action=observation-only-skip"));
    }
    for (unsigned which = 0; which < 2; ++which) {
        reset(0); racy_address = which ? POOL : JOB;
        observe("result=unavailable"); assert(strstr(output, "reason=dispatch-state"));
    }
}
static void failed_and_short_reads(void)
{
    reset(0); observe("result=captured"); const unsigned total_reads = reads;
    for (unsigned mode = 0; mode < 2; ++mode)
        for (unsigned index = 1; index <= total_reads; ++index) {
            reset(0);
            if (mode) short_read = index; else read_failure = index;
            observe("result=unavailable");
            assert(strstr(output, "action=observation-only-skip"));
        }
}
int main(void)
{
    matched_frames_and_aliases(); invalid_boundaries_and_contracts(); failed_and_short_reads();
    printf("PASS actual dispatch observer: %u controlled observations; matched Run11 images/frames, 2048 original/RX alias combinations, both pool vtables, other-path and noncurrent creator\n", observer_calls);
    puts("PASS checked-read failures and short reads at every native call, stack/overflow/version/signature/object-race refusal, fixed <=32 reads/2 logs, errno and all guest/object/stack bytes unchanged");
    puts("NOTE pool state and dispatch inputs are controlled; these tests do not establish the missing iPhone dispatch state or playable gameplay");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-self-suspend-dispatch-') as directory:
    temp = Path(directory)
    source, executable = temp / 'dispatch.c', temp / 'dispatch'
    source.write_text(FIXTURE)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(HEADER.parent), str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
