#!/usr/bin/env python3
"""Exercise the existing production cross-page store completion path.

This executes the extracted helper, not a replacement implementation. Darwin
uses real Mach region queries and real file-backed mappings. Other hosts check
the same byte/state semantics with their actual mapping protections, without
claiming that this reproduces the iOS kernel retry. The fixture owns mappings
for the entire call; concurrent unmapping is deliberately outside its scope.
"""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-darwin', action='store_true')
parser.add_argument('--sanitize', action='store_true')
args = parser.parse_args()
if args.require_darwin and platform.system() != 'Darwin':
    raise SystemExit('FAIL: real Darwin VM queries are required')

root = Path(__file__).resolve().parents[2]
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
server = (root / 'build/ntdll-unix/server_ios.c').read_text()


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


helper = function(signal, 'int ios_store_split_crossing( uint32_t insn,')
alias = function(signal, 'static uintptr_t ios_write_alias( uintptr_t addr )')
trapped = function(signal, 'static int ios_alias_write_is_trapped( uintptr_t addr )')
caller_start = server.index('        int r = ios_store_split_crossing( insn, &st,')
caller_end = server.index('        thread_resume( thread );', caller_start)
caller = server[caller_start:caller_end] + '        thread_resume( thread );\n'

C = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/ucontext.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#if defined(__arm64__) || defined(__aarch64__)
#include <mach/arm/thread_status.h>
#define NATIVE_ARM_STATE 1
#endif
#endif
#ifndef NATIVE_ARM_STATE
typedef struct { uint64_t __x[29], __fp, __lr, __sp, __pc; } arm_thread_state64_t;
typedef struct { __uint128_t __v[32]; } arm_neon_state64_t;
#define arm_thread_state64_get_pc(s) ((s).__pc)
#define __darwin_arm_thread_state64_set_pc_fptr(s,p) ((s).__pc = (uintptr_t)(p))
#define ARM_THREAD_STATE64 6
#define ARM_THREAD_STATE64_COUNT (sizeof(arm_thread_state64_t) / sizeof(uint32_t))
#endif
#ifndef __APPLE__
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef unsigned mach_msg_type_number_t;
typedef int mach_port_t;
typedef int *vm_region_info_t;
typedef uint32_t *thread_state_t;
typedef struct { int protection; } vm_region_basic_info_data_64_t;
#define VM_REGION_BASIC_INFO_COUNT_64 1
#define VM_REGION_BASIC_INFO_64 1
#define MACH_PORT_NULL 0
#define KERN_SUCCESS 0
#define VM_PROT_WRITE PROT_WRITE
static int mach_task_self(void) { return 0; }
static int mach_port_deallocate(int task, int object) { (void)task; (void)object; return 0; }
/* Actual host permissions, rather than fabricated success. Darwin executes
 * the real mach_vm_region above. No other thread changes these test mappings. */
static int mach_vm_region(int task, uintptr_t *address, size_t *size, int flavor,
                          int *info, unsigned *count, int *object)
{
    (void)task; (void)flavor; (void)count;
    FILE *maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[1024], perms[8]; unsigned long long start, end;
    while (fgets(line, sizeof(line), maps))
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) == 3 && end > *address)
        {
            *address = start; *size = end - start;
            ((vm_region_basic_info_data_64_t *)info)->protection =
                (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0);
            *object = MACH_PORT_NULL; fclose(maps); return KERN_SUCCESS;
        }
    fclose(maps); return 1;
}
#endif

enum { PAGE = 16384, SPAN = PAGE * 2 };
void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
static uintptr_t guest, alias_first, alias_second, trapped_page;
static unsigned writes;
int ios_jit_code_guard_contains(uintptr_t address, size_t size)
{ (void)address; (void)size; return 0; }
int ios_jit_low_contains(uintptr_t address) { (void)address; return 0; }
int ios_jit_pool_pc_is_fex(uintptr_t pc) { (void)pc; return 0; }
int ios_page_expected_prot(const void *address)
{
    return trapped_page && ((uintptr_t)address & ~(uintptr_t)(PAGE - 1)) == trapped_page
        ? PROT_READ : PROT_READ | PROT_WRITE;
}
uintptr_t ios_jit_anon_alias_lookup(uintptr_t address)
{
    if (guest && address >= guest && address - guest < PAGE) return alias_first + address - guest;
    if (guest && address >= guest + PAGE && address - guest - PAGE < PAGE)
        return alias_second ? alias_second + address - guest - PAGE : 0;
    return 0;
}
void ios_jit_anon_alias_note_write(unsigned long long address) { (void)address; ++writes; }
'''
C += alias + trapped + helper
C += r'''

static int set_state_error, set_state_calls, resumes;
static unsigned long long ios_stuck_fixed;
static arm_thread_state64_t kernel_state;
/* This stub models only success/failure of publishing the already-tested
 * state. It never pretends a failed set_state changed the target's PC. */
static int recovery_set_state(mach_port_t thread, int flavor, thread_state_t state, unsigned count)
{
    (void)thread; (void)flavor; (void)count; ++set_state_calls;
    if (set_state_error) return set_state_error;
    memcpy(&kernel_state, state, sizeof(kernel_state)); return KERN_SUCCESS;
}
static int recovery_resume(mach_port_t thread) { (void)thread; ++resumes; return 0; }
#define thread_set_state recovery_set_state
#define thread_resume recovery_resume
static int actual_caller(uint32_t insn, arm_thread_state64_t *state,
                         const arm_neon_state64_t *vector, int have_neon)
{
    arm_thread_state64_t st = *state;
    arm_neon_state64_t neon = *vector;
    mach_port_t thread = 1;
    uintptr_t pc = arm_thread_state64_get_pc(st);
'''
C += caller
C += r'''
    *state = st; return r;
}
#undef thread_set_state
#undef thread_resume

struct mapping { unsigned char *p, *rw; FILE *file; int kind; };
static unsigned char *reserve(size_t size)
{
    unsigned char *raw = mmap(NULL, size + PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(raw != MAP_FAILED);
    uintptr_t aligned = ((uintptr_t)raw + PAGE - 1) & ~(uintptr_t)(PAGE - 1);
    size_t prefix = aligned - (uintptr_t)raw, suffix = PAGE - prefix;
    if (prefix) assert(!munmap(raw, prefix));
    if (suffix) assert(!munmap((void *)(aligned + size), suffix));
    return (unsigned char *)aligned;
}
static struct mapping mapping(int kind)
{
    struct mapping m = {0};
    m.kind = kind; m.p = reserve(SPAN);
    if (!kind)
        assert(mmap(m.p, SPAN, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0) == m.p);
    else
    {
        m.file = tmpfile(); assert(m.file && !ftruncate(fileno(m.file), PAGE * 4));
        for (unsigned i = 0; i < 2; ++i)
        {
            off_t offset = (off_t)i * (kind == 1 ? PAGE : PAGE * 2);
            assert(mmap(m.p + i * PAGE, PAGE, PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_SHARED, fileno(m.file), offset) == m.p + i * PAGE);
        }
    }
    memset(m.p, 0x5a, SPAN);
    if (kind == 3)
    {
        m.rw = reserve(PAGE * 3);
        for (unsigned i = 0; i < 2; ++i)
            assert(mmap(m.rw + i * PAGE * 2, PAGE, PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_SHARED, fileno(m.file), i * PAGE * 2) == m.rw + i * PAGE * 2);
        /* RO models the nonwritable executable view without an entitlement or
         * executable temporary file. The same shared backing is actually used. */
        assert(!mprotect(m.p, SPAN, PROT_READ));
        guest = (uintptr_t)m.p; alias_first = (uintptr_t)m.rw; alias_second = (uintptr_t)m.rw + PAGE * 2;
    }
    return m;
}
static int protection(void *p)
{
    mach_vm_address_t address = (uintptr_t)p; mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info; mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    assert(mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&info, &count, &object) == KERN_SUCCESS);
    assert(address <= (uintptr_t)p && (uintptr_t)p < address + size);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    return info.protection;
}
static void destroy(struct mapping *m)
{
    guest = alias_first = alias_second = trapped_page = 0;
    assert(!munmap(m->p, SPAN));
    if (m->rw) assert(!munmap(m->rw, PAGE * 3));
    if (m->file) assert(!fclose(m->file));
}
static uint32_t indexed_pair(int pre)
{
    unsigned imm7 = pre ? 126 : 2; /* pre -32 / post +32, each Q element16 */
    return 0x28000000u | (2u << 30) | (1u << 26) | ((pre ? 3u : 1u) << 23)
        | (imm7 << 15) | (1u << 10) | (8u << 5);
}
static unsigned cases;
static void run(int kind, unsigned before_boundary, int indexed, int failure, int caller_mode)
{
    struct mapping m = mapping(kind);
    int pair = indexed == 1 || indexed == 2, reg_offset = indexed >= 3;
    unsigned bytes = pair ? 32 : 16;
    uintptr_t ea = (uintptr_t)m.p + PAGE - before_boundary;
    uint32_t insn = pair ? indexed_pair(indexed == 2) : reg_offset ?
        0x3ca06900u | ((indexed == 3 ? 29u : 30u) << 16) : 0x3d800500u;
    arm_thread_state64_t state, original;
    arm_neon_state64_t neon;
    memset(&state, 0, sizeof(state)); memset(&neon, 0, sizeof(neon));
    for (unsigned i = 0; i < 29; ++i) state.__x[i] = 0x150000000ull + i * 37;
    state.__x[8] = pair ? (indexed == 2 ? ea + 32 : ea) : ea - (reg_offset ? 8 : 16);
    /* Darwin has x[0..28], then separate FP/LR fields. Using Rm29/30 must
     * read those fields without indexing outside the x array. */
    state.__fp = state.__lr = 8;
    __darwin_arm_thread_state64_set_pc_fptr(state, (void *)(uintptr_t)0x1020);
    for (unsigned i = 0; i < 32; ++i) ((unsigned char *)&neon.__v[0])[i] = i * 7 + 3;
    original = state; writes = 0;
    if (failure == 1 || failure == 2)
        assert(!mprotect(m.p + PAGE, PAGE, failure == 1 ? PROT_READ : PROT_NONE));
    if (failure == 4) { assert(kind == 3); trapped_page = (uintptr_t)m.p + PAGE; }
    if (failure == 5) { assert(kind == 3); alias_second = 0; }
    int result;
    if (caller_mode)
    {
        kernel_state = original; set_state_calls = resumes = 0;
        set_state_error = caller_mode == 2 ? 5 : 0;
        result = actual_caller(insn, &state, &neon, failure != 3);
        assert(resumes == 1);
    }
    else result = ios_store_split_crossing(insn, &state, failure == 3 ? NULL : &neon, 0, 0, 0);
    if (failure == 1 || failure == 2) assert(!mprotect(m.p + PAGE, PAGE, PROT_READ | PROT_WRITE));
    int refused = failure != 0;
    if (refused)
    {
        assert(result == (failure == 3 ? 0 : -1));
        assert(!memcmp(&state, &original, sizeof(state)) && !writes);
        for (unsigned i = 0; i < SPAN; ++i) assert(m.p[i] == 0x5a);
        if (caller_mode) assert(!set_state_calls && !memcmp(&kernel_state, &original, sizeof(state)));
    }
    else
    {
        assert(result == (caller_mode == 2 ? -2 : 1));
        assert(writes == 2 && !memcmp((void *)ea, &neon.__v[0], bytes));
        for (unsigned i = 0; i < SPAN; ++i)
            if ((uintptr_t)m.p + i < ea || (uintptr_t)m.p + i >= ea + bytes) assert(m.p[i] == 0x5a);
        original.__x[8] = pair ? (indexed == 2 ? ea : ea + 32) : ea - (reg_offset ? 8 : 16);
        if (caller_mode)
        {
            assert(set_state_calls == 1);
            assert(arm_thread_state64_get_pc(kernel_state) == (caller_mode == 2 ? 0x1020 : 0x1024));
            __darwin_arm_thread_state64_set_pc_fptr(original, (void *)(uintptr_t)0x1024);
        }
        assert(!memcmp(&state, &original, sizeof(state)));
        if (m.file)
        {
            unsigned char file_page[PAGE];
            for (unsigned i = 0; i < 2; ++i)
            {
                off_t offset = (off_t)i * (kind == 1 ? PAGE : PAGE * 2);
                assert(pread(fileno(m.file), file_page, PAGE, offset) == PAGE);
                assert(!memcmp(file_page, m.p + i * PAGE, PAGE));
            }
            if (kind != 1)
            {
                /* Adjacent VA pages use file offsets0 and2*PAGE. The unused
                 * backing extent must not receive an alias-contiguous write. */
                assert(pread(fileno(m.file), file_page, PAGE, PAGE) == PAGE);
                for (unsigned i = 0; i < PAGE; ++i) assert(!file_page[i]);
            }
        }
    }
    if (kind == 3 && failure != 1 && failure != 2)
        assert(!(protection(m.p) & PROT_WRITE) && !(protection(m.p + PAGE) & PROT_WRITE));
    destroy(&m); ++cases;
}

#ifdef NATIVE_ARM_STATE
extern void recovery_original_store(void *, const void *);
extern char recovery_original_store_pc;
__asm__(".text\n.p2align 2\n.globl _recovery_original_store\n"
        "_recovery_original_store:\nmov x8,x0\nldr q0,[x1]\n"
        ".globl _recovery_original_store_pc\n_recovery_original_store_pc:\n"
        ".inst 0x3d800500\nret\n");
static sigjmp_buf fault_escape;
static volatile sig_atomic_t original_fault;
static uintptr_t original_pc, original_x8, original_far;
static unsigned char original_q0[16];
static void original_handler(int sig, siginfo_t *info, void *opaque)
{
    ucontext_t *context = opaque;
    original_fault = sig;
    original_pc = arm_thread_state64_get_pc(context->uc_mcontext->__ss);
    original_x8 = context->uc_mcontext->__ss.__x[8];
    original_far = (uintptr_t)info->si_addr;
    for (unsigned i = 0; i < 16; ++i)
        original_q0[i] = ((const unsigned char *)&context->uc_mcontext->__ns.__v[0])[i];
    /* Exit only the test-owned operation. Do not modify or advance its saved
     * instruction PC or pretend that the inaccessible store completed. */
    siglongjmp(fault_escape, 1);
}
static void original_fault_then_refusal(int kind, unsigned split)
{
    struct mapping m = mapping(kind);
    uintptr_t ea = (uintptr_t)m.p + PAGE - split;
    unsigned char payload[16];
    for (unsigned i = 0; i < sizeof(payload); ++i) payload[i] = 0x80 + i;
    assert(!mprotect(m.p + PAGE, PAGE, PROT_READ));
    struct sigaction action = {0}, old_segv, old_bus;
    action.sa_sigaction = original_handler; action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGSEGV, &action, &old_segv) && !sigaction(SIGBUS, &action, &old_bus));
    original_fault = 0;
    if (!sigsetjmp(fault_escape, 1))
    {
        recovery_original_store((void *)(ea - 16), payload);
        assert(!"inaccessible original store must genuinely fault");
    }
    assert(original_fault == SIGSEGV || original_fault == SIGBUS);
    assert(original_pc == (uintptr_t)&recovery_original_store_pc && original_x8 == ea - 16);
    assert(original_far >= (uintptr_t)m.p + PAGE && original_far < ea + sizeof(payload));
    assert(!memcmp(original_q0, payload, sizeof(payload)));
    unsigned prefix_changed = 0;
    for (unsigned i = 0; i < split; ++i) prefix_changed += ((unsigned char *)ea)[i] != 0x5a;
    printf("OBSERVATION original STR Q kind=%d split=%u/%u signal=%d prefix-changed=%u/%u; no hardware cross-page atomicity assumed\n",
           kind, split, 16 - split, original_fault, prefix_changed, split);
    assert(!sigaction(SIGSEGV, &old_segv, NULL) && !sigaction(SIGBUS, &old_bus, NULL));
    /* Separate the helper assertion from any architecture-permitted partial
     * effect of the original instruction. Only the first page needs reset. */
    memset(m.p, 0x5a, PAGE);
    arm_thread_state64_t state, before;
    arm_neon_state64_t neon;
    memset(&state, 0, sizeof(state)); memset(&neon, 0, sizeof(neon));
    state.__x[8] = ea - 16;
    __darwin_arm_thread_state64_set_pc_fptr(state, (void *)(uintptr_t)&recovery_original_store_pc);
    memcpy(&neon.__v[0], payload, sizeof(payload)); before = state; writes = 0;
    assert(ios_store_split_crossing(0x3d800500u, &state, &neon, 0, 0, 0) == -1);
    assert(!writes && !memcmp(&state, &before, sizeof(state)));
    for (unsigned i = 0; i < SPAN; ++i) assert(m.p[i] == 0x5a);
    destroy(&m);
}
#endif
int main(void)
{
    long host_page = sysconf(_SC_PAGESIZE);
    assert(host_page > 0 && PAGE % host_page == 0);
#ifdef NATIVE_ARM_STATE
    assert(*(const uint32_t *)&recovery_original_store_pc == 0x3d800500u);
    for (unsigned split = 4; split <= 6; split += 2)
    { original_fault_then_refusal(0, split); original_fault_then_refusal(2, split); }
#else
    puts("SKIP original ARM64 STR Q signal context: native Darwin ARM64 host required");
#endif
    for (int kind = 0; kind < 4; ++kind)
    for (unsigned split = 4; split <= 6; split += 2)
    for (int indexed = 0; indexed < 5; ++indexed)
    {
        run(kind, split, indexed, 0, 0);
        if (kind != 3) { run(kind, split, indexed, 1, 0); run(kind, split, indexed, 2, 0); }
        run(kind, split, indexed, 3, 0);
        if (kind == 3) { run(kind, split, indexed, 4, 0); run(kind, split, indexed, 5, 0); }
        run(kind, split, indexed, 0, 1);
        run(kind, split, indexed, 0, 2);
        run(kind, split, indexed, 3, 1);
        if (kind != 3) run(kind, split, indexed, 1, 1);
    }
    printf("PASS %u production recovery cases: native-page=%ld boundary=%d; shared extents, byte guards, genuine VM protection, no partial refusal, writeback, caller PC publication\n", cases, host_page, PAGE);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-cross-page-recovery-') as directory:
    source, binary = Path(directory) / 'recovery.c', Path(directory) / 'recovery'
    source.write_text(C)
    flags = ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
             '-fno-omit-frame-pointer'] if args.sanitize else []
    subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    *flags, str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=60)
print('PASS real Darwin Mach VM queries' if platform.system() == 'Darwin'
      else 'NOTE Linux permission/readback coverage only; Darwin/iOS validation remains separate')
