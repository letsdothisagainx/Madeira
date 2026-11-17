#!/usr/bin/env python3
"""Run the observed ARM64 store on real mappings, without skipping its PC.

This is a native-host reproducer. Passing on macOS is not proof that iOS's
file-backed fault path behaves identically. Every native case runs in a child
with an external deadline, including cases in which the kernel retries a store.
"""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-arm64', action='store_true')
args = parser.parse_args()
if platform.machine().lower() not in ('arm64', 'aarch64'):
    if args.require_arm64:
        raise SystemExit('FAIL native ARM64 execution is required')
    print('SKIP native STR Q reproducer: host is not ARM64')
    raise SystemExit(0)

C = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif
#include <unistd.h>
#ifdef __APPLE__
#include <mach/arm/thread_status.h>
#define ASM_SYMBOL(x) "_" x
#else
#define ASM_SYMBOL(x) x
#endif

enum { BOUNDARY = 16384, REGION = BOUNDARY * 3 };
extern void observed_store(void *, const void *);
extern void observed_loop(const void *, void *, size_t, void *);
extern void structure_store(void *, const void *);
extern void structure_loop(const void *, void *, size_t, void *);
extern char observed_store_pc, observed_loop_store_pc, structure_store_pc, structure_loop_store_pc;

/* These are the actual sampled store and copy-loop instructions. x28 is
 * restored for the native C ABI; the live FEX doorbell/BRK is retained. */
__asm__(
".text\n.p2align 2\n.globl " ASM_SYMBOL("observed_store") "\n"
ASM_SYMBOL("observed_store") ":\n"
"mov x8,x0\nldr q0,[x1]\n.globl " ASM_SYMBOL("observed_store_pc") "\n"
ASM_SYMBOL("observed_store_pc") ":\n.inst 0x3d800500\nret\n"
".p2align 2\n.globl " ASM_SYMBOL("observed_loop") "\n"
ASM_SYMBOL("observed_loop") ":\n"
"str x28,[sp,#-16]!\nmov x8,x1\nadd x1,x1,x2\nmov x28,x3\n"
"1:\nldr q0,[x0]\nadd x0,x0,#0x20\nstr q0,[x8]\nldur q0,[x0,#-0x10]\n"
".globl " ASM_SYMBOL("observed_loop_store_pc") "\n"
ASM_SYMBOL("observed_loop_store_pc") ":\n.inst 0x3d800500\n"
"add x8,x8,#0x20\ncmp x8,x1\nldr w11,[x28,#0x5e8]\n"
"cbz w11,2f\nbrk #0xcafe\n2:\nb.lo 1b\nldr x28,[sp],#16\nret\n"
".p2align 2\n.globl " ASM_SYMBOL("structure_store") "\n"
ASM_SYMBOL("structure_store") ":\nmov x8,x0\nldr q0,[x1]\nadd x9,x8,#16\n"
".globl " ASM_SYMBOL("structure_store_pc") "\n"
ASM_SYMBOL("structure_store_pc") ":\nst1 {v0.16b},[x9]\nret\n"
".p2align 2\n.globl " ASM_SYMBOL("structure_loop") "\n"
ASM_SYMBOL("structure_loop") ":\n"
"str x28,[sp,#-16]!\nmov x8,x1\nadd x1,x1,x2\nmov x28,x3\n"
"3:\nldr q0,[x0]\nadd x0,x0,#0x20\nstr q0,[x8]\nldur q0,[x0,#-0x10]\nadd x9,x8,#16\n"
".globl " ASM_SYMBOL("structure_loop_store_pc") "\n"
ASM_SYMBOL("structure_loop_store_pc") ":\nst1 {v0.16b},[x9]\n"
"add x8,x8,#0x20\ncmp x8,x1\nldr w11,[x28,#0x5e8]\n"
"cbz w11,4f\nbrk #0xcafe\n4:\nb.lo 3b\nldr x28,[sp],#16\nret\n");

static sigjmp_buf escape;
static volatile sig_atomic_t faults, bad_state, retry_access, fault_signal, fault_code;
static uintptr_t wanted_pc, wanted_x8, actual_pc, actual_far;
static unsigned char actual_q0[16], expected_q0[16];
static void *restore_page;
static size_t restore_length;
static uintptr_t requested_hint;
static unsigned char *fault_prefix;
static unsigned fault_prefix_size, fault_prefix_changed, initial_byte;

static uint64_t ticks(void)
{
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void on_fault(int sig, siginfo_t *info, void *opaque)
{
    ucontext_t *uc = opaque;
    uintptr_t pc, x8;
    const unsigned char *q0;
    int saved_errno = errno;
    fault_signal = sig; fault_code = info->si_code;
#ifdef __APPLE__
    pc = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    x8 = uc->uc_mcontext->__ss.__x[8];
    q0 = (const unsigned char *)&uc->uc_mcontext->__ns.__v[0];
#else
    pc = uc->uc_mcontext.pc;
    x8 = uc->uc_mcontext.regs[8];
    /* Linux reserves FPSIMD context records in this area. The native Linux
     * branch validates PC/base and byte results; Darwin checks Q0 as well. */
    q0 = expected_q0;
#endif
    actual_pc = pc; actual_far = (uintptr_t)info->si_addr;
    for (unsigned i = 0; i < 16; ++i) actual_q0[i] = q0[i];
    for (unsigned i = 0; i < fault_prefix_size; ++i)
        fault_prefix_changed += fault_prefix[i] != initial_byte;
    if ((wanted_pc && (pc != wanted_pc || x8 != wanted_x8)) || ++faults > 2) bad_state = 1;
    if (retry_access && !bad_state && faults == 1)
    {
        /* Test-owned protection only. Return with the original saved PC and
         * vector/register state so hardware retries the unfinished store. */
        if (mprotect(restore_page, restore_length, PROT_READ | PROT_WRITE)) _exit(91);
        errno = saved_errno;
        return;
    }
    siglongjmp(escape, 1);
}

static unsigned char *aligned_mapping(size_t length, uintptr_t hint)
{
    if (hint)
    {
        void *held = mmap((void *)hint, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (held == (void *)hint) return held;
        /* A POSIX hint never overwrites existing memory. Only our successfully
         * reserved span is subsequently replaced with MAP_FIXED mappings. */
        if (held != MAP_FAILED) assert(!munmap(held, length));
        printf("NOTE high-VA hint=%#llx unavailable; using an owned alternate reservation\n", (unsigned long long)hint);
    }
    size_t reserve = length + BOUNDARY;
    unsigned char *raw = mmap(NULL, reserve, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(raw != MAP_FAILED);
    uintptr_t aligned = ((uintptr_t)raw + BOUNDARY - 1) & ~(uintptr_t)(BOUNDARY - 1);
    size_t head = aligned - (uintptr_t)raw, tail = reserve - head - length;
    if (head) assert(!munmap(raw, head));
    if (tail) assert(!munmap((void *)(aligned + length), tail));
    return (unsigned char *)aligned;
}

static unsigned char *mapping(int kind, int *fd_out)
{
    unsigned char *p = aligned_mapping(REGION, requested_hint);
    int fd = -1;
    if (!kind)
        assert(mmap(p, REGION, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == p);
    else
    {
        char name[] = "/tmp/madeira-cross-store-XXXXXX";
        fd = mkstemp(name); assert(fd >= 0); assert(!unlink(name));
        assert(!ftruncate(fd, BOUNDARY * 6));
        /* Initialize the pager through the descriptor BEFORE any user mapping
         * is touched. Cold cases then execute the store as their first write. */
        unsigned char backing[BOUNDARY * 6]; memset(backing, 0xcc, sizeof(backing));
        assert(pwrite(fd, backing, sizeof(backing), 0) == (ssize_t)sizeof(backing));
        if (kind == 1)
            assert(mmap(p, REGION, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0) == p);
        else
            for (unsigned i = 0; i < 3; ++i)
                assert(mmap(p + i * BOUNDARY, BOUNDARY, PROT_READ | PROT_WRITE,
                            MAP_FIXED | MAP_SHARED, fd, i * BOUNDARY * 2) == p + i * BOUNDARY);
    }
    *fd_out = fd;
    return p;
}

static void split_control(unsigned char *dst, const unsigned char *src, size_t size)
{
    /* An independent byte-bounded control, not a replacement guest operation. */
    while (size)
    {
        size_t part = BOUNDARY - ((uintptr_t)dst & (BOUNDARY - 1));
        if (part > size) part = size;
        for (size_t i = 0; i < part; ++i) ((volatile unsigned char *)dst)[i] = src[i];
        dst += part; src += part; size -= part;
    }
}

static void operation(int variant, int loop, unsigned char *src, unsigned char *dst,
                      size_t span, size_t written, void *frame)
{
    if (variant == 2) split_control(loop ? dst : dst + 16, loop ? src : src + 16, written);
    else if (loop)
        (variant ? structure_loop : observed_loop)(src, dst, span, frame);
    else (variant ? structure_store : observed_store)(dst, src + 16);
}

static void run_case(int kind, int which, int loop, int mode, int cold, int variant)
{
    int fd;
    unsigned char *dst_map = mapping(kind, &fd), *src_map = aligned_mapping(REGION, 0);
    assert(mprotect(src_map, REGION, PROT_READ | PROT_WRITE) == 0);
    unsigned char *src = src_map + (which ? 0x2f68 : 0x0d8e);
    unsigned char *boundary = dst_map + BOUNDARY;
    unsigned char *dst = boundary - (which ? 20 : 22);
    size_t span = which ? 8268 : 22;
    size_t written = loop ? ((span + 31) & ~(size_t)31) : 16;
    unsigned char *first = loop ? dst : dst + 16;
    unsigned char *payload = loop ? src : src + 16;
    _Alignas(16) unsigned char frame[0x600] = {0};
    for (unsigned i = 0; i < REGION; ++i) src_map[i] = 1 + (i * 19 + (i >> 7)) % 127;
    initial_byte = cold && !kind ? 0 : 0xcc;
    if (!cold) memset(dst_map, initial_byte, REGION);
    wanted_pc = variant == 2 ? 0 : (uintptr_t)(variant ?
        (loop ? &structure_loop_store_pc : &structure_store_pc) :
        (loop ? &observed_loop_store_pc : &observed_store_pc));
    wanted_x8 = (uintptr_t)dst;
    memcpy(expected_q0, src + 16, 16);
    faults = bad_state = fault_signal = fault_code = 0; retry_access = mode == 2;
    fault_prefix = dst + 16; fault_prefix_size = boundary - fault_prefix; fault_prefix_changed = 0;
    restore_page = boundary; restore_length = BOUNDARY;
    if (mode) assert(!mprotect(boundary, BOUNDARY, PROT_NONE));
    uint64_t started = ticks();
    if (!sigsetjmp(escape, 1))
    {
        operation(variant, loop, src, dst, span, written, frame);
        assert(mode != 1);
    }
    else assert(mode == 1 && faults == 1 && !bad_state);
    uint64_t elapsed = ticks() - started;
    if (mode)
    {
        assert(faults == 1 && !bad_state && (!wanted_pc || actual_pc == wanted_pc));
        if (variant != 2) assert(!memcmp(actual_q0, expected_q0, 16));
        assert(actual_far >= (uintptr_t)(dst + 16) && actual_far < (uintptr_t)(dst + 32));
        assert(!mprotect(boundary, BOUNDARY, PROT_READ | PROT_WRITE));
    }
    else assert(!faults);
    if (mode != 1)
    {
        assert(!memcmp(first, payload, written));
        for (unsigned i = 0; i < (unsigned)(first - dst_map); ++i) assert(dst_map[i] == initial_byte);
        for (size_t i = first - dst_map + written; i < REGION; ++i) assert(dst_map[i] == initial_byte);
    }
    if (!mode && !cold)
    {
        const unsigned repeats = loop ? 1000 : 100000;
        started = ticks();
        for (unsigned i = 0; i < repeats; ++i)
            operation(variant, loop, src, dst, span, written, frame);
        uint64_t native = ticks() - started;
        memset(first, 0xcc, written);
        started = ticks();
        for (unsigned i = 0; i < repeats; ++i) split_control(first, payload, written);
        uint64_t split = ticks() - started;
        assert(!memcmp(first, payload, written));
        printf("PERF kind=%d case=%c loop=%d variant=%d bytes=%zu native-ns=%.2f byte-control-ns=%.2f\n",
               kind, which ? 'B' : 'A', loop, variant, written, (double)native/repeats, (double)split/repeats);
    }
    printf("PASS kind=%d case=%c loop=%d variant=%d cold=%d base=%#llx hint=%#llx mode=%s actual-bytes=%zu faults=%d signal=%d code=%d fault-prefix-changed=%u/%u elapsed-us=%.2f pc=%#llx far=%#llx\n",
           kind, which ? 'B' : 'A', loop, variant, cold, (unsigned long long)dst_map, (unsigned long long)requested_hint,
           mode == 2 ? "restore-and-retry" : mode ? "inaccessible" : "writable",
           written, faults, fault_signal, fault_code, fault_prefix_changed, fault_prefix_size,
           (double)elapsed/1000, (unsigned long long)actual_pc, (unsigned long long)actual_far);
    assert(!munmap(dst_map, REGION)); assert(!munmap(src_map, REGION));
    if (fd >= 0) close(fd);
}

int main(void)
{
    assert(*(const uint32_t *)&observed_store_pc == 0x3d800500u);
    assert(*(const uint32_t *)&observed_loop_store_pc == 0x3d800500u);
    printf("native-host-page-size=%ld target-boundary=%d machine-instruction=3d800500\n", sysconf(_SC_PAGESIZE), BOUNDARY);
    fflush(stdout);
    for (int high = 0; high < 2; ++high)
    for (int cold = 0; cold < 2; ++cold)
    for (int variant = 0; variant < 3; ++variant)
    for (int kind = 0; kind < 3; ++kind)
    for (int which = 0; which < 2; ++which)
    for (int loop = 0; loop < 2; ++loop)
    for (int mode = 0; mode < 3; ++mode)
    {
        pid_t child = fork(); assert(child >= 0);
        if (!child)
        {
            struct sigaction sa; memset(&sa, 0, sizeof(sa));
            sa.sa_sigaction = on_fault; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask);
            assert(!sigaction(SIGSEGV, &sa, NULL) && !sigaction(SIGBUS, &sa, NULL));
            requested_hint = high ? (which ? UINT64_C(0x71721e4000) : UINT64_C(0x710d6ac000)) : 0;
            run_case(kind, which, loop, mode, cold, variant); fflush(stdout); _exit(0);
        }
        int status = 0, done = 0;
        for (unsigned i = 0; i < 500; ++i)
        {
            pid_t got = waitpid(child, &status, WNOHANG); assert(got >= 0);
            if (got) { done = 1; break; }
            usleep(10000);
        }
        if (!done)
        {
            kill(child, SIGKILL); assert(waitpid(child, &status, 0) == child);
            fprintf(stderr, "FAIL deadline kind=%d case=%c loop=%d mode=%d; native operation did not complete\n", kind, which ? 'B' : 'A', loop, mode);
            return 1;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status))
        {
            fprintf(stderr, "FAIL child kind=%d case=%c loop=%d mode=%d status=%d\n", kind, which ? 'B' : 'A', loop, mode, status);
            return 1;
        }
    }
    puts("PASS exact ARM64 STR Q / observed loop: anonymous, file-shared, noncontiguous shared extents; valid writes, genuine faults, unchanged-PC recovery, byte guards");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-cross-page-vector-') as directory:
    source, binary = Path(directory) / 'repro.c', Path(directory) / 'repro'
    source.write_text(C)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=300)
