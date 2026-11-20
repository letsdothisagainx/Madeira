#!/usr/bin/env python3
"""Exercise the actual bounded self-suspend observer with safe OS adapters.

This fixture records only observer behavior. It does not execute CS2, emulate a
successful resume, or claim that the on-device suspension cause is established.
The separate suspend/handle fixture exercises real resumed thread execution.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'build/ntdll-unix/self_suspend_trace.h'

FIXTURE = r'''
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "self_suspend_protocol.h"

typedef uint64_t mach_vm_size_t;
typedef uintptr_t mach_vm_address_t;
#define KERN_SUCCESS 0
struct fixture_teb_type {
    struct { void *StackBase, *StackLimit; } Tib;
    void *Peb;
    struct { void *UniqueProcess, *UniqueThread; } ClientId;
};
static _Thread_local struct fixture_teb_type fixture_teb;
static _Thread_local struct fixture_teb_type fixture_reused_teb;
static _Thread_local struct fixture_teb_type *fixture_current_teb;
static struct fixture_teb_type *NtCurrentTeb(void) { return fixture_current_teb ? fixture_current_teb : &fixture_teb; }
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char output[131072];
static size_t output_used;
static unsigned logs, reads, maps, clocks, forbidden;
struct readable_range { uintptr_t begin; size_t bytes; };
static struct readable_range ranges[8];
static unsigned range_count;
static int short_read;

static int fixture_dprintf(int fd, const char *format, ...)
{
    assert(fd == 2 && !__atomic_load_n(&forbidden, __ATOMIC_RELAXED));
    pthread_mutex_lock(&log_mutex);
    ++logs;
    va_list ap;
    va_start(ap, format);
    int size = vsnprintf(output + output_used, sizeof(output) - output_used, format, ap);
    va_end(ap);
    assert(size >= 0 && (size_t)size < sizeof(output) - output_used);
    output_used += (size_t)size;
    pthread_mutex_unlock(&log_mutex);
    errno = EBADF;
    return size;
}
static int fixture_clock_gettime(clockid_t clock, struct timespec *ts)
{
    assert(clock == CLOCK_MONOTONIC && !__atomic_load_n(&forbidden, __ATOMIC_RELAXED));
    ts->tv_sec = 1;
    ts->tv_nsec = __atomic_add_fetch(&clocks, 1, __ATOMIC_RELAXED);
    errno = EIO;
    return 0;
}
static int mach_task_self(void) { return 7; }
static int mach_vm_read_overwrite(int task, mach_vm_address_t address, size_t bytes,
                                 mach_vm_address_t out, mach_vm_size_t *got)
{
    assert(task == 7 && !__atomic_load_n(&forbidden, __ATOMIC_RELAXED));
    __atomic_add_fetch(&reads, 1, __ATOMIC_RELAXED);
    *got = 0;
    errno = EFAULT;
    for (unsigned i = 0; i < range_count; ++i) {
        if (address >= ranges[i].begin && bytes <= ranges[i].bytes &&
            address - ranges[i].begin <= ranges[i].bytes - bytes) {
            if (short_read) { *got = bytes ? bytes - 1 : 0; return KERN_SUCCESS; }
            memcpy((void *)out, (const void *)address, bytes);
            *got = bytes;
            return KERN_SUCCESS;
        }
    }
    return 1;
}
uint64_t ios_jit_reverse_translate(uint64_t address, uint64_t *base)
{
    assert(!__atomic_load_n(&forbidden, __ATOMIC_RELAXED));
    __atomic_add_fetch(&maps, 1, __ATOMIC_RELAXED);
    if (address >= UINT64_C(0x7c00001000) && address < UINT64_C(0x7c00009000)) {
        if (base) *base = UINT64_C(0x7100000000);
        return UINT64_C(0x7100000000) + address - UINT64_C(0x7c00000000);
    }
    if (base) *base = 0;
    return 0;
}
unsigned long long ios_jit_module_base_for_va(unsigned long long address, unsigned long long *size)
{
    assert(!__atomic_load_n(&forbidden, __ATOMIC_RELAXED));
    __atomic_add_fetch(&maps, 1, __ATOMIC_RELAXED);
    if (address >= UINT64_C(0x7100001000) && address < UINT64_C(0x7100009000)) {
        if (size) *size = 0x10000;
        return UINT64_C(0x7100000000);
    }
    if (size) *size = 0;
    return 0;
}

static void *fixture_heap_forbidden(const char *kind) __attribute__((unused));
static void *fixture_heap_forbidden(const char *kind)
{
    (void)kind;
    assert(!"self-suspend observer must not allocate or free heap storage");
    abort();
}

#define dprintf fixture_dprintf
#define clock_gettime fixture_clock_gettime
#define malloc(...) fixture_heap_forbidden("malloc")
#define calloc(...) fixture_heap_forbidden("calloc")
#define realloc(...) fixture_heap_forbidden("realloc")
#define free(...) fixture_heap_forbidden("free")
#include "self_suspend_trace.h"
#undef free
#undef realloc
#undef calloc
#undef malloc
#undef clock_gettime
#undef dprintf

static void reset(void)
{
    memset(ios_self_suspend_watches, 0, sizeof(ios_self_suspend_watches));
    ios_self_suspend_limit_reported = ios_self_suspend_bad_resume_reports = 0;
    output_used = logs = reads = maps = clocks = forbidden = range_count = short_read = 0;
    output[0] = 0;
    fixture_current_teb = NULL;
    memset(&fixture_teb, 0, sizeof(fixture_teb));
}
static unsigned occurrences(const char *needle)
{
    unsigned n = 0;
    for (const char *p = output; (p = strstr(p, needle)); p += strlen(needle)) ++n;
    return n;
}
static void readable(void *p, size_t bytes)
{
    assert(range_count < sizeof(ranges) / sizeof(ranges[0]));
    ranges[range_count++] = (struct readable_range){(uintptr_t)p, bytes};
}
static struct madeira_suspend_identity_reply identity(unsigned pid, unsigned tid)
{
    return (struct madeira_suspend_identity_reply){MADEIRA_SUSPEND_IDENTITY_MAGIC, 1, tid, pid};
}
static void pure_begin(unsigned pid, unsigned tid, uintptr_t teb)
{
    const unsigned before_logs = logs, before_reads = reads, before_maps = maps, before_clocks = clocks;
    forbidden = 1; errno = 71;
    ios_self_suspend_server_begin(pid, tid, teb, pid, tid);
    assert(errno == 71 && logs == before_logs && reads == before_reads && maps == before_maps && clocks == before_clocks);
    forbidden = 0;
}

static void bounded_targets(void)
{
    reset();
    const struct ios_self_suspend_snapshot empty = {0};
    unsigned tickets = 0;
    for (unsigned i = 0; i < 32; ++i) {
        struct madeira_suspend_identity_reply id = identity(0x20 + i, 0x30);
        pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
        errno = 73;
        unsigned ticket = ios_self_suspend_client_begin(&id, UINTPTR_MAX - 1, 0, 0, &empty, 1);
        assert(errno == 73);
        tickets += !!ticket;
        assert(!ios_self_suspend_client_begin(&id, UINTPTR_MAX - 1, 0, 0, &empty, 1));
    }
    assert(tickets == 16 && occurrences("event=client-result") == 16);
    assert(occurrences("event=capture-limit") == 1 && !reads && !maps);
    for (unsigned i = 0; i < 16; ++i) assert(ios_self_suspend_watches[i].state == 2);
}

static void frame_and_candidates(void)
{
    reset();
    unsigned char frame[0x110] = {0};
    uint64_t stack[80] = {0};
    const uint64_t pc = UINT64_C(0x7c00001234), lr = UINT64_C(0x7100002345);
    uint64_t sp = (uintptr_t)stack, fp = sp + 16;
    memcpy(frame + 0xe8, &fp, 8); memcpy(frame + 0xf0, &lr, 8);
    memcpy(frame + 0xf8, &sp, 8); memcpy(frame + 0x100, &pc, 8);
    stack[0] = UINT64_C(0x544552434553); /* Non-code secret bytes must never be emitted. */
    stack[1] = UINT64_C(0x7c00003456); stack[2] = UINT64_C(0x7100004567);
    stack[3] = UINT64_C(0x7c00000080); /* Outside executable-map adapter. */
    for (unsigned i = 4; i < 80; ++i) stack[i] = pc + i;
    readable(frame, sizeof(frame)); readable(stack, sizeof(stack));
    struct ios_self_suspend_snapshot capture;
    errno = 74; ios_self_suspend_capture(&capture, frame);
    assert(errno == 74 && capture.valid && capture.pc == pc && capture.lr == lr && capture.sp == sp && capture.fp == fp);
    struct madeira_suspend_identity_reply id = identity(0x32c, 0x330);
    pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
    errno = 75;
    assert(ios_self_suspend_client_begin(&id, 0x84, 0, 2, &capture, 1));
    assert(errno == 75 && occurrences("kind=stack-candidate") == 8);
    assert(strstr(output, "rva=0x1234") && strstr(output, "rva=0x3456"));
    assert(!strstr(output, "544552434553") && !strstr(output, "7c00000080"));
    struct ios_self_suspend_snapshot copy = capture;
    ios_self_suspend_client_wait(1, 0);
    assert(!memcmp(&copy, &capture, sizeof(copy)) && !memcmp(frame + 0x100, &pc, 8));
    unsigned n = reads;
    assert(!ios_self_suspend_client_begin(&id, 0x84, 0, 2, &capture, 1) && reads == n);
    reset();
    memset(&capture, 0xff, sizeof(capture));
    errno = 76; ios_self_suspend_capture(&capture, (void *)1);
    assert(errno == 76 && !capture.valid && !capture.pc && !capture.sp);
    readable(frame, sizeof(frame)); short_read = 1;
    ios_self_suspend_capture(&capture, frame); assert(!capture.valid);
    short_read = 0;
    id = identity(0x32c, 0x330); pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
    assert(ios_self_suspend_client_begin(&id, 0x84, 0, 0, &capture, 1));
    assert(strstr(output, "frame-valid=0") && !strstr(output, "event=caller-address"));

    reset();
    memset(stack, 0, sizeof(stack));
    for (unsigned i = 64; i < 80; ++i) stack[i] = pc;
    readable(stack, sizeof(stack));
    capture = (struct ios_self_suspend_snapshot){pc, 0, (uintptr_t)stack, 0, 1};
    pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
    assert(ios_self_suspend_client_begin(&id, 0x84, 0, 0, &capture, 1));
    assert(reads == 64 && !occurrences("kind=stack-candidate"));
    reset();
    capture.sp = 1;
    pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
    assert(ios_self_suspend_client_begin(&id, 0x84, 0, 0, &capture, 1));
    assert(reads == 1 && !occurrences("kind=stack-candidate"));
}

static void early_resume_and_nesting(void)
{
    reset();
    const struct ios_self_suspend_snapshot empty = {0};
    struct madeira_suspend_identity_reply id = identity(0x32c, 0x330);
    pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
    errno = 77;
    ios_self_suspend_server_resume(id.pid, id.tid, (uintptr_t)&fixture_teb, id.pid, 0x444, 1, 0, 0, 3);
    assert(errno == 77 && occurrences("event=server-resume") == 1);
    assert(strstr(output, "by-tid=0444") && strstr(output, "count=1->0") && strstr(output, "process-suspend=3"));
    unsigned ticket = ios_self_suspend_client_begin(&id, 0x88, 0, 0, &empty, 1);
    assert(ticket == 1);
    const unsigned before_resumes = ios_self_suspend_watches[0].resumes;
    const unsigned before_old = ios_self_suspend_watches[0].last_old;
    const unsigned before_new = ios_self_suspend_watches[0].last_new;
    errno = 78; ios_self_suspend_client_wait(ticket, 0);
    assert(errno == 78 && strstr(output, "observed-resumes=1 last-count=1->0"));
    assert(ios_self_suspend_watches[0].resumes == before_resumes &&
           ios_self_suspend_watches[0].last_old == before_old && ios_self_suspend_watches[0].last_new == before_new);
    ios_self_suspend_client_wait(ticket, 0xc0000001);
    assert(occurrences("event=wait-return") == 1);

    reset(); pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
    forbidden = 1; errno = 79;
    ios_self_suspend_server_resume(id.pid, id.tid, (uintptr_t)&fixture_teb, id.pid, 0x444, 4, 3, 1, 0);
    assert(errno == 79 && !logs && !reads && !maps && !clocks);
    forbidden = 0;
    for (unsigned i = 0; i < 15; ++i)
        ios_self_suspend_server_resume(id.pid, id.tid, (uintptr_t)&fixture_teb, id.pid, 0x444, 20 - i, 19 - i, 0, 0);
    assert(occurrences("event=server-resume") == 8);
    ios_self_suspend_server_resume(id.pid, id.tid, (uintptr_t)&fixture_teb, id.pid, 0x444, 1, 0, 0, 0);
    assert(occurrences("event=server-resume") == 9 && occurrences("first-final=1") == 1);
    for (unsigned i = 0; i < 50; ++i)
        ios_self_suspend_server_resume(id.pid, id.tid, (uintptr_t)&fixture_teb, id.pid, 0x444, 1, 0, 0, 0);
    assert(occurrences("event=server-resume") == 9);
    for (unsigned i = 0; i < 20; ++i) {
        errno = 80;
        ios_self_suspend_client_resume(&id, 0x99, 0xc0000008, 7, 1);
        assert(errno == 80);
    }
    assert(occurrences("event=resume-api-failure") == 8);
}

static void *concurrent_client(void *argument)
{
    unsigned index = (unsigned)(uintptr_t)argument;
    struct madeira_suspend_identity_reply id = identity(0x100 + index, 0x44);
    const uintptr_t target_teb = (uintptr_t)&fixture_teb;
    /* Publish each target under a distinct pid despite identical numeric tid. */
    ios_self_suspend_server_begin(id.pid, id.tid, target_teb, id.pid, id.tid);
    struct ios_self_suspend_snapshot empty = {0};
    for (unsigned i = 0; i < 1000; ++i) {
        errno = 81;
        ios_self_suspend_server_resume(id.pid, id.tid, target_teb, 0x200 + index, 0x44, 1, 0, 0, index);
        assert(errno == 81);
    }
    unsigned ticket = ios_self_suspend_client_begin(&id, 0x88, 0, 0, &empty, 1);
    assert(ticket);
    struct ios_self_suspend_watch *w = &ios_self_suspend_watches[ticket - 1];
    assert(w->pid == id.pid && w->tid == id.tid && w->teb == target_teb && w->resumes == 1000);
    ios_self_suspend_client_wait(ticket, 0);
    return NULL;
}
static void concurrent_process_identity(void)
{
    reset();
    /* Wine pseudo-processes can publish the same numeric TID and TEB address;
     * the process identity must still select its own immutable watcher. */
    const struct ios_self_suspend_snapshot empty = {0};
    for (unsigned i = 0; i < 4; ++i) {
        struct madeira_suspend_identity_reply id = identity(0x80 + i, 0x44);
        pure_begin(id.pid, id.tid, (uintptr_t)&fixture_teb);
        unsigned ticket = ios_self_suspend_client_begin(&id, 0x88, 0, 0, &empty, 1);
        assert(ticket == i + 1);
        assert(ios_self_suspend_watches[ticket - 1].pid == id.pid);
    }
    reset();
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_create(&workers[i], NULL, concurrent_client, (void *)(uintptr_t)i));
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(workers[i], NULL));
    assert(occurrences("event=client-result") == 4 && occurrences("event=wait-return") == 4);
    assert(occurrences("event=server-resume") == 32);
    /* A resume for the same numeric tid in an unrelated process is not attributed. */
    unsigned n = logs;
    ios_self_suspend_server_resume(0x999, 0x44, 0, 0x999, 0x55, 1, 0, 0, 0);
    assert(logs == n);

    reset();
    struct madeira_suspend_identity_reply reused = identity(0x32c, 0x330);
    pure_begin(reused.pid, reused.tid, (uintptr_t)&fixture_teb);
    assert(ios_self_suspend_client_begin(&reused, 0x88, 0, 0, &empty, 1) == 1);
    fixture_current_teb = &fixture_reused_teb;
    pure_begin(reused.pid, reused.tid, (uintptr_t)&fixture_reused_teb);
    assert(ios_self_suspend_client_begin(&reused, 0x88, 0, 0, &empty, 1) == 2);
    ios_self_suspend_server_resume(reused.pid, reused.tid, (uintptr_t)&fixture_reused_teb,
                                   reused.pid, 0x444, 1, 0, 0, 0);
    assert(ios_self_suspend_watches[0].resumes == 0 && ios_self_suspend_watches[1].resumes == 1);
}
int main(void)
{
    bounded_targets(); frame_and_candidates(); early_resume_and_nesting(); concurrent_process_identity();
    puts("PASS actual self-suspend observer: bounded16 targets, one-shot control/candidate-only capture, alias mapping, read failures, errno, early/nested/final resumes, held no-logging, process identity and passive wait return");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-self-suspend-trace-') as directory:
    temp = Path(directory)
    source, executable = temp / 'trace.c', temp / 'trace'
    source.write_text(FIXTURE)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                    '-I', str(HEADER.parent), str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)

