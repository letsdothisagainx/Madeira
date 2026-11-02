#!/usr/bin/env python3
"""Execute the bounded VM failure diagnostic with interleaved request shapes."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include "vm_failure_trace.h"

static struct madeira_vm_failure_global concurrent_global;
static unsigned concurrent_details, concurrent_aggregates;
static void *failure_thread(void *unused)
{
    (void)unused;
    struct madeira_vm_failure_trace trace = {0};
    struct madeira_vm_failure_key key = { .owner = 1, .size = 0x200000, .status = 0xc0000018 };
    for (unsigned i = 0; i < 10000; i++)
    {
        key.size = (i % 9 + 1) * 0x10000;
        struct madeira_vm_failure_entry *entry = madeira_vm_failure_note(&trace, &key, i);
        struct madeira_vm_failure_report report = madeira_vm_failure_gate(&trace, entry, &concurrent_global);
        assert(report.thread_total == i + 1 && report.global_total <= 160000);
        if (report.detail) __atomic_fetch_add(&concurrent_details, 1, __ATOMIC_RELAXED);
        else if (report.aggregate) __atomic_fetch_add(&concurrent_aggregates, 1, __ATOMIC_RELAXED);
    }
    assert(trace.detail_reports <= MADEIRA_VM_FAILURE_THREAD_DETAILS);
    return 0;
}

int main(void)
{
    struct madeira_vm_failure_trace trace = {0};
    struct madeira_vm_failure_key key = {
        .owner = 0x500310000ULL, .window = 0x500000000ULL, .generation = 3,
        .size = 0x200000, .zero_bits = 0xffffffff, .limit = 0xffffffff,
        .alignment = 0x10000, .status = 0xc0000018, .type = 0x2000, .protect = 1
    };
    struct madeira_vm_failure_entry *entry = 0;
    unsigned reports = 0;
    for (uint64_t i = 0; i < 83968; i++)
    {
        uint64_t hint = key.window + ((i % 1024) + 1) * 0x200000;
        entry = madeira_vm_failure_note(&trace, &key, hint);
        assert(entry->matches == i + 1);
        reports += madeira_vm_count_sample(entry->matches, 4);
        if (i & 1)
        {
            struct madeira_vm_failure_key other = key;
            other.size += 0x10000;
            madeira_vm_failure_note(&trace, &other, key.window + 0x7a000000);
        }
    }
    assert(reports == 18 && entry->first_hint == key.window + 0x200000);
    assert(entry->last_hint == key.window + ((83967 % 1024) + 1) * UINT64_C(0x200000));
    assert(entry->hint_changes == 83967);
    assert(!madeira_vm_count_sample(0, 4));
    for (unsigned bit = 0; bit < 64; bit++)
        assert(madeira_vm_count_sample(UINT64_C(1) << bit, 4));
    entry->matches = UINT64_MAX; entry->hint_changes = UINT64_MAX;
    entry = madeira_vm_failure_note(&trace, &key, 0);
    assert(entry->matches == UINT64_MAX && entry->hint_changes == UINT64_MAX);
    assert(!madeira_vm_count_sample(entry->matches, 4));

    /* Owner/generation, exact limits/alignment and status are distinct keys.
     * No earlier conflict is reused as an allocation result for a new VAD. */
    struct madeira_vm_failure_key distinct = key;
    distinct.generation++;
    assert(madeira_vm_failure_note(&trace, &distinct, 123)->matches == 1);
    distinct = key; distinct.owner++;
    assert(madeira_vm_failure_note(&trace, &distinct, 123)->matches == 1);
    distinct = key; distinct.limit--;
    assert(madeira_vm_failure_note(&trace, &distinct, 123)->matches == 1);
    distinct = key; distinct.alignment *= 2;
    assert(madeira_vm_failure_note(&trace, &distinct, 123)->matches == 1);
    distinct = key; distinct.status = 0xc0000017;
    assert(madeira_vm_failure_note(&trace, &distinct, 123)->matches == 1);

    /* Unbounded caller diversity must not grow the table or its index. */
    for (unsigned i = 0; i < 100000; i++)
    {
        distinct = key; distinct.size = i + 1;
        entry = madeira_vm_failure_note(&trace, &distinct, i);
        assert(entry >= trace.entries && entry < trace.entries + MADEIRA_VM_FAILURE_KEYS);
        assert(trace.next < MADEIRA_VM_FAILURE_KEYS);
    }
    /* A ring of nine keys evicts every signature before its next use. Its
     * matches=1 samples must not turn into one log line per request. */
    struct madeira_vm_failure_trace rotating = {0};
    struct madeira_vm_failure_global global = {0};
    unsigned details = 0, aggregates = 0;
    for (unsigned i = 0; i < 83968; i++)
    {
        distinct = key; distinct.size += (i % 9) * 0x10000;
        distinct.status += i % 9;
        entry = madeira_vm_failure_note(&rotating, &distinct, key.window + i * UINT64_C(0x10000));
        assert(entry->matches == 1);
        struct madeira_vm_failure_report report = madeira_vm_failure_gate(&rotating, entry, &global);
        assert(report.thread_total == i + 1 && report.global_total == i + 1);
        details += report.detail;
        aggregates += !report.detail && report.aggregate;
    }
    assert(details == MADEIRA_VM_FAILURE_THREAD_DETAILS && aggregates == 12);
    assert(global.total == 83968 && rotating.total == 83968);
    assert(rotating.detail_reports == MADEIRA_VM_FAILURE_THREAD_DETAILS);

    /* Many short-lived native threads cannot multiply the process budget. */
    global = (struct madeira_vm_failure_global){0};
    details = aggregates = 0;
    for (unsigned i = 0; i < 83968; i++)
    {
        struct madeira_vm_failure_trace fresh = {0};
        entry = madeira_vm_failure_note(&fresh, &key, i);
        struct madeira_vm_failure_report report = madeira_vm_failure_gate(&fresh, entry, &global);
        details += report.detail;
        aggregates += !report.detail && report.aggregate;
        assert(report.thread_total == 1 && report.global_total == i + 1);
    }
    assert(details == MADEIRA_VM_FAILURE_GLOBAL_DETAILS && aggregates == 9);
    assert(global.total == 83968 && global.detail_reports == MADEIRA_VM_FAILURE_GLOBAL_DETAILS);

    /* Saturation does not wrap into a fresh first-event logging budget. */
    global.total = UINT64_MAX - 1;
    rotating.total = UINT64_MAX - 1;
    for (unsigned i = 0; i < 4; i++)
    {
        entry = madeira_vm_failure_note(&rotating, &key, i);
        struct madeira_vm_failure_report report = madeira_vm_failure_gate(&rotating, entry, &global);
        assert(!report.detail && !report.aggregate);
        assert(report.thread_total == UINT64_MAX && report.global_total == UINT64_MAX);
    }
    pthread_t workers[16];
    for (unsigned i = 0; i < 16; i++) assert(!pthread_create(&workers[i], 0, failure_thread, 0));
    for (unsigned i = 0; i < 16; i++) assert(!pthread_join(workers[i], 0));
    assert(concurrent_global.total == 160000 && concurrent_details == MADEIRA_VM_FAILURE_GLOBAL_DETAILS);
    assert(concurrent_aggregates <= 64 && concurrent_global.detail_reports == concurrent_details);
    puts("PASS: 83,968 cyclic-nine-key failures produce 16 details + 12 aggregates; 83,968 fresh threads stay at 128 details + 9 aggregates; exact counters survive eviction and saturation");
    puts("PASS: 16 concurrent threads count 160,000 failures exactly while sharing the global 128-detail budget");
}
'''
with tempfile.TemporaryDirectory() as temp:
    src = Path(temp) / 'check.c'
    exe = Path(temp) / 'check'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-pthread',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I' + str(root / 'build/ntdll-unix'), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))

signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
start = signal.index('void ios_guest32_trace_current(')
end = signal.index('\n}\n', start) + 2
actual = signal[start:end]
harness = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned long ULONG;
typedef uintptr_t ULONG_PTR;
typedef struct {
    struct { void *UniqueProcess, *UniqueThread; } ClientId;
    ULONG LastErrorValue;
    void *TlsSlots[64];
} TEB;
static TEB current;
static TEB *teb = &current;
static uint64_t window = 0x500000000;
static int readable = 1, lines, captures, reports[5];
struct ios_g32_origin { unsigned unused; };
static TEB *NtCurrentTeb(void) { return teb; }
static uint64_t ios_wow_base(void) { return window; }
static int ios_g32_read(uint64_t source, void *dest, size_t size) {
    assert(size == 8);
    if (!readable) return 0;
    uint64_t value = source == (uintptr_t)teb + offsetof(TEB,TlsSlots) + 14 * sizeof(void*)
        ? 0x111000 : 0x222000;
    memcpy(dest, &value, 8); return 1;
}
static int ios_g32_capture(struct ios_g32_origin *out, uint64_t source, uint64_t base, uint64_t frame) {
    assert(out && source == (uintptr_t)teb && base == window && frame == 0x222000);
    captures++; return 1;
}
static unsigned bucket(const char *tag) {
    return !strcmp(tag,"cef-assert") ? 0 : !strcmp(tag,"write-memory") ? 1 :
           !strcmp(tag,"alloc-first") ? 3 : !strcmp(tag,"alloc-sustained") ? 4 : 2;
}
static void ios_g32_report(const struct ios_g32_origin *g, const char *tag, uint32_t target) {
    assert(g && target == 0x123456); reports[bucket(tag)]++;
    errno = ERANGE; current.LastErrorValue = 99;
}
static void ios_cef_atexit_report(const struct ios_g32_origin *g) { assert(g); }
static int trace_dprintf(int fd, const char *format, ...) {
    assert(fd == 2 && format); lines++; errno = ERANGE; current.LastErrorValue = 99; return 0;
}
#define dprintf trace_dprintf
''' + actual + r'''
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1],"unreadable")) readable = 0;
    if (argc > 1 && !strcmp(argv[1],"no-window")) window = 0;
    if (argc > 1 && !strcmp(argv[1],"no-teb")) teb = 0;
    const char *tags[] = {"cef-assert","write-memory","other","alloc-first","alloc-sustained"};
    for (unsigned i = 0; i < 5; i++) for (unsigned n = 0; n < 1000; n++) {
        errno = EINVAL; current.LastErrorValue = 1234;
        ios_guest32_trace_current(tags[i], (void*)(uintptr_t)(window + 0x123456));
        assert(errno == EINVAL && current.LastErrorValue == 1234);
    }
    if (teb && window && readable) {
        assert(captures == 16 && lines == 16);
        assert(reports[0] == 2 && reports[1] == 4 && reports[2] == 2 && reports[3] == 4 && reports[4] == 4);
    } else {
        assert(captures == 0);
        assert(lines == (teb && window ? 16 : 0));
    }
    puts("PASS: actual guest32 origin function bounds all 5 budgets, fault-safe context failures and absent TEB/window; errno/LastError preserved");
}
'''
with tempfile.TemporaryDirectory() as temp:
    src = Path(temp) / 'origin.c'
    exe = Path(temp) / 'origin'
    src.write_text(harness)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(src), '-o', str(exe)], check=True)
    for case in ('valid', 'unreadable', 'no-window', 'no-teb'):
        subprocess.run([str(exe), case], check=True, env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))

virtual = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
af_start = virtual.index('struct ios_af_rec {')
af_end = virtual.index('/* ml797:', af_start)
map_start = virtual.index('static NTSTATUS map_view( struct file_view **view_ret')
map_brace = virtual.index('{', map_start)
reset = virtual[map_brace + 1:virtual.index(';', map_brace) + 1]
assert reset.strip().startswith('memset('), 'map_view must reset all attribution fields before any early return'
af_code = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t NTSTATUS;
''' + virtual[af_start:af_end] + '\nstatic void reset_attempt(void) {\n' + reset + r'''
}
int main(void) {
    memset(&ios_af, 0xff, sizeof(ios_af));
    reset_attempt();
    const unsigned char *bytes = (const unsigned char*)&ios_af;
    for (size_t i = 0; i < sizeof(ios_af); i++) assert(bytes[i] == 0);
    errno = EDOM;
    NTSTATUS status = ios_af_refuse("live-view-overlap", (void*)(uintptr_t)0x502000000, 0x200000, 0xc0000018);
    assert(status == 0xc0000018 && errno == EDOM);
    assert(ios_af.stage == 6 && ios_af.err == 0 && ios_af.addr == 0x502000000 && ios_af.size == 0x200000);
    assert(!strcmp(ios_af.reason,"live-view-overlap"));
    assert(!ios_af.conflict_base && !ios_af.conflict_size && !ios_af.conflict_owner && !ios_af.conflict_lease);
    ios_af_set(3, EACCES, (void*)(uintptr_t)0xdead0000, 0x1000);
    assert(!strcmp(ios_af.reason,"live-view-overlap") && ios_af.err == 0);
    reset_attempt();
    ios_af_set(3, EACCES, (void*)(uintptr_t)0xdead0000, 0x1000);
    assert(ios_af_refuse("host-address-limit", 0, 1, 0xc000000d) == 0xc000000d);
    assert(ios_af.stage == 3 && ios_af.err == EACCES && ios_af.addr == 0xdead0000 && !ios_af.reason);
    reset_attempt();
    assert(!ios_af.stage && !ios_af.err && !ios_af.addr && !ios_af.size && !ios_af.reason);
    puts("PASS: actual map_view reset clears stale Mach errors and ownership; exact refusal statuses and first-failure attribution preserved");
}
'''
with tempfile.TemporaryDirectory() as temp:
    src = Path(temp) / 'attribution.c'
    exe = Path(temp) / 'attribution'
    src.write_text(af_code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
