#!/usr/bin/env python3
"""Execute production recovery scheduling against a deterministic store trace.

Mach scheduling and cumulative CPU counters are adapters: measured elapsed times
here model the poll dependency, not iOS loading time. Store completion uses the
actual production helper and test-owned real mappings/protections; successful
publication/resume must expose the correct bytes before advancing the trace.
"""
import argparse
import ast
import os
from pathlib import Path
import platform
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sanitize', action='store_true')
parser.add_argument('--require-darwin', action='store_true')
args = parser.parse_args()
if args.require_darwin and platform.system() != 'Darwin':
    raise SystemExit('FAIL: Darwin is required')
root = Path(__file__).resolve().parents[2]
server = (root / 'build/ntdll-unix/server_ios.c').read_text()
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(text, signature):
    start = text.index(signature)
    return text[start:text.index('\n}', start) + 2] + '\n'


# Share the already-tested real mapping/protection adapters, not another copy
# of the recovery implementation. No test program is executed during import.
fixture = ast.parse((root / 'tests/host/check-cross-page-store-recovery.py').read_text())
prefix = next(ast.literal_eval(node.value) for node in fixture.body
              if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'C'
                                                     for t in node.targets))
helper = ''.join(function(signal, name) for name in (
    'static uintptr_t ios_write_alias( uintptr_t addr )',
    'static int ios_alias_write_is_trapped( uintptr_t addr )',
    'int ios_store_split_crossing( uint32_t insn,'))
start = server.index('#include "stuck_store_history.h"')
end = server.index('static void *ios_stuck_store_recovery_main', start)
production = server[start:end]
worker = function(server, 'static void *ios_stuck_store_recovery_main')
sampler = function(server, 'static void ios_thread_sampler_main')
assert 'ios_stuck_store_recovery_poll' in worker
assert 'ios_stuck_store_check(' not in sampler, 'diagnostics must not own recovery'
assert 'ios_thread_sampler_pass' not in worker and 'ios_guest_rip_profile' not in worker
startup_mark = server.index('const char *stuck_env = getenv( "MADEIRA_STUCK_CHECK" );')
startup = server[server.rfind('            {', 0, startup_mark):
                 server.index('\n            dispatch_async(', startup_mark)]
assert startup.count('{') == startup.count('}')


# Pinned actual predecessor implementation: shallow CI checkouts need no history.
BASELINE_PRODUCTION = r'''#include "stuck_store_history.h"
static struct ios_stuck_history ios_stuck;
static int ios_stuck_logs;
static unsigned long long ios_stuck_fixed;

/* Effective address and size of the load/store at insn (A64), 0 if not one. */
static int ios_ldst_ea( uint32_t insn, const arm_thread_state64_t *st, uint64_t *ea, unsigned *len )
{
    unsigned rn = (insn >> 5) & 31, size = insn >> 30, v = (insn >> 26) & 1, opc = (insn >> 22) & 3;
    unsigned scale = v ? (size | ((opc & 2) << 1)) : size;
    uint64_t base = rn == 31 ? arm_thread_state64_get_sp( *st ) : rn == 30 ? st->__lr :
                    rn == 29 ? st->__fp : st->__x[rn];

    if ((insn & 0x3b000000u) == 0x39000000u)            /* LDR/STR, unsigned immediate */
    {
        *ea = base + ((uint64_t)((insn >> 10) & 0xfff) << scale); *len = 1u << scale; return 1;
    }
    if ((insn & 0x3b200c00u) == 0x38200800u)            /* LDR/STR, register offset */
    {
        unsigned rm = (insn >> 16) & 31, option = (insn >> 13) & 7, s = (insn >> 12) & 1;
        uint64_t m = rm == 31 ? 0 : rm == 30 ? st->__lr : rm == 29 ? st->__fp : st->__x[rm];
        if (option == 2) m = (uint32_t)m;
        else if (option == 6) m = (uint64_t)(int64_t)(int32_t)m;
        *ea = base + (m << (s ? scale : 0)); *len = 1u << scale; return 1;
    }
    if ((insn & 0x3b200000u) == 0x38000000u)            /* LDUR/STUR, pre/post-index */
    {
        int64_t imm9 = (insn >> 12) & 0x1ff;
        if (imm9 & 0x100) imm9 -= 0x200;
        *ea = ((insn >> 10) & 3) == 1 ? base : base + imm9; *len = 1u << scale; return 1;
    }
    if ((insn & 0x3a000000u) == 0x28000000u)            /* LDP/STP */
    {
        unsigned psc = v ? 2 + (insn >> 30) : 2 + (insn >> 31);
        int64_t imm7 = (insn >> 15) & 0x7f;
        if (imm7 & 0x40) imm7 -= 0x80;
        *ea = ((insn >> 23) & 3) == 1 ? base : base + imm7 * (INT64_C(1) << psc); *len = 2u << psc; return 1;
    }
    if ((insn & 0x3f200c00u) == 0x19000000u)            /* LDAPUR/STLUR */
    {
        int64_t imm9 = (insn >> 12) & 0x1ff;
        if (imm9 & 0x100) imm9 -= 0x200;
        *ea = base + imm9; *len = 1u << size; return 1;
    }
    if ((insn & 0x3f000000u) == 0x08000000u)            /* LDAR/STLR/LDXR family */
    {
        *ea = base; *len = 1u << size; return 1;
    }
    return 0;
}

int ios_store_split_crossing( uint32_t insn, arm_thread_state64_t *st, const arm_neon_state64_t *neon,
                              uintptr_t rx, uintptr_t rw, size_t sz );   /* ml1289, signal_arm64_ios.c */

static void ios_stuck_store_check( void )
{
    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    mach_port_t self_port = pthread_mach_thread_np( pthread_self() );
    thread_act_array_t tl;
    mach_msg_type_number_t tc;
    struct timespec ts;
    uint64_t now;
    unsigned k;

    if (clock_gettime( CLOCK_MONOTONIC, &ts ))
    {
        ios_stuck_history_reset( &ios_stuck );
        return;
    }
    now = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    if (task_threads( mach_task_self(), &tl, &tc ) != KERN_SUCCESS)
    {
        ios_stuck_history_reset( &ios_stuck );
        return;
    }
    /* Keep the previous complete snapshot immutable while building this one.
     * The old 64-slot LRU evicted late-enumerated live threads every pass,
     * so they could never receive the two observations this check requires.
     * Failure/oversize declines before suspending or changing any thread. */
    if (!ios_stuck_history_begin( &ios_stuck, tc )) goto release_threads;
    for (k = 0; k < tc; k++)
    {
        thread_basic_info_data_t bi;
        thread_identifier_info_data_t idi;
        arm_thread_state64_t st;
        arm_neon_state64_t neon;
        mach_msg_type_number_t bic = THREAD_BASIC_INFO_COUNT, idc = THREAD_IDENTIFIER_INFO_COUNT,
                               cnt = ARM_THREAD_STATE64_COUNT, nc = ARM_NEON_STATE64_COUNT;
        uint64_t pc, bb = 0, ea = 0, dt, sys, dsys;
        uint32_t insn = 0;
        unsigned len = 0;
        struct ios_stuck_entry *entry;
        int got, have_neon, cross;

        if (tl[k] == self_port) continue;
        if (thread_info( tl[k], THREAD_BASIC_INFO, (thread_info_t)&bi, &bic ) != KERN_SUCCESS) continue;
        if (thread_info( tl[k], THREAD_IDENTIFIER_INFO, (thread_info_t)&idi, &idc ) != KERN_SUCCESS) continue;
        if (bi.system_time.seconds < 0 || bi.system_time.microseconds < 0) continue;
        sys = (uint64_t)bi.system_time.seconds * 1000 + bi.system_time.microseconds / 1000;
        entry = ios_stuck_history_observe( &ios_stuck, idi.thread_id, now, sys, &dt, &dsys );
        if (!entry) continue;
        if (bi.run_state != TH_STATE_RUNNING || !dt || (uint64_t)dsys * 10 < dt * 6)
        {
            entry->pc = 0; entry->hits = 0;
            continue;
        }

        /* kernel-bound: read it */
        if (thread_suspend( tl[k] ) != KERN_SUCCESS)
        {
            entry->pc = entry->ea = entry->hits = 0;
            continue;
        }
        got = thread_get_state( tl[k], ARM_THREAD_STATE64, (thread_state_t)&st, &cnt ) == KERN_SUCCESS;
        have_neon = thread_get_state( tl[k], ARM_NEON_STATE64, (thread_state_t)&neon, &nc ) == KERN_SUCCESS;
        if (!got || !ios_ts_read( st.__x[28], &bb, 8 ) || bb <= 0x10000)   /* not in FEX state */
        {
            entry->pc = entry->ea = entry->hits = 0;
            thread_resume( tl[k] );
            continue;
        }
        pc = arm_thread_state64_get_pc( st );
        cross = ios_ts_read( pc, &insn, 4 ) && ios_ldst_ea( insn, &st, &ea, &len ) &&
                ((ea ^ (ea + len - 1)) & ~(uint64_t)(vm_page_size - 1));
        if (cross && entry->pc == pc && entry->ea == ea)
        {
            unsigned hits = ++entry->hits;
            int r = ios_store_split_crossing( insn, &st, have_neon ? &neon : NULL,
                                              (uintptr_t)ios_jit_rx_base_global, (uintptr_t)ios_jit_rw_base_global,
                                              ios_jit_pool_size_global );
            if (r > 0)
            {
                __darwin_arm_thread_state64_set_pc_fptr( st, (void *)(uintptr_t)(pc + 4) );
                if (thread_set_state( tl[k], ARM_THREAD_STATE64, (thread_state_t)&st, ARM_THREAD_STATE64_COUNT ) != KERN_SUCCESS)
                    r = -2;   /* the store is written, pc not moved: the thread redoes the same bytes */
                else
                    ios_stuck_fixed++;
            }
            thread_resume( tl[k] );
            if (ios_stuck_logs < 400 && (r > 0 || hits <= 3 || hits % 10 == 0))
            {
                ios_stuck_logs++;
                wine_log_write( "[stuck-store] ml1292 tid=%llu hits=%u pc=0x%llx insn=%08x ea=0x%llx len=%u "
                                "sys+%llu ms in %llu ms: %s (%llu completed so far)",
                                (unsigned long long)idi.thread_id, hits, (unsigned long long)pc, insn,
                                (unsigned long long)ea, len, (unsigned long long)dsys, (unsigned long long)dt,
                                r > 0 ? "completed, pc+4" : r == -2 ? "written, set_state FAILED"
                                : r < 0 ? "refused (a page not writable)" : "not a store it decodes", ios_stuck_fixed );
            }
            if (r > 0) { entry->pc = 0; entry->hits = 0; }
        }
        else
        {
            thread_resume( tl[k] );
            entry->pc = cross ? pc : 0;
            entry->ea = cross ? ea : 0;
        }
    }
    /* Only identities observed in this task snapshot survive. Recycled Mach
     * port names and Windows thread IDs cannot inherit an earlier PC/EA. */
    ios_stuck_history_end( &ios_stuck );
release_threads:
    for (k = 0; k < tc; k++) mach_port_deallocate( mach_task_self(), tl[k] );
    vm_deallocate( mach_task_self(), (vm_address_t)tl, tc * sizeof(*tl) );
}

'''
assert __import__('hashlib').sha256(BASELINE_PRODUCTION.encode()).hexdigest() == 'c447c805fb82c78487375a690a93b51e9c5f17efe28d390c8326753e62a615ec'

ADAPTERS = r'''
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#ifndef __APPLE__
typedef mach_port_t thread_t, thread_act_t, *thread_act_array_t;
typedef uintptr_t vm_address_t;
typedef void *thread_info_t;
typedef struct { int seconds, microseconds; } time_value_t;
typedef struct { time_value_t system_time; unsigned run_state; } thread_basic_info_data_t;
typedef struct { uint64_t thread_id; } thread_identifier_info_data_t;
#define THREAD_BASIC_INFO 1
#define THREAD_IDENTIFIER_INFO 2
#define THREAD_BASIC_INFO_COUNT 1
#define THREAD_IDENTIFIER_INFO_COUNT 1
#define TH_STATE_RUNNING 1
#define MACH_PORT_RIGHT_SEND 0
#endif
#ifndef NATIVE_ARM_STATE
#define ARM_NEON_STATE64 17
#define ARM_NEON_STATE64_COUNT (sizeof(arm_neon_state64_t) / sizeof(uint32_t))
#define arm_thread_state64_get_sp(s) ((s).__sp)
#endif
enum { THREADS = 16, OPERATIONS = 20 };
static const uintptr_t store_pc = 0x7c30000000ull, frame_address = 0x10000;
static uint64_t now_ms;
static unsigned thread_count, full_scans, fast_state_reads, resumes, publications;
static int holds[THREADS], rights[THREADS];
static unsigned max_rights, mod_refs_calls, refuse_publication, refuse_retain;
static unsigned delayed_basic_port, delayed_basic_ms;
static uint64_t full_scan_at[256];
static size_t fixture_vm_page_size = PAGE;
#define vm_page_size fixture_vm_page_size
struct target {
    int alive, running, kernel_percent;
    uint64_t identity, system_us;
    unsigned completed, requested;
    unsigned char *mapping;
    arm_thread_state64_t state;
    arm_neon_state64_t neon;
};
static struct target targets[THREADS];

static void prepare_operation(unsigned id)
{
    struct target *t = targets + id;
    memset(&t->state, 0, sizeof(t->state));
    t->state.__x[28] = frame_address;
    t->state.__x[8] = (uintptr_t)t->mapping + t->completed * SPAN + PAGE - 4 - 16;
    __darwin_arm_thread_state64_set_pc_fptr(t->state, (void *)store_pc);
    memset(&t->neon, (int)(id + t->completed + 1), sizeof(t->neon));
}
static void advance_time(uint64_t next)
{
    assert(next >= now_ms);
    for (unsigned id = 1; id <= thread_count; ++id)
        if (targets[id].alive && targets[id].completed < targets[id].requested)
            targets[id].system_us += (next - now_ms) * 10 * targets[id].kernel_percent;
    now_ms = next;
}
static int fixture_clock_gettime(clockid_t clock, struct timespec *out)
{ (void)clock; out->tv_sec = now_ms / 1000; out->tv_nsec = (now_ms % 1000) * 1000000; return 0; }
static mach_port_t fixture_self(pthread_t thread) { (void)thread; return 0; }
static int fixture_task_threads(mach_port_t task, thread_act_array_t *out, unsigned *count)
{
    (void)task;
    assert(full_scans < 256); full_scan_at[full_scans++] = now_ms;
    *out = calloc(thread_count, sizeof(**out)); assert(*out);
    *count = 0;
    for (unsigned id = 1; id <= thread_count; ++id) if (targets[id].alive)
    { (*out)[(*count)++] = id; ++rights[id]; }
    return KERN_SUCCESS;
}
static int fixture_thread_info(mach_port_t port, int flavor, void *out, unsigned *count)
{
    (void)count;
    if (!port || (unsigned)port > thread_count || !targets[port].alive) return 1;
    if (flavor == THREAD_BASIC_INFO)
    {
        if ((unsigned)port == delayed_basic_port && delayed_basic_ms)
        {
            unsigned delay = delayed_basic_ms; delayed_basic_ms = 0;
            advance_time(now_ms + delay);
        }
        thread_basic_info_data_t *info = out;
        memset(info, 0, sizeof(*info));
        info->system_time.seconds = targets[port].system_us / 1000000;
        info->system_time.microseconds = targets[port].system_us % 1000000;
        info->run_state = targets[port].running ? TH_STATE_RUNNING : 0;
    }
    else if (flavor == THREAD_IDENTIFIER_INFO)
        ((thread_identifier_info_data_t *)out)->thread_id = targets[port].identity;
    else return 1;
    return KERN_SUCCESS;
}
static int fixture_suspend(mach_port_t port)
{
    assert(port && (unsigned)port <= thread_count);
    if (!targets[port].alive) return 1;
    assert(!holds[port]); ++holds[port]; return KERN_SUCCESS;
}
static int fixture_get_state(mach_port_t port, int flavor, void *out, unsigned *count)
{
    (void)count; assert(holds[port] == 1); ++fast_state_reads;
    if (flavor == ARM_THREAD_STATE64) memcpy(out, &targets[port].state, sizeof(targets[port].state));
    else if (flavor == ARM_NEON_STATE64) memcpy(out, &targets[port].neon, sizeof(targets[port].neon));
    else return 1;
    return KERN_SUCCESS;
}
static int fixture_set_state(mach_port_t port, int flavor, thread_state_t state, unsigned count)
{
    (void)flavor; (void)count; assert(holds[port] == 1);
    if (refuse_publication) return 1;
    memcpy(&targets[port].state, state, sizeof(targets[port].state)); ++publications;
    return KERN_SUCCESS;
}
static int fixture_resume(mach_port_t port)
{
    struct target *t = targets + port;
    assert(holds[port] == 1); --holds[port]; ++resumes;
    if (arm_thread_state64_get_pc(t->state) == store_pc + 4)
    {
        unsigned char *destination = t->mapping + t->completed * SPAN + PAGE - 4;
        for (unsigned i = 0; i < 16; ++i) assert(destination[i] == (unsigned char)(port + t->completed + 1));
        assert(destination[-1] == 0x5a && destination[16] == 0x5a);
        ++t->completed;
        if (t->completed < t->requested) prepare_operation(port);
        else t->running = 0;
    }
    return KERN_SUCCESS;
}
static int fixture_mod_refs(mach_port_t task, mach_port_t port, int right, int delta)
{
    (void)task; (void)right; assert(port && (unsigned)port <= thread_count); ++mod_refs_calls;
    if (!targets[port].alive || refuse_retain) return 1;
    rights[port] += delta; assert(rights[port] >= 0);
    if ((unsigned)rights[port] > max_rights) max_rights = rights[port];
    return KERN_SUCCESS;
}
static int fixture_deallocate(mach_port_t task, mach_port_t port)
{ (void)task; assert(port && (unsigned)port <= thread_count); assert(rights[port] > 0); --rights[port]; return 0; }
static int fixture_vm_deallocate(mach_port_t task, vm_address_t address, size_t size)
{ (void)task; (void)size; free((void *)address); return 0; }
static int ios_ts_read(uint64_t address, void *out, size_t size)
{
    if (address == frame_address && size == 8) { *(uint64_t *)out = 0x20000; return 1; }
    if (address == store_pc && size == 4) { *(uint32_t *)out = 0x3d800500; return 1; }
    return 0;
}
static void wine_log_write(const char *format, ...) __attribute__((format(printf,1,2)));
static void wine_log_write(const char *format, ...) { (void)format; }
#define clock_gettime fixture_clock_gettime
#define pthread_mach_thread_np fixture_self
#define task_threads fixture_task_threads
#define thread_info fixture_thread_info
#define thread_suspend fixture_suspend
#define thread_get_state fixture_get_state
#define thread_set_state fixture_set_state
#define thread_resume fixture_resume
#define mach_port_mod_refs fixture_mod_refs
#define mach_port_deallocate fixture_deallocate
#define vm_deallocate fixture_vm_deallocate
'''
STARTUP_FIXTURE = r'''
static int ios_lean_diag;
static const char *fixture_stuck_env;
static int create_error, detach_error, create_calls, detach_calls;
static void *ios_stuck_store_recovery_main(void *unused) { (void)unused; return NULL; }
static const char *fixture_getenv(const char *key)
{ assert(!strcmp(key, "MADEIRA_STUCK_CHECK")); return fixture_stuck_env; }
static int fixture_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                  void *(*entry)(void *), void *argument)
{
    assert(!attr && !argument && entry == ios_stuck_store_recovery_main);
    assert(ios_stuck_worker_started == 1); /* Ownership published before launch. */
    ++create_calls; *thread = (pthread_t)(uintptr_t)1; return create_error;
}
static int fixture_pthread_detach(pthread_t thread)
{ assert(thread == (pthread_t)(uintptr_t)1); ++detach_calls; return detach_error; }
#define getenv fixture_getenv
#define pthread_create fixture_pthread_create
#define pthread_detach fixture_pthread_detach
static void actual_startup_policy(void)
'''
STARTUP_FIXTURE += startup
STARTUP_FIXTURE += r'''
#undef getenv
#undef pthread_create
#undef pthread_detach
static void startup_cases(void)
{
    actual_startup_policy();
    assert(ios_stuck_worker_started == 1 && create_calls == 1 && detach_calls == 1);
    ios_stuck_worker_started = 0; create_error = 11;
    actual_startup_policy();
    assert(!ios_stuck_worker_started && create_calls == 2 && detach_calls == 1);
    create_error = 0; detach_error = 22;
    actual_startup_policy();
    assert(ios_stuck_worker_started == 1 && create_calls == 3 && detach_calls == 2);
    ios_stuck_worker_started = 0; ios_lean_diag = 1;
    actual_startup_policy(); assert(!ios_stuck_worker_started && create_calls == 3);
    ios_lean_diag = 0; fixture_stuck_env = "0";
    actual_startup_policy(); assert(!ios_stuck_worker_started && create_calls == 3);
    puts("PASS actual startup: success owns recovery, failed creation preserves fallback, detach failure keeps owner, lean/env opt-outs create no worker");
}
'''

SUFFIX = r'''
static void initialise(unsigned count, unsigned operations)
{
    thread_count = count; now_ms = 0;
    for (unsigned id = 1; id <= count; ++id)
    {
        struct target *t = targets + id;
        t->identity = 1000 + id; t->alive = t->running = 1; t->kernel_percent = 100;
        t->requested = operations;
        unsigned char *raw = mmap(NULL, SPAN * OPERATIONS + PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        assert(raw != MAP_FAILED);
        t->mapping = (void *)(((uintptr_t)raw + PAGE - 1) & ~(uintptr_t)(PAGE - 1));
        size_t prefix = t->mapping - raw, suffix = PAGE - prefix;
        if (prefix) assert(!munmap(raw, prefix));
        if (suffix) assert(!munmap(t->mapping + SPAN * OPERATIONS, suffix));
        memset(t->mapping, 0x5a, SPAN * OPERATIONS); prepare_operation(id);
    }
}
static uint64_t baseline_due;
static void tick(uint64_t time)
{
    advance_time(time);
#ifdef BASELINE_SCHEDULE
    if (now_ms >= baseline_due) { ios_stuck_store_check(); baseline_due = now_ms + 100; }
#else
    ios_stuck_store_recovery_tick(now_ms * 1000);
#endif
}
static void cleanup(void)
{
#ifndef BASELINE_SCHEDULE
    ios_stuck_hot_reset();
#endif
    ios_stuck_history_destroy(&ios_stuck);
    for (unsigned id = 1; id <= thread_count; ++id)
    {
        assert(!holds[id] && !rights[id]);
        assert(!munmap(targets[id].mapping, SPAN * OPERATIONS));
    }
    for (unsigned i = 1; i < full_scans; ++i) assert(full_scan_at[i] - full_scan_at[i - 1] >= 100);
}
static unsigned retained(void)
{
    unsigned count = 0;
    for (unsigned id = 1; id <= thread_count; ++id) { assert(rights[id] <= 1); count += rights[id]; }
    return count;
}
static void warm(void)
{
    tick(0); tick(100); tick(200);
    assert(targets[1].completed == 1 && publications >= 1);
}
static void trace(int blocked_diagnostics)
{
    initialise(1, OPERATIONS);
    for (uint64_t time = 0; time <= 7000 && targets[1].completed < OPERATIONS; time += 5)
    {
#ifdef BASELINE_SCHEDULE
        if (blocked_diagnostics && time < 2000) { advance_time(time); continue; }
#else
        (void)blocked_diagnostics; /* Dedicated worker never enters diagnostic work. */
#endif
        tick(time);
    }
    assert(targets[1].completed == OPERATIONS);
#ifdef BASELINE_SCHEDULE
    assert(now_ms == (blocked_diagnostics ? 6000 : 4000));
#else
    assert(now_ms == 390 && full_scans == 4);
#endif
    printf("PASS %s advancing real-byte stores: %u operations=%llu modeled ms; full-scans=%u; diagnostic-block=%d\n",
#ifdef BASELINE_SCHEDULE
           "baseline",
#else
           "candidate",
#endif
           OPERATIONS, (unsigned long long)now_ms, full_scans, blocked_diagnostics);
    cleanup();
}
#ifndef BASELINE_SCHEDULE
static void gates(void)
{
    initialise(1, OPERATIONS); warm();
    assert(retained() == 1 && ios_stuck_store_recovery_delay() == 5000);
    unsigned reads = fast_state_reads, published = publications;
    uint64_t sys = targets[1].system_us;
    advance_time(205); targets[1].system_us = sys + 2999; tick(205);
    assert(fast_state_reads == reads && publications == published); /* 59.98% declines */
    sys = targets[1].system_us;
    advance_time(210); targets[1].system_us = sys + 3000; tick(210);
    assert(publications == published); /* 60% first valid PC/EA observation */
    sys = targets[1].system_us;
    advance_time(215); targets[1].system_us = sys + 3000; tick(215);
    assert(publications == published + 1 && targets[1].completed == 2);
    reads = fast_state_reads; published = publications;
    targets[1].kernel_percent = 0;
    for (uint64_t time = 220; time <= 1220; time += 5) tick(time);
    assert(fast_state_reads == reads && publications == published);
    assert(!retained() && ios_stuck_store_recovery_delay() == 100000);
    puts("PASS exact 2999/5000us refusal, 3000/5000us qualification, user-only no suspends, hot expiry");
    cleanup();
}
static void protected_neighbor(void)
{
    initialise(1, OPERATIONS); warm();
    unsigned published = publications;
    unsigned char *neighbor = targets[1].mapping + SPAN + PAGE;
    assert(!mprotect(neighbor, PAGE, PROT_READ));
    for (uint64_t time = 205; time <= 300; time += 5) tick(time);
    assert(publications == published && targets[1].completed == 1);
    assert(arm_thread_state64_get_pc(targets[1].state) == store_pc);
    for (int i = -4; i < 16; ++i) assert(neighbor[i] == 0x5a);
    assert(!mprotect(neighbor, PAGE, PROT_READ | PROT_WRITE));
    puts("PASS protected neighbor: real helper refuses without partial bytes, PC publication or trace progress");
    cleanup();
}
static void native_lifetime(int death)
{
    initialise(1, OPERATIONS); warm();
    unsigned reads = fast_state_reads, published = publications;
    if (death) targets[1].alive = 0;
    else targets[1].identity += 10000;
    tick(205);
    assert(!retained() && fast_state_reads == reads && publications == published);
    assert(!holds[1]);
    puts(death ? "PASS dead native thread drops retained port before capture" :
                 "PASS native ID changes cannot inherit the previous port's PC/EA observations");
    cleanup();
}
static void publication_failure(void)
{
    initialise(1, OPERATIONS); warm();
    unsigned published = publications; refuse_publication = 1;
    tick(205); tick(210);
    assert(!retained() && publications == published && targets[1].completed == 1);
    assert(arm_thread_state64_get_pc(targets[1].state) == store_pc);
    unsigned char *destination = targets[1].mapping + SPAN + PAGE - 4;
    for (unsigned i = 0; i < 16; ++i) assert(destination[i] == 3);
    puts("PASS failed state publication: completed bytes observable, original target PC and execution retained, hot right dropped");
    cleanup();
}
static void bounded(void)
{
    initialise(12, 2); warm();
    assert(retained() == 8 && ios_stuck_store_recovery_delay() == 5000);
    tick(205); tick(210);
    for (unsigned id = 1; id <= 12; ++id) assert(targets[id].completed == (id <= 8 ? 2u : 1u));
    assert(full_scans == 3);
    puts("PASS follow-up cap8: only retained ports at5ms, whole-task discovery remains100ms, every right balanced");
    cleanup();
}
static void acquisition_failure(void)
{
    initialise(1, OPERATIONS); refuse_retain = 1; warm();
    assert(!retained() && ios_stuck_store_recovery_delay() == 100000);
    unsigned reads = fast_state_reads; tick(205); tick(210);
    assert(fast_state_reads == reads && targets[1].completed == 1);
    puts("PASS failed send-right acquisition never creates a follow-up candidate");
    cleanup();
}
static void fresh_cpu_sample(void)
{
    initialise(2, OPERATIONS); warm(); assert(retained() == 2);
    unsigned reads = fast_state_reads, published = publications;
    targets[1].kernel_percent = targets[2].kernel_percent = 59;
    delayed_basic_port = 1; delayed_basic_ms = 20;
    tick(205);
    assert(now_ms == 225 && fast_state_reads == reads && publications == published);
    puts("PASS delayed first native query: both targets use fresh clock/CPU pairs; 59% never becomes false 60% through scan latency");
    cleanup();
}
#endif
int main(int argc, char **argv)
{
    assert(argc == 2);
    if (!strcmp(argv[1], "trace")) trace(0);
    else if (!strcmp(argv[1], "blocked")) trace(1);
#ifndef BASELINE_SCHEDULE
    else if (!strcmp(argv[1], "gates")) gates();
    else if (!strcmp(argv[1], "protected")) protected_neighbor();
    else if (!strcmp(argv[1], "death")) native_lifetime(1);
    else if (!strcmp(argv[1], "churn")) native_lifetime(0);
    else if (!strcmp(argv[1], "publication")) publication_failure();
    else if (!strcmp(argv[1], "bounded")) bounded();
    else if (!strcmp(argv[1], "acquisition")) acquisition_failure();
    else if (!strcmp(argv[1], "startup")) startup_cases();
    else if (!strcmp(argv[1], "fresh-clock")) fresh_cpu_sample();
#endif
    else assert(!"unknown scenario");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-stuck-scheduling-') as directory:
    flags = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'] if args.sanitize else []
    for label, implementation in [('baseline', BASELINE_PRODUCTION), ('candidate', production)]:
        source, binary = Path(directory) / (label + '.c'), Path(directory) / label
        startup_code = STARTUP_FIXTURE if label == 'candidate' else ''
        source.write_text(prefix + helper + ADAPTERS + implementation + startup_code + SUFFIX)
        define = ['-DBASELINE_SCHEDULE'] if label == 'baseline' else []
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-Wno-unused-variable', *define, *flags,
                        '-I' + str(root / 'build/ntdll-unix'), str(source), '-o', str(binary)], check=True, timeout=60)
        cases = ['trace', 'blocked']
        if label == 'candidate': cases += ['gates', 'protected', 'death', 'churn', 'publication', 'bounded', 'acquisition', 'startup', 'fresh-clock']
        for case in cases:
            subprocess.run([str(binary), case], check=True, timeout=60)
print('NOTE deterministic scheduling/CPU adapters; no iPhone kernel-stall or multiplayer performance claim')
