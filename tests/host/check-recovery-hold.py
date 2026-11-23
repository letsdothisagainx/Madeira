#!/usr/bin/env python3
"""Normal writable-page checks of the actual Run15 recovery inspector/helper.
No crashes, failed APIs, protection changes or revoked mappings are exercised.
Linux uses the existing checked kernel-delivery adapter, never an iOS timing model.
Darwin additionally checks real unheld thread_get_state and scoped pthread QoS.
"""
import argparse
import ast
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-darwin', action='store_true')
args = parser.parse_args()
if args.require_darwin and platform.system() != 'Darwin':
    raise SystemExit('Darwin required')
server = (root / 'build/ntdll-unix/server_ios.c').read_text()
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
def function(text, signature):
    start = text.index(signature)
    return text[start:text.index('\n}', start) + 2] + '\n'
fixture = ast.parse((root / 'tests/host/check-cross-page-store-recovery.py').read_text())
prefix = next(ast.literal_eval(n.value) for n in fixture.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'C' for t in n.targets))
before = (root / 'tests/host/fixtures/run15-recovery-inspect-before.c').read_text()
assert hashlib.sha256(before.encode()).hexdigest() == '5bbfb56846b097b51a7579e2fc655470b8b66a6cfe5dfab38d454558d0881f5f'
# Exact inspector variants, identical successful adapters and actual helper.
helper = ''.join(function(signal, sig) for sig in (
    'static uintptr_t ios_write_alias( uintptr_t addr )',
    'static int ios_alias_write_is_trapped( uintptr_t addr )',
    'int ios_store_split_crossing_timed( uint32_t insn,',
    'int ios_store_split_crossing( uint32_t insn,'))
qos = ''.join(function(server, sig) for sig in (
    'static void ios_stuck_store_qos_begin(', 'static void ios_stuck_store_qos_end('))
native = r'''
#include <stdatomic.h>
#include <time.h>
#include "store_recovery_phases.h"
#ifdef __APPLE__
#include <pthread/qos.h>
static _Atomic int stop_native, native_ready;
static void *ordinary_worker(void *unused)
{
    (void)unused; atomic_store(&native_ready, 1);
    while (!atomic_load(&stop_native)) usleep(1000);
    return NULL;
}
static void check_native_state(void)
{
    pthread_t worker; assert(!pthread_create(&worker, NULL, ordinary_worker, NULL));
    while (!atomic_load(&native_ready)) usleep(1000);
    thread_t port = pthread_mach_thread_np(worker);
    for (unsigned i = 0; i < 20; ++i)
    {
        thread_basic_info_data_t before, after;
        mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
        assert(thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&before, &n) == KERN_SUCCESS);
#if defined(__arm64__) || defined(__aarch64__)
        arm_thread_state64_t state; n = ARM_THREAD_STATE64_COUNT;
        assert(thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&state, &n) == KERN_SUCCESS);
#else
        x86_thread_state64_t state; n = x86_THREAD_STATE64_COUNT;
        assert(thread_get_state(port, x86_THREAD_STATE64, (thread_state_t)&state, &n) == KERN_SUCCESS);
#endif
        n = THREAD_BASIC_INFO_COUNT;
        assert(thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&after, &n) == KERN_SUCCESS);
        assert(before.suspend_count == 0 && after.suspend_count == 0);
    }
    atomic_store(&stop_native, 1); assert(!pthread_join(worker, NULL));
    puts("PASS real Mach state capture on a live unsuspended ordinary worker (no suspension count acquired)");
}
#else
/* Successful pthread QoS adapter; no claim about Linux scheduling priority. */
typedef unsigned qos_class_t;
#define QOS_CLASS_UNSPECIFIED 0
#define QOS_CLASS_BACKGROUND 9
#define QOS_CLASS_UTILITY 17
#define QOS_CLASS_DEFAULT 21
#define QOS_CLASS_USER_INITIATED 25
#define QOS_CLASS_USER_INTERACTIVE 33
static qos_class_t adapter_qos = QOS_CLASS_UTILITY;
static int adapter_relative;
static int pthread_threadid_np(void *unused, uint64_t *id) { (void)unused; *id = 123; return 0; }
static int pthread_get_qos_class_np(pthread_t t, qos_class_t *q, int *relative)
{ (void)t; *q = adapter_qos; *relative = adapter_relative; return 0; }
static int pthread_set_qos_class_self_np(qos_class_t q, int relative)
{ adapter_qos = q; adapter_relative = relative; return 0; }
static void check_native_state(void) { puts("SKIP real Mach/QoS on Linux; successful adapters only"); }
#endif
'''
adapters = r'''
#include <stdarg.h>
#include "stuck_store_history.h"
#ifndef NATIVE_ARM_STATE
#define arm_thread_state64_get_sp(s) ((s).__sp)
#define ARM_NEON_STATE64 17
#define ARM_NEON_STATE64_COUNT 1
#endif
static unsigned ios_stuck_logs;
static unsigned long long ios_stuck_fixed;
static size_t fixture_page_size = PAGE;
#define vm_page_size fixture_page_size
static arm_thread_state64_t current;
static arm_neon_state64_t vector;
static uint32_t opcode;
static uint64_t frame_word = 0x20000;
static unsigned holds, initial_holds, suspends, resumes, publications, reads_held, reads_unheld;
static unsigned captures, move_at_capture, refresh_source;
static struct ios_store_recovery_phases last_phase;
static int ios_stuck_clock_us(uint64_t *out) { *out = ios_store_phase_clock(); return 1; }
static int suspend_target(mach_port_t t)
{
    (void)t;
#ifndef BEFORE
    qos_class_t q; int relative;
    assert(!pthread_get_qos_class_np(pthread_self(), &q, &relative));
    assert(q == QOS_CLASS_USER_INTERACTIVE);
#endif
    holds++; suspends++; return 0;
}
static int resume_target(mach_port_t t) { (void)t; assert(holds == initial_holds + 1); holds--; resumes++; return 0; }
static int get_target(mach_port_t t, int flavor, void *out, unsigned *count)
{
    (void)t; (void)count;
    if (flavor == ARM_THREAD_STATE64)
    {
        captures++;
        if (move_at_capture == captures) __darwin_arm_thread_state64_set_pc_fptr(current, (void *)(uintptr_t)(arm_thread_state64_get_pc(current) + 4));
        if (refresh_source && holds > initial_holds) current.__x[19] = UINT64_C(0x8899aabbccddeeff);
        memcpy(out, &current, sizeof(current));
    }
    else { assert(holds > initial_holds && flavor == ARM_NEON_STATE64); memcpy(out, &vector, sizeof(vector)); }
    return 0;
}
static int set_target(mach_port_t t, int flavor, void *state, unsigned count)
{ (void)t; (void)flavor; (void)count; assert(holds == initial_holds + 1); current = *(arm_thread_state64_t *)state; publications++; return 0; }
static int ios_ts_read(uint64_t addr, void *out, size_t bytes)
{
    if (holds > initial_holds) reads_held++; else reads_unheld++;
    if (addr == (uintptr_t)&frame_word) { assert(bytes == 8); memcpy(out, &frame_word, bytes); }
    else { assert(addr == (uintptr_t)&opcode && bytes == 4); memcpy(out, &opcode, bytes); }
    return 1;
}
static void wine_log_write(const char *fmt, ...) { (void)fmt; assert(holds == initial_holds); }
static void ios_cs2_stall_recovery_phases_note(uint64_t id, const struct ios_store_recovery_phases *phase)
{ (void)id; assert(holds == initial_holds); last_phase = *phase; }
static void ios_cs2_stall_recovery_note(uint64_t id, int inspected, uint64_t a, uint64_t b, uint64_t c,
 int d, int e, uint64_t pc, uint64_t ea, uint32_t insn, unsigned len, int r)
{ (void)id;(void)inspected;(void)a;(void)b;(void)c;(void)d;(void)e;(void)pc;(void)ea;(void)insn;(void)len;(void)r;assert(holds == initial_holds); }
#define thread_suspend suspend_target
#define thread_resume resume_target
#define thread_get_state get_target
#define thread_set_state set_target
'''
main = r'''
static unsigned char *allocation, *memory;
static void prepare(uint32_t insn)
{
    memset(memory, 0x5a, SPAN); memset(&current, 0, sizeof(current)); memset(&vector, 0x6b, sizeof(vector));
    opcode = insn; __darwin_arm_thread_state64_set_pc_fptr(current, (void *)&opcode); current.__x[28] = (uintptr_t)&frame_word;
    uintptr_t ea = (uintptr_t)memory + PAGE - 4;
    if (insn == 0xf8024373u) { current.__x[27] = ea - 36; current.__x[19] = UINT64_C(0x0102030405060708); }
    else current.__x[8] = ea - 16;
    reads_held = reads_unheld = captures = move_at_capture = refresh_source = 0;
}
int main(void)
{
    check_native_state();
    assert(!pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0));
    allocation = mmap(NULL, SPAN + PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(allocation != MAP_FAILED); memory = (void *)(((uintptr_t)allocation + PAGE-1) & ~(uintptr_t)(PAGE-1));
    struct ios_stuck_entry entry = {0};
    prepare(0xf8024373u);
    assert(!ios_stuck_store_inspect(17, 71, &entry, 100, 100));
#ifdef BEFORE
    assert(suspends == 1 && resumes == 1 && reads_held == 2 && !reads_unheld);
    puts("BASELINE actual Run15 inspector: first observation owns a suspension across both VM reads, at utility QoS");
#else
    assert(!suspends && !resumes && !reads_held && reads_unheld == 2);
    puts("PASS first observation: zero explicit suspensions, both VM reads outside owned hold");
#endif
    assert(ios_stuck_store_inspect(17, 71, &entry, 100, 100) == 1);
    assert(!holds && suspends == resumes && publications == 1);
    uint64_t actual; memcpy(&actual, memory + PAGE - 4, 8); assert(actual == UINT64_C(0x0102030405060708));
    assert(arm_thread_state64_get_pc(current) == (uintptr_t)&opcode + 4);
#ifndef BEFORE
    assert(last_phase.worker_id && last_phase.held_qos == QOS_CLASS_USER_INTERACTIVE && last_phase.qos_changed);
    assert(last_phase.qos_set_result == 0 && last_phase.qos_restore_result == 0);
    qos_class_t q; int relative; assert(!pthread_get_qos_class_np(pthread_self(), &q, &relative)); assert(q == QOS_CLASS_UTILITY);
    /* Ordinary concurrent progress: PC changes between advisory and held state. */
    prepare(0xf8024373u); entry.pc = (uintptr_t)&opcode; entry.ea = (uintptr_t)memory + PAGE - 4;
    unsigned prior = publications; move_at_capture = 2;
    assert(!ios_stuck_store_inspect(17,71,&entry,100,100)); assert(publications == prior && !holds && !entry.pc);
    for (unsigned i=0;i<SPAN;i++) assert(memory[i] == 0x5a);
    /* Fresh held source registers, not a prepared payload. */
    prepare(0xf8024373u); entry.pc = (uintptr_t)&opcode; entry.ea = (uintptr_t)memory + PAGE - 4; refresh_source = 1;
    assert(ios_stuck_store_inspect(17,71,&entry,100,100) == 1);
    memcpy(&actual, memory + PAGE - 4, 8); assert(actual == UINT64_C(0x8899aabbccddeeff));
    /* Nested ownership: release exactly our count, no force-resume. */
    holds = initial_holds = 1;
    prepare(0x3d800500u); entry.pc = (uintptr_t)&opcode; entry.ea = (uintptr_t)memory + PAGE - 4;
    assert(ios_stuck_store_inspect(17,71,&entry,100,100) == 1); assert(holds == 1);
    for (unsigned i=0;i<16;i++) assert(memory[PAGE-4+i] == 0x6b);
    holds = initial_holds = 0;
    assert(suspends == resumes);
    /* Completed live workload under repeated scope entry/exit. */
    for (unsigned i=0;i<1000;i++)
    {
        prepare(i&1 ? 0x3d800500u : 0xf8024373u); memset(&entry,0,sizeof(entry));
        assert(!ios_stuck_store_inspect(17,71,&entry,100,100));
        assert(ios_stuck_store_inspect(17,71,&entry,100,100) == 1);
        assert(!holds && suspends == resumes);
    }
    puts("PASS actual inspector/helper: 1000 repeated scalar/vector stores, checked fragment writes, fresh state, PC publication, QoS restoration, moving target and nested suspension ownership");
#endif
    assert(!munmap(allocation, SPAN + PAGE));
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-recovery-hold-') as d:
    for label, implementation in [('before', before), ('after', function(server, 'static int ios_stuck_store_inspect('))]:
        source = Path(d) / (label + '.c'); binary = source.with_suffix('')
        source.write_text(prefix + native + qos + helper + adapters +
                          function(server, 'static int ios_ldst_ea( uint32_t') + implementation + main)
        flags = ['-DBEFORE'] if label == 'before' else []
        subprocess.run([os.environ.get('CC','cc'), '-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                        '-Wno-unused-function','-Wno-unused-variable','-pthread',*flags,
                        '-I'+str(root/'build/ntdll-unix'),str(source),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
print('No deliberate faults/protection changes; phase durations and device hold reduction still require iPhone measurement')
