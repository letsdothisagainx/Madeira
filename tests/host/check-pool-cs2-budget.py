#!/usr/bin/env python3
"""Replay recorded CS2 image exhaustion through actual production pool functions.

The November 5 log has a 1 GiB pool, image head 0x1dcd0000, code tail
0x20014000 and a 0x3310000-byte phonon.dll request. Its 226 free extents
total 0x33e4000 bytes, but the largest is only 0xf0000 bytes. The fixture's
separated extents reproduce those aggregates, not the original addresses.

Compile the actual complete EC_CODE allocation branch (including fresh tail
carves and rollback), image allocation chain, failure path and process reclaim.
Only Darwin region/thread queries and unrelated platform callbacks are supplied
by the harness. Real shared file mappings check the RX/RW alias relationship.
No Wine/game execution or assertion of a successful device launch is implied.

The default matrix keeps historical exact-address controls separate from
current-policy returned-handle replays of every older lifecycle. The November
10 capture has 45 grants, an interval-censored clock boundary, and genuine
embree/client failure. Baseline and promotion-only controls must still fail;
combined production must preserve live code, retain safe future image space,
and survive bounded image/rotation stress at unchanged pool budgets.
"""
from pathlib import Path
import json
import hashlib
import os
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
native = Path(os.environ.get('MADEIRA_POOL_SOURCE', root / 'build/ntdll-unix/virtual_ios.c')).read_text()
allocator = (root / 'app/Madeira/JITAllocator.c').read_text()
content = (root / 'app/Madeira/ContentView.swift').read_text()
swift = (root / 'app/Madeira/StikJITHelper.swift').read_text()


def function(source, signature):
    start = source.index(signature)
    while source.index(';', start) < source.index('{', start):
        start = source.index(signature, start + len(signature))
    return source[start:source.index('\n}', start) + 2] + '\n'


# Explicit executable controls for the former policy. Only the two changed
# production decisions are reverted; all allocation/release/alias paths remain
# the extracted source. Never call an old-address assertion a new-policy pass.
variant = os.environ.get('MADEIRA_POOL_REPLAY_VARIANT', 'current')
if variant in ('historical', 'baseline'):
    pinned = (root / 'tests/fixtures/jit-pool/retire-owner-before-free-certification.c').read_text()
    assert hashlib.sha256(pinned.encode()).hexdigest() == '2aee569776f37cb17f8ef707c61ec5fb4f1188c4eb06b893576adf72e47816b1'
    native = native.replace(function(native, 'static unsigned ios_tail_carves_retire_owner('), pinned, 1)
if variant in ('historical', 'baseline', 'promotion') and 'static size_t ios_pool_code_carve_preserve_span(' in native:
    original = function(native, 'static size_t ios_pool_code_carve_preserve_span(')
    empty = original[:original.index('{') + 1] + '''
    (void)carves;(void)count;(void)selected;(void)total;
    (void)h1_off;(void)h1_end;(void)h2_off;(void)h2_end;
    return 0; /* former policy had no certified-span preservation */
}
'''
    native = native.replace(original, empty, 1)


carve_start = native.index('#define IOS_TAIL_CARVE_MAX ')
carve_table = native[carve_start:native.index('\n\n', carve_start)]
ec_start = native.index('size_t alloc_size = (*size_ptr + 0x3FFF) & ~0x3FFFUL;')
ec = native[ec_start:native.index('\n    }\n#endif', ec_start)]
release_start = native.index('    if ((type & MEM_RELEASE) && ios_jit_rx_base_global && ios_jit_pool_size_global &&')
release_end = native.index('\n    }\n', native.index('/* pool address but not a live tail carve', release_start)) + 7
release = native[release_start:release_end]
image_start = native.index('offset = ios_pool_alloc_range_tagged(alloc_size, jit_pool_size - ios_jit_tail_reserved, image_tag);',
                           native.index('size_t image_alloc = (image_size + page_size - 1)'))
image_end = native.index('\n            }', image_start)
image_chain = native[image_start:image_end]
failure_start = native.index('            if (offset == (size_t)-1)', image_end)
failure = native[failure_start:native.index('\n            /* Copy ENTIRE PE image', failure_start)]
loader_start = native.index('            if (ios_jit_copy_refused)\n', native.index('if (ios_resource_only_map('))
loader_failure = native[loader_start:native.index('\n#endif', loader_start)]
reserve_start = native.index('                ios_pool_head_reserve = ios_pool_parse_head_reserve( getenv( "MADEIRA_POOL_HEAD_RESERVE_MB" ) );')
reserve_init = native[reserve_start:native.index('                dprintf(', reserve_start)]
budget_helpers = function(allocator, 'bool jit_cs2_pool_plan(') + function(allocator, 'bool jit_pool_alias_layout_valid(')
if 'uint64_t jit_cs2_code_tail_limit_mb(' in allocator:
    budget_helpers += function(allocator, 'uint64_t jit_cs2_code_tail_limit_mb(')
assert 'return STATUS_NO_MEMORY;' in ec and 'ios_pool_tail_unreserve(' in ec
assert image_chain.count('ios_pool_low_image_range(') == 1
assert image_chain.count('ios_pool_recycle_code_range(') == 1
assert 'ios_jit_copy_refused = 1;' in failure and 'return -1;' in failure
assert 'status = STATUS_NO_MEMORY;' in loader_failure and 'goto done;' in loader_failure

helper_signatures = (
    'static size_t ios_pool_hole_head_place(',
    'static size_t ios_pool_hole_tail_start(',
    'static size_t ios_pool_hole_between(',
    'static size_t ios_pool_code_cap(',
    'static size_t ios_pool_code_growth_cap(',
    'static int ios_pool_code_growth_fits(',
    'static size_t ios_pool_parse_code_tail_limit(',
    'static size_t ios_pool_parse_head_reserve(',
    'static size_t ios_pool_holes_head_place(',
    'static size_t ios_pool_holes_tail_start(',
    'static size_t ios_pool_holes_between(',
    'static int ios_pool_reserve_code_tail(',
    'static int ios_pool_skip_pieces(',
    'static void ios_pool_tail_unreserve(',
    'int ios_jit_low_contains(',
    'static int ios_pool_low_take(',
    'static int ios_pool_range_execable(',
    'static int ios_pool_execable_runs(',
    'static int ios_pool_range_clean(',
    'static int ios_pool_free_put(',
    'static int ios_pool_mach_region(',
    'static int ios_pool_best_fit(',
    'static int ios_pool_keep_big(',
    'static int ios_pool_live_overlap( uintptr_t rw_start, size_t size,\n',
    'static size_t ios_pool_alloc_range_ex(',
    'static unsigned ios_pool_check_range_exec(',
    'static size_t ios_pool_alloc_range_tagged(',
    'static size_t ios_pool_low_image_range(',
    'static void ios_pool_failure_census(',
    'static size_t ios_pool_take_freed_for_tail(',
    'static int ios_tail_carve_in_low(',
    'static int ios_pool_preserve_code_carve(',
    'static size_t ios_pool_code_carve_preserve_span(',
    'static int ios_pool_code_carve_better(',
    'static int ios_pool_fresh_tail_fits(',
    'static int ios_tail_carve_scan(',
    'static int ios_tail_carve_occupied(',
    'static int ios_tail_carve_ready(',
    'static unsigned ios_tail_carves_retire_owner(',
    'static int ios_tail_carve_foreign_release(',
    'static void ios_tail_carves_owner_died(',
    'static int ios_pool_recycle_range_ready(',
    'static int ios_pool_recycle_main_range_ready(',
    'static int ios_pool_recycle_main_code_range(',
    'static int ios_pool_recycle_code_range(',
    'static int ios_pool_ledger_holds(',
    'void ios_jit_reclaim_process(',
)
# The source override permits the same regression to compile the previous
# production implementation and demonstrate its recorded capacity failure.
helpers = ''
for signature in helper_signatures:
    if signature == 'static void ios_pool_failure_census(' and '/* madeira-pool-accounting begin' in native:
        begin = native.index('/* madeira-pool-accounting begin')
        end = native.index('/* madeira-pool-accounting end */', begin) + len('/* madeira-pool-accounting end */')
        helpers += native[begin:end] + '\n'
    if signature in native:
        helpers += function(native, signature)

tail_trace = json.loads((root / 'tests/host/fixtures/pool-cs2-200111-tail.json').read_text())
nov7_trace = json.loads((root / 'tests/host/fixtures/pool-cs2-083837-tail.json').read_text())
embree_trace = json.loads((root / 'tests/host/fixtures/pool-cs2-200636-tail.json').read_text())
november8_trace = json.loads((root / 'tests/host/fixtures/pool-cs2-095621-tail.json').read_text())
fbb4_trace = json.loads((root / 'tests/host/fixtures/pool-cs2-fbb4-dep-tail.json').read_text())
november10_trace = json.loads((root / 'tests/host/fixtures/pool-cs2-011804-tail.json').read_text())
assert november10_trace['installed_commit'] == 'fce37394462fd9e1ad4288961f39b1fc636fbc33'
assert sum(e['op'] == 'allocate' for e in november10_trace['events']) == 45
assert fbb4_trace['installed_commit'] == 'fbb4a56f4e6959aef2f71651f281d844a451614f'
assert len([e for e in fbb4_trace['events'] if e['op'] == 'allocate']) == 30
dep_sweep = fbb4_trace['foreign_dep_sweep']
assert len(dep_sweep['copies']) == dep_sweep['copy_count'] == 42
assert sum(int(e['requested'], 16) for e in dep_sweep['copies']) == int(dep_sweep['bytes'], 16) == 0x25a8000
assert dep_sweep['first_failure']['image'] == 'kernelbase.dll'
assert fbb4_trace['embree']['line'] < dep_sweep['first_force_exec_line'] < dep_sweep['first_failure']['line']


def captured_rows(trace):
    rows = []
    for event in trace['events']:
        op = {'allocate': 0, 'release': 1, 'retire': 2}[event['op']]
        rows.append('    {%d, %d, %d, %d, %sULL, %s, %s, %s, %s, %d, %d},' % (
            event['line'], event['seconds'], op, event.get('handle', 0), event['owner'],
            event.get('requested', '0'), event.get('observed', '0'), event.get('head', '0'),
            hex(int(event['observed_rx'], 16) - 0x300000000) if 'observed_rx' in event else '0',
            event.get('rotation', False), event.get('lease', 0)))
    return '\n'.join(rows)


tail_replay = '''
struct captured_tail_event {
    unsigned line, seconds, op, handle;
    uintptr_t owner;
    size_t ask, observed, head, observed_off;
    int rotation;
    unsigned lease;
};
static const struct captured_tail_event captured_tail_events[] = {
''' + captured_rows(tail_trace) + '\n};\n' + '#define REPLAY_NEW_POLICY %d\n' % ('static int ios_pool_fresh_tail_fits(' in native)
tail_replay += 'static const struct captured_tail_event captured_nov7_tail_events[] = {\n' + captured_rows(nov7_trace) + '\n};\n'
tail_replay += '#define REPLAY_MAIN_TRANSFER %d\n' % ('static int ios_pool_recycle_main_code_range(' in native)
tail_replay += '#define REPLAY_CODE_TIE %d\n' % ('static int ios_pool_code_carve_better(' in native)
tail_replay += '#define REPLAY_CERTIFIED_SPAN %d\n' % ('static size_t ios_pool_code_carve_preserve_span(' in native)
tail_replay += '#define REPLAY_LEGACY_ONLY %d\n' % (os.environ.get('MADEIRA_POOL_LEGACY_REPLAY_ONLY') == '1')
tail_replay += 'static const struct captured_tail_event captured_embree_tail_events[] = {\n' + captured_rows(embree_trace) + '\n};\n'

tail_replay += 'static const struct captured_tail_event captured_november8_tail_events[] = {\n' + captured_rows(november8_trace) + '\n};\n'
tail_replay += 'static const struct captured_tail_event captured_fbb4_tail_events[] = {\n' + captured_rows(fbb4_trace) + '\n};\n'
tail_replay += 'static const size_t captured_fbb4_foreign_copy_sizes[] = {\n' + ','.join(e['requested'] for e in dep_sweep['copies']) + '\n};\n'
tail_replay += 'static const struct captured_tail_event captured_november10_tail_events[] = {\n' + captured_rows(november10_trace) + '\n};\n'

# Swift's launch plumbing is platform-owned; the decision and arithmetic run
# below as production C. Keep the selected game and the pre-Wine failure path
# connected to that decision, and reset the private reserve for later launches.
scope_start = content.index('if profile?.steamAppID == 730 {')
scope = content[scope_start:content.index('// ml694:', scope_start)]
assert '!StikJITHelper.poolTaken && measured && jit_cs2_pool_plan(' in scope
assert 'setenv("WINE_IOS_JIT_HEAD_RESERVE_MB", String(imageReserveMB), 1)' in scope
assert 'let codeTailLimitMB = jit_cs2_code_tail_limit_mb()' in scope
assert 'setenv("WINE_IOS_JIT_CODE_TAIL_LIMIT_MB", String(codeTailLimitMB), 1)' in scope
assert 'minimumPoolSize = poolSizeMB * 1024 * 1024' in scope
assert content.index('unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB")') < scope_start
assert content.index('unsetenv("WINE_IOS_JIT_CODE_TAIL_LIMIT_MB")') < scope_start
assert 'StikJITHelper.allocatePool(poolSize: poolSizeMB * 1024 * 1024, minimumPoolSize: minimumPoolSize)' in content
abort = content[content.index('logStore.log("JIT pool allocation FAILED'):content.index('// Step 1b (ml524')]
assert 'unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB")' in abort and '\n                return\n' in abort
assert 'unsetenv("WINE_IOS_JIT_CODE_TAIL_LIMIT_MB")' in abort
floor = swift[swift.index('if poolSize < minimumPoolSize {'):]
assert floor.index('return nil') < floor.index('jit26_prepare_region(')
remap_failure = swift[swift.index('guard kr1 == KERN_SUCCESS else {'):swift.index('// Validate the real aliases')]
assert 'if minimumPoolSize > 0 {' in remap_failure
assert 'vm_deallocate(mach_task_self_, rxAddrV, vm_size_t(poolSize))' in remap_failure
layout = swift[swift.index('// Validate the real aliases'):swift.index('let rwOverlaps = overlapsExeWindow(rwAddr')]
assert 'if minimumPoolSize > 0 {' in layout and 'jit_pool_alias_layout_valid(' in layout
assert 'vm_deallocate(mach_task_self_, rwAddr, vm_size_t(poolSize))' in layout
assert 'vm_deallocate(mach_task_self_, rxAddrV, vm_size_t(poolSize))' in layout
rw_failure_start = swift.index('guard kr2 == KERN_SUCCESS else {', swift.index('// Set RW protection'))
rw_failure = swift[rw_failure_start:swift.index('let rwPtr =', rw_failure_start)]
assert 'vm_deallocate(mach_task_self_, rwAddr, vm_size_t(poolSize))' in rw_failure
assert 'if minimumPoolSize > 0 {' in rw_failure
assert 'vm_deallocate(mach_task_self_, rxAddrV, vm_size_t(poolSize))' in rw_failure
assert 'if minimumPoolSize > 0 && dkr != KERN_SUCCESS {' in floor

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define MB ((size_t)1 << 20)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
static pthread_mutex_t diagnostics_lock=PTHREAD_MUTEX_INITIALIZER;
static char recycle_report[2048];
static int capture_dprintf(int fd,const char *format,...)
{
    (void)fd;char line[4096];va_list arguments;va_start(arguments,format);
    int count=vsnprintf(line,sizeof(line),format,arguments);va_end(arguments);
    pthread_mutex_lock(&diagnostics_lock);
    if(strstr(line,"[pool-recycle-main]"))snprintf(recycle_report,sizeof(recycle_report),"%.*s",(int)sizeof(recycle_report)-1,line);
    pthread_mutex_unlock(&diagnostics_lock);
    return count;
}
#define dprintf capture_dprintf
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY ((int)0xc0000017u)
#define FALL_THROUGH 7
#define MEM_RELEASE 0x8000
#define IOS_POOL_BIG_MIN (64u * 1024 * 1024)
#define IOS_POOL_LEDGER_MAX 1024
#define IOS_POOL_FREE_MAX 1024
#define IOS_POOL_REUSE_GRACE_SEC 3
#define IOS_POOL_LOW_CARVE_MAX 0x8000000u
#define ERR(...) ((void)0)
struct ios_pool_free { size_t off, size; time_t freed_at; int advised; uint64_t tag; };
struct ios_pool_alloc { size_t off, size; void *peb; uint64_t tag; };
static struct ios_pool_free ios_pool_freelist[IOS_POOL_FREE_MAX];
static struct ios_pool_alloc ios_pool_ledger[IOS_POOL_LEDGER_MAX];
static int ios_pool_free_count, ios_pool_ledger_count, ios_pool_last_alloc_reused;
static __thread int ios_pool_last_same_image;
static void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
static size_t ios_jit_pool_size_global, jit_pool_offset, ios_pool_head_reserve, ios_pool_code_tail_limit;
static volatile size_t ios_jit_tail_reserved, ios_jit_low_reserved;
static size_t ios_jit_hole_off, ios_jit_hole_end, ios_jit_hole_off_eff, ios_jit_hole_end_eff;
static size_t ios_jit_hole2_off, ios_jit_hole2_end;
static size_t ios_pool_big_off, ios_pool_big_size;
static time_t ios_pool_big_freed_at;
static int ios_pool_big_taken, ios_jit_low_full_logged;
static uintptr_t ios_jit_low_rx_global, ios_jit_low_rw_global;
static size_t ios_jit_low_size_global;
static pthread_mutex_t ios_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { uintptr_t user_va, user_va_end, jit_rx_alias, jit_rw_alias; } ios_jit_anon_aliases[8];
static struct { void *pe_base, *jit_base; size_t size; unsigned long long generation; } ios_jit_mappings[8];
static int ios_jit_anon_alias_count, ios_jit_mapping_count, ios_jit_copy_refused;
static void *ios_jit_alias_pushback_peb;
static void (*ios_jit_alias_pushback_cb)(void);
static void *arm64ec_view;
static uintptr_t owner;
static __thread unsigned schedule_role, carve_lock_depth, pool_lock_depth;
static struct { void *owner; unsigned long long lease; int quiescent; } test_leases[64];
static unsigned test_lease_count;
static void set_process_lease(void *peb, unsigned long long lease, int quiescent)
{
    unsigned i;
    for (i = 0; i < test_lease_count; ++i) if (test_leases[i].owner == peb) break;
    CHECK(i < ARRAY_SIZE(test_leases));
    if (i == test_lease_count) ++test_lease_count;
    test_leases[i].owner = peb; test_leases[i].lease = lease; test_leases[i].quiescent = quiescent;
}
unsigned long long ios_thread_process_lease(void *peb, int create)
{
    (void)create;
    CHECK(!carve_lock_depth && !pool_lock_depth);
    for (unsigned i = 0; i < test_lease_count; ++i)
        if (test_leases[i].owner == peb) return test_leases[i].lease;
    return 0;
}
unsigned long long ios_thread_process_quiescent_lease(void *peb)
{
    CHECK(!carve_lock_depth && !pool_lock_depth);
    for (unsigned i = 0; i < test_lease_count; ++i)
        if (test_leases[i].owner == peb && test_leases[i].quiescent) return test_leases[i].lease;
    return 0;
}
static time_t fake_now = 100;
static time_t fake_time(time_t *t) { if (t) *t = fake_now; return fake_now; }
#define time fake_time
static void *ios_jit_current_peb(void) { return (void *)owner; }
static uintptr_t ios_wow_base(void) { return 0; }
static unsigned aliases_retired;
static void ios_mono_alias_retire(uintptr_t va) { CHECK(va); aliases_retired++; }
static void ios_sc_grants_owner_died(void *peb) { (void)peb; }
static void ios_alias_cb_drop(void *peb) { (void)peb; }
static void ios_exe_win_note_dead_peb(void *peb) { (void)peb; }
static void clear_arm64ec_range(void *addr, size_t size) { (void)addr; (void)size; }
typedef int (*ios_pool_clean_fn)(size_t, size_t);
typedef int (*ios_pool_region_fn)(uint64_t *, uint64_t *, unsigned *);
''' + carve_table + r'''
static unsigned ios_tail_carve_n;
static pthread_mutex_t ios_tail_carve_lock = PTHREAD_MUTEX_INITIALIZER;

/* Darwin answers are supplied; allocator/retirement decisions run unchanged.
 * The final image test executes only a tiny harness-owned host ISA stub. */
typedef unsigned mach_port_t, mach_msg_type_number_t, thread_act_t;
typedef thread_act_t *thread_act_array_t;
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef int kern_return_t;
typedef void *thread_state_t, *vm_region_info_t;
typedef struct { uintptr_t pc; } arm_thread_state64_t;
typedef struct { int protection, max_protection; } vm_region_basic_info_data_64_t;
typedef struct { unsigned user_tag, share_mode; } vm_region_extended_info_data_t;
#define ARM_THREAD_STATE64 1
#define ARM_THREAD_STATE64_COUNT 1
#define KERN_SUCCESS 0
#define MACH_PORT_NULL 0
#define VM_REGION_BASIC_INFO_COUNT_64 2
#define VM_REGION_BASIC_INFO_64 1
#define VM_REGION_EXTENDED_INFO_COUNT 2
#define VM_REGION_EXTENDED_INFO 2
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define arm_thread_state64_get_pc(st) ((st).pc)
static uintptr_t scanned_pc;
static int state_query_fail, thread_list_fail, region_query_fail;
static int region_bad_alias;
static size_t region_bad_off, region_bad_size;
static unsigned region_bad_prot, region_bad_max;
static mach_port_t mach_task_self(void) { return 0; }
static mach_port_t mach_thread_self(void) { return 1; }
static int task_threads(mach_port_t task, thread_act_array_t *out, mach_msg_type_number_t *count)
{
    (void)task;
    if (thread_list_fail) return -1;
    *out = malloc(2 * sizeof **out); CHECK(*out);
    (*out)[0] = 1; (*out)[1] = 2; *count = 2;
    return KERN_SUCCESS;
}
static int thread_get_state(thread_act_t thread, int flavor, thread_state_t state, mach_msg_type_number_t *count)
{
    (void)thread; (void)flavor; (void)count;
    if (state_query_fail) return -1;
    ((arm_thread_state64_t *)state)->pc = scanned_pc;
    return KERN_SUCCESS;
}
static int mach_port_deallocate(mach_port_t task, mach_port_t port)
{ (void)task; (void)port; return 0; }
static int mach_vm_deallocate(mach_port_t task, mach_vm_address_t address, mach_vm_size_t size)
{ (void)task; (void)size; free((void *)address); return 0; }
static int mach_vm_region(mach_port_t task, mach_vm_address_t *address, mach_vm_size_t *size,
                          int flavor, vm_region_info_t raw, mach_msg_type_number_t *count, mach_port_t *object)
{
    (void)task; (void)count;
    if (region_query_fail) return -1;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global, rw = (uintptr_t)ios_jit_rw_base_global;
    int alias = *address >= rx && *address < rx + ios_jit_pool_size_global ? 1 : 2;
    uintptr_t base = alias == 1 ? rx : rw, query = *address;
    CHECK(query >= base && query < base + ios_jit_pool_size_global);
    *address = base; *size = ios_jit_pool_size_global; *object = MACH_PORT_NULL;
    if (flavor == VM_REGION_BASIC_INFO_64)
    {
        vm_region_basic_info_data_64_t *info = raw;
        info->protection = alias == 1 ? 5 : 3; info->max_protection = 7;
        if (region_bad_alias == alias && region_bad_size)
        {
            uintptr_t bad = base + region_bad_off, end = bad + region_bad_size;
            if (query < bad) *size = bad - base;
            else if (query < end)
            {
                *address = bad; *size = region_bad_size;
                info->protection = region_bad_prot; info->max_protection = region_bad_max;
            }
            else { *address = end; *size = base + ios_jit_pool_size_global - end; }
        }
    }
    else
    {
        vm_region_extended_info_data_t *info = raw;
        info->user_tag = 0; info->share_mode = 0;
    }
    return KERN_SUCCESS;
}
/* Deterministic schedules pause only at real production mutex operations.
 * They neither alter cursors nor fabricate allocation results. */
static pthread_mutex_t schedule_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t schedule_cond = PTHREAD_COND_INITIALIZER;
static int schedule_mode, tiny_has_pool, other_waiting, release_tiny;
static int scheduled_mutex_lock(pthread_mutex_t *lock)
{
    if (schedule_mode && ((schedule_role == 2 && lock == &ios_pool_lock) ||
                          (schedule_role == 3 && lock == &ios_tail_carve_lock)))
    {
        pthread_mutex_lock(&schedule_lock);
        other_waiting = 1; pthread_cond_broadcast(&schedule_cond);
        pthread_mutex_unlock(&schedule_lock);
    }
    int result = pthread_mutex_lock(lock);
    if (!result && lock == &ios_tail_carve_lock) ++carve_lock_depth;
    if (!result && lock == &ios_pool_lock) ++pool_lock_depth;
    if (!result && schedule_mode && schedule_role == 1 && lock == &ios_pool_lock && carve_lock_depth)
    {
        pthread_mutex_lock(&schedule_lock);
        tiny_has_pool = 1; pthread_cond_broadcast(&schedule_cond);
        while (!release_tiny) pthread_cond_wait(&schedule_cond, &schedule_lock);
        pthread_mutex_unlock(&schedule_lock);
    }
    return result;
}
static int scheduled_mutex_unlock(pthread_mutex_t *lock)
{
    if (lock == &ios_tail_carve_lock) { CHECK(carve_lock_depth); --carve_lock_depth; }
    if (lock == &ios_pool_lock) { CHECK(pool_lock_depth); --pool_lock_depth; }
    return pthread_mutex_unlock(lock);
}
#define pthread_mutex_lock scheduled_mutex_lock
#define pthread_mutex_unlock scheduled_mutex_unlock
''' + budget_helpers + helpers + r'''

static void initialize_head_reserve(void)
{
    size_t jit_pool_size = ios_jit_pool_size_global; (void)jit_pool_size;
''' + reserve_init + r'''
}

static int allocate_code(size_t *size_ptr, void **ret)
{
''' + ec + r'''
}
static int release_code(void *base, unsigned type, void **addr_ptr, size_t *size_ptr)
{
''' + release + r'''
    return FALL_THROUGH;
}
static int allocate_image(size_t alloc_size, size_t *result)
{
    size_t jit_pool_size = ios_jit_pool_size_global, offset;
    uint64_t image_tag = 0;
    void *image_base = (void *)(uintptr_t)0xfb7640000ULL;
    size_t image_size = alloc_size == 0x3310000 ? 0x330e000 : alloc_size;
    void *base = ios_jit_rx_base_global;
    size_t size = 0x4000;
''' + image_chain + '\n' + failure + r'''
    *result = offset;
    return 0;
}
/* The executable loader's actual refusal block consumes the protect failure. */
static int executable_load_status(void)
{
    int status = STATUS_SUCCESS;
    void *nt_name = NULL;
    struct { char Name[8]; } sec[1] = {{{'.', 't', 'e', 'x', 't', 0}}};
    int i = 0;
#define debugstr_us(p) ((void)(p), "phonon.dll")
''' + loader_failure + r'''
done:
    return status;
}

static void *rx_memory, *rw_memory;
static size_t mapped_size;
static const size_t tail_before = 0x20014000, rotation_head = 0x1ccd7000;
static const size_t phonon_head = 0x1dcd0000, retry_head = 0x1e070000;
static const size_t phonon_size = 0x3310000;
static const uintptr_t steam_owner = 0x68, helper_owner = 0x90, cs2_owner = 0x304;

static void check_budget_plan(uint64_t *selected, uint64_t *reserve)
{
    const uint64_t physical = 8192 * MB, lo = 0x100000000, hi = 0xfc0000000;
    CHECK(jit_cs2_pool_plan(1024, 5120 * MB, 1024 * MB, physical, lo, hi, selected, reserve));
    CHECK(*selected == 1152 && *reserve == 240);
    CHECK(jit_cs2_code_tail_limit_mb() == 512);
    for (uint64_t requested = 256; requested <= 1152; requested += 16)
    {
        uint64_t pool = 0, image_reserve = 0;
        CHECK(jit_cs2_pool_plan(requested, 5120 * MB, 1024 * MB, physical, lo, hi, &pool, &image_reserve));
        CHECK(pool == *selected && image_reserve == *reserve);
    }
    uint64_t pool = 1, image_reserve = 1;
#define REFUSED(req, available, footprint, ram, min_va, max_va) do { \
    pool = image_reserve = 1; \
    CHECK(!jit_cs2_pool_plan(req, available, footprint, ram, min_va, max_va, &pool, &image_reserve)); \
    CHECK(!pool && !image_reserve); \
} while (0)
    REFUSED(255, 5120 * MB, 1024 * MB, physical, lo, hi);
    REFUSED(1153, 5120 * MB, 1024 * MB, physical, lo, hi);
    REFUSED(1024, 0, 1024 * MB, physical, lo, hi);
    REFUSED(1024, UINT64_MAX, 1, physical, lo, hi);
    REFUSED(1024, 5120 * MB, UINT64_MAX, physical, lo, hi);
    REFUSED(1024, 5120 * MB, 1024 * MB, 0, lo, hi);
    REFUSED(1024, 5120 * MB, 1024 * MB, UINT64_MAX, lo, hi);
    REFUSED(1024, 5120 * MB, 1024 * MB, 6144 * MB - 1, lo, hi);
    REFUSED(1024, 3200 * MB - 1, 3000 * MB, physical, lo, hi);
    REFUSED(1024, 4000 * MB, 1994 * MB, physical, lo, hi);
    CHECK(jit_cs2_pool_plan(1024, 4000 * MB, 1994 * MB + 1, physical, lo, hi, &pool, &image_reserve));
    REFUSED(1024, 5120 * MB, 1024 * MB, physical, lo, lo);
    REFUSED(1024, 5120 * MB, 1024 * MB, physical, lo, lo + 2304 * MB - 1);
    REFUSED(1024, 5120 * MB, 1024 * MB, physical, lo, UINT64_MAX);
    CHECK(jit_cs2_pool_plan(1024, 3200 * MB, 3000 * MB, physical, lo, lo + 2304 * MB, &pool, &image_reserve));
    CHECK(!jit_cs2_pool_plan(1024, 5120 * MB, 1024 * MB, physical, lo, hi, NULL, &image_reserve));
    CHECK(!image_reserve);
#undef REFUSED
    const uint64_t rx = 0x300000000, rw = 0x350000000, size = *selected * MB;
    CHECK(jit_pool_alias_layout_valid(rx, rw, size, lo, hi, 0x140000000, 64 * MB));
    CHECK(jit_pool_alias_layout_valid(rx, rx + size, size, lo, hi, 0x140000000, 64 * MB));
    CHECK(!jit_pool_alias_layout_valid(rx, rw, size + 1, lo, hi, 0, 0));
    CHECK(!jit_pool_alias_layout_valid(rx + 1, rw, size, lo, hi, 0, 0));
    CHECK(!jit_pool_alias_layout_valid(rx, rx + size - 0x4000, size, lo, hi, 0, 0));
    CHECK(!jit_pool_alias_layout_valid(rx, rw, size, lo, rw + size - 1, 0, 0));
    CHECK(!jit_pool_alias_layout_valid(rx, rw, size, lo, hi, rx, 0x4000));
    CHECK(!jit_pool_alias_layout_valid(rx, rw, size, lo, hi, rw, 0x4000));
    CHECK(!jit_pool_alias_layout_valid(rx, rw, size, lo, hi, UINT64_MAX, 2));
    CHECK(!jit_pool_alias_layout_valid(0x118ffc000, rw, size, lo, hi, 0, 0));
    CHECK(!jit_pool_alias_layout_valid(0x6fff000000, rw, size, lo, 0x8000000000, 0, 0));
    CHECK(!jit_pool_alias_layout_valid(rx, rw, size, lo, UINT64_MAX, 0, 0));

    ios_jit_pool_size_global = *selected * MB;
    unsetenv("WINE_IOS_JIT_CODE_TAIL_LIMIT_MB");
    unsetenv("MADEIRA_POOL_HEAD_RESERVE_MB"); unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB");
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == 48 * MB);
    setenv("WINE_IOS_JIT_HEAD_RESERVE_MB", "240", 1);
    setenv("WINE_IOS_JIT_CODE_TAIL_LIMIT_MB", "512", 1);
    setenv("MADEIRA_POOL_HEAD_RESERVE_MB", "48", 1);
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == *reserve * MB);
    CHECK(ios_pool_code_tail_limit == 512 * MB);
    setenv("MADEIRA_POOL_HEAD_RESERVE_MB", "256", 1);
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == 256 * MB);
    setenv("MADEIRA_POOL_HEAD_RESERVE_MB", "48", 1);
    unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB");
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == 48 * MB);
    unsetenv("MADEIRA_POOL_HEAD_RESERVE_MB");
    unsetenv("WINE_IOS_JIT_CODE_TAIL_LIMIT_MB");
    initialize_head_reserve(); CHECK(!ios_pool_code_tail_limit);
    puts("PASS: production CS2 plan gates measured RAM/address budgets; layout bounds and private reserve cannot weaken existing checks");
}

static void reset(size_t total, size_t reserve)
{
    CHECK(total <= mapped_size);
    ios_jit_rx_base_global = rx_memory; ios_jit_rw_base_global = rw_memory;
    ios_jit_pool_size_global = total; ios_pool_head_reserve = reserve; ios_pool_code_tail_limit = 0;
    jit_pool_offset = rotation_head; ios_jit_tail_reserved = tail_before;
    ios_jit_hole_off = ios_jit_hole_end = ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    ios_jit_hole2_off = ios_jit_hole2_end = ios_pool_big_size = 0;
    ios_jit_low_size_global = ios_jit_low_reserved = ios_jit_low_full_logged = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_jit_anon_alias_count = ios_jit_mapping_count = 0;
    ios_jit_copy_refused = aliases_retired = state_query_fail = thread_list_fail = region_query_fail = 0;
    region_bad_alias = 0; region_bad_off = region_bad_size = 0; scanned_pc = 0;
    test_lease_count = 0;
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    /* The log's final rotation reused a free 16 MB buffer. Three live 128 MB
     * generations belong to Steam and its webhelper; none may be reclaimed. */
    ios_tail_carve_n = 4;
    ios_tail_carves[0] = (struct ios_tail_carve){ .off = total - 16 * MB, .size = 16 * MB, .free = 1 };
    ios_tail_carves[1] = (struct ios_tail_carve){ .off = total - tail_before, .size = 128 * MB, .peb = (void *)helper_owner };
    ios_tail_carves[2] = (struct ios_tail_carve){ .off = total - tail_before + 128 * MB, .size = 128 * MB, .peb = (void *)helper_owner };
    ios_tail_carves[3] = (struct ios_tail_carve){ .off = total - tail_before + 256 * MB, .size = 128 * MB, .peb = (void *)steam_owner };
    /* Deliberately separated page extents: the log's exact count/bytes/max,
     * without inventing a claim that their synthetic addresses were logged. */
    size_t cursor = MB, free_bytes = 0, largest = 0;
    for (int i = 0; i < 226; i++)
    {
        size_t n = i == 0 ? 0xf0000 : (i <= 111 ? 15 : 14) * 0x4000;
        ios_pool_freelist[i] = (struct ios_pool_free){ cursor, n, 0, 1, 0 };
        cursor += n + 0x4000; free_bytes += n;
        if (n > largest) largest = n;
    }
    ios_pool_free_count = 226;
    CHECK(free_bytes == 0x33e4000 && largest == 0xf0000 && cursor < rotation_head);
    owner = cs2_owner;
}

/* FEX asks for 128 MB, then halves on STATUS_NO_MEMORY; all placement,
 * cap decisions, NOP fills and reuse are the extracted production branch. */
static size_t rotate(void **ret)
{
    for (size_t ask = 128 * MB; ask >= MB; ask >>= 1)
    {
        size_t size = ask;
        int status = allocate_code(&size, ret);
        if (status == STATUS_SUCCESS) return size;
        CHECK(status == STATUS_NO_MEMORY);
    }
    return 0;
}

static void expect_failed_image(size_t request)
{
    size_t head = jit_pool_offset, tail = ios_jit_tail_reserved, result = (size_t)-1;
    int ledger = ios_pool_ledger_count, count = ios_pool_free_count;
    struct ios_pool_free saved[IOS_POOL_FREE_MAX];
    memcpy(saved, ios_pool_freelist, sizeof saved);
    errno = 0;
    CHECK(allocate_image(request, &result) == -1 && errno == ENOMEM && result == (size_t)-1);
    CHECK(ios_jit_copy_refused && executable_load_status() == STATUS_NO_MEMORY && !ios_jit_copy_refused);
    CHECK(jit_pool_offset == head && ios_jit_tail_reserved == tail);
    CHECK(ios_pool_ledger_count == ledger && ios_pool_free_count == count);
    CHECK(!memcmp(saved, ios_pool_freelist, sizeof saved));
}

static void check_original_and_growth_only(void)
{
    void *code = NULL;
    reset(1024 * MB, 48 * MB);
    CHECK(rotate(&code) == 16 * MB && ios_jit_tail_reserved == tail_before);
    CHECK((uintptr_t)code == (uintptr_t)rx_memory + ios_tail_carves[0].off);
    jit_pool_offset = phonon_head;
    CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x231c000);
    expect_failed_image(phonon_size);
    jit_pool_offset = retry_head; expect_failed_image(phonon_size);

    reset(1152 * MB, 48 * MB);
    CHECK(rotate(&code) == 128 * MB);
    CHECK(ios_jit_tail_reserved == tail_before + 128 * MB && ios_tail_carves[0].free);
    size_t off = (uintptr_t)code - (uintptr_t)rx_memory;
    CHECK(off == 1152 * MB - tail_before - 128 * MB);
    CHECK(*(const uint32_t *)code == 0xd503201f);
    CHECK(*(const uint32_t *)((const char *)code + 128 * MB - 4) == 0xd503201f);
    jit_pool_offset = phonon_head; expect_failed_image(phonon_size);
    puts("PASS: 1 GiB reproduces phonon.dll failure; growing to 1152 MiB alone gives the growth to a new 128 MiB code buffer and still fails");
}

static void check_paired_budget(size_t pool_mb, size_t reserve_mb)
{
    void *code = NULL;
    reset(pool_mb * MB, reserve_mb * MB);
    struct ios_tail_carve live[3]; memcpy(live, &ios_tail_carves[1], sizeof live);
    CHECK(rotate(&code) == 16 * MB && ios_jit_tail_reserved == tail_before);
    CHECK(ios_tail_carve_n == 4 && !memcmp(live, &ios_tail_carves[1], sizeof live));
    CHECK(*(const uint32_t *)code == 0xd503201f);
    CHECK(*(const uint32_t *)((const char *)code + 16 * MB - 4) == 0xd503201f);

    /* Use the later retry's higher head for the success check too. The plan
     * must retain at least the original 48 MB margin after copying phonon. */
    jit_pool_offset = retry_head;
    size_t image_off = (size_t)-1;
    CHECK(!allocate_image(phonon_size, &image_off) && image_off == retry_head);
    CHECK(ios_pool_ledger_holds(image_off, phonon_size, (void *)cs2_owner));
    CHECK(!ios_pool_ledger_holds(image_off, phonon_size, (void *)helper_owner));
    CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved >= 48 * MB);
    CHECK(ios_pool_free_count == 226 && ios_pool_ledger_count == 1);
    CHECK(!memcmp(live, &ios_tail_carves[1], sizeof live));
    size_t subsequent_off = (size_t)-1;
    CHECK(!allocate_image(48 * MB, &subsequent_off));
    CHECK(subsequent_off == image_off + phonon_size);
    CHECK(ios_pool_ledger_holds(subsequent_off, 48 * MB, (void *)cs2_owner));
    CHECK(ios_pool_ledger_count == 2 && !memcmp(live, &ios_tail_carves[1], sizeof live));
    size_t foreign_off = (size_t)-1;
    owner = helper_owner;
    CHECK(!allocate_image(0x4000, &foreign_off));
    CHECK(ios_pool_ledger_holds(foreign_off, 0x4000, (void *)helper_owner));
    owner = cs2_owner;

    /* Production reclaim removes the image, its mapping and aliases, and
     * retires this process's code buffer while leaving Steam's carves live. */
    ios_jit_mappings[0].pe_base = (void *)(uintptr_t)0xfb7640000ULL;
    ios_jit_mappings[0].jit_base = (char *)rx_memory + image_off;
    ios_jit_mappings[0].size = phonon_size; ios_jit_mappings[0].generation = 1; ios_jit_mapping_count = 1;
    ios_jit_mappings[1].pe_base = (void *)(uintptr_t)0x20000000;
    ios_jit_mappings[1].jit_base = (char *)rx_memory + foreign_off;
    ios_jit_mappings[1].size = 0x4000; ios_jit_mappings[1].generation = 2; ios_jit_mapping_count = 2;
    ios_jit_anon_aliases[0].user_va = 0x12340000;
    ios_jit_anon_aliases[0].user_va_end = 0x12344000;
    ios_jit_anon_aliases[0].jit_rx_alias = (uintptr_t)rx_memory + image_off;
    ios_jit_anon_aliases[0].jit_rw_alias = (uintptr_t)rw_memory + image_off;
    ios_jit_anon_aliases[1].user_va = 0x23450000;
    ios_jit_anon_aliases[1].user_va_end = 0x23454000;
    ios_jit_anon_aliases[1].jit_rx_alias = (uintptr_t)rx_memory + foreign_off;
    ios_jit_anon_aliases[1].jit_rw_alias = (uintptr_t)rw_memory + foreign_off;
    ios_jit_anon_alias_count = 2;
    ios_jit_reclaim_process((void *)cs2_owner);
    CHECK(ios_pool_ledger_count == 1 && !ios_jit_mappings[0].pe_base && !ios_jit_mappings[0].size && !ios_jit_mappings[0].generation);
    CHECK(ios_pool_ledger_holds(foreign_off, 0x4000, (void *)helper_owner));
    CHECK(ios_jit_mappings[1].pe_base && ios_jit_mappings[1].size == 0x4000 && ios_jit_mappings[1].generation == 2);
    CHECK(!ios_jit_anon_aliases[0].user_va && !ios_jit_anon_aliases[0].user_va_end && aliases_retired == 1);
    CHECK(ios_jit_anon_aliases[1].user_va == 0x23450000 && ios_jit_anon_aliases[1].user_va_end == 0x23454000);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].retired && !ios_tail_carves[0].peb);
    CHECK(!memcmp(live, &ios_tail_carves[1], sizeof live));
    CHECK(!ios_pool_ledger_holds(image_off, phonon_size, (void *)cs2_owner));

    /* Before grace the retired buffer is unavailable. An unknown thread state
     * restarts grace. After a clean scan it can be assigned to a new process. */
    CHECK(!ios_tail_carve_ready(&ios_tail_carves[0], fake_now));
    fake_now += IOS_POOL_REUSE_GRACE_SEC;
    state_query_fail = 1; owner = 0x400;
    size_t request = 16 * MB; void *other = NULL;
    CHECK(allocate_code(&request, &other) == STATUS_SUCCESS);
    CHECK(other != code && ios_tail_carves[0].free && ios_tail_carves[0].freed_at == fake_now);
    state_query_fail = 0; fake_now += IOS_POOL_REUSE_GRACE_SEC;
    request = 16 * MB;
    CHECK(allocate_code(&request, &other) == STATUS_SUCCESS && other == code);
    CHECK(!ios_tail_carves[0].free && !ios_tail_carves[0].retired && ios_tail_carves[0].peb == (void *)owner);
    void *released = NULL; size_t released_size = 0;
    owner = cs2_owner;
    CHECK(release_code(code, MEM_RELEASE, &released, &released_size) == FALL_THROUGH && !ios_tail_carves[0].free);
    owner = 0x400;
    CHECK(release_code(code, MEM_RELEASE, &released, &released_size) == STATUS_SUCCESS && released_size == 16 * MB);
    puts("PASS: paired budget reserves phonon.dll plus 48 MiB of later images; real reclaim preserves foreign owners, aliases and retirement grace");
}

''' + tail_replay + r'''

static void final_image_extents(void)
{
    static const size_t sizes[] = {0x38000, 0x28000, 0x20000, 0x18000, 0x10000};
    size_t cursor = MB, sum = 0;
    ios_pool_free_count = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(sizes); ++i)
    {
        ios_pool_freelist[i] = (struct ios_pool_free){cursor, sizes[i], 0, 1, 0};
        cursor += sizes[i] + 0x4000; sum += sizes[i];
        ++ios_pool_free_count;
    }
    CHECK(sum == 0xa8000 && ios_pool_free_count == 5);
}

static void check_captured_server_failure(void)
{
    reset(1152 * MB, 176 * MB);
    jit_pool_offset = 0x244dc000; ios_jit_tail_reserved = 0x22018000;
    final_image_extents();
    CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x1b0c000);
    expect_failed_image(0x2580000);
    puts("PASS: exact server.dll census reproduces 37.5 MiB failure with 27.046875 MiB virgin space and five fragmented image extents");
}

static uintptr_t alias_expected_fault_address;
_Static_assert(__atomic_always_lock_free(sizeof(uintptr_t), 0), "RX fault address reads must be lock-free");
static void alias_permission_fault(int signal_number, siginfo_t *info, void *context)
{
    (void)context;
    /* Require a kernel-generated permission fault at the exact access. Exit
     * directly so a Linux piped core collector cannot delay waitpid while
     * dumping the large shared mappings and the sanitizer address space. */
    int expected = (signal_number == SIGSEGV || signal_number == SIGBUS) && info &&
                   info->si_signo == signal_number && info->si_code > 0 &&
                   (uintptr_t)info->si_addr == __atomic_load_n(&alias_expected_fault_address, __ATOMIC_RELAXED);
    _exit(expected ? 77 : 92);
}

static void check_owned_executable_image(size_t off, size_t size)
{
    CHECK(off && size >= 16 && off + size < mapped_size);
    unsigned char *rw = (unsigned char *)rw_memory + off;
    const unsigned char *rx = (const unsigned char *)rx_memory + off;
    const unsigned char before = rx[-1], after = rx[size];
#if defined(__x86_64__)
    const unsigned char stub[] = {0xb8, 42, 0, 0, 0, 0xc3}; /* mov eax,42; ret */
#elif defined(__aarch64__) || defined(__arm64__)
    const uint32_t stub[] = {0x52800540, 0xd65f03c0}; /* mov w0,42; ret */
#else
#error This executable-capacity regression requires an x86-64 or ARM64 host.
#endif
    memcpy(rw, stub, sizeof stub);
    *(uint64_t *)(rw + size - 8) = 0xdecafbad12345678ULL;
    CHECK(!memcmp(rx, stub, sizeof stub));
    CHECK(*(const uint64_t *)(rx + size - 8) == 0xdecafbad12345678ULL);
    CHECK(rx[-1] == before && rx[size] == after);
    __builtin___clear_cache((char *)rx, (char *)rx + sizeof stub);
    int (*run)(void) = (int (*)(void))(uintptr_t)rx;
    CHECK(run() == 42);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child)
    {
        __atomic_store_n(&alias_expected_fault_address, (uintptr_t)rx, __ATOMIC_RELAXED);
        struct sigaction action;
        memset(&action, 0, sizeof action);
        action.sa_sigaction = alias_permission_fault;
        action.sa_flags = SA_SIGINFO;
        if (sigemptyset(&action.sa_mask) || sigaction(SIGSEGV, &action, NULL) ||
            sigaction(SIGBUS, &action, NULL)) _exit(93);
        *(volatile unsigned char *)(uintptr_t)rx = 0;
        _exit(91);
    }
    int status = 0; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    CHECK(run() == 42 && !memcmp(rx, stub, sizeof stub));
    child = fork(); CHECK(child >= 0);
    if (!child)
    {
        __atomic_store_n(&alias_expected_fault_address, (uintptr_t)rw, __ATOMIC_RELAXED);
        struct sigaction action;
        memset(&action, 0, sizeof action); action.sa_sigaction = alias_permission_fault;
        action.sa_flags = SA_SIGINFO;
        if (sigemptyset(&action.sa_mask) || sigaction(SIGSEGV, &action, NULL) ||
            sigaction(SIGBUS, &action, NULL)) _exit(93);
        int (*forbidden)(void) = (int (*)(void))(uintptr_t)rw;
        (void)forbidden(); _exit(91);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    CHECK(run() == 42 && !memcmp(rx, stub, sizeof stub));
}

static void check_captured_tail_history(size_t reserve, size_t code_limit)
{
    void *handles[64] = {0};
    struct ios_tail_carve pinned[3];
    unsigned pinned_n = 0, oversize_tiny = 0;
    reset(1152 * MB, reserve);
    ios_pool_code_tail_limit = code_limit;
    jit_pool_offset = ios_jit_tail_reserved = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_tail_carve_n = 0;
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    for (unsigned i = 0; i < ARRAY_SIZE(captured_tail_events); ++i)
    {
        const struct captured_tail_event *e = &captured_tail_events[i];
        owner = e->owner; fake_now = 1000 + e->seconds;
        if (e->op == 2) { ios_tail_carves_owner_died((void *)owner); continue; }
        if (e->op == 1)
        {
            void *released = NULL; size_t size = 0;
            CHECK(handles[e->handle]);
            CHECK(release_code(handles[e->handle], MEM_RELEASE, &released, &size) == STATUS_SUCCESS);
            CHECK(released == handles[e->handle]);
            continue;
        }
        CHECK(e->handle < ARRAY_SIZE(handles));
        jit_pool_offset = e->head;
        size_t got = e->ask;
        if (e->rotation) got = rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got, &handles[e->handle]) == STATUS_SUCCESS);
        CHECK(handles[e->handle] && got >= e->ask);
        if (!REPLAY_NEW_POLICY && (got != e->observed ||
            (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory != e->observed_off))
        {
            fprintf(stderr, "baseline replay differs at captured line %u: got=0x%zx observed=0x%zx off=0x%zx expected-off=0x%zx\n",
                    e->line, got, e->observed, (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory, e->observed_off);
            exit(2);
        }
        if (e->ask == 0x4000 && got >= 16 * MB) ++oversize_tiny;
        CHECK(*(const uint32_t *)handles[e->handle] == 0xd503201f);
        if (e->ask == 128 * MB)
        {
            CHECK(got == e->ask && pinned_n < ARRAY_SIZE(pinned));
            size_t off = (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory;
            unsigned j;
            for (j = 0; j < ios_tail_carve_n; ++j) if (ios_tail_carves[j].off == off) break;
            CHECK(j < ios_tail_carve_n);
            pinned[pinned_n] = ios_tail_carves[j];
            *(uint64_t *)((char *)rw_memory + off) = 0x1234000000000000ULL + pinned_n;
            *(uint64_t *)((char *)rw_memory + off + got - 8) = 0x5678000000000000ULL + pinned_n;
            ++pinned_n;
        }
    }
    CHECK(pinned_n == 3);
    jit_pool_offset = 0x244dc000;
    printf("captured-tail replay: tiny-oversized=%u tail=0x%zx saved=0x%zx carves=%u virgin=0x%zx\n",
           oversize_tiny, (size_t)ios_jit_tail_reserved, (size_t)(0x22018000 - ios_jit_tail_reserved),
           ios_tail_carve_n, ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved);
    printf("November6 selected reserve=%zuMiB code-limit=%zuMiB\n",reserve/MB,code_limit/MB);
    fflush(stdout);
    CHECK(!oversize_tiny && ios_jit_tail_reserved == 0x1f024000);
    for (unsigned i = 0; i < pinned_n; ++i)
    {
        unsigned j;
        for (j = 0; j < ios_tail_carve_n; ++j) if (ios_tail_carves[j].off == pinned[i].off) break;
        CHECK(j < ios_tail_carve_n && !memcmp(&ios_tail_carves[j], &pinned[i], sizeof pinned[i]));
        CHECK(*(const uint64_t *)((char *)rx_memory + pinned[i].off) == 0x1234000000000000ULL + i);
        CHECK(*(const uint64_t *)((char *)rx_memory + pinned[i].off + pinned[i].size - 8) == 0x5678000000000000ULL + i);
    }
    /* A subsequent genuine FEX 128 MiB rotation request still follows the
     * unchanged 176 MiB image-headroom policy. It must halve to a verified
     * released 16 MiB carve instead of consuming this recovered headroom. */
    size_t before_rotation = ios_jit_tail_reserved;
    unsigned before_carves = ios_tail_carve_n;
    void *late_code = NULL;
    owner = cs2_owner;
    CHECK(rotate(&late_code) == 16 * MB);
    CHECK(late_code && ios_jit_tail_reserved == before_rotation && ios_tail_carve_n == before_carves);
    CHECK(*(const uint32_t *)late_code == 0xd503201f);
    final_image_extents();
    size_t server = (size_t)-1;
    CHECK(!allocate_image(0x2580000, &server) && server == 0x244dc000);
    CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
    check_owned_executable_image(server, 0x2580000);
    size_t later;
    CHECK(!allocate_image(0x94000, &later)); /* observed later schannel image + trampoline */
    CHECK(!allocate_image(0xc4000, &later)); /* observed later rsaenh image + trampoline */
    CHECK(!allocate_image(8 * MB, &later)); /* documented synthetic additional image stress */
    CHECK(!allocate_image(12 * MB, &later));
    CHECK(!allocate_image(12 * MB, &later));
    check_owned_executable_image(later, 12 * MB);
    CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x428000);
    expect_failed_image(8 * MB);
    printf("PASS: complete captured lifetime replay loads server.dll and observed crash-path TLS image sizes plus three synthetic images totaling 32 MiB; remaining=0x%zx; three live 128 MiB generations retained; true 8 MiB exhaustion rejected\n",
           ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved);
}

static unsigned find_carve(size_t off)
{
    for (unsigned i = 0; i < ios_tail_carve_n; ++i) if (ios_tail_carves[i].off == off) return i;
    CHECK(0); return 0;
}

static void nov7_image_extents(void)
{
    /* The capture records these aggregates, not the two original addresses. */
    ios_pool_freelist[0] = (struct ios_pool_free){MB, 0x14000, 0, 1, 0};
    ios_pool_freelist[1] = (struct ios_pool_free){2 * MB, 0xc000, 0, 1, 0};
    ios_pool_free_count = 2;
}

static void check_captured_nov7_tail_history(size_t reserve, size_t code_limit)
{
    void *handles[64] = {0};
    size_t handle_sizes[64] = {0};
    struct ios_tail_carve pinned[3], frontier;
    unsigned pinned_n = 0, preserved_tiny = 0;
    reset(1152 * MB, reserve);
    ios_pool_code_tail_limit = code_limit;
    jit_pool_offset = ios_jit_tail_reserved = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_tail_carve_n = 0;
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    for (unsigned i = 0; i < ARRAY_SIZE(captured_nov7_tail_events); ++i)
    {
        const struct captured_tail_event *e = &captured_nov7_tail_events[i];
        owner = e->owner; fake_now = 1000 + e->seconds;
        set_process_lease((void *)owner, e->lease, e->op == 2);
        if (e->op == 2) { ios_tail_carves_owner_died((void *)owner); continue; }
        if (e->op == 1)
        {
            void *released = NULL; size_t size = 0;
            CHECK(handles[e->handle]);
            CHECK(release_code(handles[e->handle], MEM_RELEASE, &released, &size) == STATUS_SUCCESS);
            CHECK(released == handles[e->handle] && size == handle_sizes[e->handle]);
            continue;
        }
        CHECK(e->handle < ARRAY_SIZE(handles));
        jit_pool_offset = e->head;
        size_t got = e->ask;
        if (e->rotation) got = rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got, &handles[e->handle]) == STATUS_SUCCESS);
        handle_sizes[e->handle] = got;
        if (got != (code_limit && e->line==45921 ? 16*MB : e->observed) || (!REPLAY_CODE_TIE &&
            (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory != e->observed_off))
        {
            fprintf(stderr, "November 7 baseline geometry differs at log line %u: got=0x%zx off=0x%zx, expected=0x%zx off=0x%zx\n",
                    e->line, got, (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory, e->observed, e->observed_off);
            exit(2);
        }
        CHECK(*(const uint32_t *)handles[e->handle] == 0xd503201f);
        if (e->line == 9271 || e->line == 16039 || e->line == 16191 || e->line == 16388 || e->line == 16466)
        { CHECK(got == 0x4000); ++preserved_tiny; }
        if (e->ask == 128 * MB)
        {
            CHECK(pinned_n < ARRAY_SIZE(pinned));
            pinned[pinned_n] = ios_tail_carves[find_carve(e->observed_off)];
            *(uint64_t *)((char *)rw_memory + e->observed_off) = 0x1234000000000000ULL + pinned_n;
            *(uint64_t *)((char *)rw_memory + e->observed_off + got - 8) = 0x5678000000000000ULL + pinned_n;
            ++pinned_n;
        }
        if (e->line == 45921)
        {
            CHECK(got == (code_limit ? 16*MB:32*MB));
            CHECK(ios_jit_tail_reserved == (code_limit ? 0x1f01c000:0x2101c000));
            size_t generation_off=(uintptr_t)handles[e->handle]-(uintptr_t)rx_memory;
            *(uint64_t *)((char *)rw_memory + generation_off) = 0xfeed328000000001ULL;
            *(uint64_t *)((char *)rw_memory + generation_off + got - 8) = 0xfeed328000000002ULL;
        }
    }
    CHECK(pinned_n == 3 && preserved_tiny == 5);
    if (code_limit)
    {
        CHECK(ios_jit_tail_reserved==0x1f01c000 && ios_tail_carve_n==17);
        struct ios_tail_carve retired_generation=ios_tail_carves[find_carve(
            (uintptr_t)handles[29]-(uintptr_t)rx_memory)];
        CHECK(retired_generation.free&&!retired_generation.retired&&retired_generation.size==16*MB);
        CHECK(retired_generation.allocation_lease==24&&!retired_generation.retired_lease);
        nov7_image_extents();owner=0x110fcc000;jit_pool_offset=0x24454000;
        size_t server,client,embree;
        CHECK(!allocate_image(0x2580000,&server)&&server==0x24454000);
        CHECK(!allocate_image(0x29a8000,&client));
        CHECK(!allocate_image(0x1524000,&embree));
        CHECK(ios_pool_ledger_holds(server,0x2580000,(void *)owner));
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
        CHECK(ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
        check_owned_executable_image(server,0x2580000);
        check_owned_executable_image(client,0x29a8000);
        check_owned_executable_image(embree,0x1524000);
        CHECK(!memcmp(&ios_tail_carves[find_carve(retired_generation.off)],&retired_generation,sizeof retired_generation));
        void *active=handles[30];size_t tail=ios_jit_tail_reserved;
        for(unsigned i=0;i<4;++i)
        {
            void *next=NULL,*released=NULL;size_t size=0;
            CHECK(rotate(&next)==16*MB&&next!=active&&ios_jit_tail_reserved==tail);
            CHECK(release_code(active,MEM_RELEASE,&released,&size)==STATUS_SUCCESS&&size==16*MB);
            active=next;
        }
        for(unsigned i=0;i<4;++i)
        {
            size_t more;CHECK(!allocate_image(8*MB,&more));
            CHECK(ios_pool_ledger_holds(more,8*MB,(void *)owner));
            check_owned_executable_image(more,8*MB);
        }
        expect_failed_image(128*MB);
        for(unsigned i=0;i<pinned_n;++i)
        {
            CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)],&pinned[i],sizeof pinned[i]));
            CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off)==0x1234000000000000ULL+i);
            CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off+pinned[i].size-8)==0x5678000000000000ULL+i);
        }
        printf("PASS November7-083837 selected%zu/%zuMiB:31capturedgrants,5tiny,3live128;client/embree executable,4later16MiBrotations and32MiBsyntheticimages,trueOOM\n",reserve/MB,code_limit/MB);
        return;
    }
    CHECK(ios_tail_carve_n == 18);
    CHECK(ios_jit_tail_reserved == 0x2101c000);
    frontier = ios_tail_carves[find_carve(0x26fe4000)];
    CHECK(frontier.free && !frontier.retired && frontier.size == 32 * MB);
#if REPLAY_MAIN_TRANSFER
    CHECK(frontier.allocation_lease == 24 && !frontier.retired_lease);
#endif
    nov7_image_extents();
    owner = 0x110fcc000;
    jit_pool_offset = 0x24454000;
    size_t server = (size_t)-1;
    CHECK(!allocate_image(0x2580000, &server) && server == 0x24454000);
    CHECK(jit_pool_offset == 0x269d4000);
    CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
    check_owned_executable_image(server, 0x2580000);
    CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x610000);
    CHECK(0x610000 + 32 * MB + 0x398000 == 0x29a8000);
#if !REPLAY_MAIN_TRANSFER
    expect_failed_image(0x29a8000);
    puts("PASS: November 7 baseline reproduces client.dll refusal at exact head/tail; recovering only the fresh 32 MiB would remain 3.59375 MiB short");
    return;
#else
    size_t client = (size_t)-1;
    unsigned before_carves = ios_tail_carve_n;
    CHECK(!allocate_image(0x29a8000, &client) && client == 0x40fe4000);
    CHECK(ios_tail_carve_n == before_carves - 3);
    CHECK(ios_pool_ledger_holds(client, 0x29a8000, (void *)owner));
    CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
    CHECK(jit_pool_offset == 0x269d4000 && ios_jit_tail_reserved == 0x2101c000);
    check_owned_executable_image(client, 0x29a8000);
    /* Synthetic subsequent image pressure, not a claim about post-failure DLLs. */
    static const size_t later_sizes[] = {8 * MB, 8 * MB, 4 * MB, 4 * MB};
    size_t later;
    for (unsigned i = 0; i < ARRAY_SIZE(later_sizes); ++i)
    {
        CHECK(!allocate_image(later_sizes[i], &later));
        CHECK(ios_pool_ledger_holds(later, later_sizes[i], (void *)owner));
        check_owned_executable_image(later, later_sizes[i]);
    }
    CHECK(ios_tail_carve_n == before_carves - 4);
    for (unsigned i = 0; i < pinned_n; ++i)
    {
        CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)], &pinned[i], sizeof pinned[i]));
        CHECK(*(const uint64_t *)((char *)rx_memory + pinned[i].off) == 0x1234000000000000ULL + i);
        CHECK(*(const uint64_t *)((char *)rx_memory + pinned[i].off + pinned[i].size - 8) == 0x5678000000000000ULL + i);
    }
    CHECK(!memcmp(&ios_tail_carves[find_carve(frontier.off)], &frontier, sizeof frontier));
    CHECK(*(const uint64_t *)((char *)rx_memory + frontier.off) == 0xfeed328000000001ULL);
    CHECK(*(const uint64_t *)((char *)rx_memory + frontier.off + frontier.size - 8) == 0xfeed328000000002ULL);
    CHECK(ios_jit_tail_reserved == 0x2101c000);
    if (REPLAY_CODE_TIE)
    {
        /* Earlier equal-size code choices retain another certified 16 MiB
         * receipt. Exercise that counterfactual capacity explicitly. */
        for (unsigned i = 0; i < 2; ++i)
        {
            CHECK(!allocate_image(8 * MB, &later));
            CHECK(ios_pool_ledger_holds(later, 8 * MB, (void *)owner));
            check_owned_executable_image(later, 8 * MB);
        }
    }
    expect_failed_image(8 * MB);
    puts("PASS: November 7 allocation grants and five tiny preserves survive actual code selection; server/client and synthetic later images execute with W^X, three live 128 MiB generations and ordinary FREE 32 MiB remain untouched, and true 8 MiB exhaustion fails safely");
#endif
}

static void check_captured_embree_tail_history(size_t reserve, size_t code_limit)
{
    void *handles[64] = {0};
    struct ios_tail_carve pinned[3], dispatchers[2];
    unsigned pinned_n = 0, preserved_tiny = 0;
    unsigned grants = 0, changed_sizes = 0, changed_addresses = 0;
    size_t server = (size_t)-1, client = (size_t)-1, embree = (size_t)-1;
    int images_checked = 0, exact_baseline = !REPLAY_CODE_TIE && reserve == 176 * MB;
    reset(1152 * MB, reserve);
    ios_pool_code_tail_limit = code_limit;
    jit_pool_offset = ios_jit_tail_reserved = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_tail_carve_n = 0;
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    for (unsigned i = 0; i < ARRAY_SIZE(captured_embree_tail_events); ++i)
    {
        const struct captured_tail_event *e = &captured_embree_tail_events[i];
        owner = e->owner; fake_now = 1000 + e->seconds;
        set_process_lease((void *)owner, e->lease, e->op == 2);
        if (e->line == 46675)
        {
            /* Both image failures precede this generation rotation and its
             * frontier release. Replay the successful server/client first. */
            CHECK(pinned_n == 3 && preserved_tiny == 5);
            CHECK(ios_tail_carve_n == (reserve == 176 * MB ? 18u : 17u));
            CHECK(ios_jit_tail_reserved == (reserve == 176 * MB ? 0x2101c000 : 0x1f01c000));
            struct ios_tail_carve current = ios_tail_carves[find_carve(
                (uintptr_t)handles[27] - (uintptr_t)rx_memory)];
            CHECK(!current.free && !current.retired && current.peb == (void *)owner);
            CHECK(current.size == (reserve == 176 * MB ? 32 * MB : 16 * MB));
            CHECK(current.allocation_lease == 23 && !current.retired_lease);
            dispatchers[0] = ios_tail_carves[find_carve(0x44ff0000)];
            dispatchers[1] = ios_tail_carves[find_carve(0x44ff4000)];
            CHECK(!dispatchers[0].free && !dispatchers[1].free);
            CHECK(dispatchers[0].peb == (void *)(uintptr_t)0x500310000ULL);
            CHECK(dispatchers[1].peb == (void *)owner);
            nov7_image_extents(); /* only the old two-entry 0x20000 aggregate */
            jit_pool_offset = 0x24448000;
            CHECK(!allocate_image(0x2580000, &server) && server == 0x24448000);
            CHECK(jit_pool_offset == 0x269c8000);
            unsigned before = ios_tail_carve_n;
            CHECK(!allocate_image(0x29a8000, &client));
            CHECK(client == (REPLAY_CODE_TIE ? 0x41fe4000 : 0x40fe4000));
            CHECK(ios_tail_carve_n == before - (REPLAY_CODE_TIE ? 6u : 3u));
            CHECK(ios_pool_free_count == 3);
            CHECK(jit_pool_offset == 0x269c8000);
            CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
            CHECK(ios_pool_ledger_holds(client, 0x29a8000, (void *)owner));
            check_owned_executable_image(server, 0x2580000);
            check_owned_executable_image(client, 0x29a8000);
            CHECK(!memcmp(&ios_tail_carves[find_carve(current.off)], &current, sizeof current));
            if (reserve == 176 * MB)
            {
                struct ios_tail_carve saved[IOS_TAIL_CARVE_MAX];
                memcpy(saved, ios_tail_carves, sizeof saved);
                CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x61c000);
                expect_failed_image(0x1524000); /* first embree request */
                expect_failed_image(0x1524000); /* repeated protect attempt */
                /* Wine retains the successful parent copy after its import
                 * fails; the immediate second client request still fails. */
                expect_failed_image(0x29a8000);
                expect_failed_image(0x29a8000);
                CHECK(!memcmp(saved, ios_tail_carves, sizeof saved));
                CHECK(ios_pool_ledger_holds(client, 0x29a8000, (void *)owner));
                CHECK(!memcmp(&ios_tail_carves[find_carve(0x26fe4000)], &current, sizeof current));
                puts("PASS: 20:06:36 baseline loads server.dll and transfers 48 MiB for client.dll, then rejects embree3.dll and the retained-parent client retry before the live 32 MiB frontier is released");
            }
            else
            {
                CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x261c000);
                CHECK(!allocate_image(0x1524000, &embree) && embree == 0x269c8000);
                CHECK(ios_pool_ledger_holds(embree, 0x1524000, (void *)owner));
                check_owned_executable_image(embree, 0x1524000);
                CHECK(ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved == 0x10f8000);
                if (REPLAY_CODE_TIE)
                {
                    const struct ios_tail_carve *certified = &ios_tail_carves[find_carve(0x40fe4000)];
                    CHECK(certified->free && certified->retired && certified->allocation_lease == 10);
                    CHECK(certified->retired_lease == 10 && !certified->peb);
                }
                size_t free_bytes = 0, largest_free = 0, qualified_bytes = 0, largest_qualified = 0;
                unsigned qualified_count = 0;
                for (int j = 0; j < ios_pool_free_count; ++j)
                {
                    free_bytes += ios_pool_freelist[j].size;
                    if (ios_pool_freelist[j].size > largest_free) largest_free = ios_pool_freelist[j].size;
                }
                for (unsigned j = 0; j < ios_tail_carve_n; ++j)
                {
                    const struct ios_tail_carve *c = &ios_tail_carves[j];
                    if (!c->retired || !c->allocation_lease || c->allocation_lease != c->retired_lease ||
                        !ios_tail_carve_ready(c, fake_now) || !ios_pool_recycle_main_range_ready(c->off, c->size)) continue;
                    ++qualified_count; qualified_bytes += c->size;
                    if (c->size > largest_qualified) largest_qualified = c->size;
                }
                CHECK(free_bytes == (REPLAY_CODE_TIE ? 0x684000 : 0x678000));
                CHECK(largest_free == (REPLAY_CODE_TIE ? 0x664000 : 0x658000));
                CHECK(qualified_count == (REPLAY_CODE_TIE ? 1u : 2u));
                CHECK(qualified_bytes == (REPLAY_CODE_TIE ? 16 * MB : 0x8000));
                CHECK(largest_qualified == (REPLAY_CODE_TIE ? 16 * MB : 0x4000));
                printf("embree after-copy geometry: reserve=%zu MiB tie=%d head=0x%zx tail=0x%zx virgin=0x10f8000 image-free=0x%zx largest-free=0x%zx certified=0x%zx eligible-total=0x%zx largest-eligible=0x10f8000\n",
                       reserve / MB, REPLAY_CODE_TIE, jit_pool_offset, (size_t)ios_jit_tail_reserved,
                       free_bytes, largest_free, qualified_bytes, 0x10f8000 + free_bytes + qualified_bytes);
            }
            images_checked = 1;
        }
        if (e->op == 2) { ios_tail_carves_owner_died((void *)owner); continue; }
        if (e->op == 1)
        {
            void *released = NULL; size_t size = 0;
            CHECK(handles[e->handle]);
            CHECK(release_code(handles[e->handle], MEM_RELEASE, &released, &size) == STATUS_SUCCESS);
            CHECK(released == handles[e->handle]);
            CHECK(size == (e->line == 46682 && reserve >= 208 * MB ? 16 * MB : e->observed));
            continue;
        }
        CHECK(e->handle < ARRAY_SIZE(handles));
        if (e->head > jit_pool_offset) jit_pool_offset = e->head;
        size_t got = e->ask;
        if (e->rotation) got = rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got, &handles[e->handle]) == STATUS_SUCCESS);
        CHECK(got == (e->line == 45431 && reserve >= 208 * MB ? 16 * MB : e->observed));
        size_t off = (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory;
        ++grants; changed_sizes += got != e->observed; changed_addresses += off != e->observed_off;
        if (exact_baseline) CHECK(off == e->observed_off);
        CHECK(*(const uint32_t *)handles[e->handle] == 0xd503201f);
        if (e->line == 8932 || e->line == 8991 || e->line == 15393 || e->line == 15620 || e->line == 15694)
        { CHECK(got == 0x4000); ++preserved_tiny; }
        if (e->ask == 128 * MB)
        {
            CHECK(pinned_n < ARRAY_SIZE(pinned));
            pinned[pinned_n] = ios_tail_carves[find_carve(off)];
            *(uint64_t *)((char *)rw_memory + off) = 0x1234000000000000ULL + pinned_n;
            *(uint64_t *)((char *)rw_memory + off + got - 8) = 0x5678000000000000ULL + pinned_n;
            ++pinned_n;
        }
    }
    CHECK(images_checked && pinned_n == 3 && preserved_tiny == 5);
    if (reserve >= 208 * MB)
    {
        size_t tail = ios_jit_tail_reserved;
        unsigned count = ios_tail_carve_n;
        /* Synthetic later rotations: the failed capture has no subsequent
         * successful game loads. Two ordinary 16 MiB releases can alternate
         * without spending a certified receipt or advancing the tail. */
        void *active = handles[28];
        struct ios_tail_carve certified = {0};
        if (REPLAY_CODE_TIE) certified = ios_tail_carves[find_carve(0x40fe4000)];
        for (unsigned i = 0; i < 2; ++i)
        {
            void *next = NULL, *released = NULL; size_t size = 0;
            CHECK(rotate(&next) == 16 * MB && next != active);
            CHECK(ios_jit_tail_reserved == tail && ios_tail_carve_n == count);
            CHECK(release_code(active, MEM_RELEASE, &released, &size) == STATUS_SUCCESS);
            CHECK(released == active && size == 16 * MB); active = next;
            if (REPLAY_CODE_TIE)
                CHECK(!memcmp(&ios_tail_carves[find_carve(certified.off)], &certified, sizeof certified));
        }
        size_t later;
        for (unsigned i = 0; i < 2; ++i)
        {
            CHECK(!allocate_image(8 * MB, &later));
            CHECK(ios_pool_ledger_holds(later, 8 * MB, (void *)owner));
            check_owned_executable_image(later, 8 * MB);
        }
        if (REPLAY_CODE_TIE)
        {
            for (unsigned i = 0; i < 2; ++i)
            {
                CHECK(!allocate_image(8 * MB, &later));
                CHECK(ios_pool_ledger_holds(later, 8 * MB, (void *)owner));
                check_owned_executable_image(later, 8 * MB);
            }
            CHECK(ios_tail_carve_n == count - 1 && ios_jit_tail_reserved == tail);
            printf("PASS November7-200636 reserve=%zuMiB code-limit=%zuMiB:server/client/embree,capturedlifecycle,3live128,2laterrotations,32MiBsyntheticimages\n",reserve/MB,code_limit/MB);
        }
        else
        {
            CHECK(ios_tail_carve_n == count);
            puts("PASS: headroom-only control loads embree3.dll but consumes its last qualified 16 MiB code receipt; only 16 MiB of the synthetic later image stress fits");
        }
        expect_failed_image(8 * MB);
        CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
        CHECK(ios_pool_ledger_holds(client, 0x29a8000, (void *)owner));
        CHECK(ios_pool_ledger_holds(embree, 0x1524000, (void *)owner));
    }
    for (unsigned i = 0; i < pinned_n; ++i)
    {
        CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)], &pinned[i], sizeof pinned[i]));
        CHECK(*(const uint64_t *)((char *)rx_memory + pinned[i].off) == 0x1234000000000000ULL + i);
        CHECK(*(const uint64_t *)((char *)rx_memory + pinned[i].off + pinned[i].size - 8) == 0x5678000000000000ULL + i);
    }
    for (unsigned i = 0; i < ARRAY_SIZE(dispatchers); ++i)
        CHECK(!memcmp(&ios_tail_carves[find_carve(dispatchers[i].off)], &dispatchers[i], sizeof dispatchers[i]));
    CHECK(grants == 29);
    CHECK(changed_sizes == (reserve >= 208 * MB ? 1u : 0u));
    CHECK(changed_addresses == (reserve == 176 * MB ? 0u : REPLAY_CODE_TIE ? 4u : 1u));
    printf("embree captured grants: reserve=%zu MiB tie=%d total=%u altered-sizes=%u altered-addresses=%u; all returned handles, leases, five tiny grants and three live 128 MiB carves verified\n",
           reserve / MB, REPLAY_CODE_TIE, grants, changed_sizes, changed_addresses);
}

/* November8's order, including the ordinary generation FREE before embree.
 * Only aggregate older image extents use synthetic separated offsets. */
static void november8_image_extents(void)
{
    static const size_t sizes[] = {0x14000, 0x10000, 0x8000};
    ios_pool_free_count = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(sizes); ++i)
        ios_pool_freelist[i] = (struct ios_pool_free){(i+1)*MB, sizes[i], 0, 1, 0};
    ios_pool_free_count = ARRAY_SIZE(sizes);
}

static void check_code_image_nonoverlap(void)
{
    for (unsigned i = 0; i < ios_tail_carve_n; ++i)
    {
        const struct ios_tail_carve *c = &ios_tail_carves[i];
        if (c->free) continue;
        for (int j = 0; j < ios_pool_ledger_count; ++j)
            CHECK(c->off >= ios_pool_ledger[j].off + ios_pool_ledger[j].size ||
                  ios_pool_ledger[j].off >= c->off + c->size);
    }
}

static void check_captured_november8_tail_history(size_t reserve, size_t code_limit, int early_rotation)
{
    void *handles[64] = {0};
    struct ios_tail_carve pinned[3];
    unsigned pinned_n = 0, tiny = 0, grants = 0, resized = 0;
    size_t sizes[64] = {0};
    size_t server = (size_t)-1, client = (size_t)-1, embree = (size_t)-1;
    int server_checked = 0;
    reset(1152*MB, reserve);
    ios_pool_code_tail_limit = code_limit;
    jit_pool_offset = ios_jit_tail_reserved = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_tail_carve_n = 0;
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    for (unsigned i = 0; i < ARRAY_SIZE(captured_november8_tail_events); ++i)
    {
        const struct captured_tail_event *e = &captured_november8_tail_events[i];
        owner = e->owner; fake_now = 1000 + e->seconds;
        set_process_lease((void *)owner, e->lease, e->op == 2);
        if (e->line == 46265)
        {
            CHECK(!server_checked && pinned_n == 3 && tiny == 5);
            november8_image_extents();
            jit_pool_offset = 0x24464000;
            CHECK(!allocate_image(0x2580000, &server));
            CHECK(server == (early_rotation && !code_limit ? 0x41fe4000 : 0x24464000));
            CHECK(jit_pool_offset == (early_rotation && !code_limit ? 0x24464000 : 0x269e4000));
            CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
            check_owned_executable_image(server, 0x2580000);
            server_checked = 1;
        }
        if (e->op == 2) { ios_tail_carves_owner_died((void *)owner); continue; }
        if (e->op == 1)
        {
            void *released = NULL; size_t bytes = 0;
            CHECK(handles[e->handle]);
            CHECK(release_code(handles[e->handle], MEM_RELEASE, &released, &bytes) == STATUS_SUCCESS);
            CHECK(released == handles[e->handle] && bytes == sizes[e->handle]);
            continue;
        }
        CHECK(e->handle < ARRAY_SIZE(handles));
        if (!server_checked && e->head > jit_pool_offset) jit_pool_offset = e->head;
        if (early_rotation && e->line == 45201)
        {
            /* This adversary orders the real rotation before the image head
             * has grown. A relative headroom target alone allows larger code.
             * The fixed growth budget must still bound the same fresh tail. */
            jit_pool_offset = 0x15cdc000;
        }
        size_t got = e->ask;
        if (e->rotation || e->ask == 128*MB) got = rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got, &handles[e->handle]) == STATUS_SUCCESS);
        CHECK(got && handles[e->handle]);
        sizes[e->handle] = got;
        size_t off = (uintptr_t)handles[e->handle] - (uintptr_t)rx_memory;
        ++grants; resized += got != e->observed;
        CHECK(*(const uint32_t *)handles[e->handle] == 0xd503201f);
        if (reserve == 208*MB && !code_limit && !early_rotation)
        {
            if (got != e->observed || off != e->observed_off)
                fprintf(stderr,"November8 baseline mismatch line%u size=%zx/%zx off=%zx/%zx\n",e->line,got,e->observed,off,e->observed_off);
            CHECK(got == e->observed && off == e->observed_off);
        }
        if (e->line == 8900 || e->line == 8926 || e->line == 15464 || e->line == 15593 || e->line == 15626)
        { CHECK(got == 0x4000); ++tiny; }
        if (e->ask == 128*MB)
        {
            CHECK(pinned_n < ARRAY_SIZE(pinned));
            pinned[pinned_n] = ios_tail_carves[find_carve(off)];
            CHECK(got >= 16*MB);
            *(uint64_t *)((char *)rw_memory+off) = 0xabc0000000000000ULL+pinned_n;
            *(uint64_t *)((char *)rw_memory+off+got-8) = 0xdef0000000000000ULL+pinned_n;
            ++pinned_n;
        }
    }
    CHECK(server_checked && tiny == 5 && grants == 29 && pinned_n == 3);
    owner = 0x115afc000; fake_now = 1423;
    CHECK(jit_pool_offset == (early_rotation && !code_limit ? 0x24464000 : 0x269e4000));
    struct ios_tail_carve ordinary = ios_tail_carves[find_carve(
        (uintptr_t)handles[27] - (uintptr_t)rx_memory)];
    CHECK(ordinary.free && !ordinary.retired && ordinary.peb == (void *)owner);
    CHECK(ordinary.allocation_lease == 23 && !ordinary.retired_lease);
    unsigned before = ios_tail_carve_n;
    if (!(early_rotation && !code_limit) && !(code_limit && code_limit <= 448*MB))
    {
        /* Fork isolates the deliberately hostile thread-state answer. The
         * unmodified production recycler must refuse an executing receipt;
         * parent metadata is not reset or fabricated to make reuse succeed. */
        pid_t child=fork(); CHECK(child>=0);
        if (!child)
        {
            scanned_pc=(uintptr_t)rx_memory+0x41fe4000;
            expect_failed_image(0x29a8000);
            _exit(0);
        }
        int status=0; CHECK(waitpid(child,&status,0)==child);
        CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }
    if (early_rotation && !code_limit)
    {
        CHECK(ios_jit_tail_reserved == 0x2301c000 && sizes[27] == 64*MB);
        expect_failed_image(0x29a8000);
        CHECK(ios_pool_ledger_holds(server,0x2580000,(void *)owner));
        puts("PASS earlier-order control:240MiB soft reserve admits64MiB generation; server consumes the certified client range and client then genuinely fails");
        return;
    }
    CHECK(!allocate_image(0x29a8000, &client));
    CHECK(ios_pool_ledger_holds(client, 0x29a8000, (void *)owner));
    CHECK(ios_pool_ledger_holds(server, 0x2580000, (void *)owner));
    check_owned_executable_image(client, 0x29a8000);
    CHECK(jit_pool_offset == (code_limit && code_limit <= 448*MB ? 0x2938c000 : 0x269e4000));
    CHECK(!memcmp(&ios_tail_carves[find_carve(ordinary.off)], &ordinary, sizeof ordinary));
    if (reserve == 208*MB && !code_limit)
    {
        CHECK(client == 0x41fe4000 && ios_tail_carve_n == before-6);
        CHECK(ios_jit_tail_reserved == 0x2101c000);
        CHECK(ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved == 0x600000);
        size_t bytes = 0, largest = 0;
        for (int j = 0; j < ios_pool_free_count; ++j)
        { bytes += ios_pool_freelist[j].size; if (ios_pool_freelist[j].size > largest) largest=ios_pool_freelist[j].size; }
        CHECK(ios_pool_free_count == 4 && bytes == 0x690000 && largest == 0x664000);
        unsigned qualified=0,missing=0;size_t qualified_bytes=0,largest_qualified=0;
        for(unsigned j=0;j<ios_tail_carve_n;++j)
        {
            const struct ios_tail_carve *c=&ios_tail_carves[j];
            if(!c->free)continue;
            if(!c->retired||!c->allocation_lease||c->allocation_lease!=c->retired_lease)
            {++missing;continue;}
            CHECK(ios_tail_carve_ready(c,fake_now));
            CHECK(ios_pool_recycle_main_range_ready(c->off,c->size));
            ++qualified;qualified_bytes+=c->size;
            if(c->size>largest_qualified)largest_qualified=c->size;
        }
        CHECK(qualified==2&&qualified_bytes==32*MB&&largest_qualified==16*MB&&missing==1);
        struct ios_tail_carve snapshot[IOS_TAIL_CARVE_MAX]; memcpy(snapshot,ios_tail_carves,sizeof snapshot);
        expect_failed_image(0x1524000); expect_failed_image(0x1524000);
        expect_failed_image(0x29a8000); expect_failed_image(0x29a8000);
        CHECK(ios_pool_ledger_holds(client, 0x29a8000, (void *)owner));
        CHECK(!memcmp(snapshot,ios_tail_carves,sizeof snapshot));
        printf("PASS November8 captured208MiB:all29grants/address/leases,5tiny/3live128,ordinaryFREE32before6receiptclienttransfer; exactembree21.14MiBfailure andretainedparentretry at6MiBvirgin\n");
    }
    else
    {
        CHECK(!allocate_image(0x1524000, &embree));
        CHECK(ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
        check_owned_executable_image(embree,0x1524000);
        size_t virgin=ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved;
        printf("November8 projected reserve=%zuMiB limit=%zuMiB early=%d head=0x%zx tail=0x%zx client=0x%zx embree=0x%zx virgin=0x%zx resized=%u\n",reserve/MB,code_limit/MB,early_rotation,jit_pool_offset,(size_t)ios_jit_tail_reserved,client,embree,virgin,resized);
        /* Preserve every still-live initial process generation byte-for-byte. */
        for (unsigned i=0;i<pinned_n;++i)
        {
            CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)],&pinned[i],sizeof pinned[i]));
            CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off)==0xabc0000000000000ULL+i);
            CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off+pinned[i].size-8)==0xdef0000000000000ULL+i);
        }
        check_code_image_nonoverlap();
        /* Synthetic subsequent generations alternate two honest released16MiB
         * buffers. A live generation is not free until migration completes. */
        void *active=handles[28];
        size_t tail=ios_jit_tail_reserved;
        for (unsigned i=0;i<6;++i)
        {
            void *next=NULL,*released=NULL;size_t bytes=0;
            CHECK(rotate(&next)>=16*MB && next != active);
            CHECK(ios_jit_tail_reserved == tail);
            CHECK(!ios_tail_carves[find_carve((uintptr_t)active-(uintptr_t)rx_memory)].free);
            CHECK(release_code(active,MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS && released==active);
            active=next;check_code_image_nonoverlap();
        }
        if (!code_limit || code_limit >= 512*MB)
        {
            expect_failed_image(20*MB);
            puts("PASS bounded capacity limit:allthree128MiB generations preserved; a subsequent single20MiB image genuinely does not fit despite smaller reusable extents");
        }
        /* Bounded synthetic image stress is deliberately separated from the
         * observed game chain, which ends with the first embree failure. */
        static const size_t moderate[] = {8*MB,8*MB,8*MB,8*MB};
        static const size_t larger[] = {20*MB,40*MB};
        const size_t *requests = code_limit && code_limit<=448*MB ? larger : moderate;
        unsigned count = code_limit && code_limit<=448*MB ? ARRAY_SIZE(larger):ARRAY_SIZE(moderate);
        for(unsigned i=0;i<count;++i)
        {
            size_t more=(size_t)-1; CHECK(!allocate_image(requests[i],&more));
            CHECK(ios_pool_ledger_holds(more,requests[i],(void *)owner));
            check_owned_executable_image(more,requests[i]); check_code_image_nonoverlap();
        }
        /* Compile again after image pressure; no cursor growth or double-live
         * code assignment is allowed. True exhaustion remains honest. */
        void *next=NULL,*released=NULL;size_t bytes=0;
        CHECK(rotate(&next)>=16*MB && next!=active && ios_jit_tail_reserved==tail);
        CHECK(release_code(active,MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);
        if (!code_limit || code_limit >= 512*MB) expect_failed_image(8*MB);
        expect_failed_image(128*MB);
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
        CHECK(ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
        printf("PASS November8 policy240/%zuMiB:client+embree executable,6safe rotations,syntheticimage-stress=%zuMiB,continuedcompilation,trueOOM;noordinaryFREEimagecertification\n",code_limit/MB,code_limit&&code_limit<=448*MB?60UL:32UL);
    }
    for (unsigned i=0;i<pinned_n;++i)
    {
        CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)],&pinned[i],sizeof pinned[i]));
        CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off)==0xabc0000000000000ULL+i);
        CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off+pinned[i].size-8)==0xdef0000000000000ULL+i);
    }
}

/* The newly attached log is fbb4, not the 5b22 metadata in the repeated request.
 * Replay its actual30 grants and three CS2 rotations. It already loads embree;
 * the following failure comes from a DEP sweep copying other processes' VADs.
 * check-dep-process-isolation.py exercises that production scope boundary. */
static void check_captured_fbb4_tail_history(void)
{
    void *handles[64] = {0}; size_t sizes[64] = {0};
    struct ios_tail_carve pinned[3]; unsigned pinned_n=0, grants=0, tiny=0;
    size_t server=(size_t)-1, client=(size_t)-1, embree=(size_t)-1;
    reset(1152*MB,240*MB); ios_pool_code_tail_limit=512*MB;
    jit_pool_offset=ios_jit_tail_reserved=0;
    ios_pool_free_count=ios_pool_ledger_count=ios_tail_carve_n=0;
    memset(ios_tail_carves,0,sizeof ios_tail_carves);
    for(unsigned i=0;i<ARRAY_SIZE(captured_fbb4_tail_events);++i)
    {
        const struct captured_tail_event *e=&captured_fbb4_tail_events[i];
        owner=e->owner; fake_now=1000+e->seconds;
        set_process_lease((void *)owner,e->lease,e->op==2);
        if(e->line==45737)
        {
            /* Older image-free offsets are not in the log; these three
             * separated small extents exercise bounded fragmentation only. */
            november8_image_extents(); jit_pool_offset=0x244a8000;
            CHECK(!allocate_image(0x2580000,&server) && server==0x244a8000);
            CHECK(jit_pool_offset==0x26a28000);
        }
        if(e->op==2) { ios_tail_carves_owner_died((void *)owner); continue; }
        if(e->op==1)
        {
            void *released=NULL;size_t bytes=0;
            CHECK(handles[e->handle]);
            CHECK(release_code(handles[e->handle],MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);
            CHECK(released==handles[e->handle]&&bytes==sizes[e->handle]); continue;
        }
        if(e->head>jit_pool_offset)jit_pool_offset=e->head;
        size_t got=e->ask;
        if(e->rotation||e->ask==128*MB)got=rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got,&handles[e->handle])==STATUS_SUCCESS);
        size_t off=(uintptr_t)handles[e->handle]-(uintptr_t)rx_memory;
        if(got!=e->observed||off!=e->observed_off)
            fprintf(stderr,"fbb4 mismatch line%u size=%zx/%zx off=%zx/%zx\n",e->line,got,e->observed,off,e->observed_off);
        CHECK(got==e->observed&&off==e->observed_off);
        sizes[e->handle]=got;++grants;
        if(e->line==9017||e->line==9183||e->line==15473||e->line==15499||e->line==15567)
        { CHECK(got==0x4000);++tiny; }
        if(e->ask==128*MB&&!e->rotation)
        {
            CHECK(pinned_n<ARRAY_SIZE(pinned)&&got==128*MB);
            pinned[pinned_n]=ios_tail_carves[find_carve(off)];
            *(uint64_t *)((char *)rw_memory+off)=0xabc1000000000000ULL+pinned_n;
            *(uint64_t *)((char *)rw_memory+off+got-8)=0xdef1000000000000ULL+pinned_n;
            ++pinned_n;
        }
    }
    CHECK(grants==30&&tiny==5&&pinned_n==3);
    CHECK(ios_jit_tail_reserved==0x1f01c000&&jit_pool_offset==0x26a28000);
    owner=0x108118000; fake_now=1427;
    CHECK(!allocate_image(0x29a8000,&client)&&client==0x41fe4000);
    CHECK(!allocate_image(0x1524000,&embree)&&embree==0x26a28000);
    CHECK(jit_pool_offset==0x27f4c000);
    CHECK(ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved==0x1098000);
    CHECK(ios_pool_ledger_holds(server,0x2580000,(void *)owner));
    CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
    CHECK(ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
    check_owned_executable_image(server,0x2580000);
    check_owned_executable_image(client,0x29a8000);
    check_owned_executable_image(embree,0x1524000);
    check_code_image_nonoverlap();
    for(unsigned i=0;i<pinned_n;++i)
    {
        CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)],&pinned[i],sizeof pinned[i]));
        CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off)==0xabc1000000000000ULL+i);
        CHECK(*(const uint64_t *)((char *)rx_memory+pinned[i].off+pinned[i].size-8)==0xdef1000000000000ULL+i);
    }
    size_t copied=0;
    for(unsigned i=0;i<ARRAY_SIZE(captured_fbb4_foreign_copy_sizes);++i)copied+=captured_fbb4_foreign_copy_sizes[i];
    CHECK(ARRAY_SIZE(captured_fbb4_foreign_copy_sizes)==42&&copied==0x25a8000);
    puts("PASS fbb4 actual30grants/5tiny/3live128/3CS2rotations: nofresh32,server+client+embree executable; head27f4c000 tail1f01c000 leaves16.59375MiB,notamenuguarantee; subsequent42foreignDEPcopies cost37.65625MiB");

    /* The first observed failure is old kernelbase.dll, already copied at
     * log28086. Reproduce its exact census with separated aggregate extents;
     * their original addresses are unavailable, not invented here. */
    reset(1152*MB,240*MB);ios_pool_code_tail_limit=512*MB;
    jit_pool_offset=0x28fd4000;ios_jit_tail_reserved=0x1f01c000;
    ios_pool_free_count=ios_pool_ledger_count=ios_tail_carve_n=0;
    static const size_t remaining[]={0x4c000,0x14000,0xc000,0x8000,0x8000,0x8000,0x4000};
    size_t sum=0;
    for(unsigned i=0;i<ARRAY_SIZE(remaining);++i)
    {
        ios_pool_freelist[i]=(struct ios_pool_free){(i+1)*MB,remaining[i],0,1,0};
        sum+=remaining[i];++ios_pool_free_count;
    }
    CHECK(sum==0x88000&&ios_pool_free_count==7);
    CHECK(ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved==0x10000);
    expect_failed_image(0x180000);
    puts("PASS fbb4 firstfailure kernelbase.dll180000 with64KiBvirgin/7freeextents88000/largest4c000; scopedDEPtestpreventsforeignsweepwithoutchangingcapacityorretirementproof");
}



/* Counterfactual current-production replay of EVERY older captured lifecycle.
 * Returned handles replace historical addresses; only known terminal image
 * requests and their recorded pre-copy head snapshots are replayed as copies.
 * Historical intermediate image extent coordinates remain unspecified. */
static void check_prior_capture_current(const char *name,const struct captured_tail_event *events,unsigned count,
                                       unsigned image_line,size_t pre_server,int dependency_before_rotation,int dependencies)
{
    void *handles[64]={0},*active_code=NULL;size_t sizes[64]={0};
    struct ios_tail_carve pinned[3];unsigned pins=0,changes=0;
    size_t server=(size_t)-1,client=(size_t)-1,embree=(size_t)-1;
    int copied=0;
    reset(1152*MB,240*MB);ios_pool_code_tail_limit=512*MB;
    jit_pool_offset=ios_jit_tail_reserved=0;ios_pool_free_count=ios_pool_ledger_count=ios_tail_carve_n=0;
    memset(ios_tail_carves,0,sizeof ios_tail_carves);
    for(unsigned i=0;i<count;i++)
    {
        const struct captured_tail_event *e=&events[i];owner=e->owner;fake_now=1000+e->seconds;
        set_process_lease((void *)owner,e->lease,e->op==2);
        if(e->line==image_line)
        {
            november8_image_extents();jit_pool_offset=pre_server;
            CHECK(!allocate_image(0x2580000,&server));copied=1;
            if(dependency_before_rotation)
            {CHECK(!allocate_image(0x29a8000,&client));CHECK(!allocate_image(0x1524000,&embree));}
        }
        if(e->op==2){ios_tail_carves_owner_died((void *)owner);continue;}
        if(e->op==1)
        {
            void *released=NULL;size_t bytes=0;
            CHECK(release_code(handles[e->handle],MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);
            CHECK(released==handles[e->handle]&&bytes==sizes[e->handle]);continue;
        }
        if(!copied&&e->head>jit_pool_offset)jit_pool_offset=e->head;
        size_t got=e->ask;
        if(e->rotation)got=rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got,&handles[e->handle])==STATUS_SUCCESS);
        CHECK(got>0 && (e->rotation ? got>=16*MB : got>=e->ask));sizes[e->handle]=got;
        size_t off=(uintptr_t)handles[e->handle]-(uintptr_t)rx_memory;
        if(off!=e->observed_off||got!=e->observed)changes++;
        if(e->rotation)active_code=handles[e->handle];
        if(e->ask==128*MB&&!e->rotation)
        {
            CHECK(pins<3&&got==128*MB);pinned[pins]=ios_tail_carves[find_carve(off)];
            *(uint64_t *)((char *)rw_memory+off)=0xbabe000000000000ULL+pins;
            *(uint64_t *)((char *)rw_memory+off+got-8)=0xface000000000000ULL+pins;pins++;
        }
        check_code_image_nonoverlap();
    }
    CHECK(copied&&pins==3&&active_code);
    if(dependencies&&!dependency_before_rotation)
    {CHECK(!allocate_image(0x29a8000,&client));CHECK(!allocate_image(0x1524000,&embree));}
    CHECK(ios_pool_ledger_holds(server,0x2580000,(void *)owner));check_owned_executable_image(server,0x2580000);
    if(dependencies)
    {
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));CHECK(ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
        check_owned_executable_image(client,0x29a8000);check_owned_executable_image(embree,0x1524000);
    }
    size_t tail=ios_jit_tail_reserved;
    for(unsigned n=0;n<4;n++)
    {
        void *next=NULL,*released=NULL;size_t bytes=0;CHECK(rotate(&next)>=16*MB);
        CHECK(release_code(active_code,MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);CHECK(released==active_code);
        active_code=next;CHECK(ios_jit_tail_reserved==tail);check_code_image_nonoverlap();
    }
    for(unsigned n=0;n<pins;n++)
    {
        CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[n].off)],&pinned[n],sizeof pinned[n]));
        CHECK(*(uint64_t *)((char *)rx_memory+pinned[n].off)==0xbabe000000000000ULL+n);
        CHECK(*(uint64_t *)((char *)rx_memory+pinned[n].off+pinned[n].size-8)==0xface000000000000ULL+n);
    }
    printf("PASS current-production older-capture %s: %u events returned-handles=%u altered grants,3live128 intact,server%s and4later rotations;geometry head=%zx tail=%zx\n",name,count,changes,dependencies?"/client/embree":"",jit_pool_offset,(size_t)ios_jit_tail_reserved);
}
static void check_all_prior_captures_current(void)
{
    check_prior_capture_current("200111",captured_tail_events,ARRAY_SIZE(captured_tail_events),74400,0x244dc000,0,0);
    check_prior_capture_current("083837",captured_nov7_tail_events,ARRAY_SIZE(captured_nov7_tail_events),47060,0x24454000,1,1);
    check_prior_capture_current("200636",captured_embree_tail_events,ARRAY_SIZE(captured_embree_tail_events),46675,0x24448000,1,1);
    check_prior_capture_current("095621",captured_november8_tail_events,ARRAY_SIZE(captured_november8_tail_events),46265,0x24464000,0,1);
    check_prior_capture_current("fbb4",captured_fbb4_tail_events,ARRAY_SIZE(captured_fbb4_tail_events),45737,0x244a8000,0,1);
}

/* November10: every logged grant/release/retirement in its actual time(NULL)
 * second. In particular endpoint receipts retire at88; CS2 asks for its tiny
 * dispatcher at90, before their three-second grace expires. */
static void check_captured_november10_tail_history(void)
{
    void *handles[64]={0};size_t sizes[64]={0};
    struct ios_tail_carve pinned[3];unsigned pins=0,grants=0,changes=0;
    int shift=getenv("MADEIRA_POOL_NOV10_CLOCK_SHIFT")?atoi(getenv("MADEIRA_POOL_NOV10_CLOCK_SHIFT")):0;
    CHECK(shift>=-1&&shift<=1);
    reset(1152*MB,240*MB);ios_pool_code_tail_limit=512*MB;
    jit_pool_offset=ios_jit_tail_reserved=0;ios_pool_free_count=ios_pool_ledger_count=ios_tail_carve_n=0;
    memset(ios_tail_carves,0,sizeof ios_tail_carves);
    for(unsigned i=0;i<ARRAY_SIZE(captured_november10_tail_events);i++)
    {
        const struct captured_tail_event *e=&captured_november10_tail_events[i];
        owner=e->owner;fake_now=1000+e->seconds+(e->line>=40255?shift:0);
        set_process_lease((void *)owner,e->lease,e->op==2);
        if(e->op==2){ios_tail_carves_owner_died((void *)owner);continue;}
        if(e->op==1)
        {
            void *released=NULL;size_t bytes=0;
            CHECK(handles[e->handle]);
            CHECK(release_code(handles[e->handle],MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);
            CHECK(released==handles[e->handle]&&bytes==sizes[e->handle]);continue;
        }
        if(e->head>jit_pool_offset)jit_pool_offset=e->head;
        size_t got=e->ask;
        if(e->rotation||e->ask==128*MB)got=rotate(&handles[e->handle]);
        else CHECK(allocate_code(&got,&handles[e->handle])==STATUS_SUCCESS);
        size_t off=(uintptr_t)handles[e->handle]-(uintptr_t)rx_memory;
        CHECK(got==e->observed);
        if(off!=e->observed_off)changes++;
        if(getenv("MADEIRA_POOL_NOV10_EXPECT_BASELINE"))
        {
            if(off!=e->observed_off)fprintf(stderr,"November10 baseline mismatch line%u size%zx off%zx expected%zx\n",e->line,got,off,e->observed_off);
            CHECK(off==e->observed_off);
        }
        sizes[e->handle]=got;grants++;
        if(e->ask==128*MB&&!e->rotation)
        {
            CHECK(pins<ARRAY_SIZE(pinned)&&got==128*MB);
            pinned[pins]=ios_tail_carves[find_carve(off)];
            *(uint64_t *)((char *)rw_memory+off)=0xcafe100000000000ULL+pins;
            *(uint64_t *)((char *)rw_memory+off+got-8)=0xbeef100000000000ULL+pins; pins++;
        }
        if(e->line==40255)
            printf("November10 tiny-selection off=%zx tail=%zx time=%ld: endpoint retirement1088 age=%ld shift=%d (nonzero is separate schedule sensitivity)\n",off,(size_t)ios_jit_tail_reserved,(long)fake_now,(long)fake_now-1088,shift);
    }
    CHECK(grants==45&&pins==3);
    owner=0x1122b4000;set_process_lease((void *)owner,31,0);fake_now=1101+shift;
    /* The ten older image-free addresses are unavailable. Match the exact
     * measured aggregate using separated bounded extents, never fake a large
     * eligible receipt or claim they reproduce unlogged image coordinates. */
    static const size_t holes[]={0x28000,0x20000,0x20000,0x1c000,0x18000,0x18000,0x14000,0x10000,0xc000,0xc000};
    size_t sum=0;ios_pool_free_count=0;
    for(unsigned i=0;i<ARRAY_SIZE(holes);i++)
    {
        ios_pool_freelist[i]=(struct ios_pool_free){(i+1)*MB,holes[i],0,1,0};sum+=holes[i];ios_pool_free_count++;
    }
    CHECK(sum==0xf0000);
    jit_pool_offset=0x273c8000;
    size_t client=(size_t)-1,embree=(size_t)-1;
    CHECK(!allocate_image(0x29a8000,&client)&&client==0x273c8000);
    CHECK(jit_pool_offset==0x29d70000);
    size_t head_before=jit_pool_offset,tail_before=ios_jit_tail_reserved;
    int result=allocate_image(0x1524000,&embree);
    printf("November10 actual-capture replay: grants=%u changed-addresses=%u head=%zx tail=%zx virgin=%zx embree-status=%d embree-off=%zx\n",grants,changes,jit_pool_offset,(size_t)ios_jit_tail_reserved,ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved,result,embree);
    if(getenv("MADEIRA_POOL_NOV10_EXPECT_BASELINE")||getenv("MADEIRA_POOL_NOV10_EXPECT_FAILURE"))
    {
        if(getenv("MADEIRA_POOL_NOV10_EXPECT_BASELINE"))
        { CHECK(!changes&&tail_before==0x1e018000);CHECK(ios_jit_pool_size_global-head_before-tail_before==0x278000); }
        CHECK(result==-1&&ios_jit_copy_refused);
        CHECK(jit_pool_offset==head_before&&ios_jit_tail_reserved==tail_before);
        if(getenv("MADEIRA_POOL_NOV10_EXPECT_BASELINE"))
        {
            CHECK(strstr(recycle_report,"aged-receipts=5")&&strstr(recycle_report,"aged-bytes=0x3008000"));
            CHECK(strstr(recycle_report,"largest=0x1008000")&&strstr(recycle_report,"missing-proof=1"));
        }
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
        check_owned_executable_image(client,0x29a8000);
        size_t retry=(size_t)-1;CHECK(allocate_image(0x29a8000,&retry)==-1);
        CHECK(jit_pool_offset==head_before&&ios_jit_tail_reserved==tail_before);
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
        puts(getenv("MADEIRA_POOL_NOV10_EXPECT_BASELINE")?
             "PASS November10 installed baseline: exact45grants/bounded clocks, exact5proof/48MiB+32KiB census; embree failure and retained-client retry failure" :
             "PASS promotion-only negative control: correcting FREE ownership alone still fails embree at real age2 endpoint timing");
    }
    else
    {
        CHECK(!result);
        printf("November10 actual production transfer: %s",recycle_report);
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
        CHECK(ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
        check_owned_executable_image(client,0x29a8000);check_owned_executable_image(embree,0x1524000);
        check_code_image_nonoverlap();
        CHECK(jit_pool_offset==head_before&&ios_jit_tail_reserved==tail_before);
        unsigned ordinary=find_carve((uintptr_t)handles[44]-(uintptr_t)rx_memory);
        CHECK(ios_tail_carves[ordinary].free&&!ios_tail_carves[ordinary].retired);
        CHECK(ios_tail_carves[ordinary].peb==(void *)owner&&ios_tail_carves[ordinary].allocation_lease==31&&!ios_tail_carves[ordinary].retired_lease);
        expect_failed_image(40*MB); /* separate forced dependency failure */
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner));
        check_owned_executable_image(client,0x29a8000);
        for(unsigned n=0;n<4;n++)
        {
            void *next=NULL,*released=NULL;size_t bytes=0;
            CHECK(rotate(&next)==16*MB);
            CHECK(release_code(handles[45],MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);
            CHECK(released==handles[45]&&bytes==16*MB);handles[45]=next;
            CHECK(ios_jit_tail_reserved==tail_before);check_code_image_nonoverlap();
        }
        size_t total_free=ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved,largest=total_free;
        for(int i=0;i<ios_pool_free_count;i++)
        { total_free+=ios_pool_freelist[i].size;if(ios_pool_freelist[i].size>largest)largest=ios_pool_freelist[i].size; }
        size_t receipts=0,receipt_largest=0,live_code=0,ordinary_free=0;unsigned live_count=0;
        for(unsigned i=0;i<ios_tail_carve_n;i++)
        {
            const struct ios_tail_carve *c=&ios_tail_carves[i];
            if(!c->free){live_code+=c->size;live_count++;}
            else if(!c->retired)ordinary_free+=c->size;
            if(!c->free||!c->retired||!c->allocation_lease||c->allocation_lease!=c->retired_lease||
               fake_now-c->freed_at<IOS_POOL_REUSE_GRACE_SEC||c->off>=ios_jit_pool_size_global)continue;
            receipts+=c->size;
#if REPLAY_CERTIFIED_SPAN
            size_t span=ios_pool_code_carve_preserve_span(ios_tail_carves,ios_tail_carve_n,i,ios_jit_pool_size_global,0,0,0,0);
            if(span>receipt_largest)receipt_largest=span;
#endif
        }
        printf("November10 post-dependency capacity: image-freelist-plus-virgin=%zx largest=%zx main-virgin=%zx aged-certified-code=%zx code-span=%zx live-code=%zx live-carves=%u ordinary-free-code=%zx (logical fixture geometry; prior small image extents synthetic; nophysicalclaim)\n",total_free,largest,ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved,receipts,receipt_largest,live_code,live_count,ordinary_free);
        expect_failed_image(20*MB);expect_failed_image(40*MB);
        size_t extra[3];
        for(unsigned n=0;n<3;n++)
        { extra[n]=(size_t)-1;CHECK(!allocate_image(8*MB,&extra[n]));check_owned_executable_image(extra[n],8*MB); }
        for(unsigned n=0;n<4;n++)
        {
            void *next=NULL,*released=NULL;size_t bytes=0;CHECK(rotate(&next)==16*MB);
            CHECK(release_code(handles[45],MEM_RELEASE,&released,&bytes)==STATUS_SUCCESS);
            CHECK(released==handles[45]&&bytes==16*MB);handles[45]=next;
            CHECK(ios_jit_tail_reserved==tail_before);check_code_image_nonoverlap();
        }
        CHECK(ios_pool_ledger_holds(client,0x29a8000,(void *)owner)&&ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
        for(unsigned n=0;n<3;n++)CHECK(ios_pool_ledger_holds(extra[n],8*MB,(void *)owner));
        total_free=ios_jit_pool_size_global-jit_pool_offset-ios_jit_tail_reserved;largest=total_free;
        for(int i=0;i<ios_pool_free_count;i++)
        { total_free+=ios_pool_freelist[i].size;if(ios_pool_freelist[i].size>largest)largest=ios_pool_freelist[i].size; }
        printf("November10 post24MiB-synthetic-stress: image-freelist-plus-virgin=%zx largest=%zx head=%zx tail=%zx\n",total_free,largest,jit_pool_offset,(size_t)ios_jit_tail_reserved);
        puts("PASS corrected ownership/placement: embree+8+8+8MiB separately labeled synthetic chain,4FEX rotations AFTER images(8total);20/40MiB single requests honestly fail; no grace/proof relaxation");
        set_process_lease((void *)owner,31,1);ios_jit_reclaim_process((void *)owner);
        CHECK(!ios_pool_ledger_holds(client,0x29a8000,(void *)owner)&&!ios_pool_ledger_holds(embree,0x1524000,(void *)owner));
    }
    for(unsigned i=0;i<pins;i++)
    {
        CHECK(!memcmp(&ios_tail_carves[find_carve(pinned[i].off)],&pinned[i],sizeof pinned[i]));
        CHECK(*(uint64_t *)((char *)rx_memory+pinned[i].off)==0xcafe100000000000ULL+i);
        CHECK(*(uint64_t *)((char *)rx_memory+pinned[i].off+pinned[i].size-8)==0xbeef100000000000ULL+i);
    }
}

struct scheduled_request { unsigned role; size_t size, limit, off; void *ret; int status; };
static void *scheduled_allocate(void *opaque)
{
    struct scheduled_request *request = opaque;
    schedule_role = request->role;
    if (request->role == 2)
        request->off = ios_pool_alloc_range_tagged(request->size, request->limit, 0);
    else request->status = allocate_code(&request->size, &request->ret);
    CHECK(!carve_lock_depth);
    return NULL;
}

static void start_schedule(void)
{
    schedule_mode = 1; tiny_has_pool = other_waiting = release_tiny = 0;
}
static void wait_schedule(int *predicate)
{
    pthread_mutex_lock(&schedule_lock);
    while (!*predicate) pthread_cond_wait(&schedule_cond, &schedule_lock);
    pthread_mutex_unlock(&schedule_lock);
}
static void finish_schedule(void)
{
    pthread_mutex_lock(&schedule_lock);
    release_tiny = 1; pthread_cond_broadcast(&schedule_cond);
    pthread_mutex_unlock(&schedule_lock);
}

static void check_head_tail_and_last_slot_schedules(void)
{
    if (!REPLAY_NEW_POLICY) return; /* old source already fails the captured replay */
    reset(1152 * MB, 176 * MB); ios_pool_free_count = 0;
    size_t old_limit = ios_jit_pool_size_global - ios_jit_tail_reserved;
    jit_pool_offset = old_limit - 0x8000;
    struct scheduled_request tiny = {.role=1, .size=0x4000};
    struct scheduled_request image = {.role=2, .size=0x8000, .limit=old_limit, .off=(size_t)-1};
    pthread_t first, second;
    start_schedule();
    CHECK(!pthread_create(&first, NULL, scheduled_allocate, &tiny));
    wait_schedule(&tiny_has_pool);
    CHECK(!pthread_create(&second, NULL, scheduled_allocate, &image));
    wait_schedule(&other_waiting); finish_schedule();
    CHECK(!pthread_join(first, NULL) && !pthread_join(second, NULL)); schedule_mode = 0;
    CHECK(tiny.status == STATUS_SUCCESS && tiny.size == 0x4000 && image.off == (size_t)-1);
    CHECK(jit_pool_offset == old_limit - 0x8000 && ios_jit_tail_reserved == tail_before + 0x4000);
    CHECK(ios_tail_carves[0].free && ios_tail_carve_n == 5);

    /* Opposite order: the real image consumes the gap first, so the tiny
     * allocation must use the original whole retired carve, with no growth. */
    reset(1152 * MB, 176 * MB); ios_pool_free_count = 0;
    old_limit = ios_jit_pool_size_global - ios_jit_tail_reserved;
    jit_pool_offset = old_limit - 0x8000;
    CHECK(ios_pool_alloc_range_tagged(0x8000, old_limit, 0) == old_limit - 0x8000);
    size_t ask = 0x4000; void *ret = NULL;
    CHECK(allocate_code(&ask, &ret) == STATUS_SUCCESS && ask == 16 * MB);
    CHECK(ios_jit_tail_reserved == tail_before && ios_tail_carve_n == 4);

    /* Two concurrent tiny requests compete for one tracking-table slot.
     * Only one can reserve fresh; the other must safely reuse the big carve. */
    reset(1152 * MB, 176 * MB); ios_pool_free_count = 0;
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    ios_tail_carve_n = IOS_TAIL_CARVE_MAX - 1;
    for (unsigned i = 0; i < ios_tail_carve_n; ++i)
        ios_tail_carves[i] = (struct ios_tail_carve){.off=ios_jit_pool_size_global-tail_before+i*0x4000,
                                                  .size=0x4000, .peb=(void *)steam_owner};
    ios_tail_carves[0] = (struct ios_tail_carve){.off=ios_jit_pool_size_global-16*MB, .size=16*MB, .free=1};
    tiny = (struct scheduled_request){.role=1, .size=0x4000};
    struct scheduled_request other = {.role=3, .size=0x4000};
    start_schedule();
    CHECK(!pthread_create(&first, NULL, scheduled_allocate, &tiny)); wait_schedule(&tiny_has_pool);
    CHECK(!pthread_create(&second, NULL, scheduled_allocate, &other)); wait_schedule(&other_waiting);
    finish_schedule();
    CHECK(!pthread_join(first, NULL) && !pthread_join(second, NULL)); schedule_mode = 0;
    CHECK(tiny.status == STATUS_SUCCESS && other.status == STATUS_SUCCESS);
    CHECK(tiny.size == 0x4000 && other.size == 16 * MB && tiny.ret != other.ret);
    CHECK(ios_tail_carve_n == IOS_TAIL_CARVE_MAX && ios_jit_tail_reserved == tail_before + 0x4000);
    CHECK(!ios_tail_carves[0].free && ios_tail_carves[0].peb == (void *)owner);
    CHECK(ios_tail_carves[IOS_TAIL_CARVE_MAX-1].size == 0x4000);
    puts("PASS: actual concurrent tiny/head allocations reject a stale image ceiling; image-first fallback and two contenders for the last tracking slot preserve ownership and nonoverlap");
}

static void check_capacity_failure(void)
{
    reset(1152 * MB, 176 * MB);
    jit_pool_offset = ios_jit_pool_size_global - ios_jit_tail_reserved;
    expect_failed_image(phonon_size);
    /* With no reusable carve or head extent big enough, a one-megabyte code
     * request reaches actual tail collision and rolls its reservation back. */
    ios_tail_carves[0].free = 0; ios_tail_carves[0].peb = (void *)steam_owner;
    size_t request = MB, tail = ios_jit_tail_reserved; void *ret = NULL;
    CHECK(allocate_code(&request, &ret) == STATUS_NO_MEMORY);
    CHECK(!ret && request == MB && ios_jit_tail_reserved == tail);
    puts("PASS: true image/code capacity failure stays STATUS_NO_MEMORY and rolls back rather than returning unusable non-executable storage");
}

/* iOS aliases are 16KiB aligned. Reserve before remapping so Linux's 4KiB
 * page placement cannot accidentally make this production prerequisite flaky. */
static void *map_pool_alias(FILE *backing, int protection)
{
    size_t reserved = mapped_size + 0x4000;
    void *raw = mmap(NULL, reserved, PROT_NONE, MAP_SHARED, fileno(backing), 0);
    CHECK(raw != MAP_FAILED);
    uintptr_t aligned = ((uintptr_t)raw + 0x3fff) & ~(uintptr_t)0x3fff;
    size_t prefix = aligned - (uintptr_t)raw, suffix = reserved - prefix - mapped_size;
    if (prefix) CHECK(!munmap(raw, prefix));
    if (suffix) CHECK(!munmap((void *)(aligned + mapped_size), suffix));
    void *result = mmap((void *)aligned, mapped_size, protection,
                        MAP_SHARED | MAP_FIXED, fileno(backing), 0);
    CHECK(result == (void *)aligned);
    return result;
}

int main(void)
{
    CHECK(!setvbuf(stdout, NULL, _IOLBF, 0));
    unsetenv("MADEIRA_POOL_LOW_IMAGES"); unsetenv("MADEIRA_POOL_RECYCLE_IMAGES");
    unsetenv("MADEIRA_POOL_CODE_EXIT_RECLAIM"); unsetenv("MADEIRA_POOL_QUARANTINE");
    uint64_t selected, reserve;
    if (REPLAY_LEGACY_ONLY) { selected=1152; reserve=208; }
    else check_budget_plan(&selected, &reserve);
    mapped_size = selected * MB;
    FILE *backing = tmpfile(); CHECK(backing && !ftruncate(fileno(backing), (off_t)(mapped_size + 0x4000)));
    rw_memory = map_pool_alias(backing, PROT_READ | PROT_WRITE);
    rx_memory = map_pool_alias(backing, PROT_READ | PROT_EXEC);
    CHECK(rw_memory != MAP_FAILED && rx_memory != MAP_FAILED && rw_memory != rx_memory);
    if (REPLAY_LEGACY_ONLY)
    {
        check_captured_november8_tail_history(208*MB,0,0);
        CHECK(!munmap(rx_memory,mapped_size)&&!munmap(rw_memory,mapped_size));
        CHECK(!fclose(backing));
        return 0;
    }
    if(getenv("MADEIRA_POOL_CURRENT_PRIOR"))
    {
        check_all_prior_captures_current();
        CHECK(!munmap(rx_memory,mapped_size)&&!munmap(rw_memory,mapped_size));
        CHECK(!fclose(backing));return 0;
    }
    if(getenv("MADEIRA_POOL_NOV10_ONLY"))
    {
        check_captured_november10_tail_history();
        CHECK(!munmap(rx_memory,mapped_size)&&!munmap(rw_memory,mapped_size));
        CHECK(!fclose(backing));return 0;
    }
    check_original_and_growth_only();
    check_paired_budget(selected, reserve);
    check_capacity_failure();
    check_captured_server_failure();
    check_captured_tail_history(176*MB,0);
    check_captured_tail_history(240*MB,512*MB);
    check_captured_nov7_tail_history(176*MB,0);
    check_captured_nov7_tail_history(240*MB,512*MB);
    check_captured_embree_tail_history(REPLAY_CODE_TIE ? 208 * MB : 176 * MB,0);
    check_captured_embree_tail_history(240*MB,512*MB);
    if (!REPLAY_CODE_TIE) check_captured_embree_tail_history(208 * MB,0);
    check_captured_november8_tail_history(208*MB, 0, 0);
    check_captured_november8_tail_history(240*MB, 0, 0);
    check_captured_november8_tail_history(240*MB, 0, 1);
    check_captured_november8_tail_history(240*MB, 512*MB, 0);
    check_captured_november8_tail_history(240*MB, 512*MB, 1);
    check_captured_november8_tail_history(240*MB, 448*MB, 0);
    check_captured_fbb4_tail_history();
    check_head_tail_and_last_slot_schedules();
    CHECK(!munmap(rx_memory, mapped_size) && !munmap(rw_memory, mapped_size));
    CHECK(!fclose(backing));
    return 0;
}
'''

if __name__ == '__main__':
    if not any(os.environ.get(key) for key in ('MADEIRA_POOL_REPLAY_VARIANT', 'MADEIRA_POOL_SOURCE',
                                               'MADEIRA_POOL_NOV10_ONLY', 'MADEIRA_POOL_CURRENT_PRIOR',
                                               'MADEIRA_POOL_LEGACY_REPLAY_ONLY')):
        # Historical exact-address controls and current returned-handle
        # projections are distinct executions, never interchangeable claims.
        runs = [('historical', {}),
                ('baseline', {'MADEIRA_POOL_NOV10_ONLY': '1', 'MADEIRA_POOL_NOV10_EXPECT_BASELINE': '1'}),
                ('promotion', {'MADEIRA_POOL_NOV10_ONLY': '1', 'MADEIRA_POOL_NOV10_EXPECT_FAILURE': '1'}),
                ('current', {'MADEIRA_POOL_CURRENT_PRIOR': '1'})]
        runs += [('current', {'MADEIRA_POOL_NOV10_ONLY': '1', 'MADEIRA_POOL_NOV10_CLOCK_SHIFT': str(shift)})
                 for shift in (0, -1, 1)]
        for selected, settings in runs:
            print('POOL POLICY CONTROL:', selected, settings, flush=True)
            environment = dict(os.environ, MADEIRA_POOL_REPLAY_VARIANT=selected, **settings)
            subprocess.run([sys.executable, __file__], env=environment, check=True)
        raise SystemExit(0)
    with tempfile.TemporaryDirectory(prefix='madeira-pool-cs2-') as directory:
        temporary = Path(directory)
        unit, binary = temporary / 'cs2.c', temporary / 'cs2'
        unit.write_text(fixture)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                        '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-pthread',
                        str(unit), '-o', str(binary)], check=True)
        try:
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=90)
        except subprocess.TimeoutExpired as error:
            for output in (error.stdout, error.stderr):
                if output:
                    print(output.decode(errors='replace') if isinstance(output, bytes) else output,
                          end='', flush=True)
            raise
        print(result.stdout, end='')
        if result.returncode:
            print(result.stderr, end='')
            result.check_returncode()
