#!/usr/bin/env python3
"""Replay CS2's phonon.dll exhaustion through the production pool functions.

The November 5 log has a 1 GiB pool, image head 0x1dcd0000, code tail
0x20014000 and a 0x3310000-byte phonon.dll request. Its 226 free extents
total 0x33e4000 bytes, but the largest is only 0xf0000 bytes. The fixture's
separated extents reproduce those aggregates, not the original addresses.

Compile the actual complete EC_CODE allocation branch (including fresh tail
carves and rollback), image allocation chain, failure path and process reclaim.
Only Darwin region/thread queries and unrelated platform callbacks are supplied
by the harness. Real shared file mappings check the RX/RW alias relationship.
No Wine/game execution or assertion of a successful device launch is implied.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
native = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
allocator = (root / 'app/Madeira/JITAllocator.c').read_text()
content = (root / 'app/Madeira/ContentView.swift').read_text()
swift = (root / 'app/Madeira/StikJITHelper.swift').read_text()


def function(source, signature):
    start = source.index(signature)
    while source.index(';', start) < source.index('{', start):
        start = source.index(signature, start + len(signature))
    return source[start:source.index('\n}', start) + 2] + '\n'


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
assert 'return STATUS_NO_MEMORY;' in ec and 'ios_pool_tail_unreserve(' in ec
assert image_chain.count('ios_pool_low_image_range(') == 1
assert image_chain.count('ios_pool_recycle_code_range(') == 1
assert 'ios_jit_copy_refused = 1;' in failure and 'return -1;' in failure
assert 'status = STATUS_NO_MEMORY;' in loader_failure and 'goto done;' in loader_failure

helpers = ''.join(function(native, signature) for signature in (
    'static size_t ios_pool_hole_head_place(',
    'static size_t ios_pool_hole_tail_start(',
    'static size_t ios_pool_hole_between(',
    'static size_t ios_pool_code_cap(',
    'static size_t ios_pool_parse_head_reserve(',
    'static size_t ios_pool_holes_head_place(',
    'static size_t ios_pool_holes_tail_start(',
    'static size_t ios_pool_holes_between(',
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
    'static int ios_tail_carve_scan(',
    'static int ios_tail_carve_occupied(',
    'static int ios_tail_carve_ready(',
    'static unsigned ios_tail_carves_retire_owner(',
    'static int ios_tail_carve_foreign_release(',
    'static void ios_tail_carves_owner_died(',
    'static int ios_pool_recycle_range_ready(',
    'static int ios_pool_recycle_code_range(',
    'static int ios_pool_ledger_holds(',
    'void ios_jit_reclaim_process(',
))

# Swift's launch plumbing is platform-owned; the decision and arithmetic run
# below as production C. Keep the selected game and the pre-Wine failure path
# connected to that decision, and reset the private reserve for later launches.
scope_start = content.index('if profile?.steamAppID == 730 {')
scope = content[scope_start:content.index('// ml694:', scope_start)]
assert '!StikJITHelper.poolTaken && measured && jit_cs2_pool_plan(' in scope
assert 'setenv("WINE_IOS_JIT_HEAD_RESERVE_MB", String(imageReserveMB), 1)' in scope
assert 'minimumPoolSize = poolSizeMB * 1024 * 1024' in scope
assert content.index('unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB")') < scope_start
assert 'StikJITHelper.allocatePool(poolSize: poolSizeMB * 1024 * 1024, minimumPoolSize: minimumPoolSize)' in content
abort = content[content.index('logStore.log("JIT pool allocation FAILED'):content.index('// Step 1b (ml524')]
assert 'unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB")' in abort and '\n                return\n' in abort
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
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#define MB ((size_t)1 << 20)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
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
static size_t ios_jit_pool_size_global, jit_pool_offset, ios_pool_head_reserve;
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
static struct { void *pe_base, *jit_base; size_t size; } ios_jit_mappings[8];
static int ios_jit_anon_alias_count, ios_jit_mapping_count, ios_jit_copy_refused;
static void *ios_jit_alias_pushback_peb;
static void (*ios_jit_alias_pushback_cb)(void);
static void *arm64ec_view;
static uintptr_t owner;
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

/* Darwin answers are supplied, while the production walkers and all allocator
 * decisions run unchanged. No buffer is actually executed on the host. */
typedef unsigned mach_port_t, mach_msg_type_number_t, thread_act_t;
typedef thread_act_t *thread_act_array_t;
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef int kern_return_t;
typedef void *thread_state_t, *vm_region_info_t;
typedef struct { uintptr_t pc; } arm_thread_state64_t;
typedef struct { unsigned protection, max_protection; } vm_region_basic_info_data_64_t;
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
#define VM_PROT_EXECUTE 4
#define arm_thread_state64_get_pc(st) ((st).pc)
static uintptr_t scanned_pc;
static int state_query_fail;
static mach_port_t mach_task_self(void) { return 0; }
static mach_port_t mach_thread_self(void) { return 1; }
static int task_threads(mach_port_t task, thread_act_array_t *out, mach_msg_type_number_t *count)
{
    (void)task;
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
    uintptr_t base = (uintptr_t)ios_jit_rx_base_global;
    CHECK(*address >= base && *address < base + ios_jit_pool_size_global);
    *address = base; *size = ios_jit_pool_size_global; *object = MACH_PORT_NULL;
    if (flavor == VM_REGION_BASIC_INFO_64)
    {
        vm_region_basic_info_data_64_t *info = raw;
        info->protection = 5; info->max_protection = 7;
    }
    else
    {
        vm_region_extended_info_data_t *info = raw;
        info->user_tag = 0; info->share_mode = 0;
    }
    return KERN_SUCCESS;
}
''' + budget_helpers + helpers + r'''

static void initialize_head_reserve(void)
{
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
    CHECK(*selected == 1152 && *reserve == 176);
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

    unsetenv("MADEIRA_POOL_HEAD_RESERVE_MB"); unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB");
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == 48 * MB);
    setenv("WINE_IOS_JIT_HEAD_RESERVE_MB", "176", 1);
    setenv("MADEIRA_POOL_HEAD_RESERVE_MB", "48", 1);
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == *reserve * MB);
    setenv("MADEIRA_POOL_HEAD_RESERVE_MB", "256", 1);
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == 256 * MB);
    setenv("MADEIRA_POOL_HEAD_RESERVE_MB", "48", 1);
    unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB");
    initialize_head_reserve(); CHECK(ios_pool_head_reserve == 48 * MB);
    unsetenv("MADEIRA_POOL_HEAD_RESERVE_MB");
    puts("PASS: production CS2 plan gates measured RAM/address budgets; layout bounds and private reserve cannot weaken existing checks");
}

static void reset(size_t total, size_t reserve)
{
    CHECK(total <= mapped_size);
    ios_jit_rx_base_global = rx_memory; ios_jit_rw_base_global = rw_memory;
    ios_jit_pool_size_global = total; ios_pool_head_reserve = reserve;
    jit_pool_offset = rotation_head; ios_jit_tail_reserved = tail_before;
    ios_jit_hole_off = ios_jit_hole_end = ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    ios_jit_hole2_off = ios_jit_hole2_end = ios_pool_big_size = 0;
    ios_jit_low_size_global = ios_jit_low_reserved = ios_jit_low_full_logged = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_jit_anon_alias_count = ios_jit_mapping_count = 0;
    ios_jit_copy_refused = aliases_retired = state_query_fail = 0; scanned_pc = 0;
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
    ios_jit_mappings[0].size = phonon_size; ios_jit_mapping_count = 1;
    ios_jit_mappings[1].pe_base = (void *)(uintptr_t)0x20000000;
    ios_jit_mappings[1].jit_base = (char *)rx_memory + foreign_off;
    ios_jit_mappings[1].size = 0x4000; ios_jit_mapping_count = 2;
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
    CHECK(ios_pool_ledger_count == 1 && !ios_jit_mappings[0].pe_base && !ios_jit_mappings[0].size);
    CHECK(ios_pool_ledger_holds(foreign_off, 0x4000, (void *)helper_owner));
    CHECK(ios_jit_mappings[1].pe_base && ios_jit_mappings[1].size == 0x4000);
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

int main(void)
{
    unsetenv("MADEIRA_POOL_LOW_IMAGES"); unsetenv("MADEIRA_POOL_RECYCLE_IMAGES");
    unsetenv("MADEIRA_POOL_CODE_EXIT_RECLAIM"); unsetenv("MADEIRA_POOL_QUARANTINE");
    uint64_t selected, reserve;
    check_budget_plan(&selected, &reserve);
    mapped_size = selected * MB;
    FILE *backing = tmpfile(); CHECK(backing && !ftruncate(fileno(backing), (off_t)mapped_size));
    rw_memory = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(backing), 0);
    rx_memory = mmap(NULL, mapped_size, PROT_READ, MAP_SHARED, fileno(backing), 0);
    CHECK(rw_memory != MAP_FAILED && rx_memory != MAP_FAILED && rw_memory != rx_memory);
    check_original_and_growth_only();
    check_paired_budget(selected, reserve);
    check_capacity_failure();
    CHECK(!munmap(rx_memory, mapped_size) && !munmap(rw_memory, mapped_size));
    CHECK(!fclose(backing));
    return 0;
}
'''

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='madeira-pool-cs2-') as directory:
        temporary = Path(directory)
        unit, binary = temporary / 'cs2.c', temporary / 'cs2'
        unit.write_text(fixture)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                        '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-pthread',
                        str(unit), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        print(result.stdout, end='')
        if result.returncode:
            print(result.stderr, end='')
            result.check_returncode()
