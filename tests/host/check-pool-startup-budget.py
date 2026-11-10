#!/usr/bin/env python3
"""Exercise production EC_CODE reuse and page-fit arithmetic; no Wine/game runs.

The C fixture compiles the real allocation prefix, including its best-fit loop,
NOP prefill, region-C bump and one-shot retry after a simulated lost race.
The Swift fixture compiles the actual sizing helper on macOS CI. Linux hosts
without Swift still run the C fixture and source contracts; --require-swift
turns absence of Swift into a failure.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
native = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
swift = (root / 'app/Madeira/StikJITHelper.swift').read_text()


def function(source, signature, closing='\n}'):
    start = source.index(signature)
    return source[start:source.index(closing, start) + len(closing)] + '\n'


ec = native[native.index('size_t alloc_size = (*size_ptr + 0x3FFF) & ~0x3FFFUL;'):]
ec = ec[:ec.index('size_t reserve_offset, tail_added, tail_skipped = 0;')]
assert 'int low_ok = !ios_pool_image_limit && ios_jit_low_size_global && !ios_wow_base();' in ec
assert ec.count('goto retry_code_carve_reuse;') == 4
assert ec.count('ios_tail_carve_ready( &ios_tail_carves[') == 2, 'cap lift and reuse share one readiness rule'
assert 'if (kept_large_carve && !reuse_all_carves)' in ec
assert 'reuse_all_carves = 1;\n                low_fits = 0;' in ec
assert ec.count('(low_ok || !ios_tail_carve_in_low( ios_tail_carves[') == 2
helpers = ''.join(function(native, signature) for signature in (
    'static int ios_pool_partition_allows_code(',
    'static size_t ios_pool_hole_tail_start(',
    'static size_t ios_pool_hole_between(',
    'static size_t ios_pool_code_cap(',
    'static size_t ios_pool_holes_tail_start(',
    'int ios_jit_low_contains(',
    'static int ios_pool_low_take(',
    'static int ios_tail_carve_in_low(',
    'static int ios_pool_code_carve_matches(',
    'static int ios_pool_code_carve_better(',
    'static size_t ios_pool_code_carve_preserve_span(',
    'static int ios_pool_preserve_code_carve(',
    'static size_t ios_pool_code_growth_cap(',
    'static int ios_pool_code_growth_fits(',
    'static int ios_pool_fresh_tail_fits(',
    'static int ios_tail_carve_ready(',
    'static unsigned ios_pool_recent_retired_code_wait(',
))
carve_start = native.index('#define IOS_TAIL_CARVE_MAX ')
carve_table = native[carve_start:native.index('\n\n', carve_start)]

c_fixture = r'''
#include "fex_code_buffer_abi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#define MB ((size_t)1 << 20)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY -1
#define STATUS_INVALID_PARAMETER -2
#define FALLBACK_TAIL 2
#define IOS_POOL_LOW_CARVE_MAX 0x8000000u
#define IOS_POOL_REUSE_GRACE_SEC 3
static void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
static uintptr_t ios_jit_low_rx_global, ios_jit_low_rw_global;
static size_t ios_jit_low_size_global, ios_jit_pool_size_global;
static volatile size_t ios_jit_low_reserved;
static size_t jit_pool_offset, ios_jit_tail_reserved, ios_pool_head_reserve, ios_pool_code_tail_limit;
static size_t ios_jit_hole_off_eff, ios_jit_hole_end_eff;
static size_t ios_jit_hole2_off, ios_jit_hole2_end;
static int ios_jit_low_full_logged, wow, lose_race;
static unsigned attributes;
static size_t ios_pool_image_limit;
static unsigned ios_tail_carve_n;
static pthread_mutex_t ios_tail_carve_lock = PTHREAD_MUTEX_INITIALIZER;
''' + carve_table + r'''
static uintptr_t ios_wow_base(void) { return wow; }
static void *ios_jit_current_peb(void) { return (void *)(uintptr_t)1; }
unsigned long long ios_thread_process_lease(void *peb, int create)
{ (void)create; return (uintptr_t)peb; }
static int ios_tail_carve_scan(const void *base, size_t size, int strict)
{ (void)base; (void)size; (void)strict; return 0; }
static int ios_pool_recycle_main_range_ready(size_t off, size_t size)
{ (void)off; (void)size; CHECK(0); return 0; }
static int ios_fex_code_guard_arm(size_t off, size_t size)
{ (void)off; (void)size; CHECK(0); return 0; }
''' + helpers + r'''
static int racing_low_take(volatile size_t *used, size_t total, size_t want, size_t *off)
{
    if (lose_race) {
        *used = total;
        if (lose_race == 2) ios_tail_carves[0].free = 0;
        lose_race = 0;
    }
    return ios_pool_low_take(used, total, want, off);
}
static int allocate(size_t *size_ptr, void **ret)
{
''' + ec.replace('ios_pool_low_take(', 'racing_low_take(') + r'''
    return FALLBACK_TAIL;  /* The production tail path starts after this prefix. */
}
static const size_t used = 272 * MB + 0x14000;
static void reset(void *memory)
{
    ios_jit_low_rx_global = ios_jit_low_rw_global = (uintptr_t)memory;
    ios_jit_rx_base_global = ios_jit_rw_base_global = (void *)((uintptr_t)memory + 512 * MB);
    ios_jit_low_size_global = 288 * MB;
    ios_jit_low_reserved = used;
    ios_jit_pool_size_global = 864 * MB;
    jit_pool_offset = 600 * MB;
    ios_jit_tail_reserved = ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    ios_jit_hole2_off = ios_jit_hole2_end = 0;
    ios_pool_head_reserve = 128 * MB;
    ios_pool_code_tail_limit = 0;
    ios_jit_low_full_logged = wow = lose_race = 0;
    ios_tail_carve_n = 1;
    ios_tail_carves[0].off = (size_t)(ios_jit_low_rx_global + 2 * MB - (uintptr_t)ios_jit_rx_base_global);
    ios_tail_carves[0].size = 16 * MB;
    ios_tail_carves[0].free = 1;
    ios_tail_carves[0].freed_at = 0;
    ios_tail_carves[0].peb = NULL;
    ios_tail_carves[0].retired = 0;
}
int main(void)
{
    void *memory = NULL, *ret = NULL;
    CHECK(!posix_memalign(&memory, 0x4000, 312 * MB));
    reset(memory);
    size_t request = 0x4000;
    CHECK(allocate(&request, &ret) == STATUS_SUCCESS);
    CHECK(request == 0x4000 && (uintptr_t)ret == ios_jit_low_rx_global + used);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].size == 16 * MB);
    CHECK(ios_jit_low_reserved == used + 0x4000 && !ios_jit_tail_reserved);
    request = 16 * MB;
    CHECK(allocate(&request, &ret) == STATUS_SUCCESS);
    CHECK((uintptr_t)ret == ios_jit_low_rx_global + 2 * MB);
    CHECK(!ios_tail_carves[0].free && ios_jit_low_reserved == used + 0x4000);
    CHECK(!ios_jit_tail_reserved);
    puts("PASS: a 16KB dispatcher preserves the retired 16MB code buffer; the next code buffer reuses it without a pool-tail allocation");

    reset(memory);
    lose_race = 1;
    request = 0x4000;
    CHECK(allocate(&request, &ret) == STATUS_SUCCESS);
    CHECK(request == 16 * MB && !ios_tail_carves[0].free);
    CHECK(ios_jit_low_reserved == 288 * MB && !ios_jit_tail_reserved);
    reset(memory);
    lose_race = 2;
    request = 0x4000;
    CHECK(allocate(&request, &ret) == FALLBACK_TAIL);
    CHECK(ios_jit_low_reserved == 288 * MB && !ios_jit_tail_reserved);
    puts("PASS: losing region C retries the original reuse policy once; losing both resources reaches the normal tail path");

    reset(memory);
    ios_jit_low_reserved = ios_jit_low_size_global;
    request = 0x4000;
    CHECK(allocate(&request, &ret) == STATUS_SUCCESS && request == 16 * MB);
    reset(memory);
    ios_tail_carves[1] = ios_tail_carves[0];
    ios_tail_carves[1].off += 20 * MB;
    ios_tail_carves[1].size = 0x4000;
    ios_tail_carve_n = 2;
    request = 0x4000;
    CHECK(allocate(&request, &ret) == STATUS_SUCCESS && request == 0x4000);
    CHECK(ios_tail_carves[0].free && !ios_tail_carves[1].free && ios_jit_low_reserved == used);
    reset(memory);
    request = MB;
    CHECK(allocate(&request, &ret) == STATUS_SUCCESS && request == 16 * MB);
    CHECK(ios_jit_low_reserved == used);
    puts("PASS: full C, an exact-size retired carve and normal code-buffer requests retain the existing behavior");

    /* A 440MB low run less the unchanged 128MB margin leaves 312MB. With
     * 16MB rounding C has only 304MB: the helper's 32MB request misses by
     * 80KB and falls through to the main tail despite the unused 8MB. */
    for (int page_fit = 0; page_fit < 2; page_fit++)
    {
        reset(memory);
        ios_jit_low_size_global = (page_fit ? 312 : 304) * MB;
        ios_jit_pool_size_global = 896 * MB;
        jit_pool_offset = 0x2dea8000;
        ios_jit_hole_off_eff = 0x15ff4000;
        ios_jit_hole_end_eff = 0x2566c000;
        request = 128 * MB;
        CHECK(allocate(&request, &ret) == STATUS_NO_MEMORY);
        request = 64 * MB;
        CHECK(allocate(&request, &ret) == STATUS_NO_MEMORY);
        request = 32 * MB;
        if (!page_fit)
        {
            CHECK(ios_jit_low_size_global - used == 32 * MB - 0x14000);
            CHECK(allocate(&request, &ret) == FALLBACK_TAIL);
            CHECK(ios_jit_low_reserved == used && ios_tail_carves[0].free);
            continue;
        }
        CHECK(allocate(&request, &ret) == STATUS_SUCCESS);
        CHECK(request == 32 * MB && (uintptr_t)ret == ios_jit_low_rx_global + used);
        CHECK(ios_jit_low_reserved == used + 32 * MB && !ios_jit_tail_reserved);
        request = 0x4000;
        CHECK(allocate(&request, &ret) == STATUS_SUCCESS);
        CHECK(request == 0x4000 && ios_tail_carves[0].free);
        CHECK(ios_jit_low_reserved == used + 32 * MB + 0x4000);
        request = 16 * MB;
        CHECK(allocate(&request, &ret) == STATUS_SUCCESS);
        CHECK(request == 16 * MB && (uintptr_t)ret == ios_jit_low_rx_global + 2 * MB);
        CHECK(!ios_tail_carves[0].free && !ios_jit_tail_reserved);
        CHECK(jit_pool_offset == 0x2dea8000);
    }
    puts("PASS: fitting C to 312MB keeps the helper's 32MB buffer and game startup allocations outside the main pool; 304MB reproduces the fallback");

    reset(memory);
    wow = 1;
    request = 0x4000;
    CHECK(allocate(&request, &ret) == FALLBACK_TAIL);
    CHECK(ios_tail_carves[0].free && ios_jit_low_reserved == used);
    reset(memory);
    ios_jit_low_size_global = 0;
    ios_tail_carve_n = 0;
    request = 0x4000;
    CHECK(allocate(&request, &ret) == FALLBACK_TAIL);
    CHECK(!ios_jit_tail_reserved && ios_jit_low_reserved == used);
    free(memory);
    puts("PASS: WoW64 never receives region-C memory; disabling region C retains the normal tail path");
    return 0;
}
'''

# These contracts cover the callers, placement bounds and byte-length protocol.
page_option = swift[swift.index('let pageFit = '):swift.index('var pairA:')]
assert '.contains(splitValue)' in page_option
assert 'MadeiraConfig.gameValue("pool-page-fit")' in page_option
assert 'MadeiraConfig.get("pool-page-fit")' in page_option
assert swift.count('private static func takeSecondRegion(') == 1
assert swift.count('want: requestedPoolSize - poolSize, pageFit: pageFit,') == 2
minimum_gate = swift.index('if poolSize < minimumPoolSize {')
assert minimum_gate < swift.index('pairSecond = takeSecondRegion('), 'a reduced first region cannot obtain a split CS2 pool after bypassing its full-size requirement'
assert 'return nil' in swift[minimum_gate:swift.index('for attempt in 0..<3 {', minimum_gate)], 'the complete single-region minimum fails before debugger allocation or split fallback'
take = function(swift, 'private static func takeSecondRegion(', '\n    }')
assert 'let size = poolRunSize(available: best.size, wanted: vm_address_t(want), pageFit: pageFit)' in take
assert 'let ceiling: vm_address_t = 0x180000000' in take
assert 'b + size > ceiling' in take and 'gapHitsWindow' in take
assert 'VM_FLAGS_OVERWRITE' not in take
low = function(swift, 'private static func takeLowRegion(', '\n    }')
assert 'Int(marginText) ?? 128' in low
assert 'let available = r.size > keep ? r.size - keep : 0' in low
assert 'poolRunSize(available: available, wanted: available, pageFit: pageFit)' in low
assert 'runs.contains(where: { $0.base < r.base && $0.size >= margin }) ? 0 : margin' in low
assert 'guard let best = best, size >= 64 << 20' in low
assert 'exeWindow: (exeWinBase, exeWinSize), pageFit: pageFit)' in swift
allocator = (root / 'app/Madeira/JITAllocator.c').read_text()
prepare = function(allocator, 'void *jit26_prepare_region(')
assert 'register size_t x1 __asm__("x1") = len;' in prepare
script = (root / 'app/Madeira/madeira-jit.js').read_text()
assert 'prepResp = prepare_memory_region(addr, x1);' in script
assert 'madeiraPoolPrepareOwned(addr, x1)' in script, 'high addresses retain the full byte-length protocol through the strict helper'
print('PASS: page-fit requires pool-split, reaches B and C requests and preserves region-C margin and native mapping guards')

size_helper = function(swift, 'private static func poolRunSize(', '\n    }')
swift_fixture = 'typealias vm_address_t = UInt\n' + 'enum Production {\n' + size_helper + r'''
    static func run() {
        let mb: UInt = 1 << 20, budget: UInt = 896 << 20
        let oldA = poolRunSize(available: 571 * mb, wanted: budget, pageFit: false)
        let oldB = poolRunSize(available: 316 * mb, wanted: budget - oldA, pageFit: false)
        let a = poolRunSize(available: 571 * mb, wanted: budget, pageFit: true)
        let b = poolRunSize(available: 316 * mb, wanted: budget - a, pageFit: true)
        precondition(oldA == 560 * mb && oldB == 304 * mb)
        precondition(a == 571 * mb && b == 316 * mb && a + b <= budget)
        precondition(a + b - oldA - oldB == 23 * mb)
        precondition(UInt(0x148000000) + a <= UInt(0x16c3d0000))
        precondition(UInt(0x16c3d0000) + b <= UInt(0x180000000))
        precondition(poolRunSize(available: UInt.max, wanted: UInt.max, pageFit: false) == 0)
        precondition(poolRunSize(available: UInt.max, wanted: UInt.max, pageFit: true) == UInt.max & ~UInt(0x3fff))
        precondition(poolRunSize(available: 0x3fff, wanted: budget, pageFit: true) == 0)
        precondition(poolRunSize(available: budget, wanted: 0x4001, pageFit: true) == 0x4000)
        let lowFree: UInt = 440 * mb, margin: UInt = 128 * mb
        let oldC = poolRunSize(available: lowFree - margin, wanted: lowFree - margin, pageFit: false)
        let c = poolRunSize(available: lowFree - margin, wanted: lowFree - margin, pageFit: true)
        precondition(oldC == 304 * mb && c == 312 * mb)
        precondition(UInt(0x140000000) - c == UInt(0x12c800000))
        precondition(lowFree - oldC == 136 * mb && lowFree - c == margin)
        let used: UInt = 272 * mb + 0x14000
        precondition(oldC - used == 32 * mb - 0x14000 && c - used >= 32 * mb)
        precondition(poolRunSize(available: 64 * mb - 1, wanted: 64 * mb - 1, pageFit: true) < 64 * mb)
        var state: UInt64 = 411
        for _ in 0..<10000 {
            state = state &* 6364136223846793005 &+ 1
            let available = UInt(state % UInt64(900 * mb))
            state = state &* 6364136223846793005 &+ 1
            let wanted = UInt(state % UInt64(budget + 1))
            let old = min(available & ~(16 * mb - 1), (wanted + 16 * mb - 1) & ~(16 * mb - 1))
            precondition(poolRunSize(available: available, wanted: wanted, pageFit: false) == old)
            let fitted = poolRunSize(available: available, wanted: wanted, pageFit: true)
            precondition(fitted <= available && fitted <= wanted && fitted & 0x3fff == 0)
            let second = poolRunSize(available: 316 * mb, wanted: budget - fitted, pageFit: true)
            precondition(fitted + second <= budget)
            let lowMargin = UInt(state % 4097) * mb
            let lowAvailable = available > lowMargin ? available - lowMargin : 0
            let lowDefault = poolRunSize(available: lowAvailable, wanted: lowAvailable, pageFit: false)
            let lowFitted = poolRunSize(available: lowAvailable, wanted: lowAvailable, pageFit: true)
            precondition(lowDefault == lowAvailable & ~(16 * mb - 1))
            precondition(lowFitted <= lowAvailable && lowFitted & 0x3fff == 0)
            if lowFitted >= 64 * mb { precondition(available - lowFitted >= lowMargin) }
        }
        print("PASS: production Swift page fitting recovers 23MB in a 410-shaped layout; 10,000 default/budget comparisons and boundary cases")
        print("PASS: production Swift sizing recovers C's 8MB rounding loss in a 411-shaped layout without reducing its 128MB margin")
    }
}
Production.run()
'''

# Execute the actual launch-selection/logging block. Measurement and budget
# inputs are controlled edges here. The C plan and both arena getters below are
# compiled from production; no duplicate Swift policy constants substitute for
# the768/384 arena split. No allocation or device result is faked.
content = (root / 'app/Madeira/ContentView.swift').read_text()
reset_start = content.index('            unsetenv("WINE_IOS_JIT_HEAD_RESERVE_MB")', content.index('// Private startup policy belongs to this launch only.'))
private_reset = content[reset_start:content.index('            // A library entry\'s launch profile', reset_start)]
locks_start = content.index('            let cs2PartitionNames = ')
private_locks = content[locks_start:content.index('\n\n', locks_start)]
assert private_reset.count('unsetenv(') == 4
assert 'let cs2PartitionLocksReady = setenv("MADEIRA_ENV_LOCKED", cs2PartitionLocks.joined(separator: ","), 1) == 0' in private_locks
assert private_locks.index('unsetenv(name)') < private_locks.index('let cs2PartitionLocksReady = ')
policy_bodies = [function(allocator, signature) for signature in (
    'bool jit_cs2_pool_plan(', 'uint64_t jit_cs2_image_arena_mb(', 'uint64_t jit_cs2_code_tail_limit_mb(')]
policy_header = '#include <stdbool.h>\n#include <stdint.h>\n' + '\n'.join(body.split('{', 1)[0].rstrip() + ';' for body in policy_bodies) + '\n'
policy_c = '#include "policy.h"\n' + ''.join(policy_bodies)
selection_start = content.index('            var poolSizeMB = DockPerformancePolicy.sessionPoolMB(')
selection = content[selection_start:content.index('            // ml694:', selection_start)]
assert 'JIT pool overridden' not in selection
assert selection.count('[jit-pool-selection-v1]') == 1
assert selection.index('JIT pool requested') < selection.index('jit_cs2_pool_plan(') < selection.index('[jit-pool-selection-v1]')
swift_fixture = 'import Foundation\nimport CS2StartupPolicy\n#if canImport(Darwin)\nimport Darwin\n#else\nimport Glibc\n#endif\n' + swift_fixture + r'''
enum Level { case info, error }
final class SelectionLog {
    var lines: [String] = []
    func log(_ line: String, level: Level = .info) { lines.append(line) }
}
enum MadeiraConfig {
    static var gamePool: String?, globalPool: String?
    static func gameValue(_ key: String) -> String? { gamePool }
    static func get(_ key: String) -> String? { globalPool }
}
enum DockPerformancePolicy {
    static func sessionPoolMB(standard: Int, dock: Bool, compact: Bool) -> Int { dock && compact ? 512 : standard }
}
enum StikJITHelper { static var poolTaken = false }
enum ProcessInfo {
    struct Snapshot { let physicalMemory: UInt64 = 8192 << 20 }
    static let processInfo = Snapshot()
}
var budgetEligible = true, budgetCalls = 0, measureAvailable = true, measureMap = true
var snapshotCalls = 0, mapCalls = 0
var failingExports = Set<String>(), exportedNames: [String] = []
func platformSet(_ name: String, _ value: String) -> Int32 {
    #if canImport(Darwin)
    return Darwin.setenv(name, value, 1)
    #else
    return Glibc.setenv(name, value, 1)
    #endif
}
// These are controlled OS failure edges around the production publication
// calls, not replacement lock/selection logic. Normal calls use real setenv.
func setenv(_ name: String, _ value: String, _ overwrite: Int32) -> Int32 {
    exportedNames.append(name)
    return failingExports.contains(name) ? -1 : platformSet(name, value)
}
func environment() -> [String: String] {
    var result: [String: String] = [:]
    for name in ["MADEIRA_ENV_LOCKED", "WINE_IOS_JIT_HEAD_RESERVE_MB", "WINE_IOS_JIT_CODE_TAIL_LIMIT_MB",
                 "WINE_IOS_JIT_IMAGE_ARENA_MB", "WINE_IOS_FEX_CODE_GUARD_V1"] {
        if let value = getenv(name) { result[name] = String(cString: value) }
    }
    return result
}
func jit_memory_snapshot(_ available: inout UInt64, _ footprint: inout UInt64) -> Bool {
    snapshotCalls += 1
    available = UInt64(budgetEligible ? 6033 : 2048) << 20; footprint = 110 << 20
    return measureAvailable
}
func jit_task_map_range(_ low: inout UInt64, _ high: inout UInt64) -> Bool {
    mapCalls += 1; low = 0x104774000; high = 0xfc0000000; return measureMap
}
func fixture_cs2_pool_plan(_ requested: UInt64, _ available: UInt64, _ footprint: UInt64,
    _ physical: UInt64, _ low: UInt64, _ high: UInt64, _ selected: inout UInt64, _ reserve: inout UInt64) -> Bool {
    budgetCalls += 1
    return CS2StartupPolicy.jit_cs2_pool_plan(requested, available, footprint, physical, low, high, &selected, &reserve)
}
struct SelectionProfile { let steamAppID: Int }
struct SelectionLaunch { let dock: Bool, compact: Bool }
struct SelectionResult {
    let lines: [String], size: Int, floor: Int, failed: Bool, calls: Int
    let environment: [String: String], locksReady: Bool, publications: [String], snapshots: Int, maps: Int
}
func select(app: Int? = nil, global: String? = nil, game: String? = nil,
    existing: Bool = false, eligible: Bool = true, compact: Bool = false,
    stale: Bool = false, profileFlags: [String: String] = [:], fail: Set<String> = [],
    snapshot: Bool = true, map: Bool = true) -> SelectionResult {
    MadeiraConfig.globalPool = global; MadeiraConfig.gamePool = game
    StikJITHelper.poolTaken = existing; budgetEligible = eligible; budgetCalls = 0
    measureAvailable = snapshot; measureMap = map; snapshotCalls = 0; mapCalls = 0
    failingExports = fail; exportedNames = []
    _ = platformSet("MADEIRA_ENV_LOCKED", "OTHER, MADEIRA_EXE,WINE_IOS_JIT_IMAGE_ARENA_MB")
    for name in ["WINE_IOS_JIT_HEAD_RESERVE_MB", "WINE_IOS_JIT_CODE_TAIL_LIMIT_MB", "WINE_IOS_JIT_IMAGE_ARENA_MB", "WINE_IOS_FEX_CODE_GUARD_V1"] {
        if stale { _ = platformSet(name, "999") } else { unsetenv(name) }
    }
@PRIVATE_RESET@
    // Simulate a profile publishing stale private input AFTER the real launch
    // reset. The actual lock-preparation block must clear and lock both names.
    for (name, value) in profileFlags { _ = platformSet(name, value) }
@PRIVATE_LOCKS@
    let logStore = SelectionLog()
    let profile = app.map { SelectionProfile(steamAppID: $0) }
    let dockLaunch = SelectionLaunch(dock: compact, compact: compact)
@SELECTION@
    return SelectionResult(lines: logStore.lines, size: poolSizeMB, floor: minimumPoolSize,
        failed: cs2PoolPreflightFailure != nil, calls: budgetCalls, environment: environment(),
        locksReady: cs2PartitionLocksReady, publications: exportedNames, snapshots: snapshotCalls, maps: mapCalls)
}
func record(_ result: SelectionResult, _ fields: [String]) {
    let rows = result.lines.filter { $0.hasPrefix("[jit-pool-selection-v1]") }
    precondition(rows.count == 1)
    for field in fields { precondition(rows[0].split(separator: " ").contains(Substring(field)), field) }
    precondition(rows[0].contains("coverage=startup-plan-not-allocation"))
    precondition(!result.lines.contains { $0.contains("overridden") })
}
record(select(), ["source=app-default", "configured-mb=none", "effective-mb=896", "result=requested"])
record(select(compact: true), ["source=dock-compact-default", "effective-mb=512"])
let configured = select(global: "1024")
record(configured, ["source=global-config", "configured-mb=1024", "effective-mb=1024", "image-reserve-mb=0"])
precondition(configured.lines.contains { $0.contains("JIT pool requested at 1024MB") })
record(select(global: "1024", game: "768"), ["source=game-config", "configured-mb=768", "effective-mb=768"])
let cs2 = select(app: 730, global: "1024")
record(cs2, ["source=cs2-budget-selected", "configured-mb=1024", "effective-mb=1152", "image-reserve-mb=240",
             "code-tail-limit-mb=384", "hard-image-arena-mb=768", "private-code-guard-v1=1",
             "session-reserve-mb=2048", "existing-pool=0", "result=requested"])
precondition(cs2.size == 1152 && cs2.floor == 1152 << 20 && !cs2.failed && cs2.calls == 1)
precondition(CS2StartupPolicy.jit_cs2_image_arena_mb() == 768 && CS2StartupPolicy.jit_cs2_code_tail_limit_mb() == 384)
precondition(cs2.environment["WINE_IOS_JIT_HEAD_RESERVE_MB"] == "240")
precondition(cs2.environment["WINE_IOS_JIT_CODE_TAIL_LIMIT_MB"] == "384")
precondition(cs2.environment["WINE_IOS_JIT_IMAGE_ARENA_MB"] == "768" && cs2.environment["WINE_IOS_FEX_CODE_GUARD_V1"] == "1")
let declined = select(app: 730, global: "1024", eligible: false)
record(declined, ["source=cs2-budget-declined", "configured-mb=1024", "effective-mb=none",
                  "image-reserve-mb=0", "code-tail-limit-mb=0", "session-reserve-mb=0", "result=declined"])
precondition(declined.failed && declined.floor == 0 && declined.calls == 1)
let reused = select(app: 730, global: "1024", existing: true)
record(reused, ["source=cs2-existing-pool", "effective-mb=none", "existing-pool=1", "result=declined"])
precondition(reused.failed && reused.floor == 0 && reused.calls == 0)
let injected = ["WINE_IOS_JIT_IMAGE_ARENA_MB": "888", "WINE_IOS_FEX_CODE_GUARD_V1": "9"]
let inherited = select(stale: true, profileFlags: injected)
precondition(inherited.environment["WINE_IOS_JIT_IMAGE_ARENA_MB"] == nil && inherited.environment["WINE_IOS_FEX_CODE_GUARD_V1"] == nil)
precondition(inherited.environment["WINE_IOS_JIT_HEAD_RESERVE_MB"] == nil && inherited.environment["WINE_IOS_JIT_CODE_TAIL_LIMIT_MB"] == nil)
let locks = inherited.environment["MADEIRA_ENV_LOCKED"]!.split(separator: ",").map(String.init)
precondition(locks.contains("OTHER") && locks.contains("MADEIRA_EXE") && locks.contains("WINE_IOS_FEX_CODE_GUARD_V1"))
precondition(locks.filter { $0 == "WINE_IOS_JIT_IMAGE_ARENA_MB" }.count == 1 && inherited.locksReady)
let overridden = select(app: 730, stale: true, profileFlags: injected)
precondition(!overridden.failed && overridden.environment["WINE_IOS_JIT_IMAGE_ARENA_MB"] == "768" && overridden.environment["WINE_IOS_FEX_CODE_GUARD_V1"] == "1")
for name in ["MADEIRA_ENV_LOCKED", "WINE_IOS_JIT_IMAGE_ARENA_MB", "WINE_IOS_FEX_CODE_GUARD_V1"] {
    let refused = select(app: 730, stale: true, profileFlags: injected, fail: [name])
    record(refused, ["source=cs2-policy-export-declined", "effective-mb=none", "hard-image-arena-mb=0", "private-code-guard-v1=0", "result=declined"])
    precondition(refused.failed && refused.calls == 1 && refused.floor == 1152 << 20)
    precondition(refused.environment["WINE_IOS_JIT_IMAGE_ARENA_MB"] == nil && refused.environment["WINE_IOS_FEX_CODE_GUARD_V1"] == nil)
    if name == "MADEIRA_ENV_LOCKED" {
        precondition(!refused.locksReady && !refused.publications.contains("WINE_IOS_JIT_IMAGE_ARENA_MB") && !refused.publications.contains("WINE_IOS_FEX_CODE_GUARD_V1"))
    }
}
for result in [select(app: 730, stale: true, profileFlags: injected, snapshot: false),
               select(app: 730, stale: true, profileFlags: injected, map: false)] {
    record(result, ["source=cs2-budget-declined", "effective-mb=none", "result=declined"])
    precondition(result.failed && result.calls == 0 && result.floor == 0)
    precondition(result.environment["WINE_IOS_JIT_IMAGE_ARENA_MB"] == nil && result.environment["WINE_IOS_FEX_CODE_GUARD_V1"] == nil)
}
print("PASS actual startup selection telemetry: real C plan/getters1152=768+384; stale/profile private flags cleared and lock inheritance preserved; lock/arena/guard publication failures and measurement/existing-pool refusal decline without a smaller fallback")
'''.replace('@PRIVATE_RESET@', private_reset).replace('@PRIVATE_LOCKS@', private_locks).replace('@SELECTION@', selection.replace('jit_cs2_pool_plan(', 'fixture_cs2_pool_plan('))

with tempfile.TemporaryDirectory(prefix='madeira-pool-startup-') as directory:
    temporary = Path(directory)
    cfile, binary = temporary / 'startup.c', temporary / 'startup'
    cfile.write_text(c_fixture)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                    '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-pthread', '-I' + str(root / 'build/ntdll-unix'), str(cfile), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        result.check_returncode()
    compiler = os.environ.get('SWIFTC') or shutil.which('swiftc')
    if compiler:
        policy_source, policy_object = temporary / 'policy.c', temporary / 'policy.o'
        (temporary / 'policy.h').write_text(policy_header)
        (temporary / 'module.modulemap').write_text('module CS2StartupPolicy [system] { header "policy.h" export * }\n')
        policy_source.write_text(policy_c)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-c', str(policy_source), '-o', str(policy_object)], check=True)
        swiftfile, swift_binary = temporary / 'startup.swift', temporary / 'swift-startup'
        swiftfile.write_text(swift_fixture)
        subprocess.run([compiler, '-I', str(temporary), str(swiftfile), str(policy_object), '-o', str(swift_binary)], check=True)
        subprocess.run([str(swift_binary)], check=True)
    elif args.require_swift:
        raise SystemExit('Swift compiler required for the production sizing fixture')
    else:
        print('SKIP: Swift compiler unavailable locally; macOS CI must run this check with --require-swift')
