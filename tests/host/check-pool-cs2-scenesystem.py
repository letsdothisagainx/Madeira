#!/usr/bin/env python3
"""Replay the scenesystem refusal and prevent new image-data pool poisoning.

The captured 1152 MiB pool had head 0x26a88000, tail 0x2101c000 and
0x55c000 virgin bytes. Its 513 free entries totalled 0x84b4000, the largest
was 0x110000, and 0x7330000 bytes carried the poison-history flag. Those
flags count whole extents, not individual non-executable pages. Exact extent
offsets and page protections were not logged: the aggregate fixture below
uses explicitly synthetic, separated addresses and cannot heal that old pool.

A separate lifecycle fixture executes production allocation, full-image memcpy,
data protection and owner reclaim through real shared read/RW mappings. It
checks that preventing new RX permission mutations preserves contiguous reuse
for scenesystem's 0x97c000 request and 72 MiB of synthetic subsequent imports.
This is a host regression, not execution of CS2 or its actual DLL contents.
"""
from pathlib import Path
import os
import runpy
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
# Reuse the complete production EC_CODE/image allocation/reclaim fixture;
# importing it builds source text but does not execute its independent tests.
shared = runpy.run_path(str(root / 'tests/host/check-pool-cs2-budget.py'))
native, function = shared['native'], shared['function']
prefix = shared['fixture'].split('static void *rx_memory, *rw_memory;')[0]
prefix = prefix.replace('ios_jit_anon_aliases[8]', 'ios_jit_anon_aliases[64]')
prefix = prefix.replace('ios_jit_mappings[8]', 'ios_jit_mappings[64]')

model = r'''
/* Kernel answers model the observed Darwin loss of EXEC after an RX page is
 * made RW. No instructions run in this host's read-only alias. This is only
 * a VM response model: production code makes every protection/reuse decision. */
#define HOST_PAGE 0x4000
#define CAPTURED_POOL 0x48000000
static unsigned char page_cur[CAPTURED_POOL / HOST_PAGE], page_max[CAPTURED_POOL / HOST_PAGE];
static unsigned region_first[CAPTURED_POOL / HOST_PAGE], region_end[CAPTURED_POOL / HOST_PAGE];
static int regions_dirty;
static unsigned rx_write_grants, icache_calls, sleeps;
static unsigned sleep_ns;
static char census[2048];
static int capture(int fd, const char *format, ...)
{
    CHECK(fd == 2);
    if (strstr(format, "[pool-capacity]"))
    {
        va_list ap; va_start(ap, format); vsnprintf(census, sizeof census, format, ap); va_end(ap);
    }
    return 0;
}
#define dprintf capture
static int pool_mprotect(void *address, size_t size, int prot)
{
    uintptr_t lo = (uintptr_t)address, rx = (uintptr_t)ios_jit_rx_base_global;
    CHECK(lo >= rx && lo - rx <= ios_jit_pool_size_global && size <= ios_jit_pool_size_global - (lo - rx));
    size_t first = (lo - rx) / HOST_PAGE, last = (lo - rx + size + HOST_PAGE - 1) / HOST_PAGE;
    for (size_t p = first; p < last; p++)
    {
        page_cur[p] = prot;
        if (prot & PROT_WRITE) { page_max[p] &= ~VM_PROT_EXECUTE; rx_write_grants++; }
    }
    regions_dirty = 1;
    return 0;
}
#define mprotect pool_mprotect
static int advance_sleep(const struct timespec *delay, struct timespec *left)
{
    (void)left; CHECK(delay->tv_sec <= IOS_POOL_REUSE_GRACE_SEC);
    fake_now += delay->tv_sec; sleep_ns += delay->tv_nsec; sleeps++;
    fake_now += sleep_ns / 1000000000; sleep_ns %= 1000000000;
    return 0;
}
#define nanosleep advance_sleep
static int mach_vm_region(mach_port_t task, mach_vm_address_t *address, mach_vm_size_t *size,
                          int flavor, vm_region_info_t raw, mach_msg_type_number_t *count, mach_port_t *object)
{
    (void)task; (void)count;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    CHECK(*address >= rx && *address < rx + ios_jit_pool_size_global);
    size_t p = (*address - rx) / HOST_PAGE;
    if (regions_dirty)
    {
        /* Cache the synthetic kernel's region boundaries, not an allocation
         * verdict. Production's page diagnostics can query the same run many
         * thousands of times without making this fixture quadratic. */
        for (unsigned first = 0, last; first < ios_jit_pool_size_global / HOST_PAGE; first = last)
        {
            last = first + 1;
            while (last < ios_jit_pool_size_global / HOST_PAGE && page_cur[last] == page_cur[first] && page_max[last] == page_max[first]) last++;
            for (unsigned q = first; q < last; q++) { region_first[q] = first; region_end[q] = last; }
        }
        regions_dirty = 0;
    }
    size_t first = region_first[p], last = region_end[p];
    *address = rx + first * HOST_PAGE; *size = (last - first) * HOST_PAGE; *object = MACH_PORT_NULL;
    if (flavor == VM_REGION_BASIC_INFO_64)
    {
        vm_region_basic_info_data_64_t *info = raw;
        info->protection = page_cur[p]; info->max_protection = page_max[p];
    }
    else
    {
        vm_region_extended_info_data_t *info = raw;
        info->user_tag = 0; info->share_mode = page_max[p] == 3 ? 5 : 0;
    }
    return KERN_SUCCESS;
}
'''
prefix = prefix.replace(function(prefix, 'static int mach_vm_region('), model)
protection = function(native, 'static void ios_pool_protect_image_data(')
copy_start = native.index('            memcpy((char *)jit_rw_base + offset, image_base, image_size);',
                          native.index('/* Copy ENTIRE PE image to JIT pool'))
copy_end = native.index('\n\n', native.index('ios_jit_add_mapping(image_base,', copy_start))
copy = native[copy_start:copy_end]
pe_helpers = r'''
#undef STATUS_NO_MEMORY
#undef MEM_RELEASE
#include "windef.h"
#include "winnt.h"
#include "pool_section_policy.h"
#include "native_atomic_image.h"
#include "native_counter_alias.h"
#include "native_srw_alias.h"
#include <strings.h>
#undef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY ((int)0xc0000017u)
typedef unsigned natural_t;
typedef struct { int protection, max_protection; } vm_region_submap_short_info_data_64_t;
typedef void *vm_region_recurse_info_t;
#define VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 1
static int mach_vm_region_recurse(mach_port_t task, mach_vm_address_t *address, mach_vm_size_t *size,
                                  natural_t *depth, vm_region_recurse_info_t raw, mach_msg_type_number_t *count)
{
    (void)depth; vm_region_basic_info_data_64_t basic; mach_port_t object;
    int status = mach_vm_region(task, address, size, VM_REGION_BASIC_INFO_64, &basic, count, &object);
    vm_region_submap_short_info_data_64_t *out = raw;
    out->protection = basic.protection; out->max_protection = basic.max_protection; return status;
}
static const char *ios_pe_module_name(const void *image, size_t size)
{ (void)image; (void)size; return "synthetic PE"; }
static void sys_icache_invalidate(void *rx, size_t size) { CHECK(rx && size); icache_calls++; }
/* Registration supplies references for the actual reclaim walk. Translation
 * dispatch is independently exercised by the process-isolation fixture. */
static void ios_jit_add_mapping(void *pe, void *rx, size_t size)
{
    CHECK(ios_jit_mapping_count < (int)ARRAY_SIZE(ios_jit_mappings));
    ios_jit_mappings[ios_jit_mapping_count].pe_base = pe;
    ios_jit_mappings[ios_jit_mapping_count].jit_base = rx;
    ios_jit_mappings[ios_jit_mapping_count].generation = ios_jit_mapping_count + 1;
    ios_jit_mappings[ios_jit_mapping_count++].size = size;
}
'''
# Include the production native-only copy hook; these synthetic game images
# must retain their exact bytes. Its full lowering is covered independently.
pe_helpers += function(native, 'static void ios_jit_lower_native_atomics(')
pe_helpers += function(native, 'static void ios_jit_bind_native_counter_writer(')
allocate = r'''
static int allocate_pe(void *image_base, size_t image_size, size_t alloc_size, size_t *result)
{
    size_t jit_pool_size = ios_jit_pool_size_global, offset;
    void *reload_jit = NULL;
    void *jit_rx_base = ios_jit_rx_base_global, *jit_rw_base = ios_jit_rw_base_global;
    void *base = jit_rx_base; size_t size = HOST_PAGE;
    uint64_t image_tag = ios_pool_image_tag(image_base, image_size, alloc_size);
''' + shared['image_chain'] + '\n' + shared['failure'] + '\n' + copy + r'''
    ios_pool_protect_image_data((char *)jit_rx_base + offset, (char *)jit_rw_base + offset,
                                image_size, ((IMAGE_DOS_HEADER *)image_base)->e_lfanew,
                                HOST_PAGE, "scene-replay");
    CHECK(!memcmp((char *)jit_rx_base + offset, image_base, image_size));
    CHECK(!memcmp((char *)jit_rw_base + offset, image_base, image_size));
    *result = offset; return 0;
}
'''
prefix = prefix.replace(function(prefix, 'static int allocate_image('),
                        pe_helpers + function(native, 'static uint64_t ios_pool_image_tag(') +
                        function(native, 'static unsigned ios_jit_scan_nonexec(') +
                        function(native, 'static void ios_jit_verify_copy(') + protection + allocate)

code = prefix + r'''
static unsigned char *rx_memory, *rw_memory;
static const size_t captured_head = 0x26a88000, captured_tail = 0x2101c000, scene_want = 0x97c000;
static const uintptr_t steam_owner = 0x68, helper_owner = 0x90, cs2_owner = 0x3ec;
struct image { unsigned char *bytes; size_t size, alloc; };
static struct image make_image(size_t size, size_t allocation, unsigned stamp)
{
    CHECK(size >= 0x20000 && size <= allocation);
    struct image image = {malloc(size), size, allocation}; CHECK(image.bytes);
    memset(image.bytes, stamp & 255, size);
    IMAGE_DOS_HEADER *dos = (void *)image.bytes; memset(dos, 0, sizeof *dos);
    dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x100;
    IMAGE_NT_HEADERS *nt = (void *)(image.bytes + 0x100); memset(nt, 0, sizeof *nt);
    nt->Signature = IMAGE_NT_SIGNATURE; nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.TimeDateStamp = stamp; nt->FileHeader.NumberOfSections = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof nt->OptionalHeader; nt->OptionalHeader.SizeOfImage = size;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt); memset(sec, 0, 3 * sizeof *sec);
    memcpy(sec[0].Name, ".text", 5); sec[0].VirtualAddress = 0x1000; sec[0].Misc.VirtualSize = 0x4500;
    sec[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    memcpy(sec[1].Name, ".data", 5); sec[1].VirtualAddress = 0x6000; sec[1].Misc.VirtualSize = 0xb000;
    sec[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    memcpy(sec[2].Name, ".late", 5); sec[2].VirtualAddress = 0x1c000; sec[2].Misc.VirtualSize = 0x1000;
    sec[2].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    return image;
}
static void reset(void)
{
    ios_jit_rx_base_global = rx_memory; ios_jit_rw_base_global = rw_memory;
    ios_jit_pool_size_global = CAPTURED_POOL; ios_pool_head_reserve = 176 * MB;
    jit_pool_offset = captured_head; ios_jit_tail_reserved = captured_tail;
    ios_jit_hole_off = ios_jit_hole_end = ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    ios_jit_hole2_off = ios_jit_hole2_end = ios_pool_big_size = 0;
    ios_jit_low_size_global = ios_jit_low_reserved = ios_jit_low_full_logged = 0;
    ios_pool_free_count = ios_pool_ledger_count = ios_jit_anon_alias_count = ios_jit_mapping_count = 0;
    ios_jit_copy_refused = aliases_retired = state_query_fail = rx_write_grants = icache_calls = sleeps = sleep_ns = 0;
    scanned_pc = 0; fake_now = 100; census[0] = 0; owner = cs2_owner;
    memset(page_cur, 5, sizeof page_cur); memset(page_max, 7, sizeof page_max); regions_dirty = 1;
    memset(ios_pool_freelist, 0, sizeof ios_pool_freelist); memset(ios_pool_ledger, 0, sizeof ios_pool_ledger);
    memset(ios_jit_anon_aliases, 0, sizeof ios_jit_anon_aliases); memset(ios_jit_mappings, 0, sizeof ios_jit_mappings);
    memset(ios_tail_carves, 0, sizeof ios_tail_carves); ios_tail_carve_n = 3;
    for (unsigned i = 0; i < 3; i++)
        ios_tail_carves[i] = (struct ios_tail_carve){.off = CAPTURED_POOL - captured_tail + i * 128 * MB,
            .size = 128 * MB, .peb = (void *)(i == 2 ? steam_owner : helper_owner)};
}
static void captured_shape(void)
{
    /* Shape only: offsets, adjacency and individual max-protection values were
     * absent from the capacity census. Do not label these as captured extents. */
    size_t at = MB, bytes = 0, marked = 0, largest = 0;
    for (unsigned i = 0; i < 513; i++)
    {
        size_t pages = !i ? 68 : i < 450 ? (i <= 120 ? 17 : 16) : (i < 500 ? 18 : 17);
        size_t n = pages * HOST_PAGE;
        ios_pool_freelist[i] = (struct ios_pool_free){at, n, 0, i < 450 ? 3 : 1, 0};
        at += n + HOST_PAGE; bytes += n; if (i < 450) marked += n; if (n > largest) largest = n;
    }
    ios_pool_free_count = 513;
    CHECK(bytes == 0x84b4000 && marked == 0x7330000 && largest == 0x110000 && at < captured_head);
}
static void fail_image(struct image image)
{
    size_t result = (size_t)-1, head = jit_pool_offset, tail = ios_jit_tail_reserved;
    int ledger = ios_pool_ledger_count;
    CHECK(allocate_pe(image.bytes, image.size, image.alloc, &result) == -1 && errno == ENOMEM && result == (size_t)-1);
    CHECK(executable_load_status() == STATUS_NO_MEMORY && !ios_jit_copy_refused);
    CHECK(jit_pool_offset == head && ios_jit_tail_reserved == tail && ios_pool_ledger_count == ledger);
}
static void check_captured_failure(void)
{
    reset(); captured_shape(); struct image scene = make_image(0x978000, scene_want, 100);
    CHECK(CAPTURED_POOL - captured_head - captured_tail == 0x55c000);
    struct ios_pool_free saved[IOS_POOL_FREE_MAX]; memcpy(saved, ios_pool_freelist, sizeof saved);
    fail_image(scene);
    CHECK(strstr(census, "failed_want=0x97c000 entries=513 free_bytes=0x84b4000 largest=0x110000"));
    CHECK(strstr(census, "poison_marked_bytes=0x7330000 main_virgin=0x55c000"));
    CHECK(ios_pool_free_count == 513 && !memcmp(saved, ios_pool_freelist, sizeof saved));
    CHECK(!rx_write_grants); free(scene.bytes);
    puts("PASS: captured scenesystem request/head/tail and 513-entry aggregate shape reproduce STATUS_NO_MEMORY; old fragmented pool is not falsely repaired");
}
static void register_alias(size_t off, uintptr_t va)
{
    CHECK(ios_jit_anon_alias_count < (int)ARRAY_SIZE(ios_jit_anon_aliases));
    unsigned i = ios_jit_anon_alias_count++;
    ios_jit_anon_aliases[i].user_va = va; ios_jit_anon_aliases[i].user_va_end = va + HOST_PAGE;
    ios_jit_anon_aliases[i].jit_rx_alias = (uintptr_t)rx_memory + off;
    ios_jit_anon_aliases[i].jit_rw_alias = (uintptr_t)rw_memory + off;
}
static void check_lifecycle_capacity(void)
{
    reset(); jit_pool_offset = MB;
    owner = steam_owner; struct image foreign = make_image(0x20000, 0x20000, 1); size_t foreign_off;
    CHECK(!allocate_pe(foreign.bytes, foreign.size, foreign.alloc, &foreign_off)); register_alias(foreign_off, 0x10000000);
    struct ios_pool_alloc foreign_ledger = ios_pool_ledger[0];
    jit_pool_offset = 16 * MB; owner = helper_owner;
    struct image helper[8]; size_t helper_off[8];
    for (unsigned i = 0; i < 8; i++)
    {
        helper[i] = make_image(16 * MB, 16 * MB, i + 2);
        CHECK(!allocate_pe(helper[i].bytes, helper[i].size, helper[i].alloc, &helper_off[i]));
        CHECK(helper_off[i] == (i + 1) * 16 * MB); register_alias(helper_off[i], 0x20000000 + i * 0x10000);
    }
    CHECK(!rx_write_grants && icache_calls == 9);
    CHECK(ios_pool_range_clean(16 * MB, 128 * MB));
    jit_pool_offset = captured_head; owner = cs2_owner;
    struct image scene = make_image(0x978000, scene_want, 100);
    /* Live helpers keep their full ranges; an unrelated reclaim cannot turn
     * their references into capacity. Their eventual exit is the input to the
     * real reclaim walk, whose grace still protects laggard image references. */
    ios_jit_reclaim_process((void *)0xdead); CHECK(!ios_pool_free_count && ios_pool_ledger_count == 9);
    fail_image(scene); CHECK(!ios_pool_free_count && ios_pool_ledger_count == 9);
    ios_jit_reclaim_process((void *)helper_owner);
    CHECK(ios_pool_ledger_count == 1 && !memcmp(&foreign_ledger, &ios_pool_ledger[0], sizeof foreign_ledger));
    CHECK(ios_pool_free_count == 1 && ios_pool_freelist[0].off == 16 * MB && ios_pool_freelist[0].size == 128 * MB);
    CHECK(ios_pool_best_fit(ios_pool_freelist, 1, scene_want, fake_now, (size_t)-1, 0) == -1);
    CHECK(aliases_retired == 8 && ios_jit_anon_aliases[0].user_va == 0x10000000);
    CHECK(ios_jit_mappings[0].pe_base == foreign.bytes && ios_jit_mappings[0].size == foreign.size && ios_jit_mappings[0].generation == 1);
    for (unsigned i = 1; i < 9; i++) CHECK(!ios_jit_mappings[i].pe_base && !ios_jit_mappings[i].size && !ios_jit_mappings[i].generation);
    struct ios_tail_carve live = ios_tail_carves[2]; /* Steam's code is not this helper's. */
    size_t head = jit_pool_offset, tail = ios_jit_tail_reserved, scene_off;
    CHECK(!allocate_pe(scene.bytes, scene.size, scene.alloc, &scene_off) && scene_off == 16 * MB);
    CHECK(fake_now >= 100 + IOS_POOL_REUSE_GRACE_SEC && sleeps >= 30);
    CHECK(ios_pool_ledger_holds(scene_off, scene_want, (void *)cs2_owner));
    CHECK(!ios_pool_ledger_holds(scene_off, scene_want, (void *)helper_owner));
    struct image later[3]; const size_t asks[] = {16 * MB, 24 * MB, 32 * MB};
    for (unsigned i = 0; i < 3; i++)
    {
        later[i] = make_image(asks[i], asks[i], 200 + i); size_t off;
        CHECK(!allocate_pe(later[i].bytes, later[i].size, later[i].alloc, &off));
        CHECK(ios_pool_ledger_holds(off, asks[i], (void *)cs2_owner));
    }
    CHECK(!rx_write_grants && jit_pool_offset == head && ios_jit_tail_reserved == tail);
    CHECK(ios_pool_range_clean(16 * MB, 128 * MB) && !memcmp(&live, &ios_tail_carves[2], sizeof live));
    CHECK(ios_pool_ledger_holds(foreign_off, foreign.alloc, (void *)steam_owner));
    CHECK(!memcmp(rx_memory + foreign_off, foreign.bytes, foreign.size));
    /* The remaining free range and virgin gap cannot serve a 64MiB image.
     * An honest capacity failure still propagates, with no code/RWX fallback. */
    struct image too_large = make_image(64 * MB, 64 * MB, 250); fail_image(too_large);
    CHECK(!rx_write_grants && !memcmp(&live, &ios_tail_carves[2], sizeof live));
    free(too_large.bytes); free(scene.bytes); free(foreign.bytes);
    for (unsigned i = 0; i < 8; i++) free(helper[i].bytes);
    for (unsigned i = 0; i < 3; i++) free(later[i].bytes);
    puts("PASS: production image protection grants no RX writes; quiescent helper ranges coalesce after grace for scenesystem plus 72MiB later imports, preserving foreign references and true capacity failures");
}
static void check_existing_poison_and_overlap(void)
{
    struct image image = make_image(2 * MB, 2 * MB, 300); size_t off = 16 * MB;
    reset(); jit_pool_offset = CAPTURED_POOL - captured_tail;
    ios_pool_freelist[0] = (struct ios_pool_free){off, image.alloc, 0, 0, 0}; ios_pool_free_count = 1;
    page_cur[(off + MB) / HOST_PAGE] = page_max[(off + MB) / HOST_PAGE] = 3;
    regions_dirty = 1;
    fail_image(image); CHECK(page_max[(off + MB) / HOST_PAGE] == 3 && !rx_write_grants);
    reset(); jit_pool_offset = CAPTURED_POOL - captured_tail;
    uint64_t tag = ios_pool_image_tag(image.bytes, image.size, image.alloc);
    ios_pool_freelist[0] = (struct ios_pool_free){off, image.alloc, 0, 1, tag}; ios_pool_free_count = 1;
    ios_pool_ledger[0] = (struct ios_pool_alloc){off, image.alloc, (void *)steam_owner, tag}; ios_pool_ledger_count = 1;
    memset(rw_memory + off, 0x5a, image.alloc); fail_image(image);
    CHECK(ios_pool_ledger_holds(off, image.alloc, (void *)steam_owner) && rx_memory[off] == 0x5a);
    CHECK(!rx_write_grants && !ios_pool_last_same_image); free(image.bytes);
    puts("PASS: existing non-executable poison is still refused, and even matching-image metadata cannot override a live foreign ledger range");
}
int main(void)
{
    unsetenv("MADEIRA_POOL_LOW_IMAGES"); unsetenv("MADEIRA_POOL_RECYCLE_IMAGES");
    unsetenv("MADEIRA_POOL_CODE_EXIT_RECLAIM"); unsetenv("MADEIRA_POOL_QUARANTINE");
    FILE *backing = tmpfile(); CHECK(backing && !ftruncate(fileno(backing), CAPTURED_POOL));
    rw_memory = mmap(NULL, CAPTURED_POOL, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(backing), 0);
    rx_memory = mmap(NULL, CAPTURED_POOL, PROT_READ, MAP_SHARED, fileno(backing), 0);
    CHECK(rw_memory != MAP_FAILED && rx_memory != MAP_FAILED && rw_memory != rx_memory);
    check_captured_failure(); check_lifecycle_capacity(); check_existing_poison_and_overlap();
    CHECK(!munmap(rx_memory, CAPTURED_POOL) && !munmap(rw_memory, CAPTURED_POOL)); CHECK(!fclose(backing));
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-pool-scene-') as directory:
    temporary = Path(directory)
    unit, binary = temporary / 'scene.c', temporary / 'scene'
    unit.write_text(code)
    command = [os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
               '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-type-limits',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
               '-pthread', '-I', str(root / 'wine/include'), '-I', str(root / 'build/ntdll-unix'),
               str(unit), '-o', str(binary)]
    if os.uname().sysname == 'Linux':
        command.insert(1, '-no-pie')
    subprocess.run(command, check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        result.check_returncode()
