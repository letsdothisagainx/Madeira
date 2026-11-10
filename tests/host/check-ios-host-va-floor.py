#!/usr/bin/env python3
"""Run the production iOS address-space initialization and placement functions.

Mach is simulated as refusing __PAGEZERO and accepting the first host address.
The legacy reset control must perform 65,535 failed mappings for every small
allocation below the first WoW window; the fixed initialization must perform
none. Translated WoW bounds and fixed-address backend results are also checked.
This exercises placement policy, not the real Darwin VM or device performance.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "build/ntdll-unix/virtual_ios.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


functions = [
    function("static char *ios_query_map_floor(void)\n{"),
    function("void virtual_set_large_address_space(void)"),
    function("void ios_wow_translate_limits( ULONG_PTR *limit_low"),
    function("static int ios_wow_limits_in_window( ULONG_PTR low"),
    function("static void ios_wow_exclude_range( void **start"),
    function("static void ios_wow_high_side( void *start"),
    function("static void ios_wow_exclude_windows( void **start"),
    function("static int ios_skip_occupied( void *addr"),
    function("static void* try_map_free_area( void *base"),
    function("static void *map_free_area( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )\n{"),
    function("static void *map_free_area_inner( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )\n{"),
    function("static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size,"),
]

prefix = r'''
#define _GNU_SOURCE
#ifndef TEST_NON_IOS
#define WINE_IOS 1
#endif
#define __APPLE__ 1
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
typedef uintptr_t ULONG_PTR;
typedef uint32_t NTSTATUS;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define MEM_TOP_DOWN 0x100000
#define MEM_REPLACE_PLACEHOLDER 0x4000
#define VPROT_FREE_PLACEHOLDER 0x800
#define VPROT_PLACEHOLDER 0x400
#define VPROT_WRITEWATCH 0x40
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x20
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY 0xc0000017u
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_CONFLICTING_ADDRESSES 0xc0000018u
#define STATUS_WORKING_SET_LIMIT_RANGE 0xc00000a1u
#define KERN_SUCCESS 0
#define MACH_PORT_NULL 0
#define VM_REGION_BASIC_INFO_64 9
#define VM_REGION_BASIC_INFO_COUNT_64 9
#define TASK_VM_INFO 1
#define TASK_VM_INFO_COUNT 1
#define IOS_WOW_WINDOW_SIZE UINT64_C(0x100000000)
#define IOS_WOW_GUEST_FLOOR 0x110000
#define ROUND_ADDR(a,m) ((void *)((uintptr_t)(a) & ~(uintptr_t)(m)))
#define ROUND_SIZE(a,s,m) (((uintptr_t)(a) + (s) + (m)) & ~(uintptr_t)(m))
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define TRACE(...) ((void)0)
#define ERR(...) ((void)0)
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef unsigned mach_msg_type_number_t;
typedef unsigned mach_port_t;
typedef int vm_region_basic_info_data_64_t;
typedef void *vm_region_info_t;
typedef void *task_info_t;
typedef struct { uint64_t min_address; } task_vm_info_data_t;
static unsigned mappings, pagezero_failures, fixed_calls, reserved_calls, anon_calls;
static unsigned unmappable_failures, task_info_calls;
static uint64_t kernel_floor;
static int task_info_result;
static uintptr_t first_mapping, last_mapping, reserved_low, reserved_high;
static uintptr_t fake_wow_base;
static NTSTATUS fixed_status;
static unsigned long long clock_ms;
static unsigned attribution_lines;
static char attribution[2048];
static int quiet(int fd, const char *fmt, ...)
{
    if (strstr(fmt, "[va-scan-owner]")) {
        va_list args;

        attribution_lines++;
        va_start(args, fmt);
        vsnprintf(attribution, sizeof attribution, fmt, args);
        va_end(args);
        errno = EIO;  /* A diagnostic must restore the scan's error. */
    }
    return 0;
}
#define dprintf quiet
static void *address_space_start = (void *)UINT64_C(0x100010000);
static void *address_space_limit = (void *)UINT64_C(0x7fffffff0000);
static void *host_addr_space_limit = (void *)UINT64_C(0x1000000000);
static void *user_space_limit, *working_set_limit;
static int is_win64 = 1;
static ULONG_PTR user_space_wow_limit;
static struct { unsigned ImageCharacteristics; } main_image_info;
static const ULONG_PTR limit_4g = UINT64_C(0x100000000);
static ULONG_PTR ios_wow_base(void) { return fake_wow_base; }
static int is_wow64(void) { return fake_wow_base != 0; }
static int ios_wow_in_window(void *p) { return fake_wow_base && (uintptr_t)p >= fake_wow_base && (uintptr_t)p < fake_wow_base + IOS_WOW_WINDOW_SIZE; }
static ULONG_PTR ios_wow_ceiling_for_charact(unsigned c) { return UINT64_C(0xffffffff); }
static void ios_wow_note_laa(unsigned c) {}
static void free_reserved_memory(char *lo, char *hi) { abort(); }
static void ios_clamp_user_space_limit(const char *why) { user_space_limit = min(user_space_limit, host_addr_space_limit); }
static uintptr_t ios_furniture_ceiling = UINT64_C(0x73ffff0000);
static uintptr_t ios_usable_va_floor = UINT64_C(0x7048000000);
static size_t host_page_mask = 0x3fff, granularity_mask = 0xffff;
static void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
static size_t ios_jit_pool_size_global, ios_jit_low_size_global;
static uintptr_t ios_jit_low_rx_global, ios_jit_low_rw_global;
static unsigned long long ios_layerkit_lo, ios_layerkit_hi;
static int ios_layerkit_enforce = 1;
static unsigned long ios_layerkit_skips;
static int ios_in_layerkit(unsigned long long a, size_t s) { return 0; }
static unsigned ios_wow_window_count = 1, ios_wow_placeholder_count;
static struct { ULONG_PTR base; } ios_wow_windows[1] = {{ UINT64_C(0x400000000) }};
static struct { ULONG_PTR base; int adopted, guard_owned; } ios_wow_placeholders[1];
static size_t ios_wow_slot_reservation(void *slot) { return IOS_WOW_WINDOW_SIZE + 0x4000; }
static size_t ios_wow_guard_size(void) { return 0x4000; }
static int is_beyond_limit(void *p, size_t s, void *end) { return (uintptr_t)p > (uintptr_t)end || s > (uintptr_t)end - (uintptr_t)p; }
static unsigned ios_va_scan_tries, ios_va_scan_skips, ios_scan_views, ios_scan_stop;
static size_t ios_scan_maxgap, ios_scan_tailgap;
static void *ios_scan_base, *ios_scan_end, *ios_scan_fail_addr;
static int ios_scan_fail_errno, ios_va_pressure;
static int mach_task_self(void) { return 0; }
static int task_info(int task, int flavor, task_info_t result, mach_msg_type_number_t *count)
{
    task_info_calls++;
    ((task_vm_info_data_t *)result)->min_address = kernel_floor;
    return task_info_result;
}
static int mach_vm_region(int task, mach_vm_address_t *base, mach_vm_size_t *size,
                          int flavor, vm_region_info_t info, mach_msg_type_number_t *count,
                          mach_port_t *object)
{
    /* PAGEZERO is unmappable but not a mapped Mach region. The kernel returns
     * the next region above the candidate, so ios_skip_occupied cannot jump. */
    *base = kernel_floor; *size = 0x10000;
    return KERN_SUCCESS;
}
static void *anon_mmap_tryfixed(void *p, size_t size, int prot, int flags)
{
    if (!mappings++) first_mapping = (uintptr_t)p;
    last_mapping = (uintptr_t)p;
    if ((uintptr_t)p < kernel_floor) {
        unmappable_failures++;
        if ((uintptr_t)p < UINT64_C(0x100000000)) pagezero_failures++;
        errno = ENOMEM; return MAP_FAILED;
    }
    return p;
}
struct wine_rb_entry { int unused; };
struct file_view { void *base; size_t size; unsigned protect; struct wine_rb_entry entry; };
#define WINE_RB_ENTRY_VALUE(p,t,f) ((t *)(p))
static struct wine_rb_entry *find_view_inside_range(void **lo, void **hi, int td) { return NULL; }
static struct wine_rb_entry *rb_prev(struct wine_rb_entry *p) { return NULL; }
static struct wine_rb_entry *rb_next(struct wine_rb_entry *p) { return NULL; }
static void *map_free_area_inner(void *, void *, size_t, int, int, size_t);
static struct file_view fake_view;
static struct file_view *find_view(void *p, size_t s) { return NULL; }
static int get_unix_prot(unsigned p) { return PROT_READ | PROT_WRITE; }
static void set_vprot(struct file_view *v, void *p, size_t s, unsigned vp) {}
static void kernel_writewatch_register_range(struct file_view *v, void *p, size_t s) {}
static void reset_write_watches(void *p, size_t s) {}
static int use_kernel_writewatch;
static struct { int unused; } ios_af;
static NTSTATUS ios_af_refuse(const char *s, void *p, size_t n, NTSTATUS st) { return st; }
static void ios_af_set(int s, int e, void *p, size_t n) {}
static int ios_arena_guard_refuses(void *p, size_t s, ULONG_PTR l, ULONG_PTR h) { return 0; }
static NTSTATUS map_fixed_area(void *p, size_t n, int prot) { fixed_calls++; return fixed_status; }
static ULONG_PTR ios_fex_arena_base_unix, ios_fex_arena_end_unix;
static int ios_native_high_fex_legacy_request(ULONG_PTR lo, ULONG_PTR hi) { return 0; }
static int fex_arena_covers(void *lo, void *hi) { return 0; }
static int ios_stack_spill_enabled(void) { return 0; }
static void *ios_wow_bias_end(void *lo, void *hi) { return hi; }
static int ios_wow_laa_synth;
static int ios_wow_laa_low_first(void) { return 0; }
static int madeira_vm_count_sample(unsigned long n, unsigned first) { return n <= first; }
static const ULONG_PTR limit_2g = 0x80000000;
static void *map_reserved_area(void *lo, void *hi, size_t s, int td, int prot, size_t mask)
{
    reserved_calls++; reserved_low = (uintptr_t)lo; reserved_high = (uintptr_t)hi;
    /* A guest window is reserved; its guest requests are served in place. */
    return fake_wow_base && (uintptr_t)lo >= fake_wow_base &&
           (uintptr_t)hi <= fake_wow_base + IOS_WOW_WINDOW_SIZE ? lo : NULL;
}
static void ios_fex_arena_headroom(void *lo, void *hi) {}
static int ios_cage_release_on_exhaustion(void *lo, void *hi, size_t size) { return 0; }
static unsigned long long ios_now_ms(void) { return ++clock_ms; }
static struct { struct { void *UniqueThread; } ClientId; void *ChpeV2CpuAreaInfo; } fake_teb;
typedef typeof(fake_teb) TEB;
static TEB *NtCurrentTeb(void) { return &fake_teb; }
static void *ios_jit_current_peb(void) { return (void *)UINT64_C(0x111bcc000); }
static void ios_furniture_census(void) {}
static void ios_va_describe(void *p, char *s, size_t n) {}
static int ios_storm_gate(unsigned long *n) { return ++*n <= 4; }
static const char *ios_scan_stop_name(unsigned s) { return "test"; }
static void ios_fex_arena_census(void *lo, void *hi, size_t s, size_t a) {}
static void *ios_map_between_wow_windows(void *lo, void *hi, size_t s, int td, int p, size_t a, int f) { return NULL; }
static void *anon_mmap_alloc(size_t s, int p) { anon_calls++; return (void *)UINT64_C(0xe00000000); }
static uintptr_t ios_spill_cap;
static void ios_pool_va_warn(const char *s, void *p, size_t n) {}
static size_t unmap_area_above_user_limit(void *p, size_t s) { return s; }
static void *unmap_extra_space(void *p, size_t a, size_t b, size_t c) { return p; }
static NTSTATUS create_view(struct file_view **v, void *p, size_t s, unsigned prot) { fake_view.base=p; fake_view.size=s; *v=&fake_view; return 0; }
static void ios_fex_tag_view(struct file_view *v, ULONG_PTR lo, ULONG_PTR hi) {}
static void unmap_area(void *p, size_t s) {}
'''

suffix = r'''
static void reset_counts(void)
{
    mappings = pagezero_failures = unmappable_failures = fixed_calls = reserved_calls = anon_calls = 0;
    first_mapping = last_mapping = 0;
}
static struct file_view *place(void *base, size_t size, ULONG_PTR lo, ULONG_PTR hi)
{
    struct file_view *view = NULL;
    NTSTATUS status = map_view(&view, base, size, 0x3000, 0x23, lo, hi, 0);
    assert(!status && view);
    return view;
}
int main(int argc, char **argv)
{
#ifdef TEST_NON_IOS
    virtual_set_large_address_space();
    assert(address_space_start == (void *)0x10000 && !task_info_calls);
    puts("PASS: non-iOS large-address initialization retains its original 64 KB floor");
    return 0;
#endif
    int query_failed = argc > 1 && !strcmp(argv[1], "failed-query");
    int query_low = argc > 1 && !strcmp(argv[1], "low-query");
    kernel_floor = query_low ? UINT64_C(0x100000000) :
                   query_failed ? UINT64_C(0x100010000) : UINT64_C(0x104998000);
    task_info_result = query_failed ? 5 : KERN_SUCCESS;
    uintptr_t expected_floor = max(kernel_floor, UINT64_C(0x100010000));
    uintptr_t legacy_aligned_floor = (kernel_floor + 0xffff) & ~UINT64_C(0xffff);
    uintptr_t aligned_floor = (expected_floor + 0xffff) & ~UINT64_C(0xffff);
    fake_teb.ClientId.UniqueThread = (void *)0x19c;
    fake_teb.ChpeV2CpuAreaInfo = (void *)UINT64_C(0x12f7c0000);
    /* Exact old reset, then repeated real map_view/try_map_free_area calls:
     * this is a costly successful allocation, not an inferred caller retry. */
    for (unsigned repeat = 0; repeat < 6; repeat++) {
        address_space_start = (void *)0x10000;
        user_space_limit = host_addr_space_limit;
        reset_counts();
        struct file_view *v = place(NULL, 0x1000, 0, 0);
        assert(v->base == (void *)legacy_aligned_floor);
        assert(first_mapping == 0x10000 && pagezero_failures == 65535);
        assert(mappings == legacy_aligned_floor / 0x10000 && unmappable_failures == mappings - 1);
        assert(reserved_high == UINT64_C(0x400000000));
        assert(errno == ENOMEM);
    }
    assert(attribution_lines == 4);
    assert(strstr(attribution, "tid=019c peb=0x111bcc000") &&
           strstr(attribution, "cpu-area=0x12f7c0000") &&
           strstr(attribution, "window=0x10000..0x400000000") && strstr(attribution, "elapsed-ms="));
    puts("PASS: old reset repeats 65,535 failed PAGEZERO mappings per allocation; attribution is capped at four");

    address_space_start = (void *)UINT64_C(0x100010000);
    virtual_set_large_address_space();
    assert(address_space_start == (void *)expected_floor && task_info_calls == 1);
    for (unsigned repeat = 0; repeat < 6; repeat++) {
        reset_counts();
        struct file_view *v = place(NULL, repeat % 2 ? 0x3000 : 0x1000, 0, 0);
        assert(v->base == (void *)aligned_floor);
        assert(first_mapping == aligned_floor && mappings == 1 && !unmappable_failures);
        assert(reserved_high == UINT64_C(0x400000000) && !anon_calls);
    }
    puts(query_low ? "PASS: a reported floor below the established iOS floor never lowers it" :
         query_failed ? "PASS: a failed task query retains the established iOS floor without failed mappings" :
                        "PASS: the measured iOS floor skips PAGEZERO and the ASLR prefix without failed mappings");

    /* A real guest ceiling is translated first; neither process init nor
     * native floor preservation raises its low bound out of the guest window. */
    fake_wow_base = UINT64_C(0x400000000);
    virtual_set_large_address_space();
    assert(address_space_start == (void *)expected_floor && task_info_calls == 1);
    ULONG_PTR lo = 0, hi = UINT64_C(0x7fffffff);
    ios_wow_translate_limits(&lo, &hi);
    assert(lo == fake_wow_base + IOS_WOW_GUEST_FLOOR && hi == fake_wow_base + UINT64_C(0x7fffffff));
    reset_counts();
    struct file_view *v = place(NULL, 0x1000, lo, hi);
    assert((uintptr_t)v->base == lo && reserved_low == lo && reserved_high == hi + 1);
    assert(!mappings && !fixed_calls && !anon_calls);
    puts("PASS: translated WoW bounds retain their guest-window reserved-area placement");

    fake_wow_base = 0;
    for (unsigned i = 0; i < 3; i++) {
        void *fixed = (void *)(i ? UINT64_C(0x130000000) : UINT64_C(0x80000000));
        struct file_view *view = NULL;
        fixed_status = i == 2 ? STATUS_CONFLICTING_ADDRESSES : 0;
        reset_counts();
        NTSTATUS got = map_view(&view, fixed, 0x1000, 0x3000, 0x23, 0, 0, 0);
        assert(got == fixed_status && fixed_calls == 1 && !mappings && !reserved_calls && !anon_calls);
        if (!got) assert(view->base == fixed);
    }
    puts("PASS: fixed requests reach the original backend once and retain its address/result");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="madeira-ios-host-va-floor-") as directory:
    cfile = Path(directory) / "floor.c"
    binary = Path(directory) / "floor"
    cfile.write_text(prefix + "\n".join(functions) + suffix)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11",
                    "-Werror=implicit-function-declaration", "-fsanitize=undefined",
                    str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    subprocess.run([str(binary), "failed-query"], check=True)
    subprocess.run([str(binary), "low-query"], check=True)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-DTEST_NON_IOS",
                    "-Werror=implicit-function-declaration", "-fsanitize=undefined",
                    str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
