#!/usr/bin/env python3
"""Compile production logical pool accounting as C and C++, without Mach stubs.

Both real shared aliases and allocator metadata remain unchanged. The snapshot
uses the actual carve -> pool locks; no owner/lease provider is queried.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/virtual_ios.c').read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


start = source.index('/* madeira-pool-accounting begin')
end = source.index('/* madeira-pool-accounting end */', start) + len('/* madeira-pool-accounting end */')
accounting = source[start:end]
for prohibited in ('mprotect(', 'mmap(', 'munmap(', 'madvise(', 'malloc(',
                   'ios_thread_process_', 'ios_jit_current_peb(', 'mach_vm_'):
    assert prohibited not in accounting, prohibited
carve_start = source.index('#define IOS_TAIL_CARVE_MAX ')
carve_table = source[carve_start:source.index('\n\n', carve_start)]

fixture = r'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>
#define MB ((size_t)1 << 20)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define IOS_POOL_LEDGER_MAX 1024
#define IOS_POOL_FREE_MAX 1024
#define IOS_POOL_REUSE_GRACE_SEC 3
struct ios_pool_alloc { size_t off, size; void *peb; uint64_t tag; };
struct ios_pool_free { size_t off, size; time_t freed_at; int advised; uint64_t tag; };
static struct ios_pool_alloc ios_pool_ledger[IOS_POOL_LEDGER_MAX];
static struct ios_pool_free ios_pool_freelist[IOS_POOL_FREE_MAX];
static int ios_pool_ledger_count, ios_pool_free_count;
static size_t ios_jit_pool_size_global, jit_pool_offset, ios_jit_tail_reserved;
static size_t ios_jit_hole_off_eff, ios_jit_hole_end_eff, ios_jit_hole2_off, ios_jit_hole2_end;
static size_t ios_jit_low_size_global, ios_jit_low_reserved;
static uintptr_t ios_jit_low_rx_global;
static void *ios_jit_rx_base_global, *rw_alias;
static pthread_mutex_t ios_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned ios_tail_carve_n;
static pthread_mutex_t ios_tail_carve_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static char output[131072];
static size_t output_length;
static unsigned output_lines;
static int capture(int fd, const char *format, ...)
{
    assert(fd == 2);
    pthread_mutex_lock(&output_lock);
    va_list args;
    va_start(args, format);
    int n = vsnprintf(output + output_length, sizeof(output) - output_length, format, args);
    va_end(args);
    assert(n > 0 && output_length + (size_t)n < sizeof(output));
    output_length += (size_t)n; output_lines++;
    pthread_mutex_unlock(&output_lock);
    return n;
}
#define dprintf capture
''' + carve_table + '\n' + function('static size_t ios_pool_hole_between(') + function('static size_t ios_pool_holes_between(') + r'''
static __thread unsigned accounting_held;
static unsigned accounting_lock_pairs;
static int accounting_lock(pthread_mutex_t *lock)
{
    if (lock == &ios_pool_lock) assert(accounting_held == 1);
    else { assert(lock == &ios_tail_carve_lock); assert(!accounting_held); }
    int result = pthread_mutex_lock(lock);
    assert(!result);
    if (lock == &ios_pool_lock) { accounting_held |= 2; __sync_fetch_and_add(&accounting_lock_pairs, 1); }
    else accounting_held |= 1;
    return result;
}
static int accounting_unlock(pthread_mutex_t *lock)
{
    if (lock == &ios_pool_lock) { assert(accounting_held == 3); accounting_held &= ~2u; }
    else { assert(lock == &ios_tail_carve_lock && accounting_held == 1); accounting_held &= ~1u; }
    return pthread_mutex_unlock(lock);
}
#define pthread_mutex_lock accounting_lock
#define pthread_mutex_unlock accounting_unlock
''' + accounting + r'''
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
''' + function('static void ios_pool_failure_census( size_t want )') + r'''
#undef dprintf

static void *peb(unsigned n) { return (void *)(uintptr_t)(0x1000 + n * 0x100); }
static size_t c_off(size_t off) { return (size_t)(ios_jit_low_rx_global - (uintptr_t)ios_jit_rx_base_global) + off; }
static void reset(void)
{
    memset(ios_pool_ledger, 0, sizeof ios_pool_ledger);
    memset(ios_pool_freelist, 0, sizeof ios_pool_freelist);
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    ios_pool_ledger_count = ios_pool_free_count = 0; ios_tail_carve_n = 0;
    ios_jit_pool_size_global = 64 * MB; jit_pool_offset = 48 * MB; ios_jit_tail_reserved = 16 * MB;
    ios_jit_low_rx_global = (uintptr_t)ios_jit_rx_base_global - 32 * MB;
    ios_jit_low_size_global = 32 * MB; ios_jit_low_reserved = 20 * MB;
    ios_jit_hole_off_eff = 32 * MB; ios_jit_hole_end_eff = 36 * MB;
    ios_jit_hole2_off = ios_jit_hole2_end = 0;
}
static void image(size_t off, size_t bytes, void *owner)
{
    struct ios_pool_alloc *p = &ios_pool_ledger[ios_pool_ledger_count++];
    p->off = off; p->size = bytes; p->peb = owner;
}
static void code(size_t off, void *owner, unsigned long long lease, int is_free, int retired, unsigned long long receipt)
{
    struct ios_tail_carve *c = &ios_tail_carves[ios_tail_carve_n++];
    c->off = off; c->size = 4 * MB; c->peb = owner; c->allocation_lease = lease;
    c->free = is_free; c->retired = retired; c->retired_lease = receipt;
}
static const struct ios_pool_account_owner *owner_row(const struct ios_pool_account_snapshot *s, void *owner, unsigned long long lease)
{
    for (unsigned i = 0; i < s->owner_count; i++)
        if (s->owners[i].peb == owner && s->owners[i].lease == lease) return &s->owners[i];
    assert(!"owner row absent"); return NULL;
}
static size_t sum(const struct ios_pool_account_snapshot *s, unsigned region)
{
    size_t bytes = 0;
    for (unsigned k = 0; k < IOS_ACCOUNT_KIND_COUNT; k++) bytes += s->bytes[region][k];
    return bytes;
}
static void permissions(void *address, char result[5])
{
    FILE *file = fopen("/proc/self/maps", "r");
    assert(file);
    char line[512], perms[5]; unsigned long lo, hi;
    while (fgets(line, sizeof line, file))
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) == 3 &&
            (uintptr_t)address >= lo && (uintptr_t)address < hi)
        { memcpy(result, perms, 5); fclose(file); return; }
    assert(!"mapping absent");
}
static void classifications(void)
{
    struct ios_pool_account_snapshot s;
    reset();
    image(0, 4 * MB, peb(1)); image(20 * MB, 4 * MB, peb(2)); image(c_off(0), 4 * MB, peb(1));
    code(4 * MB, peb(1), 11, 0, 0, 0);
    code(8 * MB, peb(1), 11, 1, 0, 0); /* FREE alone is not owner retirement */
    code(12 * MB, NULL, 21, 1, 1, 21); /* PEB cleared, certified lease retained */
    code(16 * MB, NULL, 22, 1, 1, 23); /* mismatched receipt */
    code(24 * MB, peb(1), 24, 1, 1, 24); /* stale owner cannot be certified */
    code(c_off(4 * MB), peb(1), 31, 0, 0, 0); /* same PEB, different generation */
    code(c_off(8 * MB), NULL, 0, 1, 0, 0); /* foreign/unknown release proof */
    code(c_off(12 * MB), NULL, 21, 1, 1, 21);
    ios_pool_free_count = 3;
    ios_pool_freelist[0].off = 28 * MB; ios_pool_freelist[0].size = 4 * MB;
    ios_pool_freelist[1].off = 36 * MB; ios_pool_freelist[1].size = 4 * MB; ios_pool_freelist[1].advised = 2;
    ios_pool_freelist[2].off = c_off(16 * MB); ios_pool_freelist[2].size = 4 * MB; ios_pool_freelist[2].advised = 3;
    unsigned char ledger_before[sizeof ios_pool_ledger], free_before[sizeof ios_pool_freelist], carve_before[sizeof ios_tail_carves];
    memcpy(ledger_before, ios_pool_ledger, sizeof ledger_before);
    memcpy(free_before, ios_pool_freelist, sizeof free_before);
    memcpy(carve_before, ios_tail_carves, sizeof carve_before);
    size_t geometry_before[] = { (size_t)ios_pool_ledger_count, (size_t)ios_pool_free_count, ios_tail_carve_n,
        ios_jit_pool_size_global, jit_pool_offset, ios_jit_tail_reserved, ios_jit_low_size_global, ios_jit_low_reserved,
        ios_jit_hole_off_eff, ios_jit_hole_end_eff, ios_jit_hole2_off, ios_jit_hole2_end };
    char rx_before[5], rw_before[5], rx_after[5], rw_after[5];
    permissions(ios_jit_rx_base_global, rx_before); permissions(rw_alias, rw_before);
    ios_pool_account_snapshot(&s);
    assert(s.valid_records == 14 && !s.invalid_records && !s.invalid_geometry);
    assert(sum(&s, 0) == 36 * MB && sum(&s, 1) == 20 * MB);
    assert(s.main_head_highwater == 48 * MB && s.main_holes == 4 * MB && !s.main_virgin && s.c_virgin == 12 * MB);
    assert(owner_row(&s, peb(1), 0)->bytes[0][IOS_ACCOUNT_IMAGE] == 4 * MB);
    assert(owner_row(&s, peb(1), 0)->bytes[1][IOS_ACCOUNT_IMAGE] == 4 * MB);
    assert(owner_row(&s, peb(1), 11)->bytes[0][IOS_ACCOUNT_CODE_ALLOCATED] == 4 * MB);
    assert(owner_row(&s, peb(1), 11)->bytes[0][IOS_ACCOUNT_CODE_FREE] == 4 * MB);
    assert(owner_row(&s, peb(1), 31)->bytes[1][IOS_ACCOUNT_CODE_ALLOCATED] == 4 * MB);
    assert(owner_row(&s, NULL, 21)->bytes[0][IOS_ACCOUNT_CODE_RETIRED] == 4 * MB);
    assert(owner_row(&s, NULL, 21)->bytes[1][IOS_ACCOUNT_CODE_RETIRED] == 4 * MB);
    assert(owner_row(&s, NULL, 22)->bytes[0][IOS_ACCOUNT_CODE_UNPROVED] == 4 * MB);
    assert(owner_row(&s, peb(1), 24)->bytes[0][IOS_ACCOUNT_CODE_UNPROVED] == 4 * MB);
    assert(s.bytes[0][IOS_ACCOUNT_IMAGE_FREE] == 4 * MB && s.bytes[0][IOS_ACCOUNT_IMAGE_POISON] == 4 * MB);
    ios_pool_failure_census(6 * MB);
    assert(strstr(output, "image_generation=unknown") && strstr(output, "physical_bytes=unknown"));
    assert(strstr(output, "aliases=shared_backing") && strstr(output, "allocation_lease=21"));
    assert(strstr(output, "snapshot=post_failure_serialized") && strstr(output, "reuse_eligibility=unchecked"));
    size_t before_length = output_length;
    ios_pool_failure_census(6 * MB); assert(output_length == before_length);
    permissions(ios_jit_rx_base_global, rx_after); permissions(rw_alias, rw_after);
    assert(!memcmp(rx_before, rx_after, 5) && !memcmp(rw_before, rw_after, 5));
    assert(!memcmp(ledger_before, ios_pool_ledger, sizeof ledger_before));
    assert(!memcmp(free_before, ios_pool_freelist, sizeof free_before));
    assert(!memcmp(carve_before, ios_tail_carves, sizeof carve_before));
    size_t geometry_after[] = { (size_t)ios_pool_ledger_count, (size_t)ios_pool_free_count, ios_tail_carve_n,
        ios_jit_pool_size_global, jit_pool_offset, ios_jit_tail_reserved, ios_jit_low_size_global, ios_jit_low_reserved,
        ios_jit_hole_off_eff, ios_jit_hole_end_eff, ios_jit_hole2_off, ios_jit_hole2_end };
    assert(!memcmp(geometry_before, geometry_after, sizeof geometry_before));
    assert(((unsigned char *)ios_jit_rx_base_global)[123] == 0xa5 && ((unsigned char *)rw_alias)[123] == 0xa5);
    image(2 * MB, 4 * MB, peb(99));
    ios_pool_account_snapshot(&s);
    assert(sum(&s, 0) == 36 * MB && s.bytes[0][IOS_ACCOUNT_OVERLAP] == 4 * MB);
    assert(s.bytes[0][IOS_ACCOUNT_IMAGE] == 6 * MB && s.bytes[0][IOS_ACCOUNT_CODE_ALLOCATED] == 2 * MB);
}
static void bounds_and_owners(void)
{
    struct ios_pool_account_snapshot s;
    reset();
    image(64 * MB - 1, 2, peb(1)); image(c_off(32 * MB - 1), 2, peb(1));
    image(32 * MB, MB, peb(1)); image(0, 0, peb(1));
    ios_pool_account_snapshot(&s); assert(s.invalid_records == 4 && !s.valid_records && !sum(&s, 0));
    reset(); image(0, MB, peb(1));
    jit_pool_offset = 65 * MB; ios_jit_low_reserved = 33 * MB;
    ios_pool_account_snapshot(&s); assert(!s.main_virgin && !s.c_virgin);
    ios_jit_hole_end_eff = 65 * MB;
    ios_pool_account_snapshot(&s); assert(s.invalid_geometry && s.invalid_records == 1);
    reset(); image(0, MB, peb(1)); ios_jit_low_rx_global = (uintptr_t)ios_jit_rx_base_global;
    ios_pool_account_snapshot(&s); assert(s.invalid_geometry && !s.valid_records);
    reset(); ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    for (unsigned i = 0; i < 64; i++) image(i * 0x4000, 0x4000, peb(i));
    image(64 * 0x4000, 0x4000, peb(63));
    ios_pool_account_snapshot(&s);
    assert(s.owner_count == 32 && s.omitted_owners == 32);
    assert(s.omitted.bytes[0][IOS_ACCOUNT_IMAGE] == 33 * 0x4000);
    output_length = 0; output_lines = 0;
    ios_pool_failure_accounting_report(7 * MB);
    assert(output_lines == 34 && strstr(output, "group=omitted_aggregate"));
    assert(strstr(output, "omitted_owners=32"));
    uintptr_t lo, hi; unsigned region;
    assert(ios_pool_account_range(0, 4, UINTPTR_MAX - 4, 4, 0, 0, &region, &lo, &hi) && hi == UINTPTR_MAX);
    ios_pool_account_collect(&s, ios_pool_ledger, 1, ios_pool_freelist, 0, ios_tail_carves, 0,
        UINTPTR_MAX - 0x4000, 0x4000, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(sum(&s, 0) == 0x4000); /* a valid last endpoint must not be mistaken for a sentinel */
}
static void *writer(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 500; i++)
    {
        pthread_mutex_lock(&ios_tail_carve_lock); pthread_mutex_lock(&ios_pool_lock);
        ios_pool_ledger[0].peb = ios_pool_ledger[1].peb = peb(i & 1);
        ios_pool_ledger[0].size = (i & 1 ? 2 : 4) * MB;
        ios_pool_ledger[1].size = (i & 1 ? 4 : 2) * MB;
        pthread_mutex_unlock(&ios_pool_lock); pthread_mutex_unlock(&ios_tail_carve_lock);
    }
    return NULL;
}
static void maximum_bounds(void)
{
    struct ios_pool_account_snapshot s;
    reset(); ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    ios_pool_ledger_count = IOS_POOL_LEDGER_MAX;
    ios_pool_free_count = IOS_POOL_FREE_MAX;
    ios_tail_carve_n = IOS_TAIL_CARVE_MAX;
    for (unsigned i = 0; i < IOS_POOL_LEDGER_MAX; i++)
    { ios_pool_ledger[i].off = i * 0x4000; ios_pool_ledger[i].size = 0x4000; ios_pool_ledger[i].peb = peb(i % 64); }
    for (unsigned i = 0; i < IOS_POOL_FREE_MAX; i++)
    { ios_pool_freelist[i].off = 16 * MB + i * 0x4000; ios_pool_freelist[i].size = 0x4000; }
    for (unsigned i = 0; i < IOS_TAIL_CARVE_MAX; i++)
    { ios_tail_carves[i].off = 32 * MB + i * 0x4000; ios_tail_carves[i].size = 0x4000; }
    ios_pool_account_snapshot(&s);
    assert(s.valid_records == IOS_POOL_ACCOUNT_RANGE_MAX && !s.invalid_records && sum(&s, 0) == 36 * MB);
    assert(s.owner_count == IOS_POOL_ACCOUNT_OWNER_MAX);
    memset(ios_pool_ledger, 0, sizeof ios_pool_ledger);
    memset(ios_pool_freelist, 0, sizeof ios_pool_freelist);
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    ios_pool_account_collect(&s, ios_pool_ledger, UINT_MAX, ios_pool_freelist, UINT_MAX, ios_tail_carves, UINT_MAX,
        (uintptr_t)ios_jit_rx_base_global, 64 * MB, 48 * MB, 16 * MB, 0, 0, 0, 0, 0, 0, 0);
    assert(!s.valid_records && s.invalid_records == (size_t)UINT_MAX * 3);
    ios_pool_account_collect(&s, ios_pool_ledger, 1, ios_pool_freelist, 0, ios_tail_carves, 0,
        (uintptr_t)ios_jit_rx_base_global, SIZE_MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(s.invalid_geometry && s.invalid_records == 1);
}
static void concurrency(void)
{
    reset(); ios_jit_hole_off_eff = ios_jit_hole_end_eff = 0;
    image(0, 4 * MB, peb(0)); image(8 * MB, 2 * MB, peb(0));
    pthread_t worker; assert(!pthread_create(&worker, NULL, writer, NULL));
    for (unsigned i = 0; i < 500; i++)
    {
        struct ios_pool_account_snapshot s;
        ios_pool_account_snapshot(&s);
        assert(s.owner_count == 1 && !s.invalid_records && !s.omitted_owners);
        assert(s.bytes[0][IOS_ACCOUNT_IMAGE] == 6 * MB);
        assert(s.owners[0].bytes[0][IOS_ACCOUNT_IMAGE] == 6 * MB);
    }
    assert(!pthread_join(worker, NULL));
    assert(accounting_lock_pairs >= 500 && !accounting_held);
}
int main(void)
{
    FILE *backing = tmpfile(); assert(backing && !ftruncate(fileno(backing), 64 * MB));
    rw_alias = mmap(NULL, 64 * MB, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(backing), 0);
    ios_jit_rx_base_global = mmap(NULL, 64 * MB, PROT_READ | PROT_EXEC, MAP_SHARED, fileno(backing), 0);
    assert(rw_alias != MAP_FAILED && ios_jit_rx_base_global != MAP_FAILED);
    ((unsigned char *)rw_alias)[123] = 0xa5;
    classifications(); bounds_and_owners(); maximum_bounds(); concurrency();
    assert(!munmap(ios_jit_rx_base_global, 64 * MB) && !munmap(rw_alias, 64 * MB)); fclose(backing);
    puts("PASS: production owner accounting, leases, region C, poison, overlap union, bounds, owner cap, shared aliases/protections, serialized snapshots");
}
'''

with tempfile.TemporaryDirectory(prefix='pool-owner-accounting-') as directory:
    temp = Path(directory)
    for compiler, standard, suffix in ((os.environ.get('CC', 'cc'), 'c11', 'c'),
                                       (os.environ.get('CXX', 'c++'), 'c++17', 'cpp')):
        unit = temp / ('test.' + suffix)
        unit.write_text(fixture)
        exe = temp / ('test-' + suffix)
        subprocess.run([compiler, '-std=' + standard, '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        str(unit), '-pthread', '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
