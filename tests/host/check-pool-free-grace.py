#!/usr/bin/env python3
"""Coalescing pool ranges must retain every constituent's reuse grace.

Compile the production free-list merge and best-fit helpers. The old control
omits only the timestamp maximum; no pool capacity or device-success claim is
made. Both main-pool and wrapping region-C offsets use the same merge helper.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/virtual_ios.c').read_text()


def body(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


start = source.index('struct ios_pool_free\n{')
record = source[start:source.index('\n};', start) + 3]
merge = body('static int ios_pool_free_put(')
update = '            if (fl[i].freed_at > now) now = fl[i].freed_at;\n'
assert merge.count(update) <= 1
baseline = merge.replace(update, '').replace('ios_pool_free_put(', 'baseline_free_put(', 1)
for caller in ('static int ios_pool_recycle_main_code_range(', 'static int ios_pool_recycle_code_range('):
    assert 'off, size, freed_at, ios_pool_range_clean' in body(caller), caller

code = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MB ((size_t)1 << 20)
#define IOS_POOL_REUSE_GRACE_SEC 3
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
''' + record + r'''
typedef int (*ios_pool_clean_fn)(size_t, size_t);
static size_t poisoned_off = SIZE_MAX;
static unsigned clean_calls;
static int clean(size_t off, size_t size)
{ CHECK(size); clean_calls++; return off != poisoned_off; }
''' + merge + baseline + body('static int ios_pool_best_fit(') + r'''

static void recent_image_neighbour(void)
{
    struct ios_pool_free old[2] = {{MB, MB, 99, 1, 17}}, current[2];
    int old_n = 1, current_n = 1;
    memcpy(current, old, sizeof(old));
    CHECK(baseline_free_put(old, &old_n, 2, 2*MB, MB, 90, clean));
    CHECK(old_n == 1 && old[0].freed_at == 90);
    CHECK(ios_pool_best_fit(old, old_n, 2*MB, 100, SIZE_MAX, 0) == 0);
    CHECK(ios_pool_free_put(current, &current_n, 2, 2*MB, MB, 90, clean));
    CHECK(current_n == 1 && current[0].off == MB && current[0].size == 2*MB);
    CHECK(current[0].freed_at == 99); /* production must not backdate image grace */
    CHECK(!current[0].advised && !current[0].tag);
    CHECK(ios_pool_best_fit(current, current_n, 2*MB, 100, SIZE_MAX, 0) == -1);
    CHECK(ios_pool_best_fit(current, current_n, 2*MB, 101, SIZE_MAX, 0) == -1);
    CHECK(ios_pool_best_fit(current, current_n, 2*MB, 102, SIZE_MAX, 0) == 0);
    puts("PASS: old merge backdates a recent image; production preserves its full three-second grace");
}

static void newest_insert_and_future_neighbour(void)
{
    struct ios_pool_free fl[2] = {{0, MB, 90, 0, 0}};
    int n = 1;
    CHECK(ios_pool_free_put(fl, &n, 2, MB, MB, 99, clean));
    CHECK(n == 1 && fl[0].freed_at == 99);
    fl[0] = (struct ios_pool_free){0, MB, 150, 0, 0}; n = 1;
    CHECK(ios_pool_free_put(fl, &n, 2, MB, MB, 90, clean));
    CHECK(n == 1 && fl[0].freed_at == 150);
    CHECK(ios_pool_best_fit(fl, n, 2*MB, 100, SIZE_MAX, 0) == -1);
    CHECK(ios_pool_best_fit(fl, n, 2*MB, 152, SIZE_MAX, 0) == -1);
    CHECK(ios_pool_best_fit(fl, n, 2*MB, 153, SIZE_MAX, 0) == 0);
    puts("PASS: newer insertions and future timestamps retain the latest constituent's grace");
}

static void transitive_merge(void)
{
    const struct ios_pool_free pieces[3] = {
        {0, MB, 105, 1, 1}, {2*MB, MB, 97, 0, 2}, {3*MB, MB, 99, 1, 3}
    };
    for (unsigned a = 0; a < 3; ++a)
        for (unsigned b = 0; b < 3; ++b)
        {
            if (a == b) continue;
            unsigned c = 3-a-b;
            struct ios_pool_free fl[5] = {pieces[a], pieces[b], pieces[c], {10*MB, MB, 500, 1, 9}};
            int n = 4;
            CHECK(ios_pool_free_put(fl, &n, 5, MB, MB, 90, clean));
            CHECK(n == 2);
            int merged = fl[0].off == 0 ? 0 : 1, other = !merged;
            CHECK(fl[merged].size == 4*MB && fl[merged].freed_at == 105);
            CHECK(!fl[merged].advised && !fl[merged].tag);
            CHECK(fl[other].off == 10*MB && fl[other].freed_at == 500 &&
                  fl[other].advised && fl[other].tag == 9);
            CHECK(ios_pool_best_fit(fl, n, 4*MB, 107, SIZE_MAX, 0) == -1);
            CHECK(ios_pool_best_fit(fl, n, 4*MB, 108, SIZE_MAX, 0) == merged);
        }
    puts("PASS: all neighbour orders retain the newest timestamp through transitive coalescing");
}

static void poison_and_capacity(void)
{
    struct ios_pool_free fl[3] = {{0, MB, 200, 1, 19}, {2*MB, MB, 97, 0, 0}};
    int n = 2;
    poisoned_off = 0;
    CHECK(ios_pool_free_put(fl, &n, 3, MB, MB, 90, clean));
    CHECK(n == 2);
    int poison = fl[0].off == 0 ? 0 : 1, merged = !poison;
    CHECK(fl[poison].size == MB && fl[poison].freed_at == 200 && fl[poison].advised && fl[poison].tag == 19);
    CHECK(fl[merged].off == MB && fl[merged].size == 2*MB && fl[merged].freed_at == 97);
    poisoned_off = SIZE_MAX;
    fl[0] = (struct ios_pool_free){0, MB, 99, 1, 17}; n = 1;
    struct ios_pool_free saved; memcpy(&saved, fl, sizeof(saved));
    CHECK(!ios_pool_free_put(fl, &n, 1, 2*MB, MB, 90, clean));
    CHECK(n == 1 && !memcmp(fl, &saved, sizeof(saved)));
    CHECK(ios_pool_free_put(fl, &n, 1, MB, MB, 90, clean));
    CHECK(n == 1 && fl[0].size == 2*MB && fl[0].freed_at == 99);
    puts("PASS: poisoned neighbours and full-list refusal retain their existing metadata semantics");
}

static void region_c_offset(void)
{
    size_t off = (size_t)0 - (size_t)0x100000000ULL;
    struct ios_pool_free fl[2] = {{off, 16*MB, 99, 0, 0}};
    int n = 1;
    CHECK(ios_pool_free_put(fl, &n, 2, off + 16*MB, 16*MB, 90, clean));
    CHECK(n == 1 && fl[0].off == off && fl[0].size == 32*MB && fl[0].freed_at == 99);
    CHECK(ios_pool_best_fit(fl, n, 32*MB, 100, SIZE_MAX, 0) == -1);
    CHECK(ios_pool_best_fit(fl, n, 32*MB, 102, SIZE_MAX, 0) == 0);
    puts("PASS: region-C wrapping offsets use the same timestamp-preserving transfer helper");
}

int main(void)
{
    recent_image_neighbour();
    newest_insert_and_future_neighbour();
    transitive_merge();
    poison_and_capacity();
    region_c_offset();
    CHECK(clean_calls);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pool-free-grace-') as directory:
    path, executable = Path(directory) / 'test.c', Path(directory) / 'test'
    path.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(path), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
