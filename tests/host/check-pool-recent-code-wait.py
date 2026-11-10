#!/usr/bin/env python3
"""Bounded grace waits exercise production receipt and code-reuse functions.

Reuse the existing native fixture without running its historical scenarios.
Only clock, sleep and thread-state answers are supplied here; selection,
retirement identity, grace and code handout remain production code.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
shared = root / 'tests/host/check-pool-code-exit.py'
text = shared.read_text()
context = {'__file__': str(shared)}
exec(text[:text.index("with tempfile.TemporaryDirectory(prefix='madeira-pool-code-exit-')")], context)
code = context['fixture']
helper = context['function']('static unsigned ios_pool_recent_retired_code_wait(')
assert code.count(helper) == 1
wrapper = r'''
static int disable_wait;
static unsigned ios_pool_recent_retired_code_wait(const struct ios_tail_carve *c, unsigned n,
                                                  size_t want, size_t total, time_t now, int guarded)
{ return disable_wait ? 0 : production_recent_wait(c,n,want,total,now,guarded); }
'''
code = code.replace(helper, helper.replace('ios_pool_recent_retired_code_wait(', 'production_recent_wait(', 1) + wrapper)
code = code.replace('#include <stdint.h>', '#include <stdint.h>\n#include <errno.h>', 1)
code = code.replace('#define time(t) fake_time(t)', r'''
#define time(t) fake_time(t)
static unsigned sleep_count, sleep_ms;
static int sleep_mode;
static pthread_mutex_t ios_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static int test_nanosleep(const struct timespec *, struct timespec *);
#define nanosleep test_nanosleep
''', 1)
code = code[:code.index('int main(void)\n{')]
code += r'''
static int test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)remaining;
    CHECK(request->tv_sec == 0 && request->tv_nsec == 100000000);
    CHECK(!pthread_mutex_trylock(&ios_tail_carve_lock));
    CHECK(!pthread_mutex_unlock(&ios_tail_carve_lock));
    CHECK(!pthread_mutex_trylock(&ios_pool_lock));
    CHECK(!pthread_mutex_unlock(&ios_pool_lock));
    CHECK(++sleep_count <= 30);
    if (sleep_mode == 1)
    {
        /* A competing owner takes this existing allocation while we sleep. */
        ios_tail_carves[0].free = ios_tail_carves[0].retired = 0;
        ios_tail_carves[0].peb = (void *)99;
        ios_tail_carves[0].allocation_lease = 99;
        ios_tail_carves[0].retired_lease = 0;
    }
    if (sleep_mode == 2) { errno = EINTR; return -1; } /* stalled/backwards clock */
    sleep_ms += 100;
    if (sleep_ms >= 1000) { fake_now += sleep_ms / 1000; sleep_ms %= 1000; }
    return 0;
}

static void setup(void)
{
    reset();
    ios_jit_low_size_global = 0;
    ios_jit_tail_reserved = 128*MB;
    jit_pool_offset = 16*MB;
    ios_tail_carves[0] = (struct ios_tail_carve){.off=0x30000000, .size=16*MB,
        .free=1, .retired=1, .allocation_lease=70, .retired_lease=70, .freed_at=98};
    ios_tail_carve_n = 1;
    owner = 9; fake_now = 100;
    disable_wait = sleep_mode = sleep_count = sleep_ms = 0;
}

static void helper_guards(void)
{
    setup();
    struct ios_tail_carve c = ios_tail_carves[0], saved;
    CHECK(production_recent_wait(&c,1,16*MB,ios_jit_pool_size_global,100,0) == 1);
    CHECK(production_recent_wait(&c,1,16*MB,ios_jit_pool_size_global,99,0) == 2);
    CHECK(production_recent_wait(&c,1,16*MB,ios_jit_pool_size_global,98,0) == 3);
    CHECK(!production_recent_wait(&c,1,16*MB,ios_jit_pool_size_global,101,0));
    CHECK(!production_recent_wait(&c,1,0x4000,ios_jit_pool_size_global,100,0));
    CHECK(!production_recent_wait(&c,1,32*MB,ios_jit_pool_size_global,100,0));
    CHECK(!production_recent_wait(NULL,1,16*MB,ios_jit_pool_size_global,100,0));
    CHECK(!production_recent_wait(&c,IOS_TAIL_CARVE_MAX+1,16*MB,ios_jit_pool_size_global,100,0));
    CHECK(!production_recent_wait(&c,1,16*MB,0,100,0));
    saved = c;
    for (unsigned kind = 0; kind < 11; ++kind)
    {
        c = saved;
        if (!kind) c.free = 0;
        else if (kind == 1) c.retired = 0;
        else if (kind == 2) c.allocation_lease = 0;
        else if (kind == 3) c.retired_lease = 71;
        else if (kind == 4) c.freed_at = 0;
        else if (kind == 5) c.freed_at = 101;
        else if (kind == 6) c.off++;
        else if (kind == 7) c.off = ios_jit_pool_size_global;
        else if (kind == 8) c.off = ios_jit_pool_size_global-8*MB;
        else if (kind == 9) c.size = 32*MB;
        else c.off = SIZE_MAX-0x3fff; /* wrapping region-C offset */
        struct ios_tail_carve untouched;
        memcpy(&untouched,&c,sizeof(c));
        CHECK(!production_recent_wait(&c,1,16*MB,ios_jit_pool_size_global,100,0));
        CHECK(!memcmp(&c,&untouched,sizeof(c)));
    }
    puts("PASS: only matching, recent, exact16MiB main receipts justify waiting; active, stale, future, invalid and larger classes do not");
}

static void baseline_and_wait(void)
{
    void *rx = NULL; size_t want = 16*MB;
    setup(); disable_wait = 1;
    struct ios_tail_carve before;
    memcpy(&before,&ios_tail_carves[0],sizeof(before));
    CHECK(allocate(&want,&rx) == FALLBACK_TAIL && !sleep_count && !scans);
    CHECK(!memcmp(&before,&ios_tail_carves[0],sizeof(before)));
    setup(); want = 16*MB;
    size_t head = jit_pool_offset, tail = ios_jit_tail_reserved;
    CHECK(allocate(&want,&rx) == STATUS_SUCCESS && off_of(rx) == 0x30000000 && want == 16*MB);
    CHECK(sleep_count == 10 && fake_now == 101 && scans == 1);
    CHECK(jit_pool_offset == head && ios_jit_tail_reserved == tail);
    CHECK(!ios_tail_carves[0].free && !ios_tail_carves[0].retired &&
          ios_tail_carves[0].peb == (void *)9 && ios_tail_carves[0].allocation_lease == 9 &&
          !ios_tail_carves[0].retired_lease);
    CHECK(*(uint32_t *)rx == 0xd503201fu && *(uint32_t *)((char *)rx+16*MB-4) == 0xd503201fu);
    puts("PASS: old wait-disabled control grows fresh; production sleeps unlocked until unchanged grace and strict scan permit existing16MiB reuse");
}

static void refusal_and_contention(void)
{
    for (unsigned kind = 0; kind < 6; ++kind)
    {
        setup();
        if (!kind) ios_tail_carves[0].free = 0;
        else if (kind == 1) ios_tail_carves[0].retired_lease = 0;
        else if (kind == 2) ios_tail_carves[0].retired_lease = 71;
        else if (kind == 3) ios_tail_carves[0].freed_at = 101;
        else if (kind == 4) ios_tail_carves[0].size = 32*MB;
        else { ios_jit_low_size_global = 0x71d0000; ios_jit_low_reserved = ios_jit_low_size_global; }
        void *rx = NULL; size_t want = 16*MB;
        CHECK(allocate(&want,&rx) == FALLBACK_TAIL && !sleep_count && !scans);
    }
    setup(); ios_tail_carves[0].retired = 0;
    void *rx = NULL; size_t want = 16*MB;
    CHECK(allocate(&want,&rx) == STATUS_SUCCESS && !sleep_count); /* normal ordinary reuse */
    setup(); sleep_mode = 1; want = 16*MB;
    CHECK(allocate(&want,&rx) == FALLBACK_TAIL && sleep_count == 1 && !scans);
    CHECK(ios_tail_carves[0].peb == (void *)99 && !ios_tail_carves[0].free);
    setup(); sleep_mode = 2; want = 16*MB;
    CHECK(allocate(&want,&rx) == FALLBACK_TAIL && sleep_count == 30 && !scans && fake_now == 100);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].retired);
    setup(); scan_busy = 1; want = 16*MB;
    CHECK(allocate(&want,&rx) == FALLBACK_TAIL && sleep_count == 10 && scans == 1);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].freed_at == 101); /* strict guard retained */
    setup(); fake_now = 101; scan_busy = 1; want = 16*MB;
    CHECK(allocate(&want,&rx) == FALLBACK_TAIL && !sleep_count && scans == 1);
    puts("PASS: no wait for unproved or ordinary-ready carves; concurrent theft, stalled/EINTR clock and busy-PC results retain bounded original fallback");
}

int main(void)
{
    void *memory = NULL;
    CHECK(!posix_memalign(&memory,0x4000,0x38000000));
    pool = memory; low = pool+0x38000000;
    helper_guards();
    baseline_and_wait();
    refusal_and_contention();
    free(memory);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pool-recent-code-wait-') as directory:
    path, executable = Path(directory) / 'test.c', Path(directory) / 'test'
    path.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                    '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-fno-omit-frame-pointer', '-pthread', str(path), '-o', str(executable)], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=15)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
    result.check_returncode()
