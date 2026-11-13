#!/usr/bin/env python3
"""Actual old/new swap cores: decommit zeroing without an APFS wait under VM lock.

The data, mappings and hole punches are real owned sparse-file operations. Only
the native-call delay/failures are injected; these are controlled host tests,
not measurements of iPhone loading speed or APFS latency.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASELINE = 'fd6b7c03564c2ca15ccb6cdba68083676928f318'
OLD_RESV = r'''static int ios_swap_punch_resv( char *lo, size_t len )
{
    unsigned i;
    if (ios_swap_fd < 0 || !ios_swap_n) return 0;
    for (i = 0; i < ios_swap_n; i++)
    {
        char *a = ios_swap_ext[i].va;
        if (!ios_swap_ext[i].resv || lo < a || lo + len > a + ios_swap_ext[i].len) continue;
        msync( lo, len, MS_KILLPAGES );   /* ml1293: drop the dead dirty pages before the punch */
        if (ios_swap_punch_timed( ios_swap_ext[i].off + (lo - a), len, "decommit" ))   /* ml1291: timed */
        {
            static int said;
            if (said++ < 8) dprintf( 2, "[swap] ml1257 hole %p+0x%zx failed errno=%d: releasing instead\n", lo, len, errno );
            return 0;
        }
        mprotect( lo, len, PROT_READ | PROT_WRITE );
        if (++ios_swap_holes <= 8 || (ios_swap_holes % 1024) == 0)
            dprintf( 2, "[swap] ml1257 decommit %p+0x%zx punched in place (%llu holes)\n", lo, len, ios_swap_holes );
        return 1;
    }
    return 0;
}'''
# Verbatim production function at BASELINE; independent of shallow CI history.
assert hashlib.sha256(OLD_RESV.encode()).hexdigest() == 'a7b0424929211b15da0917ecfb8406a6941a23f129127b77b86da85b6409addf'
coverage = ROOT / 'tests/host/check-swap-coverage.py'
namespace = {'__file__': str(coverage)}
exec(compile(coverage.read_text().split("\nharness = r'''", 1)[0], str(coverage), 'exec'), namespace)
prelude = namespace['prelude']

INJECT = r'''
#ifdef fcntl
#undef fcntl
#endif
static pthread_mutex_t injection_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t injection_cond = PTHREAD_COND_INITIALIZER;
static int punch_block, punch_entered, punch_release, punch_fail, create_fail, fixed_fail, discard_fail;
static unsigned punch_calls, fixed_calls, create_calls, discard_calls;

static int native_punch( int fd, int cmd, struct fpunchhole *ph )
{
#ifdef __linux__
    (void)cmd;
    return fallocate( fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, ph->fp_offset, ph->fp_length );
#else
    return fcntl( fd, cmd, ph );
#endif
}
static int injected_fcntl( int fd, int cmd, struct fpunchhole *ph )
{
    int fail;
    pthread_mutex_lock( &injection_lock );
    punch_calls++;
    if (punch_block)
    {
        punch_entered = 1;
        pthread_cond_broadcast( &injection_cond );
        while (!punch_release) pthread_cond_wait( &injection_cond, &injection_lock );
    }
    fail = punch_fail;
    if (punch_fail) punch_fail--;
    pthread_mutex_unlock( &injection_lock );
    if (fail) { errno = EIO; return -1; }
    return native_punch( fd, cmd, ph );
}
static int injected_create( pthread_t *thread, const pthread_attr_t *attr,
                            void *(*entry)(void *), void *arg )
{
    create_calls++;
    return create_fail ? EAGAIN : pthread_create( thread, attr, entry, arg );
}
static void *injected_mmap( void *addr, size_t len, int prot, int flags, int fd, off_t off )
{
    if ((flags & MAP_FIXED) && fd >= 0)
    {
        fixed_calls++;
        if (fixed_fail) { fixed_fail--; errno = ENOMEM; return MAP_FAILED; }
    }
    return mmap( addr, len, prot, flags, fd, off );
}
static int injected_msync( void *addr, size_t len, int flags )
{
    if (flags == MS_KILLPAGES)
    {
        discard_calls++;
        if (discard_fail) { discard_fail--; errno = EIO; return -1; }
    }
    return msync(addr, len, flags);
}
#define fcntl(fd, cmd, ph) injected_fcntl(fd, cmd, ph)
#define pthread_create(thread, attr, entry, arg) injected_create(thread, attr, entry, arg)
#define mmap(addr, len, prot, flags, fd, off) injected_mmap(addr, len, prot, flags, fd, off)
#define msync(addr, len, flags) injected_msync(addr, len, flags)
'''

HARNESS = r'''
#undef fcntl
#undef pthread_create
#undef mmap
#undef msync
static unsigned long long ios_swap_footprint_mb( void ) { return 4321; }
static void ios_swap_cfg( int *mode, int *min_mb ) { *mode = 1; *min_mb = 0; }
static unsigned long long ios_swap_disk_used( void ) { return 0; }
static int bad;
#define CHECK(c, text) do { if (!(c)) { fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, text); bad++; } } while (0)
#define MUST(c) do { if (!(c)) { perror(#c); exit(3); } } while (0)
#define P 0x4000u
#define FILE_BYTES (32u << 20)
static char *region;
static size_t region_bytes;
static uint64_t original_off;

static int zeroes( const void *data, size_t bytes )
{
    const unsigned char *p = data;
    while (bytes--) if (*p++) return 0;
    return 1;
}
static int all_value( const void *data, size_t bytes, unsigned char value )
{
    const unsigned char *p = data;
    while (bytes--) if (*p++ != value) return 0;
    return 1;
}
static void setup( unsigned pages )
{
    char name[] = "/tmp/madeira-decommit-remap-XXXXXX";
    int fd = mkstemp( name );
    char *whole;
    uintptr_t aligned;
    MUST(fd >= 0);
    unlink( name );
    MUST(!ftruncate(fd, FILE_BYTES));
    ios_swap_fd = fd;
    ios_swap_cap = ios_swap_logical = FILE_BYTES;
    ios_swap_v2 = ios_swap_wide = 1;
    ios_swap_broad = 0;
    ios_swap_min = P;
    region_bytes = pages * P;
    whole = mmap( NULL, region_bytes + P, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
    MUST(whole != MAP_FAILED);
    aligned = ((uintptr_t)whole + P - 1) & ~(uintptr_t)(P - 1);
    if ((char *)aligned > whole) MUST(!munmap(whole, (char *)aligned - whole));
    if ((char *)aligned + region_bytes < whole + region_bytes + P)
        MUST(!munmap((char *)aligned + region_bytes,
                     whole + region_bytes + P - ((char *)aligned + region_bytes)));
    region = (char *)aligned;
    MUST(ios_swap_map(region, region_bytes, PROT_READ | PROT_WRITE) == IOS_SW_BACKED);
    ios_swap_ext[0].resv = 1;
    ios_swap_ext[0].key = region_bytes;
    ios_swap_ext[0].born = 12345;
    original_off = ios_swap_ext[0].off;
    memset(region, 0x33, region_bytes);
    memset(region, 0x11, 2 * P);
    memset(region + region_bytes - 2 * P, 0x77, 2 * P);
    MUST(!msync(region, region_bytes, MS_SYNC));
    unsetenv("MADEIRA_SWAP_PUNCH_DEFER");
}
static int run_decommit( char *start, size_t bytes )
{
    int result;
    pthread_mutex_lock(&virtual_mutex);
    result = ios_swap_punch_resv(start, bytes);
    pthread_mutex_unlock(&virtual_mutex);
    return result;
}
static void wait_done( unsigned long long target )
{
    unsigned i;
    for (i = 0; i < 5000; i++)
    {
        int done;
        pthread_mutex_lock(&virtual_mutex);
        done = ios_swap_pq_done >= target;
        pthread_mutex_unlock(&virtual_mutex);
        if (done) return;
        usleep(1000);
    }
    CHECK(0, "deferred punch did not finish after released test barrier");
}
static int free_overlaps( uint64_t off, uint64_t bytes )
{
    unsigned i;
    for (i = 0; i < ios_swap_nfree; i++)
        if (off < ios_swap_free[i].off + ios_swap_free[i].len && off + bytes > ios_swap_free[i].off) return 1;
    return 0;
}
static uint64_t offset_at( char *addr )
{
    unsigned i;
    for (i = 0; i < ios_swap_n; i++)
        if (addr >= ios_swap_ext[i].va && addr < ios_swap_ext[i].va + ios_swap_ext[i].len)
            return ios_swap_ext[i].off + (addr - ios_swap_ext[i].va);
    return UINT64_MAX;
}
static void check_live_layout( void )
{
    unsigned i, j;
    size_t total = 0;
    for (i = 0; i < ios_swap_n; i++)
    {
        total += ios_swap_ext[i].len;
        CHECK(ios_swap_ext[i].resv && !ios_swap_ext[i].img &&
              ios_swap_ext[i].key == region_bytes && ios_swap_ext[i].born == 12345,
              "reservation provenance preserved across replacement/splits");
        CHECK(!((uintptr_t)ios_swap_ext[i].va & (P-1)) && !(ios_swap_ext[i].len & (P-1)) &&
              !(ios_swap_ext[i].off & (P-1)), "host-page aligned extent");
        CHECK(!free_overlaps(ios_swap_ext[i].off, ios_swap_ext[i].len), "live file offsets cannot also be free");
        for (j = 0; j < i; j++)
        {
            CHECK(!(ios_swap_ext[i].va < ios_swap_ext[j].va + ios_swap_ext[j].len &&
                    ios_swap_ext[i].va + ios_swap_ext[i].len > ios_swap_ext[j].va), "live VA extents disjoint");
            CHECK(!(ios_swap_ext[i].off < ios_swap_ext[j].off + ios_swap_ext[j].len &&
                    ios_swap_ext[i].off + ios_swap_ext[i].len > ios_swap_ext[j].off), "live file offsets disjoint");
        }
    }
    CHECK(total == region_bytes && ios_swap_bytes == region_bytes && ios_swap_peak == region_bytes,
          "replacement adds no live backing capacity or peak capacity");
    for (i = 0; i < region_bytes / P; i++) CHECK(offset_at(region + i * P) != UINT64_MAX, "reservation coverage survives");
}
static pthread_mutex_t caller_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t caller_cond = PTHREAD_COND_INITIALIZER;
static int caller_done, caller_result;
static void *decommit_caller( void *unused )
{
    (void)unused;
    int result = run_decommit(region + 2 * P, 4 * P);
    pthread_mutex_lock(&caller_lock);
    caller_result = result;
    caller_done = 1;
    pthread_cond_broadcast(&caller_cond);
    pthread_mutex_unlock(&caller_lock);
    return NULL;
}
static void wait_barrier( void )
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 3;
    pthread_mutex_lock(&injection_lock);
    while (!punch_entered)
    {
        int result = pthread_cond_timedwait(&injection_cond, &injection_lock, &deadline);
        MUST(result != ETIMEDOUT);
    }
    pthread_mutex_unlock(&injection_lock);
}
static void test_blocked( void )
{
    pthread_t caller;
    int lock_result;
    unsigned char old_bytes[64];
    setup(8);
    punch_block = 1;
    MUST(!pthread_create(&caller, NULL, decommit_caller, NULL));
    wait_barrier();
#ifdef BASELINE_OLD
    lock_result = pthread_mutex_trylock(&virtual_mutex);
    CHECK(lock_result == EBUSY, "old production decommit holds VM lock during blocked native punch");
    if (!lock_result) pthread_mutex_unlock(&virtual_mutex);
    pthread_mutex_lock(&caller_lock);
    CHECK(!caller_done, "old production caller cannot return before native punch");
    pthread_mutex_unlock(&caller_lock);
#else
    {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 3;
        pthread_mutex_lock(&caller_lock);
        while (!caller_done)
        {
            if (pthread_cond_timedwait(&caller_cond, &caller_lock, &deadline) == ETIMEDOUT) break;
        }
        CHECK(caller_done && caller_result, "new decommit returns before delayed old-offset punch");
        pthread_mutex_unlock(&caller_lock);
    }
    lock_result = pthread_mutex_trylock(&virtual_mutex);
    CHECK(!lock_result, "VM lock available while old backing punch is blocked");
    if (!lock_result)
    {
        uint64_t probe;
        CHECK(!free_overlaps(original_off + 2 * P, 4 * P), "pending old offset remains quarantined");
        probe = ios_swap_take(P);
        CHECK(probe != UINT64_MAX && !(probe < original_off + 6 * P && probe + P > original_off + 2 * P),
              "new allocation cannot reuse old pending offsets");
        pthread_mutex_unlock(&virtual_mutex);
    }
    CHECK(zeroes(region + 2 * P, 4 * P), "fresh target reads zero before punch completion");
    CHECK(all_value(region, 2 * P, 0x11) && all_value(region + 6 * P, 2 * P, 0x77), "live neighbors unchanged");
    MUST(pread(ios_swap_fd, old_bytes, sizeof(old_bytes), original_off + 2 * P) == sizeof(old_bytes));
    CHECK(all_value(old_bytes, sizeof(old_bytes), 0x33), "old file data still exists before deferred punch");
    memset(region + 2 * P, 0xa5, 4 * P);
#endif
    pthread_mutex_lock(&injection_lock);
    punch_release = 1;
    pthread_cond_broadcast(&injection_cond);
    pthread_mutex_unlock(&injection_lock);
    MUST(!pthread_join(caller, NULL));
    CHECK(caller_result, "decommit succeeded with genuine zero backing");
#ifndef BASELINE_OLD
    wait_done(1);
    CHECK(all_value(region + 2 * P, 4 * P, 0xa5), "late old punch cannot erase newly committed writes");
    pthread_mutex_lock(&virtual_mutex);
    check_live_layout();
    pthread_mutex_unlock(&virtual_mutex);
#else
    CHECK(zeroes(region + 2 * P, 4 * P), "old control zeroed only after punch");
#endif
    MUST(pread(ios_swap_fd, old_bytes, sizeof(old_bytes), original_off + 2 * P) == sizeof(old_bytes));
    CHECK(zeroes(old_bytes, sizeof(old_bytes)), "real sparse-file punch zeroed retired file bytes");
}
static unsigned overlaps( char *lo, size_t len )
{
    unsigned n = 0, i;
    for (i = 0; i < ios_swap_n; i++) if (ios_swap_ext[i].va < lo + len && ios_swap_ext[i].va + ios_swap_ext[i].len > lo) n++;
    return n;
}
static void test_overlap( void )
{
    unsigned k;
    static const unsigned ranges[][2] = {{4,4}, {6,5}, {2,11}, {0,16}};
    unsigned char expected[16 * P];
    setup(16);
    memcpy(expected, region, sizeof(expected));
    for (k = 0; k < sizeof(ranges)/sizeof(ranges[0]); k++)
    {
        unsigned parts = overlaps(region + ranges[k][0] * P, ranges[k][1] * P);
        unsigned long long done = ios_swap_pq_done;
        CHECK(run_decommit(region + ranges[k][0] * P, ranges[k][1] * P), "cross-split reservation decommit handled");
        memset(expected + ranges[k][0] * P, 0, ranges[k][1] * P);
        CHECK(!memcmp(expected, region, sizeof(expected)), "actual mapped bytes agree with decommit model");
        memset(region + ranges[k][0] * P, 0x90 + k, ranges[k][1] * P);
        memset(expected + ranges[k][0] * P, 0x90 + k, ranges[k][1] * P);
        wait_done(done + parts);
        CHECK(!memcmp(expected, region, sizeof(expected)), "post-punch writes preserved across overlapping remaps");
        pthread_mutex_lock(&virtual_mutex);
        check_live_layout();
        pthread_mutex_unlock(&virtual_mutex);
    }
}
static void test_fallback( const char *which )
{
    unsigned initial_fixed, i;
    uint64_t initial_bump;
    int result;
    setup(8);
    initial_fixed = fixed_calls;
    initial_bump = ios_swap_bump;
    if (!strcmp(which,"thread")) create_fail = 1;
    else if (!strcmp(which,"offset")) ios_swap_logical = ios_swap_bump;
    else if (!strcmp(which,"map")) fixed_fail = 1;
    else if (!strcmp(which,"discard")) discard_fail = 1;
    else if (!strcmp(which,"queue")) { ios_swap_pq_state = 1; ios_swap_pq_n = IOS_SWAP_PQ; }
    else if (!strcmp(which,"capacity"))
    {
        for (i = 1; i < 16384; i++)
        {
            ios_swap_ext[i] = ios_swap_ext[0];
            ios_swap_ext[i].va = region + region_bytes + (size_t)i * P;
            ios_swap_ext[i].off = (uint64_t)FILE_BYTES + (uint64_t)i * P;
            ios_swap_ext[i].len = P;
        }
        ios_swap_n = 16384;
    }
    else MUST(0);
    result = run_decommit(region + 2 * P, 4 * P);
    CHECK(result && zeroes(region + 2 * P, 4 * P), "fallback honestly zeroes existing file backing");
    CHECK(offset_at(region + 2 * P) == original_off + 2 * P, "fallback preserves original mapped file offset");
    CHECK(all_value(region, 2 * P, 0x11) && all_value(region + 6 * P, 2 * P, 0x77), "fallback preserves live neighbors");
    CHECK(ios_swap_bytes == region_bytes, "fallback adds no live capacity");
    if (!strcmp(which,"map"))
    {
        CHECK(fixed_calls == initial_fixed + 1, "injected MAP_FAILED was exercised");
        CHECK(ios_swap_bump == initial_bump, "unused known-zero offset returned after mapping failure");
    }
    else CHECK(fixed_calls == initial_fixed, "fallback does not attempt unsafe mapping");
    if (!strcmp(which,"discard"))
    {
        CHECK(!discard_fail && discard_calls >= 2, "failed native discard enters real synchronous punch fallback");
        CHECK(ios_swap_bump == initial_bump, "unused known-zero offset returned after discard failure");
        CHECK(!ios_swap_pq_n, "failed discard never queues retirement of still-mapped backing");
    }
    if (!strcmp(which,"thread")) CHECK(create_calls == 1, "thread creation failure was exercised");
}
static void test_punch_failure( void )
{
    uint64_t old;
    unsigned char bytes[64];
    setup(8);
    old = original_off + 2 * P;
    punch_fail = 1;
    CHECK(run_decommit(region + 2 * P, 4 * P), "fresh zero remap succeeds independently of retired punch failure");
    wait_done(1);
    CHECK(ios_swap_punch_leaks == 1 && !free_overlaps(old, 4 * P), "failed retired offset never reused");
    CHECK(zeroes(region + 2 * P, 4 * P), "current target zeroed despite old punch failure");
    MUST(pread(ios_swap_fd, bytes, sizeof(bytes), old) == sizeof(bytes));
    CHECK(all_value(bytes, sizeof(bytes), 0x33), "failed punch retains its old file data (not a fabricated zero)");
    check_live_layout();
}
static void test_sync_failure( void )
{
    setup(8);
    create_fail = punch_fail = 1;
    CHECK(!run_decommit(region + 2 * P, 4 * P), "failed synchronous zeroing is honestly declined");
    CHECK(offset_at(region + 2 * P) == original_off + 2 * P &&
          all_value(region + 2 * P, 4 * P, 0x33), "failed fallback retains original file mapping/data for caller recovery");
    CHECK(!ios_swap_decommit_remaps && !ios_swap_pq_n, "no fabricated remap or queued success after failure");
}
static void test_split_fallback( void )
{
    unsigned before, parts;
    setup(16);
    /* Represent the real existing file mapping with three contiguous extent
     * records. The separate overlap test creates such splits through actual
     * production remaps. Here no worker is started, so synthetic occupied
     * queue slots can never be consumed as real native punches. */
    ios_swap_ext[1] = ios_swap_ext[2] = ios_swap_ext[0];
    ios_swap_ext[0].len = 4 * P;
    ios_swap_ext[1].va += 4 * P; ios_swap_ext[1].off += 4 * P; ios_swap_ext[1].len = 4 * P;
    ios_swap_ext[2].va += 8 * P; ios_swap_ext[2].off += 8 * P; ios_swap_ext[2].len = 8 * P;
    ios_swap_n = 3;
    memset(region + 4 * P, 0xa5, 4 * P);
    MUST(!msync(region, region_bytes, MS_SYNC));
    parts = overlaps(region + 2 * P, 10 * P);
    CHECK(parts > 1, "fallback exercise spans multiple actual reservation extents");
    before = fixed_calls;
    pthread_mutex_lock(&virtual_mutex);
    ios_swap_pq_state = 1;
    ios_swap_pq_n = IOS_SWAP_PQ - 1;
    CHECK(ios_swap_punch_resv(region + 2 * P, 10 * P), "queue-pressure fallback handles complete union");
    ios_swap_pq_n = 0;
    CHECK(fixed_calls == before, "insufficient room for all retired parts avoids any remap/enqueue");
    CHECK(zeroes(region + 2 * P, 10 * P), "fallback really zeroes every split part");
    CHECK(all_value(region, 2 * P, 0x11) && all_value(region + 14 * P, 2 * P, 0x77), "split fallback preserves live neighbors");
    check_live_layout();
    pthread_mutex_unlock(&virtual_mutex);
}
int main( int argc, char **argv )
{
    MUST(argc == 2);
    if (!strcmp(argv[1],"blocked")) test_blocked();
#ifndef BASELINE_OLD
    else if (!strcmp(argv[1],"overlap")) test_overlap();
    else if (!strcmp(argv[1],"punch-failure")) test_punch_failure();
    else if (!strcmp(argv[1],"sync-failure")) test_sync_failure();
    else if (!strcmp(argv[1],"split-fallback")) test_split_fallback();
    else test_fallback(argv[1]);
#else
    else MUST(0);
#endif
    if (bad) return 1;
    printf("PASS actual %s core %s (controlled host faults/delay; not iPhone performance)\n",
#ifdef BASELINE_OLD
           "old",
#else
           "new",
#endif
           argv[1]);
    return 0;
}
'''


def core_of(text):
    return text[text.index('/* swap-tier core begin'):text.index('/* swap-tier core end */')]


def main():
    current = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
    start = current.index('static int ios_swap_punch_resv( char *lo, size_t len )\n{')
    end = current.index('\nstatic int ios_swap_overlaps', start)
    old = current[:start] + OLD_RESV + current[end:]
    compiler = os.environ.get('CC', 'cc')
    with tempfile.TemporaryDirectory(prefix='madeira-decommit-remap-') as tmp:
        tmp = Path(tmp)
        for name, text in [('old', old), ('new', current)]:
            source, binary = tmp / (name + '.c'), tmp / name
            source.write_text(prelude + INJECT + core_of(text) + HARNESS)
            command = [compiler, '-std=gnu11', '-O1', '-g', '-pthread', '-Wno-unused-function',
                       '-Wno-unused-variable', str(source), '-o', str(binary)]
            if name == 'old':
                command.insert(1, '-DBASELINE_OLD=1')
            if os.environ.get('MADEIRA_REMAP_SANITIZERS') == '1':
                command[1:1] = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(command, check=True, timeout=90)
            cases = ['blocked'] if name == 'old' else ['blocked', 'overlap', 'thread', 'offset', 'map', 'discard', 'queue', 'capacity', 'punch-failure', 'sync-failure', 'split-fallback']
            for case in cases:
                subprocess.run([str(binary), case], check=True, timeout=15)
    print('PASS real sparse-file old/new decommit: VM-lock availability, zeroes, preserved writes, crossing splits and honest bounded fallbacks')


if __name__ == '__main__':
    main()
