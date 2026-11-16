#!/usr/bin/env python3
"""Real swap-backed migration: bounded scratch, partial failure, guards and data.

Runs the production swap core on owned sparse-file/anonymous mappings. The old
release routine below is verbatim 7e6ce444. Allocation ceilings/map failures are
injected. Scratch bytes are measured, not iPhone footprint or CS2 performance.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
fixture = ROOT / 'tests/host/check-swap-coverage.py'
ns = {'__file__': str(fixture)}
exec(compile(fixture.read_text().split("\nharness = r'''", 1)[0], str(fixture), 'exec'), ns)
OLD_RELEASE = r'''static void ios_swap_release_range( void *base, size_t size, int copy_back )
{
    char *lo = (char *)base, *hi = (char *)base + size;
    unsigned i = 0;
    unsigned long long releases_before = ios_swap_releases;
    uint64_t noted_born = 0;   /* ml1258: pieces of one split extent are one death */
    if (ios_swap_fd < 0 || !ios_swap_n) return;
    if (copy_back)
    {
        lo = (char *)((uintptr_t)lo & ~(uintptr_t)host_page_mask);
        hi = (char *)(((uintptr_t)hi + host_page_mask) & ~(uintptr_t)host_page_mask);
    }
    while (i < ios_swap_n)
    {
        char *a = ios_swap_ext[i].va, *b = a + ios_swap_ext[i].len;
        char *oa = a > lo ? a : lo, *ob = b < hi ? b : hi;
        if (oa >= ob) { i++; continue; }
        {
            uint64_t ooff = ios_swap_ext[i].off + (oa - a);
            size_t olen = ob - oa;
            if (copy_back)
            {
                void *tmp = malloc( olen );
                char *pg;
                if (!tmp)
                {
                    static int said;
                    if (said++ < 8) dprintf( 2, "[swap] copy-back of %p+0x%zx: no buffer, range stays file-backed\n", oa, olen );
                    i++;
                    continue;
                }
                for (pg = oa; pg < ob; pg += host_page_mask + 1)
                    if (!(get_unix_prot( get_host_page_vprot( pg ) ) & PROT_READ)) { mprotect( oa, olen, PROT_READ ); break; }
                memcpy( tmp, oa, olen );
                if (anon_mmap_fixed( oa, olen, PROT_READ | PROT_WRITE, 0 ) == MAP_FAILED)
                {
                    static int said;
                    if (said++ < 8) dprintf( 2, "[swap] copy-back of %p+0x%zx: anonymous map failed errno=%d, range stays file-backed\n", oa, olen, errno );
                    free( tmp );
                    mprotect_range( oa, olen, 0, 0 );
                    i++;
                    continue;
                }
                memcpy( oa, tmp, olen );
                free( tmp );
                mprotect_range( oa, olen, 0, 0 );
                ios_swap_unbacks++;
            }
            /* ml1293: the range's contents are dead (decommit/release), but its dirty pages would
             * still be written to the file by the pageout daemon -- I/O that slowed every other
             * fault on the file and the punch behind it. Discard them first: no writeback. */
            if (!copy_back) msync( oa, olen, MS_KILLPAGES );
            ios_swap_give( ooff, olen );
            ios_swap_bytes -= olen;
            if (ios_swap_ext[i].img) ios_swap_img_bytes -= olen;   /* madeira-bcd swap-images */
            ios_swap_releases++;
            /* trim the extent: up to two remaining pieces */
            if (oa == a && ob == b)
            {
                if (!copy_back && ios_swap_broad && ios_swap_ext[i].born != noted_born)   /* ml1258: freed whole; how long did it live? */
                {
                    uint64_t lived = ios_swap_now_ns() - ios_swap_ext[i].born;
                    noted_born = ios_swap_ext[i].born;
                    if (lived < IOS_SWAP_CHURN_NS) ios_swap_churn_note( ios_swap_ext[i].key, lived );
                }
                ios_swap_ext[i] = ios_swap_ext[--ios_swap_n];
                continue;
            }
            if (oa == a) { ios_swap_ext[i].va = ob; ios_swap_ext[i].off += olen; ios_swap_ext[i].len -= olen; i++; continue; }
            if (ob == b) { ios_swap_ext[i].len = oa - a; i++; continue; }
            if (ios_swap_n < 16384)
            {
                ios_swap_ext[ios_swap_n] = ios_swap_ext[i];   /* resv, key, born carry over */
                ios_swap_ext[ios_swap_n].va = ob; ios_swap_ext[ios_swap_n].off = ios_swap_ext[i].off + (ob - a);
                ios_swap_ext[ios_swap_n].len = b - ob; ios_swap_n++;
            }
            ios_swap_ext[i].len = oa - a; i++;
        }
    }
    if (ios_swap_releases != releases_before && (ios_swap_releases <= 16 || (ios_swap_releases % 64) == 0))
        dprintf( 2, "[swap] ml1077 released %p+0x%zx%s: %llu MB in %u extents, %llu releases, %llu unbacks\n",
                 base, size, copy_back ? " (copied back to anonymous)" : "", ios_swap_bytes >> 20, ios_swap_n, ios_swap_releases, ios_swap_unbacks );
}'''
assert hashlib.sha256(OLD_RELEASE.strip().encode()).hexdigest() == 'be06cc03ccd56ffc67626e2e37a3bb93b7922674b7dce8b06155fcbde176ccfb'
prelude = ns['prelude']
prelude = prelude.replace('static int fail_malloc;\nstatic void *test_malloc( size_t n ) { return fail_malloc ? NULL : malloc( n ); }', r'''
static int fail_malloc;
static size_t scratch_peak, scratch_limit = SIZE_MAX;
static void *test_malloc( size_t n )
{
    if (n > scratch_peak) scratch_peak = n;
    return fail_malloc || n > scratch_limit ? NULL : malloc(n);
}
''')
prelude = prelude.replace('/* the production helper asserts host-page alignment; so does this one */',
    'static unsigned map_calls, map_fail_at;\n/* the production helper asserts host-page alignment; so does this one */')
prelude = prelude.replace('    (void)flags;\n    assert( !((uintptr_t)a & host_page_mask) );',
    '    (void)flags;\n    if (++map_calls >= map_fail_at && map_fail_at) { errno = ENOMEM; return MAP_FAILED; }\n    assert( !((uintptr_t)a & host_page_mask) );')

prelude += 'static const char *prot_of( const void *p )\n' + ns['body_of'](fixture.read_text(), 'static const char *prot_of( const void *p )') + '\n'


# Execute the real protection entry point too: a failed migration must not
# modify guest protection bookkeeping or claim executable/guarded backing.
PROTECTION_STUBS = r'''
typedef unsigned int NTSTATUS;
typedef size_t SIZE_T;
typedef unsigned int ULONG;
typedef unsigned char BYTE;
typedef int BOOL;
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY 0xc0000017u
#define STATUS_INVALID_PAGE_PROTECTION 0xc0000045u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define VPROT_X64DATA 0x8000u
static unsigned set_vprot_calls;
static NTSTATUS get_vprot_flags(ULONG flags, unsigned int *out, int image)
{ (void)image; *out = flags; return 0; }
static BOOL set_vprot(struct file_view *view, void *base, size_t len, BYTE flags)
{ (void)view; (void)base; (void)len; (void)flags; set_vprot_calls++; return 1; }
'''
protection_sig = 'static NTSTATUS set_protection( struct file_view *view, void *base, SIZE_T size, ULONG protect )'
PROTECTION = PROTECTION_STUBS + protection_sig + '\n' + ns['body_of'](ns['virt'], protection_sig)

HARNESS = r'''
static unsigned long long ios_swap_footprint_mb(void) { return 0; }
static void ios_swap_cfg(int *mode, int *min_mb) { *mode = 1; *min_mb = 0; }
static unsigned long long ios_swap_disk_used(void) { return 0; }
#define LENGTH (32u << 20)
static unsigned char pattern(size_t i) { return (unsigned char)(i * 7 + (i >> 14) * 11 + 3); }
static void verify(const unsigned char *p) { size_t i; for(i=0;i<LENGTH;i++) assert(p[i] == pattern(i)); }
static void seed(unsigned char *p)
{
    size_t i;
    ios_swap_n = ios_swap_nfree = 0; ios_swap_bump = ios_swap_bytes = 0;
    assert(ios_swap_map(p, LENGTH, PROT_READ | PROT_WRITE) == IOS_SW_BACKED);
    for(i=0;i<LENGTH;i++) p[i] = pattern(i);
    scratch_peak = map_calls = map_fail_at = 0; scratch_limit = SIZE_MAX;
}
int main(void)
{
    char path[] = "/tmp/madeira-copyback-XXXXXX";
    int fd = mkstemp(path);
    unsigned char *p;
    size_t peak;
    assert(fd >= 0); close(fd);
    setenv("MADEIRA_SWAP_FILE",path,1); setenv("MADEIRA_SWAP_MB","256",1);
    setenv("MADEIRA_SWAP_PUNCH_DEFER","0",1); setenv("MADEIRA_SWAP_COVERAGE","blocks",1);
    ios_swap_init(); unlink(path); assert(ios_swap_fd >= 0);
    p = mmap((void *)0x7050000000ULL,LENGTH,PROT_NONE,MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,-1,0);
    assert(p != MAP_FAILED);
    seed(p);
    ios_swap_release_range(p,LENGTH,1);
    assert(!ios_swap_n && !ios_swap_bytes); verify(p);
    peak = scratch_peak;
#if NEW_POLICY
    assert(scratch_peak == (1u << 20));
#else
    assert(scratch_peak == LENGTH);
#endif
    seed(p); scratch_limit = 2u << 20;
    ios_swap_release_range(p,LENGTH,1);
#if NEW_POLICY
    assert(!ios_swap_n && !ios_swap_bytes);
#else
    assert(ios_swap_n == 1 && ios_swap_bytes == LENGTH);
#endif
    verify(p); scratch_limit = SIZE_MAX;
    ios_swap_release_range(p,LENGTH,0);
#if NEW_POLICY
    /* A partial failure migrates only the successful prefix. Its suffix
     * keeps the original file offset and can be retried without data loss. */
    seed(p); map_fail_at = 2;
    ios_swap_release_range(p,LENGTH,1);
    assert(ios_swap_bytes == LENGTH - (1u << 20) && ios_swap_n == 1);
    assert(ios_swap_ext[0].va == (char *)p + (1u << 20));
    assert(ios_swap_ext[0].off == (1u << 20));
    assert(!ios_swap_overlaps(p,1u << 20) && ios_swap_overlaps(p+(1u << 20),1u << 20));
    verify(p);
    {
        unsigned char *reused;
        unsigned char zero;
        uint64_t off = ios_swap_take(1u << 20);
        assert(off == 0 && pread(ios_swap_fd,&zero,1,(off_t)off) == 1 && zero == 0);
        reused = mmap(NULL,1u<<20,PROT_READ|PROT_WRITE,MAP_SHARED,ios_swap_fd,(off_t)off);
        assert(reused != MAP_FAILED); memset(reused,0xaa,1u<<20);
        verify(p); /* Reusing old file offsets must not alter migrated pages. */
        munmap(reused,1u<<20); ios_swap_give(off,1u<<20);
    }
    map_fail_at = 0;
    ios_swap_release_range(p,LENGTH,1); assert(!ios_swap_n && !ios_swap_bytes); verify(p);
    /* Interior partial migration preserves both untouched neighbouring pieces. */
    seed(p); map_fail_at = 2;
    ios_swap_release_range(p+(2u<<20),8u<<20,1);
    assert(ios_swap_n == 2 && ios_swap_bytes == LENGTH-(1u<<20));
    assert(ios_swap_overlaps(p,2u<<20) && !ios_swap_overlaps(p+(2u<<20),1u<<20));
    assert(ios_swap_overlaps(p+(3u<<20),LENGTH-(3u<<20))); verify(p);
    map_fail_at = 0; ios_swap_release_range(p,LENGTH,1);
    assert(!ios_swap_n && !ios_swap_bytes); verify(p);
    /* Full metadata capacity must refuse an interior start before any copy:
     * a later chunk failure would otherwise lose the still-backed suffix. */
    seed(p);
    {
        unsigned i;
        for (i=1;i<16384;i++) { ios_swap_ext[i].va=(char *)p+LENGTH; ios_swap_ext[i].len=0; }
        ios_swap_n=16384;
        ios_swap_release_range(p+(1u<<20),LENGTH-(1u<<20),1);
        assert(ios_swap_n == 16384 && ios_swap_bytes == LENGTH && !scratch_peak && !map_calls);
        verify(p); ios_swap_n=1;
    }
    ios_swap_release_range(p,LENGTH,1); assert(!ios_swap_n && !ios_swap_bytes); verify(p);
    /* Scratch failure and first-map failure preserve contents/ownership. */
    seed(p); fail_malloc = 1; ios_swap_release_range(p,LENGTH,1); fail_malloc = 0;
    assert(ios_swap_n == 1 && ios_swap_bytes == LENGTH); verify(p);
    map_fail_at = 1; map_calls = 0; ios_swap_release_range(p,LENGTH,1);
    assert(ios_swap_n == 1 && ios_swap_bytes == LENGTH); verify(p); map_fail_at = 0;
    /* Guard pages across the scratch boundary retain data and protection. */
    tv_lo = (uintptr_t)p+(1u<<20)-0x4000; tv_hi = tv_lo+0x8000;
    tv_in = VPROT_READ | VPROT_WRITE | VPROT_GUARD | VPROT_COMMITTED;
    assert(!mprotect_range((void *)tv_lo,0x8000,0,0));
    ios_swap_release_range(p,LENGTH,1); assert(!ios_swap_n && !ios_swap_bytes);
    assert(!strcmp(prot_of((void *)tv_lo),"--"));
    assert(!strcmp(prot_of((void *)(tv_hi-0x4000)),"--"));
    assert(!strcmp(prot_of(p),"rw") && !strcmp(prot_of(p+(2u<<20)),"rw"));
    assert(!mprotect((void *)tv_lo,0x8000,PROT_READ | PROT_WRITE)); tv_lo=tv_hi=0; verify(p);
#endif
#if NEW_POLICY
    {
        struct file_view view = {p,LENGTH,0};
        seed(p); fail_malloc = 1; set_vprot_calls = 0;
        assert(set_protection(&view,p,LENGTH,VPROT_EXEC) == STATUS_NO_MEMORY);
        assert(!set_vprot_calls && ios_swap_bytes == LENGTH); verify(p);
        fail_malloc = 0;
        assert(set_protection(&view,p,LENGTH,VPROT_EXEC) == STATUS_SUCCESS);
        assert(set_vprot_calls == 1 && !ios_swap_bytes); verify(p);
    }
#endif
    munmap(p,LENGTH); close(ios_swap_fd);
    printf("%s scratch-peak=%zu bytes; data/ownership preserved\n", NEW_POLICY ? "current" : "7e6ce444", peak);
    return 0;
}
'''

core = ns['core']
start = core.index('static void ios_swap_release_range( void *base, size_t size, int copy_back )\n{')
end = core.index('\n/* Decommit wholly covered', start)
old_core = core[:start] + OLD_RELEASE.strip() + core[end:]
with tempfile.TemporaryDirectory() as tmp:
    for label, actual, enabled in [('baseline',old_core,0),('current',core,1)]:
        source = Path(tmp) / (label + '.c')
        binary = Path(tmp) / label
        source.write_text(prelude + actual + PROTECTION + HARNESS)
        subprocess.run(['cc','-O1','-Wall','-Werror','-Wno-unused-function','-pthread',f'-DNEW_POLICY={enabled}','-o',str(binary),str(source)],check=True)
        result = subprocess.run([str(binary)],capture_output=True,text=True,env=dict(os.environ))
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr + f'FAIL: {label} exited {result.returncode}')
        print(result.stdout.strip())
setprot = ns['body_of'](ns['virt'], 'static NTSTATUS set_protection( struct file_view *view, void *base, SIZE_T size, ULONG protect )')
assert setprot.index('if (ios_swap_overlaps( base, size )) return STATUS_NO_MEMORY;') < setprot.index('if (!set_vprot(')
print('PASS: real bounded copy-back, constrained allocation, partial-map recovery, guards and truthful protection failure')

# Exercise the monitor's real bridge with and without the weak native backend.
# It reuses an existing valid footprint sample, never walks VM regions, and
# preserves errno even if the public availability query/backend changes it.
monitor_sig = 'static void ios_native_memory_pressure_sample( uint64_t footprint )'
optional_start = ns['virt'].index('#ifdef __APPLE__\n#define IOS_NATIVE_MEMORY_OPTIONAL')
optional_end = ns['virt'].index('\nstatic void ios_native_memory_pressure_sample', optional_start)
optional_linkage = ns['virt'][optional_start:optional_end]
monitor = optional_linkage + '\n' + monitor_sig + '\n' + ns['body_of'](ns['virt'], monitor_sig)
warmer = ns['body_of'](ns['virt'], 'static void *ios_pool_warmer_thread( void *arg )')
poll_start = warmer.index('        {\n            extern void madeira_native_memory_relief_poll')
poll_end = warmer.index('\n        }', poll_start) + len('\n        }')
poll_bridge = 'static void poll_bridge(void)\n' + warmer[poll_start:poll_end] + '\n'
bridge = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
static unsigned available_calls, request_calls, poll_calls;
static uint64_t last_footprint, last_available;
size_t os_proc_available_memory(void)
{ available_calls++; errno = EIO; return 1234; }
'''
bridge_main = r'''
#if WITH_BACKEND
void madeira_native_memory_relief_request(uint64_t footprint, uint64_t available)
{ request_calls++; last_footprint = footprint; last_available = available; errno = EBADF; }
void madeira_native_memory_relief_poll(void) { poll_calls++; }
#endif
int main(void)
{
    errno = ENOMEM; ios_native_memory_pressure_sample(0);
    assert(errno == ENOMEM && !available_calls && !request_calls);
    ios_native_memory_pressure_sample(5678);
    assert(errno == ENOMEM);
    poll_bridge();
#if WITH_BACKEND
    assert(available_calls == 1 && request_calls == 1 && last_footprint == 5678 && last_available == 1234);
    assert(poll_calls == 1);
#else
    assert(!available_calls && !request_calls && !last_footprint && !last_available);
    assert(!poll_calls);
#endif
    return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    source, binary = Path(tmp) / 'monitor.c', Path(tmp) / 'monitor'
    source.write_text(bridge + monitor + poll_bridge + bridge_main)
    for enabled in (0, 1):
        subprocess.run(['cc', '-O1', '-Wall', '-Werror', f'-DWITH_BACKEND={enabled}', '-o', str(binary), str(source)], check=True)
        subprocess.run([str(binary)], check=True)
assert warmer.count('ios_native_memory_pressure_sample(') == 2
assert 'ios_native_memory_pressure_sample( (uint64_t)fvmi.phys_footprint );' in warmer
assert 'ios_native_memory_pressure_sample( (uint64_t)vmi.phys_footprint );' in warmer
assert warmer.index('madeira_native_memory_relief_poll();') < warmer.index('pthread_mutex_lock(')
assert 'task_info(' not in monitor and 'mach_vm_' not in monitor
print('PASS: existing fast/full footprint samples queue pressure work; absent backend is inert; errno preserved')
