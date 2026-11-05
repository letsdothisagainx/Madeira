#!/usr/bin/env python3
"""Execute production FEX arena placement, free ranges and owner reclamation.

The native mappings are synthetic; Wine's actual searches, RB tree, VAD
creation/deletion and owner/lease checks execute. The workload uses the failed
run's live size classes; its deterministic allocation order is synthetic.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
ownership = (root / 'build/ntdll-unix/fex_view_ownership.h').read_text()


def body(text, marker):
    start = text.index(marker)
    opening = text.index('{', start)
    depth = 0
    tokens = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]'
    for token in re.finditer(tokens, text[opening:], re.S):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return text[start:opening + token.end()]
    raise AssertionError('Unclosed helper: ' + marker)


code = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
typedef uintptr_t ULONG_PTR;
typedef uintptr_t UINT_PTR;
typedef uintptr_t SIZE_T;
typedef unsigned char BYTE;
typedef unsigned NTSTATUS;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TRACE(...) ((void)0)
#define TRACE_(channel) TRACE
#define ERR(...) ((void)0)
#define WARN(...) ((void)0)
#define FIXME(...) ((void)0)
#define VIRTUAL_DEBUG_DUMP_RANGES() ((void)0)
#define STATUS_NO_MEMORY 0xc0000017
#define STATUS_SUCCESS 0
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
'''
code += f'#include "{root / "wine/include/wine/rbtree.h"}"\n'
code += f'#include "{root / "wine/include/wine/list.h"}"\n'
for struct in ('struct file_view\n{', 'struct reserved_area\n{', 'struct range_entry\n{'):
    code += body(source, struct) + ';\n'
for macro in ('IOS_VIEW_QUARANTINED', 'VPROT_READ', 'VPROT_WRITE', 'VPROT_EXEC',
              'VPROT_WRITEWATCH', 'VPROT_COMMITTED', 'VPROT_ARM64EC', 'VPROT_SYSTEM',
              'VPROT_PLACEHOLDER', 'VPROT_FREE_PLACEHOLDER', 'ROUND_ADDR', 'ROUND_SIZE'):
    code += re.search(r'^#define ' + macro + r'\b[^\n]+', source, re.M).group() + '\n'
nt = (root / 'wine/include/winnt.h').read_text()
for macro in ('SEC_FILE', 'SEC_IMAGE', 'SEC_RESERVE', 'SEC_COMMIT'):
    code += re.search(r'^#define ' + macro + r'\s+[^\n]+', nt, re.M).group() + '\n'
code += r'''
static const uintptr_t arena_lo = 0xb50000000ULL, arena_hi = 0xd50000000ULL;
static const size_t granularity_mask = 0xffff, host_page_mask = 0xfff, page_mask = 0xfff;
static const size_t page_size = 0x1000, view_block_size = 0x100000;
static struct list reserved_areas = LIST_INIT(reserved_areas);
static struct reserved_area arena;
static struct wine_rb_tree views_tree;
static struct range_entry ranges[8192], *free_ranges = ranges, *free_ranges_end;
static struct file_view storage[2048];
static unsigned char used[2048];
static unsigned live, map_calls, restored, fail_map, fail_view, drops;
static void *last_map;
static void *preload_reserve_start, *preload_reserve_end;
static int use_kernel_writewatch, ios_retire_trace_armed, virtual_mutex;
static void *current_owner = (void *)0x1071a8000;
static struct { void *owner; unsigned long long lease; int quiescent; } owners[3] = {
    {(void *)0x1071a8000,5,0}, {(void *)0x400310000,4,0}, {(void *)0x600310000,7,0}};
static void *ios_jit_current_peb(void) { return current_owner; }
static unsigned long long ios_thread_process_lease(void *owner, int create)
{
    (void)create;
    for (unsigned i=0;i<ARRAY_SIZE(owners);i++) if (owners[i].owner==owner) return owners[i].lease;
    return 0;
}
static unsigned long long ios_thread_process_quiescent_lease(void *owner)
{
    for (unsigned i=0;i<ARRAY_SIZE(owners);i++)
        if (owners[i].owner==owner && owners[i].quiescent) return owners[i].lease;
    return 0;
}
static int fex_arena_covers(const void *lo, const void *hi)
{ return (uintptr_t)lo>=arena_lo && (uintptr_t)hi<=arena_hi; }
static int mmap_is_in_reserved_area(const void *base, size_t size)
{ return (uintptr_t)base>=arena_lo && size<=arena_hi-(uintptr_t)base; }
static struct file_view *alloc_view(void)
{
    if (fail_view) { fail_view=0; return NULL; }
    for (unsigned i=0;i<ARRAY_SIZE(storage);i++) if (!used[i]) { used[i]=1; live++; return storage+i; }
    assert(!"fixture full"); return NULL;
}
static void free_view(struct file_view *v) { assert(used[v-storage]); used[v-storage]=0; live--; }
static int alloc_pages_vprot(void *p,size_t n) { (void)p;(void)n;return 1; }
static void set_page_vprot(void *p,size_t n,BYTE b) { (void)p;(void)n;(void)b; }
static BYTE get_page_vprot(const void *p) { (void)p;return 0; }
static void kernel_writewatch_register_range(struct file_view *v,void *p,size_t n) { (void)v;(void)p;(void)n; }
static void ios_af_set(int s,int e,void *p,size_t n) { (void)s;(void)e;(void)p;(void)n; }
static void ios_vh_note(char c,const struct file_view *v) { (void)c;(void)v; }
static void ios_retire_mark(const char *s) { (void)s; }
static int ios_jit_image_retire_enabled(void) { return 0; }
static void ios_jit_retire_image(void *p,size_t n) { (void)p;(void)n; }
static void ios_jit_note_image_unmapped(void *p,size_t n) { (void)p;(void)n; }
static void ios_swap_release_range(void *p,size_t n,int x) { (void)p;(void)n;(void)x; }
static int ios_jit_anon_alias_overlaps(void *p,size_t n,uintptr_t *a,uintptr_t *b)
{ (void)p;(void)n;(void)a;(void)b;return 0; }
static void ios_jit_anon_alias_retire_range(void *p,size_t n) { (void)p;(void)n; }
static void clear_arm64ec_range(void *p,size_t n) { (void)p;(void)n; }
static void unmap_area(void *p,size_t n) { assert(mmap_is_in_reserved_area(p,n)); restored++; }
static void server_enter_uninterrupted_section(int *m,sigset_t *s) { assert(m==&virtual_mutex);(void)s; }
static void server_leave_uninterrupted_section(int *m,sigset_t *s) { assert(m==&virtual_mutex);(void)s; }
static void ios_hold_release_drop(void *o) { assert(o); drops++; }
'''
for marker in (
    'static int compare_view( const void *addr, const struct wine_rb_entry *entry )',
    'static struct range_entry *free_ranges_lower_bound( void *addr )',
    'static void free_ranges_insert_view( struct file_view *view )',
    'static void free_ranges_remove_view( struct file_view *view )',
    'static inline int is_view_valloc( const struct file_view *view )',
    'static struct file_view *find_view_range( const void *addr, size_t size )\n{',
    'static void unregister_view( struct file_view *view )',
    'static void register_view( struct file_view *view )',
    'static void delete_view( struct file_view *view )',
    'static NTSTATUS create_view( struct file_view **view_ret, void *base, size_t size, unsigned int vprot )',
    'static struct wine_rb_entry *find_view_inside_range( void **base_ptr, void **end_ptr, int top_down )',
    'static void *find_reserved_free_area( void *base, void *end, size_t size, int top_down, size_t align_mask )',
    'static void *find_reserved_free_area_outside_preloader( void *start, void *end, size_t size,'):
    code += body(source, marker) + '\n'
code += r'''
static void *anon_mmap_fixed(void *p,size_t n,int prot,int flags)
{
    (void)prot;(void)flags;map_calls++;last_map=p;
    assert(mmap_is_in_reserved_area(p,n) && !find_view_range(p,n));
    if (fail_map) { fail_map=0;return MAP_FAILED; }
    return p;
}
'''
marker = ('static void *map_reserved_area_inner( void *limit_low, void *limit_high, size_t size, int top_down,\n'
          '                                      int unix_prot, size_t align_mask, int fex_allowed )\n{')
placement = body(source, marker)
policy = 'int area_top_down = area->fex_only && align_mask > granularity_mask;'
assert placement.count(policy) == 1
code += placement + '\n'
code += placement.replace('map_reserved_area_inner(', 'legacy_map_reserved_area_inner(', 1).replace(
    policy, 'int area_top_down = top_down;') + '\n'
code += r'''
static unsigned ios_scan_views;
static size_t ios_scan_maxgap, ios_scan_tailgap;
static int ios_scan_stop, ios_scan_fail_errno;
static void *ios_scan_base,*ios_scan_end,*ios_scan_fail_addr;
static int ios_layerkit_enforce;
static unsigned long ios_layerkit_skips;
static unsigned long long ios_layerkit_lo,ios_layerkit_hi;
static void *try_map_free_area(void *base,void *end,ptrdiff_t step,void *start,size_t size,int prot)
{
    (void)step;(void)prot;
    /* The whole arena is natively reserved PROT_NONE. The generic mapper
     * cannot overwrite it after the authorized reserved search fails. */
    if (start && start>=base && start<end && (size_t)((char *)end-(char *)start)>=size)
        assert(mmap_is_in_reserved_area(start,size));
    return NULL;
}
'''
for marker in (
    'static void *map_free_area_inner( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )\n{',
    'static void *map_free_area( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )\n{'):
    code += body(source, marker) + '\n'
code += '#define IOS_FEX_OWNERS 64\n'
code += body(ownership, 'static struct ios_fex_owner_record\n{') + ' ios_fex_owners[IOS_FEX_OWNERS];\n'
for marker in ('static void ios_fex_tag_view(struct file_view *view, ULONG_PTR low, ULONG_PTR high)',
               'void ios_fex_reclaim_process_views(void *owner)'):
    code += body(ownership, marker) + '\n'
code += r'''
static struct file_view *allocate(size_t size,size_t alignment,unsigned flags,int legacy)
{
    void *p = legacy ? legacy_map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,size,0,0,alignment-1,1)
                     : map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,size,0,0,alignment-1,1);
    struct file_view *v=NULL;
    if (!p) return NULL;
    assert(!((uintptr_t)p & (alignment-1)));
    if (create_view(&v,p,size,flags)) { unmap_area(p,size); return NULL; }
    ios_fex_tag_view(v,arena_lo,arena_hi-1);
    assert(v->ios_fex_owner==current_owner && v->ios_fex_lease==ios_thread_process_lease(current_owner,0));
    return v;
}
static void reset(void)
{
    memset(storage,0,sizeof(storage));memset(used,0,sizeof(used));
    memset(ios_fex_owners,0,sizeof(ios_fex_owners));
    wine_rb_init(&views_tree,compare_view);
    list_init(&reserved_areas);
    arena=(struct reserved_area){.base=(void *)arena_lo,.size=arena_hi-arena_lo,.fex_only=1};
    list_add_tail(&reserved_areas,&arena.entry);
    /* Free ranges include a terminal sentinel, as in virtual_init. */
    ranges[0]=(struct range_entry){(void *)arena_lo,(void *)arena_hi};
    ranges[1]=(struct range_entry){(void *)(arena_hi+0x1000000),(void *)UINTPTR_MAX};
    free_ranges_end=ranges+2;
    for (unsigned i=0;i<ARRAY_SIZE(owners);i++) {
        ios_fex_owners[i]=(struct ios_fex_owner_record){owners[i].owner,NULL,owners[i].lease};
        owners[i].quiescent=0;
    }
    current_owner=owners[0].owner;
    live=map_calls=restored=fail_map=fail_view=drops=0;
}
static void gaps(size_t *total,size_t *largest)
{
    *total=*largest=0;
    for(struct range_entry *r=free_ranges;r<free_ranges_end;r++) {
        uintptr_t lo=max((uintptr_t)r->base,arena_lo),hi=min((uintptr_t)r->end,arena_hi);
        if (hi>lo) { *total+=hi-lo; if(hi-lo>*largest) *largest=hi-lo; }
    }
}
static struct file_view *must_allocate(size_t n,size_t a,unsigned flags,int legacy)
{ struct file_view *v=allocate(n,a,flags,legacy); assert(v); return v; }

static void workload(int legacy)
{
    struct file_view *first_frontend8=NULL;
    /* Reconstruct the observed live census, with synthetic ordering and
     * individual sizes for the census's 44 unlisted allocations. */
    for(unsigned i=0;i<114;i++) {
        current_owner=owners[i<49 ? 0 : i<53 ? 1 : 2].owner;
        for(unsigned j=0;j<(i<97 ? 3u : 2u);j++) must_allocate(0x1000000,0x1000000,3,legacy);
        must_allocate(0x200000,0x10000,0x23,legacy);
        if(i<113) must_allocate(0x802000,0x10000,0,legacy);
        if(i<50) must_allocate(0x1000000,0x10000,0x23,legacy);
        if(i<38) must_allocate(0x900000,0x10000,0x23,legacy);
        else if(i<50) {
            struct file_view *v=must_allocate(0x800000,0x10000,0x23,legacy);
            if(!first_frontend8) first_frontend8=v;
        }
    }
    static const struct { size_t size;unsigned count; } small[]={
        {0x8c000,6},{0x5d000,5},{0x3e000,5},{0x29000,7},{0xc6000,1},
        {0x1b000,7},{0xad000,1},{0x8b000,1},{0x79000,1},{0x1000,117},
        {0x12000,6},{0x57000,1},{0xc000,6},{0x1e000,2},{0x32000,1},
        {0x8000,6},{0x2a000,1},{0x28000,1},{0x21000,1},{0x5000,6},
        {0x3000,6},{0xe000,1},{0x2000,6},{0x9000,1},{0x6000,1},{0x1000,6}};
    for(unsigned i=0;i<ARRAY_SIZE(small);i++)
        for(unsigned j=0;j<small[i].count;j++) must_allocate(small[i].size,0x10000,i==9 ? 3 : 0x23,legacy);
    for(unsigned i=0;i<44;i++) must_allocate(i<43 ? 0x103000 : 0x10c000,0x10000,0x23,legacy);
    /* Ordinary frontend churn leaves the isolated 8 MB hole seen in the
     * failed run. Every live view's size/count is preserved. */
    must_allocate(0x800000,0x10000,0x23,legacy);
    delete_view(first_frontend8);
    size_t covered=0;
    for(unsigned i=0;i<ARRAY_SIZE(storage);i++) if(used[i]) covered+=storage[i].size;
    assert(live==899 && covered==0x1dcd01000ULL && arena_hi-arena_lo-covered==0x232ff000);
    current_owner=owners[0].owner;
}

int main(void)
{
    reset();
    /* Only an authorized FEX area changes direction; generic and explicit
     * top-down requests keep their existing policy and caller bounds. */
    assert(!map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x1000000,0,0,0xffffff,0));
    assert(!map_calls);
    arena.fex_only=0;
    assert(map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x1000000,0,0,0xffffff,0)==(void *)arena_lo);
    arena.fex_only=1;
    assert(map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x1000000,1,0,0xffffff,1)==(void *)(arena_hi-0x1000000));
    assert(map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x802000,1,0,0xffff,1)==ROUND_ADDR((void *)(arena_hi-0x802000),0xffff));
    assert(map_reserved_area_inner((void *)(arena_lo+0x1000000),(void *)(arena_lo+0x5000000),0x1000000,0,0,0xffffff,1)==(void *)(arena_lo+0x4000000));
    /* Failed mapping and failed VAD construction consume no free range. */
    fail_map=1;
    assert(!allocate(0x1000000,0x1000000,3,0));
    void *retry=last_map;
    assert(allocate(0x1000000,0x1000000,3,0)->base==retry);
    fail_view=1;
    assert(!allocate(0x802000,0x10000,0,0));
    retry=last_map;
    struct file_view *stack=allocate(0x802000,0x10000,0,0);
    assert(stack && stack->base==retry && stack->size==0x802000);
    /* Failed thread initialization releases the entire guarded reservation. */
    void *old_stack=stack->base;
    delete_view(stack);
    assert(allocate(0x802000,0x10000,0,0)->base==old_stack);

    for(int legacy=1;legacy>=0;legacy--) {
        reset(); workload(legacy);
        size_t total,largest;gaps(&total,&largest);
        assert(live==899);
        if(legacy) {
            assert(total>500*1024*1024 && largest==0x800000);
            assert(!allocate(0x802000,0x10000,0,1));
            assert(!map_free_area((void *)arena_lo,(void *)arena_hi,0x802000,0,0,0xffff));
            assert(ios_scan_maxgap==0x800000);
            printf("legacy: live=%u free=%zu maxgap=%zu next-guarded-stack=failed\n",live,total,largest);
        } else {
            assert(largest>500*1024*1024);
            stack=allocate(0x802000,0x10000,0,0);
            assert(stack && stack->size==0x802000);
            printf("patched: live=%u free-before=%zu maxgap-before=%zu next-guarded-stack=success\n",live,total,largest);
            void *stack_base=stack->base;
            delete_view(stack);
            assert(allocate(0x802000,0x10000,0,0)->base==stack_base);
            /* Active owners cannot be reclaimed; stale PEB generations
             * cannot release the previous generation's still-live views. */
            unsigned before=live;
            ios_fex_reclaim_process_views(owners[0].owner);
            assert(live==before && !drops);
            owners[0].lease++;owners[0].quiescent=1;
            ios_fex_reclaim_process_views(owners[0].owner);
            assert(live==before);
            owners[0].lease--;owners[0].quiescent=0;
            struct file_view *survivor=NULL;
            for(unsigned i=0;i<ARRAY_SIZE(storage);i++)
                if(used[i] && storage[i].ios_fex_owner==owners[1].owner) { survivor=storage+i;break; }
            assert(survivor);
            void *survivor_base=survivor->base;size_t survivor_size=survivor->size;
            owners[0].quiescent=1;
            ios_fex_reclaim_process_views(owners[0].owner);
            assert(live<before && used[survivor-storage] && survivor->base==survivor_base && survivor->size==survivor_size);
            current_owner=owners[1].owner;
            assert(allocate(0x802000,0x10000,0,0));
            assert(allocate(0x1000000,0x1000000,3,0));
            for(unsigned i=1;i<ARRAY_SIZE(owners);i++) {
                owners[i].quiescent=1;
                ios_fex_reclaim_process_views(owners[i].owner);
            }
            assert(!live);
            assert(ranges[0].base==(void *)arena_lo && ranges[0].end==(void *)arena_hi);
            /* A fresh owner can use the whole unchanged arena for either
             * class: the two search directions create no fixed partition. */
            owners[1].lease++;owners[1].quiescent=0;
            ios_fex_owners[0]=(struct ios_fex_owner_record){owners[1].owner,NULL,owners[1].lease};
            assert(allocate(arena_hi-arena_lo,0x1000000,3,0)->base==(void *)arena_lo);
        }
    }
    puts("PASS: actual FEX placement/free ranges, failed map/view/initialization reuse, owner leases and sibling preservation");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='fex-arena-placement-') as temporary:
    path = Path(temporary) / 'placement.c'
    executable = Path(temporary) / 'placement'
    path.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-O1',
                    '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-sign-compare',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(path), '-o', str(executable)], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        result.check_returncode()
