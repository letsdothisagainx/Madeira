#!/usr/bin/env python3
"""Exercise the production native scan around disjoint WoW64 reservations."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
start = source.index('static void *ios_map_between_wow_windows(')
end = source.index('\n}\n', start) + 3
function = source[start:end]
assert source.count('if (area->fex_only && !fex_allowed) continue;') == 2
allocation = source[source.index('static NTSTATUS map_view('):] if 'static NTSTATUS map_view(' in source else source
assert 'wow_scan_start = start; wow_scan_end = end;' in allocation
assert 'wow_fex_allowed = fex_arena_covers( (void *)limit_low, (void *)limit_high );' in allocation
assert 'top_down, unix_prot, align_mask, wow_fex_allowed )))' in allocation
assert 'fex_arena_covers' not in function
assert '(ptr = ios_map_between_wow_windows( wow_scan_start, wow_scan_end, host_size,' in allocation
assert allocation.index('(ptr = ios_map_between_wow_windows(') < allocation.index('if (!ceiling_relaxable)', allocation.index('(ptr = ios_map_between_wow_windows('))

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uintptr_t ULONG_PTR;
#define IOS_WOW_MAX_WINDOWS 8
#define IOS_WOW_WINDOW_SIZE (4ull << 30)
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
struct ios_wow_window { ULONG_PTR base; int guard_owned; };
struct ios_wow_placeholder { ULONG_PTR base; int guard_owned, adopted; };
static struct ios_wow_window ios_wow_windows[8];
static struct ios_wow_placeholder ios_wow_placeholders[8];
static unsigned ios_wow_window_count, ios_wow_placeholder_count;
static ULONG_PTR ios_wow_guard_size(void) { return 0x4000; }
static ULONG_PTR ios_wow_slot_reservation(const struct ios_wow_window *p) {
    return IOS_WOW_WINDOW_SIZE + (p->guard_owned ? ios_wow_guard_size() : 0);
}
struct interval { ULONG_PTR lo, hi; };
static struct interval obstacles[24];
static unsigned obstacle_count, free_calls, reserved_calls, maps;
static int reserved_mode;
static uintptr_t arena;
static uintptr_t fex_lo, fex_hi;
static int expected_fex;
static const uint64_t gib = 1ull << 30;
static const size_t arena_size = 64ull << 30;
static int fex_arena_covers(const void *low,const void *high) {
    return fex_lo && (uintptr_t)low>=fex_lo && (uintptr_t)high<=fex_hi;
}
static void log_note(int fd, const char *s, ...) { assert(fd == 2 && strstr(s, "[wow-placement-v1]")); }
#define dprintf log_note
static void reset(void) {
    memset(ios_wow_windows,0,sizeof(ios_wow_windows));
    memset(ios_wow_placeholders,0,sizeof(ios_wow_placeholders));
    ios_wow_window_count=ios_wow_placeholder_count=obstacle_count=0;
    free_calls=reserved_calls=maps=0;reserved_mode=0;fex_lo=fex_hi=0;expected_fex=0;
}
static void window(unsigned at,int owned) {
    ios_wow_windows[ios_wow_window_count++] = (struct ios_wow_window){arena+at*gib,owned};
}
static void obstacle(unsigned at,unsigned size) {
    obstacles[obstacle_count++] = (struct interval){arena+at*gib,arena+(at+size)*gib};
}
static void assert_window_excluded(ULONG_PTR lo,ULONG_PTR hi) {
    for(unsigned i=0;i<ios_wow_window_count;i++) {
        ULONG_PTR a=ios_wow_windows[i].base,b=a+ios_wow_slot_reservation(&ios_wow_windows[i]);
        if(a)assert(hi<=a||lo>=b);
    }
    for(unsigned i=0;i<ios_wow_placeholder_count;i++) {
        struct ios_wow_placeholder p=ios_wow_placeholders[i];
        if(p.base&&!p.adopted)assert(hi<=p.base||lo>=p.base+IOS_WOW_WINDOW_SIZE+(p.guard_owned?0x4000:0));
    }
}
static size_t largest_gap(ULONG_PTR lo,ULONG_PTR hi) {
    struct interval all[2*IOS_WOW_MAX_WINDOWS+25];
    unsigned count=0;
    for(unsigned i=0;i<obstacle_count;i++)all[count++]=obstacles[i];
    if(fex_lo)all[count++]=(struct interval){fex_lo,fex_hi};
    for(unsigned i=0;i<ios_wow_window_count;i++) {
        struct ios_wow_window p=ios_wow_windows[i];
        if(p.base)all[count++]=(struct interval){p.base,p.base+ios_wow_slot_reservation(&p)};
    }
    for(unsigned i=0;i<ios_wow_placeholder_count;i++) {
        struct ios_wow_placeholder p=ios_wow_placeholders[i];
        if(p.base&&!p.adopted)all[count++]=(struct interval){p.base,p.base+IOS_WOW_WINDOW_SIZE+(p.guard_owned?0x4000:0)};
    }
    for(unsigned i=1;i<count;i++)for(unsigned j=i;j&&all[j].lo<all[j-1].lo;j--) {
        struct interval saved=all[j];all[j]=all[j-1];all[j-1]=saved;
    }
    ULONG_PTR cursor=lo;size_t gap=0;
    for(unsigned i=0;i<count&&cursor<hi;i++) {
        if(all[i].hi<=cursor||all[i].lo>=hi)continue;
        if(all[i].lo>cursor)gap=max(gap,all[i].lo-cursor);
        cursor=max(cursor,all[i].hi);
    }
    if(cursor<hi)gap=max(gap,hi-cursor);
    return gap;
}
static void *real_map(ULONG_PTR lo,ULONG_PTR hi,size_t size,int down,int prot,size_t align,int allow_fex) {
    assert(lo>=arena && hi<=arena+arena_size && lo<hi);
    assert_window_excluded(lo,hi);
    ULONG_PTR a=down?((hi-size)&~align):((lo+align)&~align);
    for(unsigned iteration=0;iteration<=obstacle_count+1;iteration++) {
        if(a<lo||a>=hi||size>hi-a)return NULL;
        int blocked=0;
        /* The kernel holds the FEX reservation even where no Wine view exists.
         * Free-area mapping cannot replace it; only authorized reserved mapping can. */
        if(!allow_fex && fex_lo && a<fex_hi && a+size>fex_lo) {
            a=down?((fex_lo-size)&~align):((fex_hi+align)&~align);
            continue;
        }
        for(unsigned j=0;j<obstacle_count;j++) {
            if(a<obstacles[j].hi && a+size>obstacles[j].lo) {
                a=down?((obstacles[j].lo-size)&~align):((obstacles[j].hi+align)&~align);
                blocked=1;break;
            }
        }
        if(blocked)continue;
        void *p=mmap((void *)a,size,prot,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
        assert(p==(void *)a);maps++;return p;
    }
    return NULL;
}
static void *map_reserved_area_scoped(void *lo,void *hi,size_t size,int down,int prot,size_t align,int fex_allowed) {
    reserved_calls++;assert_window_excluded((ULONG_PTR)lo,(ULONG_PTR)hi);
    assert(fex_allowed==expected_fex); /* original caller scope, not derived segment */
    if(fex_allowed && fex_lo && (uintptr_t)lo<fex_hi && (uintptr_t)hi>fex_lo) {
        return real_map(max((uintptr_t)lo,fex_lo),min((uintptr_t)hi,fex_hi),size,down,prot,align,1);
    }
    return reserved_mode?real_map((ULONG_PTR)lo,(ULONG_PTR)hi,size,down,prot,align,0):NULL;
}
static void *map_free_area(void *lo,void *hi,size_t size,int down,int prot,size_t align) {
    free_calls++;return real_map((ULONG_PTR)lo,(ULONG_PTR)hi,size,down,prot,align,0);
}
''' + function + r'''
static void *scan(unsigned lo,unsigned hi,size_t bytes,int down,size_t align) {
    expected_fex=fex_arena_covers((void *)(arena+lo*gib),(void *)(arena+hi*gib));
    return ios_map_between_wow_windows((void *)(arena+lo*gib),(void *)(arena+hi*gib),bytes,down,PROT_NONE,align-1,expected_fex);
}
int main(void) {
    void *a=mmap(NULL,arena_size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(a!=MAP_FAILED);arena=(uintptr_t)a;
    /* Real 32 GiB native reservation in the middle hole that the former
     * low-side/above-every-window search never examined. */
    const size_t request=0x7ffff0000ull;
    for(int down=0;down<2;down++) {
        reset();window(56,1);window(16,1); /* deliberately unsorted */
        void *p=scan(4,63,request,down,0x10000);
        assert(p && (uintptr_t)p>=arena+20*gib+0x4000 && (uintptr_t)p+request<=arena+56*gib);
        assert(!((uintptr_t)p&0xffff)&&maps==1);
    }
    /* Caller-specified bounds cannot be relaxed, even with a larger free hole
     * elsewhere in the address map. Neither zero nor a short reservation wins. */
    reset();window(16,1);window(56,1);
    assert(!scan(4,40,request,0,0x10000)&&!maps);
    assert(!scan(32,63,request,1,0x10000)&&!maps);
    assert(!scan(16,20,0x4000,0,0x4000)&&!maps);
    /* A placeholder and every owned 16 KiB overrun guard stay unavailable. */
    reset();window(16,1);
    ios_wow_placeholders[ios_wow_placeholder_count++] = (struct ios_wow_placeholder){arena+40*gib,1,0};
    assert(!scan(4,63,request,0,0x10000));
    void *p=scan(20,21,0x4000,0,0x4000);
    assert(p&&(uintptr_t)p>=arena+20*gib+0x4000);
    /* Captured layout: WoW windows 16..20 and 24..28 GiB with 16 KiB
     * guards, FEX 45..53 GiB, JIT aliases 12..14 GiB. Its largest hole is
     * 28 GiB + 16 KiB .. 45 GiB, far smaller than CEF's real request. */
    for(int down=0;down<2;down++) {
        reset();obstacle(12,2);window(16,1);window(24,1);
        fex_lo=arena+45*gib;fex_hi=arena+53*gib;
        assert(largest_gap(arena+4*gib,arena+63*gib)==17*gib-0x4000);
        assert(!scan(4,63,request,down,0x10000)&&!maps);
    }
    /* Reused slots and adopted placeholder records do not expose a live
     * owner's mapping, and Wine-owned reserved areas keep their normal path. */
    reset();window(56,1);window(16,1);
    ios_wow_placeholders[ios_wow_placeholder_count++] = (struct ios_wow_placeholder){arena+16*gib,1,1};
    reserved_mode=1;p=scan(4,63,request,0,0x10000);
    assert(p&&reserved_calls==1&&!free_calls);
    ios_wow_windows[1].base=0;reserved_mode=0;
    assert(scan(4,63,request,0,0x10000));
    /* Window segmentation must never turn a generic native request into an
     * FEX-authorized one merely because the resulting middle gap equals the arena. */
    for(int down=0;down<2;down++) {
        reset();window(41,0);window(53,0);
        fex_lo=arena+45*gib;fex_hi=arena+53*gib;
        obstacle(4,37);obstacle(57,6);reserved_mode=1;
        assert(!scan(4,63,gib,down,0x10000)&&!maps);
        assert(!scan(44,54,gib,down,0x10000)&&!maps);
        /* An advisory placement clamp may itself equal the FEX range, but
         * an originally unbounded native request still has no FEX authority. */
        expected_fex=0;
        assert(!ios_map_between_wow_windows((void *)fex_lo,(void *)fex_hi,gib,down,PROT_NONE,0xffff,0)&&!maps);
        void *owned=scan(45,53,gib,down,0x10000);
        assert(owned&&(uintptr_t)owned>=fex_lo&&(uintptr_t)owned+gib<=fex_hi);
    }
    /* Ordinary Wine reserved areas remain usable outside FEX-only regions. */
    reset();window(41,0);window(53,0);fex_lo=arena+45*gib;fex_hi=arena+53*gib;
    reserved_mode=1;p=scan(4,63,gib,0,0x10000);
    assert(p&&(uintptr_t)p+gib<=fex_lo&&reserved_calls==1&&!free_calls);
    assert(!ios_map_between_wow_windows((void *)(arena+5*gib),(void *)(arena+4*gib),0x4000,0,0,0x3fff,0));
    assert(!scan(4,63,0,0,0x4000));
    assert(!munmap((void *)arena,arena_size));
    puts("PASS production native WoW64-segment scan: real 32 GiB middle-hole reservation, both directions, caller bounds/guards/reuse; derived FEX-sized gap does not grant ownership, original FEX scope and ordinary reserved mapping preserved; captured fragmentation still returns NULL");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-wow-placement-') as directory:
    path=Path(directory);src=path/'placement.c';exe=path/'placement';src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=30)
