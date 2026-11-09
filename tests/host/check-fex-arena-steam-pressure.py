#!/usr/bin/env python3
"""Replay the 1005-view Steam census through production Wine arena code.

The census counts/bytes and nine owner leases are from the device. Allocation
order and the 59 unlisted small sizes are deliberately synthetic. Both A/B
runs use identical requests, releases and leases; only placement differs.
"""
import json
import re
import runpy
from pathlib import Path

root = Path(__file__).resolve().parents[2]
fixture = json.loads((root / 'tests/fixtures/fex-arena/steam-1005-view-census.json').read_text())
shared = runpy.run_path(str(root / 'tests/host/check-fex-arena-placement.py'), run_name='arena_fixture')
code = shared['code'].split('static void workload(int legacy)', 1)[0]
code = code.replace('0xb50000000ULL, arena_hi = 0xd50000000ULL', '0xb60000000ULL, arena_hi = 0xd60000000ULL')
owner_init = ','.join('{(void *)0x%x,%d,0}' % (owner['owner'], owner['lease']) for owner in fixture['owners'])
code, changes = re.subn(r'owners\[3\] = \{.*?\};', 'owners[9] = {' + owner_init + '};', code, count=1, flags=re.S)
assert changes == 1
code = code.replace('legacy ? legacy_map_reserved_area_inner(', 'legacy ? alignment_only_map_reserved_area_inner(')
classes = ',\n'.join('{' + ','.join(str(n) for n in owner['classes']) + '}' for owner in fixture['owners'])
small = [row for row in fixture['visible_size_buckets'] if row['size'] < 0x200000]
small_c = ','.join('{0x%x,%d,0x%x}' % (row['size'], row['views'], row['flags']) for row in small)
code += 'static const unsigned observed_classes[9][7] = {' + classes + '};\n'
code += 'static const struct { size_t size;unsigned count,flags; } observed_small[]={' + small_c + '};\n'
code += r'''
static unsigned other_owner,other_used[9];
static struct file_view *other(size_t size,unsigned flags,int prior)
{
    while(other_owner<9 && other_used[other_owner]==observed_classes[other_owner][6])other_owner++;
    assert(other_owner<9);
    current_owner=owners[other_owner].owner;other_used[other_owner]++;
    return must_allocate(size,0x10000,flags,prior);
}
static void measurements(size_t *total,size_t *largest,size_t *aligned)
{
    struct file_view *view;uintptr_t cursor=arena_lo;*total=*largest=*aligned=0;
    /* Raw logical-VAD complement, as in the production census. The allocator's
     * free_ranges additionally rounds to64KiB and is not a raw-free census. */
    WINE_RB_FOR_EACH_ENTRY(view,&views_tree,struct file_view,entry){
        uintptr_t lo=cursor,hi=min((uintptr_t)view->base,arena_hi);
        if((uintptr_t)view->base>=arena_hi)break;
        if(hi>lo){*total+=hi-lo;if(hi-lo>*largest)*largest=hi-lo;}
        if(lo>UINTPTR_MAX-0xffffff)continue;
        lo=(lo+0xffffff)&~(uintptr_t)0xffffff;
        if(hi>lo&&hi-lo>*aligned)*aligned=hi-lo;
        if((uintptr_t)view->base+view->size>cursor)cursor=(uintptr_t)view->base+view->size;
    }
    if(cursor<arena_hi){size_t tail=arena_hi-cursor;*total+=tail;if(tail>*largest)*largest=tail;
        cursor=(cursor+0xffffff)&~(uintptr_t)0xffffff;
        if(arena_hi>cursor&&arena_hi-cursor>*aligned)*aligned=arena_hi-cursor;}
}
static void pressure(int prior)
{
    struct file_view *scratch[61];unsigned scratch_count=0;
    size_t total,largest,aligned,covered=0;
    reset();other_owner=0;memset(other_used,0,sizeof(other_used));
    /* 336 genuine 16MiB-aligned reserved rpmalloc spans. */
    for(unsigned owner=0;owner<9;owner++){
        current_owner=owners[owner].owner;
        for(unsigned i=0;i<observed_classes[owner][0];i++)must_allocate(0x1000000,0x1000000,3,prior);
    }
    /* One of the 59 unlisted sizes plus an observed4KiB metadata view make
     * the first scratch base 0x570000 off the16MiB grid under the old policy.
     * This is a controlled order, not a claim about device instruction order. */
    other(0x560000,0x23,prior);other(0x1000,3,prior);
    for(unsigned owner=0;owner<9;owner++){
        current_owner=owners[owner].owner;
        for(unsigned i=0;i<observed_classes[owner][1];i++)scratch[scratch_count++]=must_allocate(0x1000000,0x10000,0x23,prior);
        for(unsigned i=0;i<observed_classes[owner][2];i++)must_allocate(0x802000,0x10000,0,prior);
        for(unsigned i=0;i<observed_classes[owner][3];i++)must_allocate(0x200000,0x10000,0x23,prior);
        for(unsigned i=0;i<observed_classes[owner][4];i++)must_allocate(0x900000,0x10000,0x23,prior);
        for(unsigned i=0;i<observed_classes[owner][5];i++)must_allocate(0x800000,0x10000,0x23,prior);
    }
    assert(scratch_count==61);
    unsigned skipped=0;
    for(unsigned i=0;i<ARRAY_SIZE(observed_small);i++)for(unsigned j=0;j<observed_small[i].count;j++){
        if(!skipped&&observed_small[i].size==0x1000&&observed_small[i].flags==3){skipped=1;continue;}
        other(observed_small[i].size,observed_small[i].flags,prior);
    }
    /* Remaining51 synthetic sizes plus7 one-MiB metadata views below total
     * exactly44.390625MiB across59views, the unlisted non-span census bytes. */
    for(unsigned i=0;i<50;i++)other(0xa0000,0x23,prior);
    other(0xc4000,0x23,prior);
    /* Release the same fixed scratch indices6..0 in both A/B runs. These
     * descend in address in the old policy. Each one-MiB metadata
     * request takes the earliest free location; no fixed guest mapping is
     * manufactured. Then replace that ordinary16MiB scratch reservation. */
    for(unsigned n=0;n<7;n++){
        unsigned selected=6-n;
        struct file_view *old=scratch[selected];void *owner=old->ios_fex_owner;
        current_owner=owner;delete_view(old);other(0x100000,0x23,prior);
        current_owner=owner;must_allocate(0x1000000,0x10000,0x23,prior);
    }
    for(unsigned i=0;i<ARRAY_SIZE(storage);i++)if(used[i])covered+=storage[i].size;
    measurements(&total,&largest,&aligned);
    assert(live==1005&&covered==0x1f7ced000ULL&&total==0x8313000);
    for(unsigned owner=0;owner<9;owner++){
        unsigned count=0;
        assert(other_used[owner]==observed_classes[owner][6]);
        for(unsigned i=0;i<ARRAY_SIZE(storage);i++)if(used[i]&&storage[i].ios_fex_owner==owners[owner].owner){
            assert(storage[i].ios_fex_lease==owners[owner].lease);count++;
        }
        unsigned wanted=0;for(unsigned i=0;i<7;i++)wanted+=observed_classes[owner][i];
        assert(count==wanted);
    }
    current_owner=owners[3].owner;
    struct file_view *next=allocate(0x1000000,0x1000000,3,prior);
    printf("steam1005 policy=%s views-before=1005 covered=0x%zx free=0x%zx largest=0x%zx max-aligned=0x%zx next16=%s\n",
           prior?"prior":"production",covered,total,largest,aligned,next?"success":"failure");
    if(prior){assert(largest==0xf00000&&aligned==0x570000);assert(!next);return;}
    assert(next);
    /* Continued helper/thread creation can use guarded call/return stacks,
     * lookup caches and larger dispatcher scratch without changing budgets. */
    assert(allocate(0x802000,0x10000,0,0));
    assert(allocate(0x200000,0x10000,0x23,0));
    assert(allocate(0x2000000,0x10000,0x23,0));
    unsigned before=live;ios_fex_reclaim_process_views(owners[3].owner);assert(live==before);
    owners[3].lease++;owners[3].quiescent=1;ios_fex_reclaim_process_views(owners[3].owner);assert(live==before);
    owners[3].lease--;owners[3].quiescent=1;ios_fex_reclaim_process_views(owners[3].owner);assert(live<before);
    for(unsigned i=0;i<ARRAY_SIZE(storage);i++)if(used[i]){
        assert(storage[i].ios_fex_owner!=owners[3].owner);
        assert(storage[i].ios_fex_lease==ios_thread_process_lease(storage[i].ios_fex_owner,0));
    }
    owners[3].lease++;owners[3].quiescent=0;current_owner=owners[3].owner;
    ios_fex_owners[3]=(struct ios_fex_owner_record){owners[3].owner,NULL,owners[3].lease,0};
    for(unsigned i=0;i<32;i++)assert(allocate(0x1000000,0x1000000,3,0));
    for(unsigned owner=0;owner<9;owner++){owners[owner].quiescent=1;ios_fex_reclaim_process_views(owners[owner].owner);}
    assert(!live&&ranges[0].base==(void *)arena_lo&&ranges[0].end==(void *)arena_hi);
}
int main(void)
{
    /* A preferred16MiB grid must never tighten the caller's real contract:
     * an exact16MiB hole beginning64KiB off-grid still succeeds on fallback. */
    reset();
    void *low=(void *)(arena_lo+0x10000),*high=(void *)(arena_lo+0x1010000);
    assert(map_reserved_area_inner(low,high,0x1000000,0,0,0xffff,1)==low);
    assert(map_calls==1&&last_map==low);
    /* Explicit TOP_DOWN uses the original alignment unchanged. */
    assert(map_reserved_area_inner(low,high,0x1000000,1,0,0xffff,1)==low);
    /* A stricter32MiB caller requirement is never relaxed to16MiB/64KiB. */
    unsigned before_maps=map_calls;
    assert(!map_reserved_area_inner((void *)(arena_lo+0x1000000),(void *)(arena_lo+0x2000000),0x1000000,0,0,0x1ffffff,1));
    assert(map_calls==before_maps);
    /* Nonmultiple9MiB and unrelated reserved regions keep bottom-up placement. */
    assert(map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x900000,0,0,0xffff,1)==(void *)arena_lo);
    arena.fex_only=0;
    assert(map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x1000000,0,0,0xffff,0)==(void *)arena_lo);
    arena.fex_only=1;
    assert(!map_reserved_area_inner((void *)arena_lo,(void *)arena_hi,0x1000000,0,0,0xffff,0));
    pressure(1);pressure(0);
    puts("PASS Steam1005 production allocator: exact census geometry A/B, nine owner generations, guarded stacks, continued allocation and reclamation");
    return 0;
}
'''
shared['run_fixture'](code, 'fex-arena-steam-pressure-')
