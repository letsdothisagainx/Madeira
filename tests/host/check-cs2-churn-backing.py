#!/usr/bin/env python3
"""Actual allocation decision and policy on ordinary lifetime/budget metadata.

No mmap, mprotect, fault, captured instruction or guest payload is executed.
The file-map adapter counts normal calls; it does not invent allocation success
for a guest. Native budget/credit locking is tested by the real-header fixture.
"""
from pathlib import Path
import os, subprocess, tempfile, hashlib

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/virtual_ios.c').read_text()

def function(sig):
    a = source.index(sig)
    b = source.index('{', a)
    d, e = 1, b + 1
    while d:
        d += (source[e] == '{') - (source[e] == '}')
        e += 1
    return source[a:e]

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "cs2_churn_backing.h"
enum {VPROT_READ=1,VPROT_WRITE=2,VPROT_EXEC=4,VPROT_WRITECOPY=8,VPROT_GUARD=16,VPROT_COMMITTED=32,
 VPROT_WRITEWATCH=64,VPROT_ARM64EC=256,VPROT_SYSTEM=512,VPROT_PLACEHOLDER=1024,VPROT_FREE_PLACEHOLDER=2048,
 SEC_FILE=0x800000,SEC_IMAGE=0x1000000,SEC_RESERVE=0x4000000,SEC_COMMIT=0x8000000,IOS_VIEW_QUARANTINED=4};
enum {IOS_SW_BACKED,IOS_SW_SMALL,IOS_SW_BAND,IOS_SW_FEXJIT,IOS_SW_PROT,IOS_SW_VIEW,
 IOS_SW_RECOMMIT,IOS_SW_PRESENT,IOS_SW_REFUSED,IOS_SW_MAPFAIL,IOS_SW_CHURN};
struct file_view {void *base;size_t size;unsigned protect,ios_flags;uint64_t ios_evidence_owner,ios_evidence_id;};
static int ios_swap_fd=1,ios_swap_v2=1,ios_swap_wide=1,ios_swap_broad=0;
static unsigned ios_swap_n;static size_t ios_swap_min=256u<<10;
static size_t host_page_size=MD_CHURN_PAGE;
static uint64_t ios_swap_churn_skips, now=1, map_calls, query_calls;
static uintptr_t user_space_limit=UINTPTR_MAX-16384, current_owner=1;
static uint64_t current_lease=34, native_available=UINT64_C(1024)<<20, native_floor=UINT64_C(192)<<20;
static int fixture_is_cs2=1,fixture_budget_valid=1;
static unsigned last_reason;
static int ios_swap_eligible(void*a,size_t n,unsigned p,struct file_view*v){(void)a;(void)n;(void)p;(void)v;return 0;}
static void ios_swap_back(void*a,size_t n,unsigned p){(void)a;(void)n;(void)p;assert(0);}
static int ios_swap_overlaps(const void*a,size_t n){(void)a;(void)n;return 0;}
static int ios_swap_churny(size_t n){(void)n;return 0;}
static int ios_swap_is_fexjit(uintptr_t a,size_t n){return a<0x80000000u && a+n>0x7c000000u;}
static int ios_jit_anon_alias_overlaps(const void*a,size_t n,uintptr_t*b,uintptr_t*e){(void)a;(void)n;(void)b;(void)e;return 0;}
static int is_view_valloc(const struct file_view*v){return !(v->protect&(SEC_FILE|SEC_RESERVE|SEC_COMMIT));}
static int get_unix_prot(unsigned p){return p;}
static int ios_swap_map(void*a,size_t n,int p){(void)a;(void)n;(void)p;++map_calls;return IOS_SW_BACKED;}
static void ios_swap_note(int why,size_t n){(void)n;last_reason=why;}
static uint64_t ios_swap_now_ns(void){return now;}
int ios_cs2_current_private_owner(uintptr_t p){return fixture_is_cs2 && p==current_owner;}
int ios_native_current_process_identity(uintptr_t*o,uint64_t*l,unsigned*p){*o=current_owner;*l=current_lease;*p=1;return 1;}
''' + function('static int ios_swap_why(') + '\n' + function('static void ios_swap_commit(') + r'''
static uint64_t generation;
static struct file_view commit(uintptr_t base,size_t bytes){
 struct file_view v={(void*)base,bytes,VPROT_READ|VPROT_WRITE|VPROT_COMMITTED,0,current_owner,++generation};
 ios_swap_commit(v.base,v.size,v.protect,&v);return v;
}
static void reset(void){
 memset(md_churn_classes,0,sizeof(md_churn_classes));memset(md_churn_views,0,sizeof(md_churn_views));
 memset(&md_churn_stats,0,sizeof(md_churn_stats));now=1;map_calls=query_calls=0;
 current_owner=1;current_lease=34;fixture_is_cs2=fixture_budget_valid=1;
 native_available=UINT64_C(1024)<<20;ios_swap_wide=ios_swap_v2=1;
}
static void warm_n(size_t bytes,unsigned count){
 int valid=fixture_budget_valid;fixture_budget_valid=0;
 for(unsigned i=0;i<count;++i){commit(0x1000000,bytes);now+=1000000;md_churn_unmapped(0x1000000,bytes,now);}
 fixture_budget_valid=valid;
 assert(map_calls==count && MD_CHURN_GET(held)==0);
}
static void warm(size_t bytes){warm_n(bytes,8);assert(!query_calls);}
static uint64_t ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static pthread_mutex_t vm=PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *arg){
 uintptr_t base=0x10000000+(uintptr_t)arg*(1u<<20);
 for(unsigned i=0;i<1000;++i){
  pthread_mutex_lock(&vm);++now;commit(base,512u<<10);pthread_mutex_unlock(&vm);
  pthread_mutex_lock(&vm);md_churn_unmapped(base,512u<<10,++now);pthread_mutex_unlock(&vm);
 }
 return NULL;
}
int main(void){
 const size_t n=512u<<10;reset();warm(n);
 struct file_view v=commit(0x1000000,n);
 assert(map_calls==8 && query_calls==1 && last_reason==IOS_SW_CHURN && MD_CHURN_GET(held)==n);
 assert(md_churn_charged_range((uintptr_t)v.base,n,v.ios_evidence_id));
 assert(!md_churn_charged_range((uintptr_t)v.base,n,v.ios_evidence_id+1));
 /* Decommit/protection changes do not uncharge or recycle a live commitment. */
 assert(MD_CHURN_GET(held)==n);
 md_churn_unmapped((uintptr_t)v.base,n/2,++now);
 assert(MD_CHURN_GET(held)==n/2 && !md_churn_charged_range((uintptr_t)v.base,n/2,v.ios_evidence_id));
 assert(md_churn_charged_range((uintptr_t)v.base+n/2,n/2,v.ios_evidence_id));
 assert(!md_churn_begin(1,34,++generation,(uintptr_t)v.base,n/2,now));
 md_churn_unmapped((uintptr_t)v.base+n/2,n/2,++now);assert(!MD_CHURN_GET(held));
 md_churn_unmapped((uintptr_t)v.base,n,++now);assert(!MD_CHURN_GET(held));
 puts("PASS learned turnover; actual commit skips the file-map adapter; generation, partial split, duplicate unmap and decommit/quarantine accounting");

 reset();warm_n(n,128);map_calls=0;query_calls=0;
 for(unsigned i=0;i<MD_CHURN_CAP/n;++i)commit(0x1000000+(uintptr_t)i*n,n);
 assert(MD_CHURN_GET(held)==MD_CHURN_CAP && MD_CHURN_GET(peak)==MD_CHURN_CAP);
 uint64_t queries=query_calls;commit(0x7000000,n);
 assert(query_calls==queries && MD_CHURN_GET(cap_denied)==1 && map_calls==1);
 for(unsigned i=0;i<MD_CHURN_CAP/n;++i)md_churn_unmapped(0x1000000+(uintptr_t)i*n,n,++now);
 assert(!MD_CHURN_GET(held));
 puts("PASS full committed-cost aggregate cap; no native budget query once exhausted; actual-unmap release balances all credits");

 reset();warm(n);native_available=2*native_floor+n-1;
 commit(0x1000000,n);assert(map_calls==9 && !MD_CHURN_GET(held) && MD_CHURN_GET(pressure_denied)==1);
 md_churn_unmapped(0x1000000,n,++now);native_available=2*native_floor+n;
 commit(0x1000000,n);assert(MD_CHURN_GET(held)==n && map_calls==9);
 puts("PASS fresh headroom threshold leaves two unchanged floors and charges the full commitment; destination shortage is not concealed");

 reset();warm(n);current_lease=35;commit(0x2000000,n);assert(map_calls==9 && !MD_CHURN_GET(held));
 current_owner=2;commit(0x3000000,n);assert(map_calls==10 && !MD_CHURN_GET(held));
 reset();warm(n);fixture_is_cs2=0;commit(0x2000000,n);assert(map_calls==9 && !MD_CHURN_GET(held));
 fixture_is_cs2=1;
 struct file_view sub={(void*)0x3000000,2*n,35,0,1,++generation};
 ios_swap_commit(sub.base,n,35,&sub);assert(!MD_CHURN_GET(held));
 unsigned excluded[]={VPROT_EXEC,VPROT_GUARD,VPROT_WRITECOPY,VPROT_WRITEWATCH,SEC_FILE,SEC_IMAGE,VPROT_ARM64EC,VPROT_SYSTEM};
 for(unsigned i=0;i<sizeof(excluded)/sizeof(*excluded);++i){
  struct file_view x={(void*)0x4000000,n,35|excluded[i],0,1,++generation};
  ios_swap_commit(x.base,n,x.protect,&x);assert(!MD_CHURN_GET(held));
 }
 struct file_view j={(void*)0x7c000000u,n,35,0,1,++generation};ios_swap_commit(j.base,n,35,&j);assert(!MD_CHURN_GET(held));
 puts("PASS CS2 owner/lease isolation; Steam, reservation subcommits, executable, guarded, watched, section/image, native/system and JIT exclusions");

 reset();for(unsigned i=0;i<12;++i){commit(0x1000000,n);now+=MD_CHURN_YOUNG_NS;md_churn_unmapped(0x1000000,n,now);}
 assert(!MD_CHURN_GET(bypasses) && !query_calls);
 reset();warm(n);v=commit(0x1000000,n);current_lease=35;
 assert(!md_churn_begin(1,35,++generation,(uintptr_t)v.base,n,now));assert(MD_CHURN_GET(held)==n);
 md_churn_unmapped((uintptr_t)v.base,n,++now);commit(0x1000000,n);assert(!MD_CHURN_GET(held));
 puts("PASS long-lived classes remain file-backed; unretired/quarantined old lifetime cannot transfer credit to a recycled owner/address");

 reset();warm(n);fixture_budget_valid=0;commit(0x2000000,n);
 assert(map_calls==9 && !MD_CHURN_GET(held));
 puts("PASS unavailable native budget fails closed to ordinary backing");

 reset();warm(n);pthread_t threads[4];
 for(uintptr_t i=0;i<4;++i)assert(!pthread_create(&threads[i],NULL,worker,(void*)i));
 for(unsigned i=0;i<4;++i)assert(!pthread_join(threads[i],NULL));
 assert(!MD_CHURN_GET(held) && MD_CHURN_GET(peak)<=MD_CHURN_CAP);
 puts("PASS 4000 overlapping ordinary lifetimes serialized by the existing VM-lock contract; no stranded commitment");

 reset();warm(n);uint64_t start=ns();
 for(unsigned i=0;i<10000;++i){commit(0x1000000,n);md_churn_unmapped(0x1000000,n,++now);}
 printf("normal metadata decision+retirement: %llu ns/op (host only; native query adapter excluded); policy storage=%zu bytes\n",
  (unsigned long long)((ns()-start)/10000),sizeof(md_churn_views)+sizeof(md_churn_classes)+sizeof(md_churn_stats));
 assert(!MD_CHURN_GET(held));return 0;
}
'''

budget = r'''
#include <stdint.h>
extern uint64_t native_available,native_floor,query_calls;
extern int fixture_budget_valid;
int madeira_private_commit_budget(uint64_t*a,uint64_t*f){++query_calls;*a=native_available;*f=native_floor;return fixture_budget_valid;}
'''
# Shared fixture variables are not production state; keep the weak provider in
# another translation unit, just as the real VM consumer links its native peer.
for name in ('native_available','native_floor','query_calls','fixture_budget_valid'):
    code = code.replace('static uint64_t current_lease=34, native_available=', 'uint64_t current_lease=34, native_available=') if name=='native_available' else code
code=code.replace('static uint64_t ios_swap_churn_skips, now=1, map_calls, query_calls;',
                  'static uint64_t ios_swap_churn_skips, now=1, map_calls; uint64_t query_calls;')
code=code.replace('static int fixture_is_cs2=1,fixture_budget_valid=1;', 'static int fixture_is_cs2=1; int fixture_budget_valid=1;')
with tempfile.TemporaryDirectory(prefix='madeira-churn-normal-') as tmp:
    p=Path(tmp);(p/'test.c').write_text(code);(p/'budget.c').write_text(budget)
    baseline=(root/'tests/fixtures/run26-swap-commit-baseline.c').read_text()
    assert hashlib.sha256(baseline.encode()).hexdigest()=='826e71695636df28579662241ed9e5d406c18353f07b8181719841c52ce338d0'
    before=code.split('static uint64_t generation;',1)[0].replace(function('static void ios_swap_commit('),baseline,1)
    before+=r'''
int main(void){
 for(unsigned i=0;i<9;++i){
  struct file_view v={(void*)0x1000000,512u<<10,35,0,1,i+1};
  ios_swap_commit(v.base,v.size,35,&v);now+=1000000;md_churn_unmapped((uintptr_t)v.base,v.size,now);
 }
 assert(map_calls==9 && !MD_CHURN_GET(bypasses));
 puts("BASELINE actual ae1a6498 decision: 9/9 repeated private commits choose file mapping; no learned bypass");return 0;
}
'''
    (p/'baseline.c').write_text(before)
    subprocess.run([os.getenv('CC','cc'),'-std=c11','-D_POSIX_C_SOURCE=200809L','-O2','-Wall','-Wextra','-Werror',
                    '-Wno-unused-function','-Wno-unused-variable','-I'+str(root/'build/ntdll-unix'),str(p/'baseline.c'),str(p/'budget.c'),
                    '-o',str(p/'baseline')],check=True)
    subprocess.run([str(p/'baseline')],check=True)
    subprocess.run([os.getenv('CC','cc'),'-std=c11','-D_POSIX_C_SOURCE=200809L','-O2','-Wall','-Wextra','-Werror','-pthread',
                    '-I'+str(root/'build/ntdll-unix'),str(p/'test.c'),str(p/'budget.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)

# Verify the real producer hooks: no policy-triggered unmap, migration, payload
# read, protection change or successful allocation fabrication.
assert 'if (!munmap( start,' in source
assert source.count('ios_churn_unmap_note(start,')==4
assert 'md_churn_charged_range' in function('static void ios_verify_commit_zero(')
assert 'churn-anonymous-zero' in function('static NTSTATUS decommit_pages_evidence_impl(')
decision=function('static void ios_swap_commit(')
assert 'view->base == base && view->size == size' in decision
assert 'madeira_private_commit_budget(&available,&floor)' in decision
assert 'mmap(' not in decision and 'memcpy(' not in decision and 'mprotect(' not in decision
print('PASS actual production eligibility/decision and safe native-unmap hooks; no iPhone paging or FPS improvement inferred')
