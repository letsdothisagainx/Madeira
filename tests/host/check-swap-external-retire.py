#!/usr/bin/env python3
"""Actual retirement functions against safe metadata models, no memory mappings,
page protection, instruction execution or fault injection. XNU external discard
is modelled as success WITHOUT dirty-state disposal. This is not an APFS test.
"""
from pathlib import Path
import subprocess,tempfile,os,re
root=Path(__file__).resolve().parents[2]
new=(root/'build/ntdll-unix/virtual_ios.c').read_text()
import hashlib
old=(root/'tests/fixtures/run18-retire-baseline.c').read_text()
assert hashlib.sha256(old.encode()).hexdigest()=='fe81797df70faa581d5c81a087fb3bdb0d940bbb58e12db589e4b17de3b56818'

def function(s,name):
    m=re.search(r'^static [^\n]+\b'+name+r'\([^;]*?\)\n\{',s,re.M)
    if not m:raise ValueError(name)
    at=s.index('{',m.start());depth=0
    for end in range(at,len(s)):
        depth+=(s[end]=='{')-(s[end]=='}')
        if depth==0:return s[m.start():end+1]
    raise ValueError('unclosed '+name)
prelude=r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#define MS_KILLPAGES 4
#define P 16384u
#define IOS_SWAP_CHURN_NS 3000000000ull
struct ios_swap_extent {uint64_t evidence_id;char *va;size_t len;uint64_t off;int resv;size_t key;uint64_t born;int img;};
static struct ios_swap_extent ios_swap_ext[16384];
static struct {uint64_t off,len;} ios_swap_free[8192];
static struct {uint64_t off,len;} quarantine[32];
static unsigned ios_swap_n,ios_swap_nfree,queued;
static uint64_t ios_swap_bump,ios_swap_logical=16u<<20,ios_ev_extent_id,ios_ev_vm_generation;
static uintptr_t host_page_mask=P-1;
static int ios_swap_fd=7,ios_swap_v2=1,ios_swap_broad,ios_swap_nchurny;
static unsigned long long ios_swap_merges,ios_swap_bump_back,ios_swap_free_drop,ios_swap_punch_leaks,ios_swap_holes,ios_swap_decommit_remaps,ios_swap_decommit_fallbacks,ios_swap_bytes,ios_swap_img_bytes,ios_swap_releases,ios_swap_unbacks;
static unsigned discarded,remapped,punched,deferred_enabled=1;
static int dirty=1;
static uint64_t ios_swap_now_ns(void){return 100;}
static void ios_swap_churn_note(size_t key,uint64_t age){(void)key;(void)age;}
static size_t ios_swap_copyback(char *a,size_t n){(void)a;return n;}
/* Ordinary metadata result: external pager stays dirty despite successful msync. */
static int ios_ev_discard(void *a,size_t n,int flags){(void)a;(void)n;(void)flags;discarded++;return 0;}
static void *ios_ev_swap_map(void *a,size_t n,int prot,uint64_t off){(void)n;(void)prot;(void)off;remapped++;return a;}
static int ios_swap_punch_room(unsigned n){return queued+n<32;}
static int ios_swap_punch_defer(uint64_t off,size_t len,...){if(!deferred_enabled)return 0;quarantine[queued].off=off;quarantine[queued++].len=len;return 1;}
static int ios_swap_punch_timed(uint64_t off,uint64_t len,const char *why,...){(void)off;(void)len;(void)why;punched++;dirty=0;return 0;}
static void ios_swap_free_add(uint64_t,uint64_t);
static int protect_metadata(void *a,size_t n,int p){(void)a;(void)n;(void)p;return 0;}
#define mprotect protect_metadata
struct fpunchhole {uint64_t fp_offset,fp_length;};
#define F_PUNCHHOLE 1
static int fcntl_metadata(int fd,int op,struct fpunchhole *ph){(void)fd;(void)op;(void)ph;punched++;dirty=0;return 0;}
#define fcntl fcntl_metadata
'''
harness=r'''
#define CHECK(c) do{if(!(c)){fprintf(stderr,"metadata failure line %d: %s\n",__LINE__,#c);return 1;}}while(0)
int main(void){
 char *base=(char *)(uintptr_t)0x100000;
 ios_swap_ext[0]=(struct ios_swap_extent){1,base,4*P,0,1,4*P,1,0};ios_swap_n=1;ios_swap_bytes=4*P;ios_swap_bump=4*P;
 CHECK(ios_swap_punch_resv(base+P,2*P));
 CHECK(dirty==1 && queued==1 && quarantine[0].off==P && quarantine[0].len==2*P);
 CHECK(ios_swap_nfree==0 && ios_swap_bytes==4*P && remapped==1);
 CHECK(ios_swap_take(P)==6*P); /* old offset not reusable while quarantined */
 /* Metadata completion of the real zero-on-reuse contract: only a successful
  * hole-punch receipt permits actual free-list insertion. No syscall issued. */
 dirty=0;ios_swap_free_add(quarantine[0].off,quarantine[0].len);
 CHECK(ios_swap_take(P)==P);
 unsigned before=discarded;
 ios_swap_release_range(base, P,0);
 CHECK(ios_swap_bytes==3*P && queued==2);
 CHECK(discarded==EXPECTED_DISCARD*2 && discarded-before==EXPECTED_DISCARD);
 deferred_enabled=0;unsigned prior=punched;
 ios_swap_give(8*P,P);CHECK(punched==prior+1);
 CHECK(!ios_swap_nchurny);
 printf("external retirement metadata: discard-calls=%u dirty-after-discard-unverified; fresh mapping, splits, quarantine, free-list reuse and timed synchronous fallback PASS\n",discarded);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    t=Path(tmp)
    for label,s,expected in [('baseline',old,1),('corrected',new,0)]:
        bodies=(function(s,'ios_swap_give_extent')+'\n' if label=='corrected' else '')+'\n'.join(function(s,n) for n in ['ios_swap_take','ios_swap_free_add','ios_swap_give','ios_swap_release_range','ios_swap_punch_resv'])
        c=t/(label+'.c');c.write_text(prelude+'\n#define EXPECTED_DISCARD '+str(expected)+'\n'+bodies+harness)
        subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wno-unused-function',str(c),'-o',str(t/label)],check=True)
        subprocess.run([str(t/label)],check=True)
assert 'ios_ev_discard(' not in new
assert 'ios_swap_punch_timed( off, len, "sync-release", extent )' in function(new,'ios_swap_give_extent')
print('PASS baseline/corrected actual-function metadata replay; no device latency or physical-memory saving claimed')
