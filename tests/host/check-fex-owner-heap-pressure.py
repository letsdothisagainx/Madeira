#!/usr/bin/env python3
"""Execute production Windows/iOS rpmalloc and the owned module-heap boundary.

Four isolated ELF images stand in for four PE images; Windows VM/TLS calls are
owned host shims. The pinned allocator, its 16MiB spans and size classes, Wine's
production reserved-area search/tree/owner tags, and owner_allocator.cpp execute.
The 119-thread allocation sequence and external VAD positions are deliberately
synthetic. Calibrating 383 rpmalloc spans to the captured size/flags count is not
proof that every captured view came from rpmalloc. No original VAD positions or
malloc call sequence can be recovered from the bounded device census. The old
run matches total views, covered/free bytes and maximum gap; its hole count is
not a reconstruction of the captured505holes.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import runpy
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RPM = ROOT / 'FEX/External/rpmalloc'
COMPAT = ROOT / 'build/fex-compat'
PIN = '812c2b9cf4310ffacf14e6b64066e78ab0c394b5'
HASH = 'd810c3695daab1c74e92ba971f1f068b44b3d6172e0a69c5a0c6f8a07234f96b'
fixture = json.loads((ROOT / 'tests/host/fixtures/fex-cs2-081641.json').read_text())
assert subprocess.check_output(['git','-C',str(RPM),'rev-parse','HEAD'],text=True).strip() == PIN
original = (RPM / 'rpmalloc/rpmalloc.c').read_text()
assert hashlib.sha256(original.encode()).hexdigest() == HASH
assert hashlib.sha256((RPM/'rpmalloc/rpmalloc.h').read_bytes()).hexdigest() == '81c4970f89951c177cd83f29ec7c1989e14c31f3bb5e2eda4a2b84e1dd338fb6'
entry=subprocess.check_output(['git','-C',str(ROOT/'FEX'),'ls-tree','HEAD','External/rpmalloc'],text=True).split()
assert entry[:3]==['160000','commit',PIN]
# The two reviewed failure-propagation guards are the complete generated diff.
checked = original
for before, after in [
    ('block_t* block = global_memory_interface->memory_map(heap_size, 0, &offset, &mapped_size);\n#if ENABLE_DECOMMIT',
     'block_t* block = global_memory_interface->memory_map(heap_size, 0, &offset, &mapped_size);\n\tif (!block)\n\t\treturn 0;\n#if ENABLE_DECOMMIT'),
    ('heap_t* heap = heap_allocate(1);\n\trpmalloc_assume(heap != 0);',
     'heap_t* heap = heap_allocate(1);\n\tif (!heap)\n\t\treturn 0;\n\trpmalloc_assume(heap != 0);'),
]:
    assert checked.count(before) == 1
    checked = checked.replace(before,after)
checked = checked.replace('void fex_ios_rpm_lock(void) {\n\tuintptr_t self, expected = 0;',
    '#include "owner_allocator_backoff.h"\nvoid fex_ios_rpm_lock(void) {\n\tuintptr_t self;\n\tunsigned madeira_contended_polls = 0;').replace(
    '\twhile (!atomic_compare_exchange_weak_explicit(&fex_ios_rpm_owner, &expected, self, memory_order_acquire,\n\t                                              memory_order_relaxed)) {\n\t\texpected = 0;\n\t\twait_spin();\n\t}\n\tfex_ios_rpm_depth = 1;',
    '\twhile (!madeira_fex_rpm_try_owner(self)) {\n\t\tif (++madeira_contended_polls == 64) {\n\t\t\tmadeira_contended_polls = 0;\n\t\t\tmadeira_fex_rpm_backoff();\n\t\t} else {\n\t\t\twait_spin();\n\t\t}\n\t}\n\tmadeira_fex_rpm_publish_depth();')

WINDOWS = r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
#define WINAPI
#define NTAPI
#define NTSYSAPI
#define CALLBACK
#define VOID void
#define FALSE 0
#define TRUE 1
#define MEM_RESERVE 0x2000
#define MEM_COMMIT 0x1000
#define MEM_RELEASE 0x8000
#define MEM_DECOMMIT 0x4000
#define MEM_LARGE_PAGES 0x20000000
#define PAGE_NOACCESS 1
#define PAGE_READWRITE 4
#define MemExtendedParameterAddressRequirements 1
#define INVALID_HANDLE_VALUE ((void*)(uintptr_t)-1)
typedef void* PVOID;
typedef void* HANDLE;
typedef void* HMODULE;
typedef size_t SIZE_T;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef int BOOL;
typedef int32_t NTSTATUS;
typedef unsigned char BOOLEAN;
typedef union { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { void* LowestStartingAddress; void* HighestEndingAddress; size_t Alignment; } MEM_ADDRESS_REQUIREMENTS;
typedef struct { unsigned long Type; void* Pointer; } MEM_EXTENDED_PARAMETER;
typedef struct { size_t dwPageSize; size_t dwAllocationGranularity; void* lpMaximumApplicationAddress; } SYSTEM_INFO;
#ifdef __cplusplus
extern "C" {
#endif
void* VirtualAlloc(void*,size_t,unsigned long,unsigned long);
int VirtualFree(void*,size_t,unsigned long);
void* VirtualAlloc2(void*,void*,size_t,unsigned long,unsigned long,MEM_EXTENDED_PARAMETER*,unsigned long);
void GetSystemInfo(SYSTEM_INFO*);
void* GetCurrentProcess(void);
void* GetModuleHandleW(const void*);
void* GetModuleHandleA(const char*);
void* GetProcAddress(void*,const char*);
void* NtCurrentTeb(void);
void* GetStdHandle(unsigned long);
int WriteFile(void*,const void*,unsigned long,unsigned long*,void*);
void* CreateFileA(const char*,unsigned long,unsigned long,void*,unsigned long,unsigned long,void*);
unsigned long FlsAlloc(void (*)(void*));
int FlsSetValue(unsigned long,void*);
int FlsFree(unsigned long);
unsigned long TlsAlloc(void);
void* TlsGetValue(unsigned long);
int TlsSetValue(unsigned long,void*);
int TlsFree(unsigned long);
#ifdef __cplusplus
}
#endif
'''
ABI = r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
struct bridge {
 uintptr_t lo,hi;
 void* (*reserve)(unsigned,size_t,size_t,unsigned);
 int (*commit)(unsigned,void*,size_t);
 void (*decommit)(unsigned,void*,size_t);
 void (*release)(unsigned,void*);
};
struct measurement { size_t spans[4],views[4],reserved[4],committed[4],free_bytes,maxgap; unsigned failed_maps; };
'''
MODULE_C = r'''
#define _GNU_SOURCE
#include "windows.h"
#include "abi.h"
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
static struct bridge host;
static unsigned owner;
static _Thread_local struct { unsigned char pad[0x30]; void* self; } teb;
void* NtCurrentTeb(void) { teb.self=&teb;return &teb; }
NTSTATUS NtDelayExecution(BOOLEAN alertable,const LARGE_INTEGER* timeout) {
 assert(!alertable && timeout->QuadPart==-1000);
 struct timespec t={0,100000}; nanosleep(&t,NULL); return 0;
}
void* GetCurrentProcess(void) { return (void*)1; }
void GetSystemInfo(SYSTEM_INFO* i) { memset(i,0,sizeof(*i));i->dwPageSize=4096;i->dwAllocationGranularity=65536;i->lpMaximumApplicationAddress=(void*)UINTPTR_MAX; }
void* GetModuleHandleW(const void* n) { (void)n;return (void*)1; }
void* GetModuleHandleA(const char* n) { (void)n;return (void*)1; }
void* GetProcAddress(void* h,const char* n) { (void)h;return !strcmp(n,"VirtualAlloc2")?(void*)VirtualAlloc2:NULL; }
void* VirtualAlloc2(void* h,void* p,size_t n,unsigned long flags,unsigned long prot,MEM_EXTENDED_PARAMETER* e,unsigned long count) {
 (void)h;(void)prot;assert(!p && count==1 && e->Type==MemExtendedParameterAddressRequirements);
 MEM_ADDRESS_REQUIREMENTS* r=e->Pointer;assert((uintptr_t)r->LowestStartingAddress==host.lo && (uintptr_t)r->HighestEndingAddress==host.hi-1);
 void* result=host.reserve(owner,n,r->Alignment?r->Alignment:65536,(flags&MEM_COMMIT)?0x23:3);
 if(result&&(flags&MEM_COMMIT))assert(host.commit(owner,result,n));
 return result;
}
void* VirtualAlloc(void* p,size_t n,unsigned long f,unsigned long prot) { (void)prot;assert(p&&f==MEM_COMMIT);return host.commit(owner,p,n)?p:NULL; }
int VirtualFree(void* p,size_t n,unsigned long f) { if(f==MEM_DECOMMIT)host.decommit(owner,p,n);else {assert(f==MEM_RELEASE&&!n);host.release(owner,p);}return 1; }
void* GetStdHandle(unsigned long n) { (void)n;return NULL; }
int WriteFile(void* h,const void* p,unsigned long n,unsigned long* written,void* x) { (void)h;(void)p;(void)x;*written=n;return 1; }
void* CreateFileA(const char* p,unsigned long a,unsigned long s,void* x,unsigned long c,unsigned long f,void* t) { (void)p;(void)a;(void)s;(void)x;(void)c;(void)f;(void)t;return NULL; }
unsigned long FlsAlloc(void (*d)(void*)) { pthread_key_t key;assert(!pthread_key_create(&key,d));return key; }
int FlsSetValue(unsigned long k,void* p) { return !pthread_setspecific((pthread_key_t)k,p); }
int FlsFree(unsigned long k) { return !pthread_key_delete((pthread_key_t)k); }
unsigned long TlsAlloc(void) { pthread_key_t key;assert(!pthread_key_create(&key,NULL));return key; }
void* TlsGetValue(unsigned long k) { return pthread_getspecific((pthread_key_t)k); }
int TlsSetValue(unsigned long k,void* p) { return !pthread_setspecific((pthread_key_t)k,p); }
int TlsFree(unsigned long k) { return !pthread_key_delete((pthread_key_t)k); }
volatile int FEX_AllocWatch_Armed;
void FEX_AllocWatch_Event(const void* p,unsigned e) { (void)p;(void)e; }
#include "rpmalloc-checked.c"
_Static_assert(PLATFORM_WINDOWS && !PLATFORM_POSIX,"Execute production Windows callbacks");
_Static_assert(SPAN_SIZE==0x1000000,"Execute production iOS 16MiB geometry");
_Static_assert(SMALL_PAGE_SIZE==0x10000 && MEDIUM_PAGE_SIZE==0x400000 && LARGE_PAGE_SIZE==0x1000000,"Preserve production class geometry");
void module_bind(unsigned o,const struct bridge* b) {
 owner=o;host=*b;ios_fex_band_base=b->lo;ios_fex_band_end=b->hi-1;
 rpmalloc_config_t c={.page_size=4096};assert(!rpmalloc_initialize_config(NULL,&c));
 assert(get_size_class(7184)==76 && global_size_class[76].block_size==8192);
 assert(get_page_type(get_size_class(8*1024*1024))==PAGE_LARGE);
}
void module_old_attach(void) { fex_ios_rpm_lock();rpmalloc_thread_initialize();fex_ios_rpm_unlock(); }
void module_detach(void) { fex_ios_rpm_lock();rpmalloc_thread_finalize();fex_ios_rpm_unlock(); }
void* module_old_alloc(size_t n) { fex_ios_rpm_lock();void* p=rpmalloc(n);fex_ios_rpm_unlock();return p; }
void* module_old_final_alloc(size_t a,size_t n) { fex_ios_rpm_lock();void* p=rpaligned_alloc(a,n);fex_ios_rpm_unlock();return p; }
void module_old_free(void* p) { fex_ios_rpm_lock();rpfree(p);fex_ios_rpm_unlock(); }
void module_old_collect(void) { fex_ios_rpm_lock();rpmalloc_thread_collect();fex_ios_rpm_unlock(); }
'''
MODULE_CPP = r'''
#include "owner_allocator.h"
extern "C" {
void* module_new_alloc(size_t n) { return FEXCore::Allocator::malloc(n); }
void* module_new_calloc(size_t n,size_t s) { return FEXCore::Allocator::calloc(n,s); }
void* module_new_align(size_t a,size_t n) { return FEXCore::Allocator::memalign(a,n); }
int module_new_posix(void** p,size_t a,size_t n) { return FEXCore::Allocator::posix_memalign(p,a,n); }
void* module_new_valloc(size_t n) { return FEXCore::Allocator::valloc(n); }
void* module_new_realloc(void* p,size_t n) { return FEXCore::Allocator::realloc(p,n); }
void module_new_free(void* p) { FEXCore::Allocator::free(p); }
size_t module_new_usable(void* p) { return FEXCore::Allocator::malloc_usable_size(p); }
void module_old_attach(void);
void module_new_attach(void) { module_old_attach(); FEXCore::Allocator::InitializeThread(); }
void* module_new_final_alloc(size_t a,size_t n) { return FEXCore::Allocator::aligned_alloc(a,n); }
}
'''

# Reuse the extraction of actual Wine placement, VAD insertion/removal, free
# ranges and owner generation checks. Only the fixture's native syscall stubs
# change: these ones hold real zero-filled virtual memory for allocator payloads.
shared = runpy.run_path(str(ROOT/'tests/host/check-fex-arena-placement.py'),run_name='arena_fixture')
arena = shared['code'].split('static void workload(int legacy)',1)[0]
arena = arena.replace('static const uintptr_t arena_lo = 0xb50000000ULL, arena_hi = 0xd50000000ULL;', 'static uintptr_t arena_lo, arena_hi;')
arena = arena.replace('static struct file_view storage[2048];','static struct file_view storage[4096];').replace('static unsigned char used[2048];','static unsigned char used[4096];')
owner_init=','.join('{(void*)0x%x,%d,0}'%(o['owner'],o['lease']) for o in fixture['owners'])
arena,n=re.subn(r'owners\[3\] = \{.*?\};','owners[4] = {'+owner_init+'};',arena,count=1,flags=re.S)
assert n==1
arena = arena.replace('static void unmap_area(void *p,size_t n) { assert(mmap_is_in_reserved_area(p,n)); restored++; }', 'static void unmap_area(void *p,size_t n) { assert(mmap_is_in_reserved_area(p,n));host_vm_decommit(p,n);restored++; }')
# anon_mmap_fixed is an owned syscall stub, not Wine placement code.
arena = arena.replace('    return p;\n}\nstatic void *map_reserved_area_inner', '    host_vm_protect(p,n,PROT_NONE);\n    return p;\n}\nstatic void *map_reserved_area_inner',1)
external=[]
for row in fixture['visible_size_buckets']:
    if (row['size'],row['flags']) in [(0x1000000,3),(0x1000,3)]:continue
    external.extend([(row['size'],row['flags'])]*row['views'])
external.extend([(0x800000,0x23)]*fixture['derived_other']['frontend_800000_views'])
# Exactly 17 unlisted sizes/25.7MiB are unknown: this split is synthetic.
unknown_bytes=fixture['derived_other']['remaining_reserved']
external.extend([(0x100000,0x23)]*16+[(unknown_bytes-16*0x100000,0x23)])
assert len(external)==530
assert sum(n for n,_ in external)==fixture['summary']['covered']-383*0x1000000-130*0x1000
# The captured130 4KiB metadata views exceed four initializing thread heaps
# plus119 active worker heaps by seven. Preserve seven opaque metadata views
# in both runs; the helper adds four explicit image heaps in the new run.
external.extend([(0x1000,3)]*7)
last=external.pop(next(i for i,r in enumerate(external) if r==(0x1000000,0x23)))
external.append(last)
arena += '\n#include "abi.h"\n#include <pthread.h>\n'
arena = arena.replace('#include <sys/mman.h>', r'''
#include <sys/mman.h>
#include <unistd.h>
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif
/* Windows4KiB logical protections are represented by the commit bitmap.
 * A coarser native page cannot protect either4KiB edge independently, so this
 * owned syscall shim preserves neighboring live bytes and zeros only the
 * requested decommit range. Production allocation/guard decisions are unchanged.
 */
static size_t host_vm_page_size;
static void host_vm_protect(void* p,size_t n,int prot) {
 uintptr_t lo=(uintptr_t)p&~(uintptr_t)(host_vm_page_size-1);
 uintptr_t hi=((uintptr_t)p+n+host_vm_page_size-1)&~(uintptr_t)(host_vm_page_size-1);
 assert(n&&!((uintptr_t)p&4095)&&!(n&4095));
 assert(!mprotect((void*)lo,hi-lo,prot));
}
static void host_vm_decommit(void* p,size_t n) {
 uintptr_t lo=(uintptr_t)p,hi=lo+n;
 uintptr_t first=(lo+host_vm_page_size-1)&~(uintptr_t)(host_vm_page_size-1);
 uintptr_t last=hi&~(uintptr_t)(host_vm_page_size-1);
 host_vm_protect(p,n,PROT_READ|PROT_WRITE);
 if(first>hi) { memset(p,0,n);return; }
 if(first>lo)memset((void*)lo,0,first-lo);
 if(last<hi)memset((void*)last,0,hi-last);
 if(last>first) {
  assert(!(first&(host_vm_page_size-1))&&!((last-first)&(host_vm_page_size-1)));
  assert(mmap((void*)first,last-first,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void*)first);
 }
}
''')
arena += 'static const struct {size_t size;unsigned flags;} external[]={'+','.join('{0x%x,0x%x}'%r for r in external)+'};\n'
arena += r'''
static pthread_mutex_t arena_mutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned char* committed_pages;
static size_t committed_count[4];
static unsigned failed_maps,fail_next;
static unsigned owner_index(const struct file_view* v) {
 for(unsigned i=0;i<4;i++)if(v->ios_fex_owner==owners[i].owner)return i;
 assert(!"missing owner");return 0;
}
void arena_initialize(void) {
 size_t native_page=(size_t)sysconf(_SC_PAGESIZE);
 const char* requested=getenv("MADEIRA_PRESSURE_HOST_PAGE_SIZE");
 host_vm_page_size=requested?(size_t)strtoul(requested,NULL,10):native_page;
 assert(host_vm_page_size>=native_page&&!(host_vm_page_size&(host_vm_page_size-1))&&host_vm_page_size<=0x10000);
 printf("host VM shim: native-page=%zu modeled-page=%zu Windows4KiB protections tracked logically\n",native_page,host_vm_page_size);
 size_t n=0x200000000ULL;
 void* raw=mmap(NULL,n+0x1000000,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);assert(raw!=MAP_FAILED);
 arena_lo=((uintptr_t)raw+0xffffff)&~(uintptr_t)0xffffff;arena_hi=arena_lo+n;
 committed_pages=calloc(n/4096,1);assert(committed_pages);reset();
 /* Fixed external views are a transparent synthetic layout. Their aggregate
  * bytes/sizes are captured; their offsets/order and 17 sizes are unknown.
  * Leave exactly383 aligned16MiB slots plus capturedfree+130metadata pages.
  * Spread all small holes across the low region, each below16MiB. */
 uintptr_t cursor=arena_lo,end=arena_hi-383*0x1000000ULL;
 size_t rounded=0;for(unsigned i=0;i<ARRAY_SIZE(external);i++)rounded+=(external[i].size+0xffff)&~(size_t)0xffff;
 assert(end-cursor>rounded+0x600000);
 size_t units=(end-cursor-rounded)/0x10000;
 assert(!((end-cursor-rounded)&0xffff));
 size_t tail_units=0x600000/0x10000;
 units-=tail_units;
 for(unsigned i=0;i<ARRAY_SIZE(external);i++) {
  struct file_view* v=NULL;current_owner=owners[i%4].owner;
  assert(!create_view(&v,(void*)cursor,external[i].size,external[i].flags));ios_fex_tag_view(v,arena_lo,arena_hi-1);
  cursor+=(external[i].size+0xffff)&~(uintptr_t)0xffff;
  size_t extra=i+1==ARRAY_SIZE(external)?tail_units:units/(ARRAY_SIZE(external)-i-1);
  if(i+1!=ARRAY_SIZE(external))units-=extra;
  cursor+=extra*0x10000;assert(extra<=96);
 }
 assert(cursor==end && !units);
}
uintptr_t arena_start(void) {return arena_lo;}
uintptr_t arena_end(void) {return arena_hi;}
void arena_fail_next(void) {fail_next=1;}
void* arena_reserve(unsigned owner,size_t n,size_t a,unsigned flags) {
 assert(owner<4);pthread_mutex_lock(&arena_mutex);current_owner=owners[owner].owner;
 struct file_view* v=NULL;if(fail_next)fail_next=0;else v=allocate(n,a,flags,0);
 if(!v)failed_maps++;pthread_mutex_unlock(&arena_mutex);return v?v->base:NULL;
}
int arena_commit(unsigned owner,void* p,size_t n) {
 pthread_mutex_lock(&arena_mutex);struct file_view* v=find_view_range(p,n);assert(v&&owner_index(v)==owner);
 host_vm_protect(p,n,PROT_READ|PROT_WRITE);
 for(uintptr_t q=(uintptr_t)p;q<(uintptr_t)p+n;q+=4096){size_t i=(q-arena_lo)/4096;if(!committed_pages[i]){committed_pages[i]=1;committed_count[owner]+=4096;}}
 pthread_mutex_unlock(&arena_mutex);return 1;
}
void arena_decommit(unsigned owner,void* p,size_t n) {
 pthread_mutex_lock(&arena_mutex);struct file_view* v=find_view_range(p,n);assert(v&&owner_index(v)==owner);
 /* Only aligned native interior pages are replaced. Partial host-page
  * edges are zeroed without replacing live headers or adjacent payloads. */
 host_vm_decommit(p,n);
 for(uintptr_t q=(uintptr_t)p;q<(uintptr_t)p+n;q+=4096){size_t i=(q-arena_lo)/4096;if(committed_pages[i]){committed_pages[i]=0;committed_count[owner]-=4096;}}
 pthread_mutex_unlock(&arena_mutex);
}
void arena_release(unsigned owner,void* p) {
 pthread_mutex_lock(&arena_mutex);struct file_view* v=find_view_range(p,1);assert(v&&v->base==p&&owner_index(v)==owner);
 for(uintptr_t q=(uintptr_t)p;q<(uintptr_t)p+v->size;q+=4096){size_t i=(q-arena_lo)/4096;if(committed_pages[i]){committed_pages[i]=0;committed_count[owner]-=4096;}}
 delete_view(v);pthread_mutex_unlock(&arena_mutex);
}
void arena_measure(struct measurement* m) {
 memset(m,0,sizeof(*m));pthread_mutex_lock(&arena_mutex);uintptr_t cursor=arena_lo;
 struct file_view* v;WINE_RB_FOR_EACH_ENTRY(v,&views_tree,struct file_view,entry) {
  unsigned o=owner_index(v);m->views[o]++;m->reserved[o]+=v->size;
  if(v->size==0x1000000&&v->protect==3)m->spans[o]++;
  if((uintptr_t)v->base>cursor){size_t n=(uintptr_t)v->base-cursor;m->free_bytes+=n;if(n>m->maxgap)m->maxgap=n;}
  cursor=(uintptr_t)v->base+v->size;
 }
 if(cursor<arena_hi){m->free_bytes+=arena_hi-cursor;if(arena_hi-cursor>m->maxgap)m->maxgap=arena_hi-cursor;}
 memcpy(m->committed,committed_count,sizeof(committed_count));m->failed_maps=failed_maps;pthread_mutex_unlock(&arena_mutex);
}
void arena_check_leases(void) {
 for(unsigned i=0;i<4;i++) {
  unsigned before=live;owners[i].quiescent=0;ios_fex_reclaim_process_views(owners[i].owner);assert(live==before);
  owners[i].quiescent=1;owners[i].lease++;ios_fex_reclaim_process_views(owners[i].owner);assert(live==before);owners[i].lease--;owners[i].quiescent=0;
 }
}
void arena_retire(unsigned o) {
 pthread_mutex_lock(&arena_mutex);owners[o].quiescent=1;ios_fex_reclaim_process_views(owners[o].owner);owners[o].lease++;pthread_mutex_unlock(&arena_mutex);
}
'''

MAIN = r'''
#include "abi.h"
#include "owner_allocator.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <barrier>
#include <thread>
#include <vector>
extern "C" {
void arena_initialize(void);uintptr_t arena_start(void);uintptr_t arena_end(void);
void* arena_reserve(unsigned,size_t,size_t,unsigned);int arena_commit(unsigned,void*,size_t);
void arena_decommit(unsigned,void*,size_t);void arena_release(unsigned,void*);
void arena_measure(measurement*);void arena_check_leases(void);void arena_retire(unsigned);void arena_fail_next(void);
}
struct Module {
 void* image;void (*bind)(unsigned,const bridge*);void (*attach)();void (*detach)();
 void* (*alloc)(size_t);void* (*final_alloc)(size_t,size_t);void (*free)(void*);void* (*calloc)(size_t,size_t);void* (*align)(size_t,size_t);void* (*realloc)(void*,size_t);size_t (*usable)(void*);int (*posix)(void**,size_t,size_t);void* (*valloc)(size_t);
 int (*snapshot)(MadeiraFEXOwnerAllocatorStats*,size_t);
};
static void* symbol(void* h,const char* n) {void* p=dlsym(h,n);if(!p){fprintf(stderr,"%s: %s\n",n,dlerror());abort();}return p;}
template<typename T>static void load(T& p,void* h,const char* n){p=reinterpret_cast<T>(symbol(h,n));}
static Module modules[4];
static const unsigned counts[4]={64,36,4,15},old_spans[4]={227,107,12,37};
struct Payload {void* small;void* medium;void* large;void* second;unsigned owner,index;};
static Payload payloads[119];
static void fill(void* p,size_t n,unsigned value) {
 assert(p&&n);auto* b=(unsigned char*)p;
 size_t stride=n>=0x100000?0x100000:4096;
 for(size_t i=0;i<n;i+=stride)b[i]=(unsigned char)value;
 b[n-1]=(unsigned char)value;
}
static void verify(void* p,size_t n,unsigned value) {
 assert(p);auto* b=(unsigned char*)p;
 size_t stride=n>=0x100000?0x100000:4096;
 for(size_t i=0;i<n;i+=stride)assert(b[i]==(unsigned char)value);
 assert(b[n-1]==(unsigned char)value);
}
static void check(Payload& p) {
 verify(p.small,64,p.index+1);if(p.medium)verify(p.medium,7184,p.index+2);
 verify(p.large,0x800000,p.index+3);if(p.second)verify(p.second,0x800000,p.index+4);
}
static void print_measure(const char* mode,const measurement& m) {
 for(unsigned i=0;i<4;i++)printf("%s owner=%u threads=%u spans=%zu modeled-reserved=0x%zx allocator-logical-committed=0x%zx\n",mode,i,counts[i],m.spans[i],m.reserved[i],m.committed[i]);
 printf("%s free=0x%zx maxgap=0x%zx failed-maps=%u\n",mode,m.free_bytes,m.maxgap,m.failed_maps);
}
int main(int argc,char** argv) {
 assert(argc==6);setvbuf(stdout,nullptr,_IONBF,0);bool shared=!strcmp(argv[1],"new"),oom=!strncmp(argv[1],"oom-",4);
 bool cold=!strcmp(argv[1],"oom-default"),span_oom=!strcmp(argv[1],"oom-span");
 arena_initialize();bridge b={arena_start(),arena_end(),arena_reserve,arena_commit,arena_decommit,arena_release};
 for(unsigned i=0;i<4;i++) {
  Module& m=modules[i];m.image=dlopen(argv[i+2],RTLD_NOW|RTLD_LOCAL);assert(m.image);
  load(m.bind,m.image,"module_bind");if(cold&&!i)arena_fail_next();m.bind(i,&b);load(m.detach,m.image,"module_detach");
  load(m.attach,m.image,shared||oom?"module_new_attach":"module_old_attach");
  load(m.alloc,m.image,shared||oom?"module_new_alloc":"module_old_alloc");
  load(m.final_alloc,m.image,shared||oom?"module_new_final_alloc":"module_old_final_alloc");
  load(m.free,m.image,shared||oom?"module_new_free":"module_old_free");
  load(m.calloc,m.image,"module_new_calloc");load(m.align,m.image,"module_new_align");load(m.realloc,m.image,"module_new_realloc");load(m.usable,m.image,"module_new_usable");load(m.posix,m.image,"module_new_posix");load(m.valloc,m.image,"module_new_valloc");
  load(m.snapshot,m.image,"MadeiraFEXOwnerAllocatorSnapshot");
 }
 if(oom) {
  if(span_oom)modules[0].attach();
  if(!cold){arena_fail_next();assert(!modules[0].alloc(64));}
  MadeiraFEXOwnerAllocatorStats s;assert(modules[0].snapshot(&s,sizeof(s)));
  assert(s.heap_acquires==(span_oom?1u:0u)&&s.allocation_failures==(cold?0u:1u));
  void* p=modules[0].alloc(64);assert(p);fill(p,64,0x5a);verify(p,64,0x5a);modules[0].free(p);
  assert(!modules[0].alloc(SIZE_MAX));assert(!modules[0].calloc(SIZE_MAX,2));assert(!modules[0].align(3,100));
  assert(modules[0].snapshot(&s,sizeof(s))&&s.heap_acquires==1&&s.rejected_arguments==3);
  modules[0].detach();printf("PASS %s checked pinned OOM propagation/recovery and argument checks\n",argv[1]);return 0;
 }
 for(unsigned i=0;i<4;i++)for(unsigned j=0;j<i;j++)assert(symbol(modules[i].image,"MadeiraFEXOwnerAllocatorSnapshot")!=symbol(modules[j].image,"MadeiraFEXOwnerAllocatorSnapshot"));
 std::barrier ready(120),finish(120),after_request(120);std::atomic<int> final_result{-1};
 std::vector<std::thread> workers;unsigned at=0;
 for(unsigned owner=0;owner<4;owner++)for(unsigned local=0;local<counts[owner];local++) {
  unsigned index=at++;workers.emplace_back([=,&ready,&finish,&after_request,&final_result]{
   Module& m=modules[owner];m.attach();Payload& p=payloads[index];p.owner=owner;p.index=index;
   p.small=m.alloc(64);bool skip=(owner==1&&local==0)||(owner==3&&local<8);
   p.medium=skip?nullptr:m.alloc(7184);p.large=m.alloc(0x800000);p.second=owner==0&&local<35?m.alloc(0x800000):nullptr;
   fill(p.small,64,index+1);if(p.medium)fill(p.medium,7184,index+2);fill(p.large,0x800000,index+3);if(p.second)fill(p.second,0x800000,index+4);
   ready.arrive_and_wait();finish.arrive_and_wait();
   if(owner==3&&local==0){void* last=m.final_alloc(1,7184);final_result=last?1:0;if(last){fill(last,7184,0xa9);verify(last,7184,0xa9);m.free(last);}}
   after_request.arrive_and_wait();m.detach();
  });
 }
 ready.arrive_and_wait();assert(at==119);
 measurement initial;arena_measure(&initial);print_measure(shared?"owner-heap":"thread-heap",initial);
 for(unsigned i=0;i<4;i++)assert(initial.spans[i]==(shared?(i==0?101u:counts[i]+2u):old_spans[i]));
 size_t spans=0;for(size_t n:initial.spans)spans+=n;assert(spans==(shared?162:383));
 {
  size_t views=0,reserved=0;for(unsigned i=0;i<4;i++){views+=initial.views[i];reserved+=initial.reserved[i];}
  if(!shared)assert(views==1043&&reserved==0x1faf6e000ULL&&initial.free_bytes==0x5092000&&initial.maxgap==0x600000);
  else assert(views==826&&reserved==0x1faf6e000ULL-221*0x1000000ULL+4*0x1000&&initial.free_bytes==0x5092000ULL+221*0x1000000ULL-4*0x1000);
 }
 /* Independent direct16/9MiB reservations are distinct from the tiny final
  * FEXAlloc request, whose absent medium page asks rpmalloc for a new span. */
 for(size_t size:{size_t(0x1000000),size_t(0x900000)}){
  measurement before,after;arena_measure(&before);void* probe=arena_reserve(0,size,0x10000,0x23);
  assert((probe!=nullptr)==shared);if(probe)arena_release(0,probe);arena_measure(&after);
  assert(before.free_bytes==after.free_bytes);for(unsigned i=0;i<4;i++)assert(before.views[i]==after.views[i]&&before.reserved[i]==after.reserved[i]);
 }
 /* Exercise real page contents and Windows decommit zero semantics over
  * every byte of a small mapping, without faulting1.2GiB of large payloads. */
 void* zero=arena_reserve(0,0x10000,0x10000,0x23);assert(zero);assert(arena_commit(0,zero,0x10000));
 memset(zero,0xa5,0x10000);arena_decommit(0,zero,0x10000);assert(arena_commit(0,zero,0x10000));
 for(unsigned i=0;i<0x10000;i++)assert(!((unsigned char*)zero)[i]);
 /* Both4KiB edges share16KiB native pages with this decommitted interior.
  * A Windows-small-page decommit must preserve the live header and neighbor. */
 memset(zero,0xa5,0x10000);memset(zero,0x3c,0x1000);memset((char*)zero+0xf000,0x7e,0x1000);
 arena_decommit(0,(char*)zero+0x1000,0xe000);
 for(unsigned i=0;i<0x1000;i++){assert(((unsigned char*)zero)[i]==0x3c);assert(((unsigned char*)zero)[i+0xf000]==0x7e);}
 assert(arena_commit(0,(char*)zero+0x1000,0xe000));
 for(unsigned i=0;i<0x10000;i++)assert(((unsigned char*)zero)[i]==(i<0x1000?0x3c:i>=0xf000?0x7e:0));
 arena_release(0,zero);
 arena_check_leases();for(Payload& p:payloads)check(p);
 if(shared) {
  /* APIs use the same image heap on a native thread which never owned the
   * allocation. Whole small calloc blocks are checked, not just canaries. */
  for(unsigned i=0;i<4;i++) {
   Module& m=modules[i];auto* z=(unsigned char*)m.calloc(64,32);assert(z);for(unsigned k=0;k<2048;k++)assert(!z[k]);
   fill(z,2048,0x6b);void* grown=m.realloc(z,4096);assert(grown);verify(grown,2048,0x6b);m.free(grown);
   void* aligned=m.align(65536,513);assert(aligned&&!((uintptr_t)aligned&65535));fill(aligned,513,0x2c);verify(aligned,513,0x2c);m.free(aligned);
   void* v=m.valloc(129);assert(v&&!((uintptr_t)v&65535));fill(v,129,0x7a);verify(v,129,0x7a);m.free(v);
   void* posix=(void*)0x1234;assert(m.posix(&posix,3,100)==22&&posix==(void*)0x1234);
   assert(m.posix(&posix,65536,513)==0&&posix&&!((uintptr_t)posix&65535));m.free(posix);
   posix=(void*)0x1234;assert(m.posix(&posix,64,0x200000000ULL)==12&&posix==(void*)0x1234);
   void* nullable=m.realloc(nullptr,64);assert(nullable);fill(nullable,64,0x36);assert(!m.realloc(nullable,0));
   void* retained=m.alloc(64);fill(retained,64,0x29);assert(!m.realloc(retained,0x200000000ULL));verify(retained,64,0x29);m.free(retained);
   Payload* own=nullptr;for(Payload& p:payloads)if(p.owner==i){own=&p;break;}assert(own&&m.usable(own->small)>=64);
   size_t other=(i+1)%4;void* foreign=nullptr;for(Payload& p:payloads)if(p.owner==other){foreign=p.small;break;}
   m.free(foreign);assert(!m.realloc(foreign,128));assert(!m.usable(foreign));
   MadeiraFEXOwnerAllocatorStats s;assert(m.snapshot(&s,sizeof(s))&&s.heap_acquires==1&&s.rejected_owners==3);
  }
  assert(!modules[0].alloc(0x200000000ULL)); /* True bounded arena OOM. */
  for(Payload& p:payloads)check(p);
 }
 finish.arrive_and_wait();after_request.arrive_and_wait();
 for(std::thread& t:workers)t.join();assert(final_result==(shared?1:0));
 /* Thread detach/exit must preserve all payloads; another native thread frees
  * them. Compare pressure before any payload has been released. */
 measurement retired;arena_measure(&retired);assert(retired.failed_maps==(shared?9u:3u));for(unsigned i=0;i<4;i++)assert(retired.spans[i]==initial.spans[i]);
 for(Payload& p:payloads)check(p);
 if(shared)for(unsigned i=0;i<32;i++){std::thread successor([i]{Module& m=modules[i%4];m.attach();void* p=m.alloc(128);fill(p,128,0x7c);verify(p,128,0x7c);m.free(p);m.detach();});successor.join();}
 measurement reused;arena_measure(&reused);for(unsigned i=0;i<4;i++)assert(reused.views[i]==retired.views[i]&&reused.spans[i]==retired.spans[i]);
 std::thread freer([]{for(Payload& p:payloads){Module& m=modules[p.owner];m.free(p.small);if(p.medium)m.free(p.medium);m.free(p.large);if(p.second)m.free(p.second);}});freer.join();
 for(unsigned i=0;i<4;i++)modules[i].detach();
 /* Actual production reaper: matching quiescent generation only. Sibling
  * views survive each retirement; owner-private heaps are never shared. */
 for(unsigned i=0;i<4;i++){measurement before,after;arena_measure(&before);arena_retire(i);arena_measure(&after);assert(!after.views[i]);for(unsigned j=i+1;j<4;j++)assert(after.views[j]==before.views[j]);}
 puts(shared?"PASS four private owner heaps:162 real16MiB spans, unchanged payloads, zero/alignment/realloc, foreign-owner rejection, cross-thread free, thread-exit lifetime, generation reaping and true OOM":"PASS four private thread-heap images:383 real16MiB spans calibrated per owner; bounded8GiB arena rejects the final7184-byte request; payloads survive thread exit");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-owner-heap-pressure-') as directory:
    d=Path(directory)
    for name,data in [('windows.h',WINDOWS),('winternl.h','#include "windows.h"\n'),('fibersapi.h','#include "windows.h"\n'),('abi.h',ABI),('rpmalloc-checked.c',checked),('module.c',MODULE_C),('module.cpp',MODULE_CPP),('arena.c',arena),('main.cpp',MAIN)]:
        (d/name).write_text(data)
    cc=shlex.split(os.environ.get('CC','cc'));cxx=shlex.split(os.environ.get('CXX','c++'))
    common=['-O1','-g','-pthread','-fPIC','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(d),'-I'+str(RPM),'-I'+str(RPM/'rpmalloc'),'-I'+str(COMPAT)]
    defines=['-D_WIN32','-DFEX_IOS_HOST','-DRPMALLOC_FIRST_CLASS_HEAPS=1','-DDYNAMIC_TLS_NO_FLS=1','-DENABLE_OVERRIDE=0','-DENABLE_ASSERTS=0','-DENABLE_DECOMMIT=1']
    subprocess.run(cc+['-std=gnu11']+common+defines+['-c',str(d/'module.c'),'-o',str(d/'module.o')],check=True)
    subprocess.run(cxx+['-std=c++20']+common+defines+['-c',str(d/'module.cpp'),'-o',str(d/'module-cpp.o')],check=True)
    subprocess.run(cxx+['-std=c++20']+common+defines+['-c',str(COMPAT/'owner_allocator.cpp'),'-o',str(d/'owner.o')],check=True)
    link_shared=['-dynamiclib'] if platform.system()=='Darwin' else ['-shared','-Wl,-Bsymbolic']
    for i in range(4):
        identity=['-Wl,-install_name,@rpath/module'+str(i)+'.so'] if platform.system()=='Darwin' else []
        subprocess.run(cxx+link_shared+identity+['-pthread','-fsanitize=undefined','-fno-sanitize-recover=all',str(d/'module.o'),str(d/'module-cpp.o'),str(d/'owner.o'),'-o',str(d/f'module{i}.so')],check=True)
    subprocess.run(cc+['-std=gnu11']+common+['-DWINE_IOS','-c',str(d/'arena.c'),'-o',str(d/'arena.o')],check=True)
    subprocess.run(cxx+['-std=c++20']+common+[str(d/'main.cpp'),str(d/'arena.o')]+([] if platform.system()=='Darwin' else ['-ldl'])+['-o',str(d/'pressure')],check=True)
    # Linux4KiB hosts also execute16KiB edge handling, so Apple-sized native
    # page behavior is covered before the separate macOS CI run.
    native_page=os.sysconf('SC_PAGE_SIZE')
    host_pages=[native_page]+([16384] if native_page<16384 else [])
    for host_page in host_pages:
        for mode in ['old','new','oom-default','oom-heap','oom-span']:
            result=subprocess.run([str(d/'pressure'),mode]+[str(d/f'module{i}.so') for i in range(4)],text=True,capture_output=True,timeout=120,
                                  env=dict(os.environ,MADEIRA_PRESSURE_HOST_PAGE_SIZE=str(host_page)))
            print(''.join(line+'\n' for line in result.stdout.splitlines() if not line.startswith('[fex-owner-v1]')),end='')
            if result.returncode:print(result.stderr,end='');result.check_returncode()
print('PASS pinned input hash; generated copy contains the two NULL guards and bounded recursive-owner backoff')
