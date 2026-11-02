#!/usr/bin/env python3
"""Reproduce the exact dense-map growth and exercise its staged replacement."""
from pathlib import Path
import os, subprocess, tempfile

root=Path(__file__).resolve().parents[2]
def function(text,marker):
    a=text.index(marker); b=text.index('{',a); level=1; end=b+1
    while level:
        level+=(text[end]=='{')-(text[end]=='}'); end+=1
    return text[a:end]

with tempfile.TemporaryDirectory() as temp:
    d=Path(temp); stage=d/'staged'
    subprocess.run(['python3',str(root/'tools/build/stage-fex-compat.py'),'stage',str(stage)],check=True)
    source=(stage/'FEXCore/Source/Interface/Core/LookupCache.h').read_text()
    original=(root/'FEX/FEXCore/Source/Interface/Core/LookupCache.h').read_text()
    # Existing lock/publication/invalidation code is byte-identical.
    for marker in ('const BlockEntry& AddBlockMapping(', 'const BlockEntry* FindBlock(',
                   'bool Erase(', 'void InvalidateRange('):
        assert function(source,marker)==function(original,marker)
    a=source.index('  struct BlockEntry {'); b=source.index('\n  fextl::map<uint64_t, fextl::vector<uint64_t>> CodePages;',a)
    members=source[a:b]
    methods=function(source,'const BlockEntry& AddBlockMapping(')+'\n'+function(source,'const BlockEntry* FindBlock(')
    stub=d/'include/FEXCore/Utils'; stub.mkdir(parents=True)
    (stub/'AllocatorHooks.h').write_text('''#pragma once
#include <cstddef>
#define FEX_DEFAULT_VISIBILITY
namespace FEXCore::Allocator {void* aligned_alloc(size_t,size_t);void aligned_free(void*);}
''')
    cpp=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <algorithm>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/robin_map.h>
struct Fatal{};
static size_t failed_bytes, failed_alignment, native_size, native_alignment, largest, allocations, frees;
static size_t live[3];static thread_local unsigned process_owner;
static std::mutex allocator_mutex;
struct Record{size_t bytes;unsigned owner;};static std::unordered_map<void*,Record> records;
namespace fextl {[[noreturn]]void ReportAllocationFailure(size_t a,size_t n){failed_alignment=a;failed_bytes=n;throw Fatal{};}}
namespace FEXCore::Allocator {
void* aligned_alloc(size_t a,size_t n){
 std::lock_guard guard(allocator_mutex);largest=std::max(largest,n);
 // The adjacent actual-rpmalloc harness verifies this native huge-map geometry.
 if(n>(32u<<20)){native_size=(n+128+4095)&~size_t(4095);native_alignment=16u<<20;return nullptr;}
 void* p=nullptr;assert(!posix_memalign(&p,std::max(a,sizeof(void*)),std::max(n,size_t(1))));
 assert(records.emplace(p,Record{n,process_owner}).second);live[process_owner]+=n;allocations++;return p;
}
void aligned_free(void* p){if(!p)return;std::lock_guard guard(allocator_mutex);auto it=records.find(p);assert(it!=records.end());live[it->second.owner]-=it->second.bytes;records.erase(it);frees++;std::free(p);}
}
struct LookupCacheWriteLockToken{};struct LookupCacheReadLockToken{};
#define FEX_IOS_HOST 1
#define _WIN32 1
namespace FEXCore {struct GuestToHostMap {
''' + members + '\n' + methods + r'''
};}
#undef _WIN32
using Map=FEXCore::GuestToHostMap;
using Dense=fextl::robin_map<uint64_t,Map::BlockEntry>;
static_assert(sizeof(Dense::value_type)==40&&alignof(Dense::value_type)==8);
static_assert(sizeof(Map::BlockListType::value_type)==40&&alignof(Map::BlockListType::value_type)==8);
static constexpr size_t count=524289;
static void fill(Map& map,size_t count,uint64_t hostbase){
 LookupCacheWriteLockToken write;fextl::vector<uint64_t> pages;
 for(size_t i=0;i<count;i++){const auto& value=map.AddBlockMapping(i,pages,(void*)(uintptr_t)(hostbase+i),write);assert(value.HostCode==hostbase+i);}
}
static void verify(Map& map,size_t count,uint64_t hostbase){
 LookupCacheReadLockToken read;for(size_t i=0;i<count;i++){auto* entry=map.FindBlock(i,read);assert(entry&&entry->HostCode==hostbase+i);}
}
int main(){
 // Same pinned library, actual FEXAlloc and same 40-byte values: old map fails
 // at the captured 20->40 MiB capacity transition, with all old entries intact.
 {
  Dense old;bool failed=false;
  try{for(size_t i=0;i<count;i++)old.insert_or_assign(i,Map::BlockEntry{i,{}});}catch(Fatal&){failed=true;}
  assert(failed&&failed_bytes==0x2800000&&failed_alignment==8);
  assert(native_size==0x2801000&&native_alignment==0x1000000&&old.size()==524288);
  for(size_t i=0;i<old.size();i++)assert(old.at(i).HostCode==i);
 }
 assert(records.empty()&&!live[0]);failed_bytes=0;largest=0;
 {
  Map owner_a;fill(owner_a,count,0x100000000ull);verify(owner_a,count,0x100000000ull);
  assert(!failed_bytes&&largest<(1u<<20));
  // Entry replacement destroys/replaces CodePages through the real method.
  LookupCacheWriteLockToken write;LookupCacheReadLockToken read;
  {fextl::vector<uint64_t> pages{0x123000,0x124000};owner_a.AddBlockMapping(123,pages,(void*)0xfeed000,write);}
  assert(owner_a.FindBlock(123,read)->CodePages.size()==2);
  {fextl::vector<uint64_t> pages{0x456000};owner_a.AddBlockMapping(123,pages,(void*)0xbeef000,write);}
  assert(owner_a.FindBlock(123,read)->HostCode==0xbeef000&&owner_a.FindBlock(123,read)->CodePages[0]==0x456000);
  assert(owner_a.BlockList.erase(123)==1&&!owner_a.FindBlock(123,read));
  for(size_t i=0;i<count;i+=1009)if(i!=123)assert(owner_a.FindBlock(i,read)->HostCode==0x100000000ull+i);
  owner_a.BlockList.clear();assert(owner_a.BlockList.empty());size_t before=allocations;
  fill(owner_a,count,0x200000000ull);verify(owner_a,count,0x200000000ull);
  assert(allocations==before); // retained segments and buckets reused on clear
  // Other process/code-generation map has the same guest keys, separate state.
  process_owner=1;
  {Map owner_b;fill(owner_b,4097,0x300000000ull);verify(owner_b,4097,0x300000000ull);
   verify(owner_a,count,0x200000000ull);assert(live[0]&&live[1]);}
  assert(!live[1]&&live[0]);process_owner=0;
  // Existing external read/write-lock contract, two writers and a reader.
  std::shared_mutex lock;std::atomic<bool> finished=false;
  auto writer=[&](unsigned parity){for(size_t i=0;i<20000;i++){std::unique_lock guard(lock);fextl::vector<uint64_t> pages;owner_a.AddBlockMapping(2*i+parity,pages,(void*)(uintptr_t)(0x400000000ull+2*i+parity),write);}};
  std::thread reader([&]{while(!finished.load()){std::shared_lock guard(lock);auto* v=owner_a.FindBlock(11,read);assert(v);}});
  std::thread first(writer,0),second(writer,1);first.join();second.join();finished=true;reader.join();
  for(size_t i=0;i<40000;i++)assert(owner_a.FindBlock(i,read)->HostCode==0x400000000ull+i);
 }
 assert(records.empty()&&!live[0]&&!live[1]&&allocations==frees);
 // Repeated code-generation/process destruction releases every allocation.
 for(unsigned cycle=0;cycle<100;cycle++){Map fresh;fill(fresh,4097,cycle+1);}
 assert(records.empty()&&!live[0]&&allocations==frees&&!failed_bytes);
 puts("PASS actual pinned BlockList: old 40MiB allocation reproduced at 524289 entries; segmented staged type grows under 32MiB cap, retains exact lookups/replacement/erase/isolation/locking, reuses clear capacity and frees all allocations across 100 lifetimes");
}
'''
    p=d/'blocklist.cpp'; p.write_text(cpp); exe=d/'blocklist'
    compiler=os.environ.get('CXX','c++')
    subprocess.run([compiler,'-std=c++20','-O1','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
                    '-I'+str(d/'include'),'-I'+str(root/'FEX/FEXCore/include'),
                    '-I'+str(root/'FEX/External/unordered_dense/include'),str(p),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)

    # The exact native request comes from the actual pinned rpmalloc huge path,
    # not a caller alignment requirement. Span-base masking requires SPAN_SIZE.
    rpm=(root/'FEX/External/rpmalloc/rpmalloc/rpmalloc.c').read_text()
    huge=function(rpm,'heap_allocate_block_huge(')
    rounded=function(rpm,'get_page_aligned_size(size_t size)')
    policy=r'''
#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define EXPECTED(x) (x)
#define ENABLE_DECOMMIT 1
#define PAGE_HUGE 3
#define SPAN_SIZE (16u<<20)
#define SPAN_HEADER_SIZE 128
#define LARGE_PAGE_MASK (~((uintptr_t)(SPAN_SIZE-1)))
struct heap_t;
typedef struct {struct heap_t* heap;unsigned is_full,generic_free,page_type;} page_t;
typedef struct span_t {struct heap_t* heap;unsigned page_type,page_size,page_count;uintptr_t page_address_mask;uint32_t offset;size_t mapped_size;page_t page;struct span_t* next;} span_t;
typedef struct heap_t {unsigned id,owner_thread;span_t* span_used[4];} heap_t;
static heap_t heap={1,1,{0}};
static struct {size_t page_size;} global_config={4096};
static size_t requested,alignment,commits;static void* mapped;
static void* map_spy(size_t n,size_t a,size_t* offset,size_t* mapped_size){requested=n;alignment=a;*offset=0;*mapped_size=n;return mapped;}
static void commit_spy(void* p,size_t n){assert(p==mapped&&n==requested);commits++;}
static struct {void*(*memory_map)(size_t,size_t,size_t*,size_t*);void(*memory_commit)(void*,size_t);} interface={map_spy,commit_spy},*global_memory_interface=&interface;
static void rpmalloc_initialize(void* p){(void)p;}
static heap_t* get_thread_heap(void){return &heap;}
static void* pointer_offset(void* p,size_t n){return (char*)p+n;}
'''+ '\nstatic size_t\n' + rounded + '\nstatic void*\n' + huge + r'''
int main(void){
 assert(!heap_allocate_block_huge(&heap,0x2800000,0));
 assert(requested==0x2801000&&alignment==0x1000000&&!commits);
 assert(!posix_memalign(&mapped,SPAN_SIZE,requested));
 assert(heap_allocate_block_huge(&heap,0x2800000,0)==(char*)mapped+SPAN_HEADER_SIZE);
 span_t* span=mapped;assert(span->heap==&heap&&span->page_type==PAGE_HUGE&&span->page_count==requested/4096&&commits==1);
 free(mapped);mapped=NULL;global_config.page_size=16384;
 assert(!heap_allocate_block_huge(&heap,0x2800000,0)&&requested==0x2804000&&alignment==0x1000000);
 puts("PASS actual rpmalloc huge path: 40MiB/align8 container request maps40MiB+4KiB at16MiB span alignment, header ownership retained;16KiB page rounding also verified, alignment policy unchanged");
}
'''
    c=d/'huge-policy.c';c.write_text(policy); exe=d/'huge-policy'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
