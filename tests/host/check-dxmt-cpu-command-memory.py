#!/usr/bin/env python3
"""Compile actual queue producer/retirement/ring/host backing with CPU ownership.

GPU completion and pressure readings are controlled. Tests use real allocations
and closure destruction; capacity is not an iPhone physical-footprint claim.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


STAGE = module('cpu_command_stage', ROOT / 'tools/build/stage-dxmt-upload-memory.py')
UPLOAD_TEST = module('cpu_command_ring', ROOT / 'tests/host/check-dxmt-upload-memory.py')


def braced(source, anchor):
    start = source.index(anchor)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def fragments():
    src = ROOT / 'dxmt/src/dxmt'
    ring = STAGE.stage_ring((src / 'dxmt_ring_bump_allocator.hpp').read_text())
    queue_original = (src / 'dxmt_command_queue.cpp').read_text()
    queue = STAGE.stage_queue(queue_original)
    header_original = (src / 'dxmt_command_queue.hpp').read_text()
    header = STAGE.stage_queue_header(header_original)
    context = (src / 'dxmt_context.hpp').read_text()
    assert 'constexpr size_t kCommandChunkCPUHeapSize = 0x400000;' in context
    old_commit = braced(queue_original, 'void\nCommandQueue::CommitCurrentChunk()')
    commit = braced(queue, 'void\nCommandQueue::CommitCurrentChunk()')
    assert commit.replace('maintainCompletedCommandData', 'cpu_command_allocator.free_blocks') == old_commit
    helper = braced(queue, 'uint64_t\nCommandQueue::maintainCompletedCommandData(')
    drain = braced(header, '  uint64_t trimCompletedTransientMemory()')
    reset = braced(header_original, '  void\n  reset() noexcept')
    allocate = braced(header_original, '  void *\n  AllocateCommandData(')
    start = queue_original.index('    chunk.reset();', queue_original.index('CommandQueue::WaitForFinishThread'))
    end = queue_original.index('\n\n    staging_allocator.', start)
    publication = queue_original[start:end]
    assert publication.index('chunk.reset();') < publication.index('cpu_coherent.signal(internal_seq)')
    assert 'cpu_command_allocator' not in braced(queue, 'uint32_t\nCommandQueue::WaitForFinishThread()')
    assert 'cpu_command_allocator' not in drain
    assert 'cpu_command_release_requested_.store(true' in drain
    assert 'std::atomic<bool> cpu_command_release_requested_{false};' in header
    assert 'MemoryPressureController cpu_command_pressure_controller_;' in header
    assert 'unsigned cpu_command_pressure_reports_ = 0;' in header
    host = braced((src / 'dxmt_ring_bump_allocator.hpp').read_text(), 'class HostBufferBlockAllocator {') + ';'
    vm = braced(ring, 'class CpuCommandBlockAllocator {') + ';'
    assert 'RingBumpState<CpuCommandBlockAllocator, kCommandChunkCPUHeapSize, dxmt::null_mutex> cpu_command_allocator;' in header
    assert 'RingBumpState<HostBufferBlockAllocator, 0x1000' in header
    pressure = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
    pressure = pressure[pressure.index('struct MemoryPressureSnapshot'):pressure.index('\nnamespace memory_pressure_detail')]
    return locals()


PREFIX = r'''
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#define WARN(...) ((void)0)
using clock_type = std::chrono::steady_clock;
void require(bool yes,const char *message){if(!yes){std::cerr<<message<<'\n';std::abort();}}
static std::thread::id producer;
static std::unordered_map<void *,size_t> backing;
static size_t owned=0,owned_peak=0,allocations=0,frees=0,logs=0,fresh_queries=0;
static bool fail_vm_allocation=false,fail_vm_release=false,oversize_reuse=false;
void *tracked_malloc(size_t bytes){
 require(std::this_thread::get_id()==producer,"CPU backing allocated by a foreign thread");
 void *p=std::malloc(bytes);require(p,"real malloc failed");backing.emplace(p,bytes);
 owned+=bytes;owned_peak=std::max(owned_peak,owned);++allocations;return p;
}
void tracked_free(void *p){
 require(std::this_thread::get_id()==producer,"null-mutex CPU ring accessed by another thread");
 if(!p)return;auto i=backing.find(p);require(i!=backing.end(),"unowned/double free");
 owned-=i->second;backing.erase(i);++frees;std::free(p);
}
void *tracked_mmap(void *hint,size_t bytes,int protection,int flags,int fd,off_t offset){
 require(std::this_thread::get_id()==producer,"VM allocation by a foreign producer");
 require(!hint&&protection==(PROT_READ|PROT_WRITE)&&fd==-1&&!offset,"incorrect/non-data VM request");
 require((flags&MAP_PRIVATE)&&(flags&MAP_ANON),"incorrect anonymous VM ownership");
 if(fail_vm_allocation){fail_vm_allocation=false;errno=ENOMEM;return MAP_FAILED;}
 void *p=::mmap(hint,bytes,protection,flags,fd,offset);if(p==MAP_FAILED)return p;
 require(backing.emplace(p,bytes).second,"duplicate VM ownership");owned+=bytes;owned_peak=std::max(owned_peak,owned);++allocations;return p;
}
int tracked_munmap(void *p,size_t bytes){
 require(std::this_thread::get_id()==producer,"VM release by a foreign producer");
 auto i=backing.find(p);require(i!=backing.end()&&i->second==bytes,"wrong VM release range");
 if(fail_vm_release){errno=EBUSY;return -1;}
 const int result=::munmap(p,bytes);if(result)return result;
 owned-=bytes;backing.erase(i);++frees;return 0;
}
namespace dxmt {
using mutex=std::mutex;
struct null_mutex{void lock(){}void unlock(){}};
template<typename T,typename U>size_t align(T n,U a){return(size_t(n)+size_t(a)-1)&~(size_t(a)-1);}
template<typename T>void *ptr_add(void *p,T n){return static_cast<char *>(p)+n;}
constexpr size_t kStagingBlockSize=32ull<<20,kStagingBlockLifetime=300,kCommandChunkCPUHeapSize=4ull<<20;
constexpr size_t kCommandChunkCount=32;
size_t madeiraRingBlockSize(size_t natural){return natural;}
bool ringOversizeReuseEnabled(){return oversize_reuse;}
struct Logger{template<class...T>static void info(T&&...){++logs;}};
// ACTUAL_PRESSURE
static MemoryPressureSnapshot reading;
MemoryPressureSnapshot memoryPressureSnapshot(bool fresh=false){if(fresh)++fresh_queries;return reading;}
}
'''

BACKEND = r'''
namespace dxmt {
using clock=clock_type;
template<class T>void atomic_notify_one(std::atomic<T>&a){a.notify_one();}
template<class T>void atomic_wait(std::atomic<T>&a,T old,std::memory_order order){a.wait(old,order);}
static std::atomic<size_t>gpu_live{0},closures_live{0},resets{0};
struct GpuResource{GpuResource(){++gpu_live;}~GpuResource(){--gpu_live;}};
struct Closure{
 unsigned char *p;size_t bytes;unsigned char value;std::shared_ptr<GpuResource>resource;
 Closure(void *data,size_t n,unsigned char v):p((unsigned char*)data),bytes(n),value(v),resource(std::make_shared<GpuResource>()){
  ++closures_live;std::memset(p,v,n);
 }
 ~Closure(){require(p[0]==value&&p[bytes-1]==value,"CPU payload released/overwritten while referenced");--closures_live;}
};
struct List{std::vector<std::unique_ptr<Closure>>items;void reset(){items.clear();++resets;}};
struct Tracker{void clear(){}};
struct CommandChunk{
 uint64_t chunk_id=0,chunk_event_id=0,frame_=0,resource_initializer_event_id=0,signal_frame_latency_fence_=0;
 std::unique_ptr<int>visibility_readback;
 std::vector<std::shared_ptr<GpuResource>>completion_targets;
 List list_enc;Tracker ref_tracker;std::shared_ptr<int>attached_cmdbuf;
 // ACTUAL_CHUNK_RESET
};
struct Fence{
 std::atomic<uint64_t>v{0};uint64_t signaledValue()const{return v.load(std::memory_order_acquire);}
 void signal(uint64_t n){require(resets>0,"frontier published before closure destruction");v.store(n,std::memory_order_release);}
};
struct Initializer{uint64_t flushToWait(){return 0;}};
struct Statistics{size_t command_buffer_count=0;clock::duration commit_interval{};};
struct GpuRing{uint64_t trim_completed(uint64_t,bool){return 0;}};
class CommandQueue{
public:
 std::atomic<uint64_t>ready_for_encode{1},chunk_ongoing{0};
 Fence cpu_coherent;std::array<CommandChunk,kCommandChunkCount>chunks;
 uint64_t frame_count=0,next_event=0;Initializer initializer;Statistics stats;
 RingBumpState<COMMAND_ALLOCATOR,kCommandChunkCPUHeapSize,null_mutex>cpu_command_allocator{COMMAND_ALLOCATOR{}};
 MemoryPressureController cpu_command_pressure_controller_;
 std::atomic<bool>cpu_command_release_requested_{false};
 unsigned cpu_command_pressure_reports_=0;
 std::atomic<uint64_t>allocation_transient_frontier_{UINT64_MAX};
 GpuRing staging_allocator,copy_temp_allocator,argbuf_allocator;
 uint64_t memoryDomain()const{return 1;}
 uint64_t CoherentSeqId(){return cpu_coherent.signaledValue();}
 uint64_t GetNextEventSeqId(){return++next_event;}
 Statistics&CurrentFrameStatistics(){return stats;}
 void CommitCurrentChunk();uint64_t maintainCompletedCommandData(uint64_t completed);
 // ACTUAL_DRAIN
 // ACTUAL_ALLOCATE
 void record(unsigned blocks,size_t payload=4ull<<20){
  require(std::this_thread::get_id()==producer,"foreign producer");
  auto seq=ready_for_encode.load();auto &c=chunks[seq%kCommandChunkCount];
  require(c.list_enc.items.empty(),"chunk reused before completion");
  for(unsigned i=0;i<blocks;i++){
   void *p=AllocateCommandData(payload,16);require(p,"null actual CPU backing");
   c.list_enc.items.emplace_back(std::make_unique<Closure>(p,payload,(unsigned char)(i+seq)));
  }
 }
 bool finish(uint64_t internal_seq,bool gpu_done,bool encode_done=true){
  if(!gpu_done||!encode_done)return false;
  auto &chunk=chunks[internal_seq%kCommandChunkCount];
  require(chunk.chunk_id==internal_seq,"wrong chunk completion identity");
  // Actual publication block follows controlled genuine completion and CPU
  // closure checks. Encoding/Metal adapters cannot publish this watermark.
  // ACTUAL_FINISH_PUBLICATION
  return true;
 }
};
#define ASYNC_ENCODING 1
// ACTUAL_COMMIT
// ACTUAL_MAINTENANCE
}
'''


MAIN = r'''
using dxmt::CommandQueue;
static void pressure(uint64_t available){
 dxmt::reading={0,available,6ull<<30,768ull<<20,dxmt::reading.sampled_ns+1,true};
}
int main(){
 producer=std::this_thread::get_id();constexpr size_t B=4ull<<20;
 {
  CommandQueue q;pressure(2ull<<30);
  q.record(20);q.CommitCurrentChunk();
  require(owned==20*B&&dxmt::closures_live==20,"actual burst did not allocate/retain closures");
  pressure(128ull<<20);
  require(!q.finish(1,false),"completion adapter accepted unfinished GPU");
  q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned==20*B&&dxmt::closures_live==20,"pending/current CPU payload freed");
  require(!q.finish(1,true,false),"completion adapter accepted unconsumed CPU work");
  q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned==20*B,"GPU event alone was treated as chunk ownership completion");
  q.finish(1,true);
  require(!dxmt::closures_live&&!dxmt::gpu_live,"actual reset did not release CPU closures/resources");
  q.CommitCurrentChunk();
  const auto after=owned;
  require(after==(CANDIDATE?B:20*B),"old/new completed CPU retention incorrect");
  for(unsigned i=0;i<100;i++)q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned==after,"frontier/idle maintenance invented completion or expiration");
  std::cout<<(CANDIDATE?"CORRECTED":"BASELINE")<<" completed80MiB burst retained="<<after
           <<" after100maintenancecalls; host capacity, not iPhone footprint\n";
  q.finish(2,true);
  const auto count=allocations;
  for(unsigned n=0;n<64;n++){
   auto seq=q.ready_for_encode.load();q.record(1,B);q.CommitCurrentChunk();q.finish(seq,true);
  }
  require(allocations<=count+1,"repeated pressure workload recreates CPU backing each frame");
  q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned<=(CANDIDATE?B:20*B),"pressure cache grew across repeated frames");
  if(CANDIDATE){
   require(logs<=8&&fresh_queries==logs,"bounded release reporter exceeded budget");
   std::thread denial([&]{q.trimCompletedTransientMemory();});denial.join();
   require(owned==B,"denial thread accessed the null-mutex CPU ring");
   q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
   require(!owned,"producer did not consume explicit completed drain");
   for(unsigned n=0;n<16;n++){
    auto seq=q.ready_for_encode.load();q.record(1);q.CommitCurrentChunk();q.finish(seq,true);
    std::thread request([&]{q.trimCompletedTransientMemory();});request.join();
    q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
   }
   require(!owned&&logs==8&&fresh_queries==8,"first8 release-report limit did not hold");
   auto seq=q.ready_for_encode.load();q.record(1);q.CommitCurrentChunk();q.finish(seq,true);
   pressure(0);q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());require(!owned,"zero headroom retained warm CPU backing");
   pressure(2ull<<30);seq=q.ready_for_encode.load();q.record(3);q.CommitCurrentChunk();q.finish(seq,true);
   q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());require(owned==3*B,"healthy cache policy changed");
   dxmt::reading.valid=false;q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());require(owned==3*B,"unknown pressure invented a limit");
  }
 }
 require(!owned&&backing.empty()&&!dxmt::gpu_live&&!dxmt::closures_live,"queue/ring destruction leaked owned backing/resources");
 if(CANDIDATE){
  CommandQueue q;pressure(128ull<<20);q.record(12);q.CommitCurrentChunk();
  std::atomic<bool>go{false},done{false};
  std::thread finisher([&]{
   while(!go.load(std::memory_order_acquire))std::this_thread::yield();
   q.finish(1,true);q.trimCompletedTransientMemory();done.store(true,std::memory_order_release);
  });
  for(unsigned n=0;n<1000;n++)q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned==12*B,"maintenance guessed a pending CPU frontier");
  go.store(true,std::memory_order_release);
  while(!done.load(std::memory_order_acquire))q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  finisher.join();q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(!owned&&!dxmt::closures_live&&!dxmt::gpu_live,"concurrent reset/frontier/drain publication lost ownership");
  for(unsigned cycle=0;cycle<12;cycle++){
   pressure(128ull<<20);auto seq=q.ready_for_encode.load();q.record(1);q.CommitCurrentChunk();q.finish(seq,true);
   for(uint64_t available:{512ull<<20,760ull<<20,820ull<<20,900ull<<20}){
    pressure(available);q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());require(owned==B,"pressure jitter destroyed hot block or grew cache");
   }
   pressure(2ull<<30);q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  }
 }
 require(!owned&&backing.empty()&&!dxmt::gpu_live&&!dxmt::closures_live,"concurrent queue destruction leaked ownership");
 if(CANDIDATE){
  CommandQueue q;pressure(128ull<<20);q.record(2);q.CommitCurrentChunk();q.finish(1,true);
  pressure(64ull<<20);q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned==B,"64MiB headroom did not permit the bounded whole4MiB spare");
  pressure((64ull<<20)-1);q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(!owned,"sub64MiB headroom retained a whole4MiB block beyond its allowance");
  pressure(2ull<<30);auto seq=q.ready_for_encode.load();q.record(1);q.CommitCurrentChunk();q.finish(seq,true);
  pressure(64ull<<20);dxmt::reading.reserve=128ull<<20;
  q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(!owned,"reserve-based allowance did not bound completed command capacity");
  pressure(2ull<<30);seq=q.ready_for_encode.load();q.record(1);q.CommitCurrentChunk();q.finish(seq,true);
  dxmt::reading.reserve=0;++dxmt::reading.sampled_ns;
  q.maintainCompletedCommandData(q.cpu_coherent.signaledValue());
  require(owned==B,"unknown zero-reserve policy invented a pressure limit");
 }
 require(!owned&&backing.empty(),"threshold queue destruction leaked owned backing");
 if(CANDIDATE){
  CommandQueue q;pressure(2ull<<30);
  const auto stale=q.cpu_coherent.signaledValue();
  q.record(2);q.CommitCurrentChunk();q.finish(1,true);
  std::thread request([&]{q.trimCompletedTransientMemory();});request.join();
  q.maintainCompletedCommandData(stale);
  require(!owned,"new drain request consumed with caller's stale completion snapshot");
 }
 require(!owned&&backing.empty(),"stale-frontier queue destruction leaked owned backing");
 std::cout<<"PASS actual CommitCurrentChunk/HostBuffer/ring/reset/publication: pending protection, warm reuse, producer-only drain and balanced ownership\n";
}
'''


def generated_sources():
    f = fragments()
    result = {}
    for name, candidate in [('baseline', False), ('bounded', True)]:
        backend = BACKEND.replace('// ACTUAL_CHUNK_RESET', f['reset']).replace('// ACTUAL_DRAIN', f['drain'])
        backend = backend.replace('// ACTUAL_ALLOCATE', f['allocate']).replace('// ACTUAL_FINISH_PUBLICATION', f['publication'])
        backend = backend.replace('// ACTUAL_COMMIT', f['commit'] if candidate else f['old_commit'])
        helper = f['helper'] if candidate else '''uint64_t CommandQueue::maintainCompletedCommandData(uint64_t completed) {
  cpu_command_allocator.free_blocks(completed);return 0;
}'''
        backend = backend.replace('// ACTUAL_MAINTENANCE', helper)
        host = '\nnamespace dxmt {\n#define malloc tracked_malloc\n#define free tracked_free\n' + f['host'] + '\n#undef malloc\n#undef free\n'
        host += '#define mmap tracked_mmap\n#define munmap tracked_munmap\n' + f['vm'] + '\n#undef mmap\n#undef munmap\n}\n'
        backend = backend.replace('COMMAND_ALLOCATOR', 'CpuCommandBlockAllocator' if candidate else 'HostBufferBlockAllocator')
        result[name] = PREFIX.replace('// ACTUAL_PRESSURE', f['pressure']) + UPLOAD_TEST.ring_code(f['ring']) + host + backend + MAIN.replace('CANDIDATE', '1' if candidate else '0')
    return result


WINDOWS_VM_ADAPTER = r'''
#define VM_WINDOWS_TEST 1
// Compile the actual Windows branch with a bounded host adapter. Its calls,
// flags, release extent and failure results are checked; this is not Wine.
using DWORD=unsigned long;
struct SYSTEM_INFO{DWORD dwPageSize;};
constexpr DWORD MEM_RESERVE=0x2000,MEM_COMMIT=0x1000,MEM_RELEASE=0x8000,PAGE_READWRITE=4;
static DWORD win_error=0;
static DWORD win_page_size=4096;
DWORD GetLastError(){return win_error;}
void SetLastError(DWORD e){win_error=e;}
void GetSystemInfo(SYSTEM_INFO *info){info->dwPageSize=win_page_size;}
void *VirtualAlloc(void *hint,size_t bytes,DWORD flags,DWORD protection){
 require(!hint&&flags==(MEM_RESERVE|MEM_COMMIT)&&protection==PAGE_READWRITE,"incorrect Windows VM creation flags");
 void *p=tracked_mmap(hint,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(p==MAP_FAILED){win_error=8;return nullptr;}return p;
}
int VirtualFree(void *ptr,size_t bytes,DWORD operation){
 require(!bytes&&operation==MEM_RELEASE,"Windows VM must release exact reservation with size zero");
 const int result=tracked_munmap(ptr,backing.at(ptr));if(result)win_error=487;return result==0;
}
'''

ALLOCATOR_MAIN = r'''
int main(){
 producer=std::this_thread::get_id();using Allocator=dxmt::CpuCommandBlockAllocator;
 require(Allocator::rounded_size(1,4096)==4096&&Allocator::rounded_size(4096,4096)==4096&&
         Allocator::rounded_size(4097,4096)==8192,"page rounding is incorrect");
 require(!Allocator::rounded_size(0,4096)&&!Allocator::rounded_size(1,0)&&
         !Allocator::rounded_size(1,123)&&!Allocator::rounded_size(SIZE_MAX,4096),"invalid size accepted");
 Allocator allocator;
 {
  auto first=allocator.allocate(4097);void *ptr=first.ptr;size_t bytes=first.allocation_size;
#if defined(VM_WINDOWS_TEST)
  const size_t expected_page=win_page_size;
#else
  const size_t expected_page=size_t(sysconf(_SC_PAGESIZE));
#endif
  require(bytes==Allocator::rounded_size(4097,expected_page),"actual allocation extent is wrong");
  std::memset(ptr,0x73,4097);
  auto moved=std::move(first);
  require(!first.ptr&&!first.allocation_size&&first.backend==Allocator::Backend::None,"move retained ownership");
  require(moved.ptr==ptr&&moved.allocation_size==bytes&&((char*)ptr)[4096]==0x73,"move lost backing or payload");
  auto state=moved.reports;
  fail_vm_release=true;
  errno=ERANGE;
#if defined(VM_WINDOWS_TEST)
  SetLastError(123);
#endif
  for(unsigned i=0;i<12;i++)require(!moved.try_release(),"failed OS release fabricated success");
#if defined(VM_WINDOWS_TEST)
  require(GetLastError()==123,"release logging changed Windows caller error");
#else
  require(errno==ERANGE,"release logging changed POSIX caller error");
#endif
  require(moved.ptr==ptr&&moved.allocation_size==bytes&&backing.count(ptr)&&state->failures==12,"release failure lost ownership or report budget");
  fail_vm_release=false;require(moved.try_release()&&!moved.ptr&&!moved.allocation_size,"OS retry did not release owned extent");
 }
 void *leaked=nullptr;size_t leaked_bytes=0;
 {
  Allocator separate;auto block=separate.allocate(1);leaked=block.ptr;leaked_bytes=block.allocation_size;
  fail_vm_release=true; // destructor must not terminate or pretend it returned pages.
 }
 require(backing.count(leaked),"failed destructor reported released storage");
 fail_vm_release=false;require(!tracked_munmap(leaked,leaked_bytes),"fixture could not clean injected OS failure");
#if defined(VM_WINDOWS_TEST)
 // The adapted Windows page size is independent of the test host's Darwin
 // 16 KiB (or Linux 4 KiB) pages. Check all supported adapter configurations.
 for(DWORD page:{DWORD(4096),DWORD(16384),DWORD(65536)}){
  win_page_size=page;auto block=allocator.allocate(4097);
  require(block.allocation_size==Allocator::rounded_size(4097,page),"Windows allocation used host page geometry");
 }
 win_page_size=4096;
#endif
 for(size_t bytes:{size_t(0),SIZE_MAX}){
  bool threw=false;try{auto block=allocator.allocate(bytes);(void)block;}catch(const std::bad_alloc&){threw=true;}
  require(threw,"invalid allocation did not fail honestly");
 }
 fail_vm_allocation=true;bool threw=false;
 try{auto block=allocator.allocate(8192);(void)block;}catch(const std::bad_alloc&){threw=true;}
 require(threw&&!owned,"VM allocation failure fabricated backing");
 {
  // Test-only visibility exposes actual FIFO/accounting; no production hook.
  dxmt::RingBumpState<Allocator,4ull<<20,dxmt::null_mutex> ring{Allocator{}};
  oversize_reuse=true;fail_vm_allocation=true;threw=false;
  try{ring.allocate(1,0,8ull<<20,16);}catch(const std::bad_alloc&){threw=true;}
  require(threw&&ring.fifo.empty()&&!ring.reusable_oversize_blocks_&&!owned,"failed oversized allocation mutated ring publication/accounting");
  auto value=ring.allocate(1,0,8ull<<20,16);
  require(value.first.ptr&&ring.fifo.size()==1&&ring.reusable_oversize_blocks_==1,"post-failure ring cannot publish correct backing");
  ring.trim_completed_budget(1,0);
  require(ring.fifo.empty()&&!ring.reusable_oversize_blocks_&&!owned,"oversized VM retirement is unbalanced");
 }
 require(!owned&&backing.empty()&&allocations==frees,"VM ownership not balanced");
 std::cout<<"PASS actual VM allocator: rounding, RW backing, move, OS failures, release retry, bounded errors, destructor safety, ring exception publication\n";
}
'''


def allocator_sources():
    f = fragments()
    # All standard headers are already included before exposing ring internals
    # for exception-publication assertions. The allocator itself is unchanged.
    ring = UPLOAD_TEST.ring_code(f['ring']).replace('private:', 'public:')
    prefix = PREFIX.replace('// ACTUAL_PRESSURE', f['pressure'])
    posix = '#define mmap tracked_mmap\n#define munmap tracked_munmap\n'
    native = '\nnamespace dxmt {\n' + posix + f['vm'] + '\n#undef mmap\n#undef munmap\n}\n'
    windows = WINDOWS_VM_ADAPTER + '\n#define _WIN32 1\nnamespace dxmt {\n' + f['vm'] + '\n}\n#undef _WIN32\n'
    return {'allocator-posix': prefix + ring + native + ALLOCATOR_MAIN,
            'allocator-windows': prefix + ring + windows + ALLOCATOR_MAIN}


def main():
    compiler = os.environ.get('CXX', 'c++')
    with tempfile.TemporaryDirectory(prefix='dxmt-cpu-command-') as directory:
        directory = Path(directory)
        for name, source in {**generated_sources(), **allocator_sources()}.items():
            cpp, binary = directory / (name + '.cpp'), directory / name
            cpp.write_text(source)
            subprocess.run([compiler, '-std=c++20', '-O1', '-g', '-pthread', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', str(cpp), '-o', str(binary)], check=True)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=120)
            print(run.stdout, end='')
            assert run.returncode == 0, run.stderr
            if name.startswith('allocator-'):
                assert run.stderr.count('event=release-failed') == 9, run.stderr
                assert ('error=487' if name.endswith('windows') else 'error=16') in run.stderr, run.stderr
    print('PASS source frontier ordering, no finisher/denial CPU-ring access, unchanged healthy production path; device performance unmeasured')


if __name__ == '__main__':
    main()
