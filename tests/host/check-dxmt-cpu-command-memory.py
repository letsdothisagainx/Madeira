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
    pressure = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
    pressure = pressure[pressure.index('struct MemoryPressureSnapshot'):pressure.index('\nnamespace memory_pressure_detail')]
    return locals()


PREFIX = r'''
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#define WARN(...) ((void)0)
using clock_type = std::chrono::steady_clock;
void require(bool yes,const char *message){if(!yes){std::cerr<<message<<'\n';std::abort();}}
static std::thread::id producer;
static std::unordered_map<void *,size_t> backing;
static size_t owned=0,owned_peak=0,allocations=0,frees=0,logs=0,fresh_queries=0;
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
namespace dxmt {
using mutex=std::mutex;
struct null_mutex{void lock(){}void unlock(){}};
template<typename T,typename U>size_t align(T n,U a){return(size_t(n)+size_t(a)-1)&~(size_t(a)-1);}
template<typename T>void *ptr_add(void *p,T n){return static_cast<char *>(p)+n;}
constexpr size_t kStagingBlockSize=32ull<<20,kStagingBlockLifetime=300,kCommandChunkCPUHeapSize=4ull<<20;
constexpr size_t kCommandChunkCount=32;
size_t madeiraRingBlockSize(size_t natural){return natural;}
bool ringOversizeReuseEnabled(){return false;}
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
 RingBumpState<HostBufferBlockAllocator,kCommandChunkCPUHeapSize,null_mutex>cpu_command_allocator{HostBufferBlockAllocator{}};
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
        host = '\nnamespace dxmt {\n#define malloc tracked_malloc\n#define free tracked_free\n' + f['host'] + '\n#undef malloc\n#undef free\n}\n'
        result[name] = PREFIX.replace('// ACTUAL_PRESSURE', f['pressure']) + UPLOAD_TEST.ring_code(f['ring']) + host + backend + MAIN.replace('CANDIDATE', '1' if candidate else '0')
    return result


def main():
    compiler = os.environ.get('CXX', 'c++')
    with tempfile.TemporaryDirectory(prefix='dxmt-cpu-command-') as directory:
        directory = Path(directory)
        for name, source in generated_sources().items():
            cpp, binary = directory / (name + '.cpp'), directory / name
            cpp.write_text(source)
            subprocess.run([compiler, '-std=c++20', '-O1', '-g', '-pthread', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', str(cpp), '-o', str(binary)], check=True)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=120)
            print(run.stdout, end='')
            assert run.returncode == 0, run.stderr
    print('PASS source frontier ordering, no finisher/denial CPU-ring access, unchanged healthy production path; device performance unmeasured')


if __name__ == '__main__':
    main()
