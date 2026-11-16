#!/usr/bin/env python3
"""Compile real pinned/staged ring methods and check upload completion policy.

The counting allocator supplies ordinary owned byte arrays, not a replacement
ring algorithm. Metal execution/physical footprint still require the iPhone.
"""
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "dxmt/src/dxmt"
SPEC = importlib.util.spec_from_file_location("upload_stage", ROOT / "tools/build/stage-dxmt-upload-memory.py")
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


PRELUDE = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>
#define WARN(...) ((void)0)
namespace dxmt {
using mutex = std::mutex;
template <typename T, typename U> size_t align(T value, U alignment) {
  return (size_t(value) + size_t(alignment) - 1) & ~(size_t(alignment) - 1);
}
constexpr size_t kStagingBlockSize = 256;
constexpr size_t kStagingBlockLifetime = 300;
size_t madeiraRingBlockSize(size_t natural) { return natural; }
bool ringOversizeReuseEnabled() { return false; }
}
'''


ALLOCATOR = r'''
struct Counters { std::atomic<size_t> allocated=0, freed=0, bytes=0; } counts;
struct CountingAllocator {
  struct Payload {
    std::vector<uint8_t> data;
    explicit Payload(size_t size) : data(size, 0) {
      ++counts.allocated; counts.bytes += size;
    }
    ~Payload() { ++counts.freed; counts.bytes -= data.size(); }
  };
  struct Block {
    std::unique_ptr<Payload> payload;
    Block() = default;
    Block(Block&&) = default;
    Block& operator=(Block&&) = default;
    Block(const Block&) = delete;
  };
  Block allocate(size_t size) {
    Block block;
    block.payload = std::make_unique<Payload>(size);
    return block;
  }
};
void require(bool ok, const char *message) {
  if (!ok) { std::cerr << message << '\n'; std::exit(1); }
}
'''


OLD_MAIN = r'''
int main() {
  dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
  ring.allocate(1,0,256,16);
  ring.allocate(2,1,256,16);
  require(counts.allocated == 1, "FAIL: completed equality allocated a redundant live block");
}
'''


NEW_MAIN = r'''
int main() {
  {
    dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
    auto &first = ring.allocate(1,0,256,16).first;
    first.payload->data[0] = 0xa1;
    require(ring.allocation_growth(0,16,16)==256, "pending block cannot be reused");
    require(ring.allocation_growth(1,16,16)==0, "completed block is reusable");
    const size_t before=counts.allocated;
    auto &reused = ring.allocate(2,1,256,16).first;
    require(counts.allocated==before, "inclusive completed block was not reused");
    require(reused.payload->data[0]==0xa1, "backing unexpectedly replaced");
    require(ring.trim_completed(1)==0, "executing generation was reclaimed");
    require(ring.trim_completed(2)==256, "completed latest block was retained");
    require(counts.bytes==0, "completed block backing remains live");
  }
  {
    dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
    ring.allocate(1,0,256,16);
    auto &pending=ring.allocate(2,0,256,16).first;
    pending.payload->data[0]=0x72;
    ring.allocate(3,0,256,16);
    require(ring.trim_completed(1)==256, "completed prefix not reclaimed");
    require(counts.bytes==512, "live pending resources were destroyed");
    require(pending.payload->data[0]==0x72, "pending payload corrupted");
    require(ring.trim_completed(1)==0, "duplicate trim released pending data");
    require(ring.trim_completed(2)==256, "second completed block not reclaimed");
    require(ring.trim_completed(3)==256, "third completed block not reclaimed");
  }
  {
    dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
    ring.preallocate(1);
    const size_t before=counts.allocated;
    ring.allocate(1,0,256,16);
    require(counts.allocated==before, "construction-time backing not reused");
    ring.free_blocks(1);
    require(counts.bytes==256, "normal non-pressure cache policy changed");
    require(ring.trim_completed(0)==0, "precompletion trim released a live block");
    require(ring.trim_completed(1)==256, "pressure failed to release normal cached block");
  }
  {
    dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
    ring.allocate(1,0,1024,16);
    require(ring.trim_completed(0)==0, "oversized pending upload was released");
    require(ring.trim_completed(1)==1024, "completed oversized upload retained");
  }
  {
    dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
    ring.allocate(1,0,256,16);
    ring.allocate(2,0,256,16);
    ring.allocate(3,0,256,16);
    require(ring.trim_completed(3,true)==512, "soft pressure retained more than one completed block");
    require(counts.bytes==256, "soft pressure destroyed warm normal block");
    const size_t before=counts.allocated;
    ring.allocate(4,3,256,16);
    require(counts.allocated==before, "soft pressure warm block was not actually reused");
    require(ring.trim_completed(3,false)==0, "critical trim reclaimed pending warm block");
    require(ring.trim_completed(4,false)==256, "critical pressure retained completed warm block");
    ring.allocate(5,4,1024,16);
    require(ring.trim_completed(5,true)==1024, "soft pressure retained unbounded oversized warm block");
  }
  {
    dxmt::RingBumpState<CountingAllocator,256> ring(CountingAllocator{});
    std::atomic<uint64_t> completed{0};
    std::atomic<bool> done{false};
    std::thread consumer([&] {
      while (!done.load(std::memory_order_acquire))
        ring.trim_completed(completed.load(std::memory_order_acquire));
    });
    for (uint64_t seq=1;seq<=20000;++seq) {
      auto [block, offset]=ring.allocate(seq,completed.load(std::memory_order_acquire),16,16);
      block.payload->data[offset]=uint8_t(seq);
      require(block.payload->data[offset]==uint8_t(seq), "concurrent producer payload corrupted");
      // A real queue publishes completion only after all consumers finish.
      completed.store(seq,std::memory_order_release);
    }
    done.store(true,std::memory_order_release);
    consumer.join();
    ring.trim_completed(completed);
    require(counts.bytes==0, "concurrent completed backing leaked");
  }
  require(counts.allocated==counts.freed, "owned allocations leaked");
  std::cout << "PASS inclusive reuse, pending protection, pressure trim, byte integrity, concurrent completion\n";
}
'''


INITIALIZER_BACKEND = r'''
namespace dxmt {
/* ACTUAL_MEMORY_PRESSURE_POLICY */
MemoryPressureSnapshot pressure=[] {
  MemoryPressureSnapshot snapshot;
  snapshot.reserve=1024;
  snapshot.valid=true;
  return snapshot;
}();
MemoryPressureSnapshot memoryPressureSnapshot(bool = false) { return pressure; }
}
namespace WMT {
int MakeAutoreleasePool() { return 0; }
struct EventState {
  uint64_t value=0, submitted=0, waited=0, timeout=0;
  unsigned waits=0, commits=0;
  bool complete_on_wait=false;
  uint64_t signaledValue() { return value; }
  bool waitUntilSignaledValue(uint64_t target,uint64_t millis) {
    waited=target; timeout=millis; ++waits;
    if (complete_on_wait) value=target;
    return value>=target;
  }
};
struct CommandBuffer {
  EventState *state;
  uint64_t signal=0;
  void encodeSignalEvent(EventState&,uint64_t target) { signal=target; }
  void commit() { state->submitted=signal; ++state->commits; }
};
struct Queue {
  EventState *state;
  CommandBuffer commandBuffer() { return {state}; }
};
}
namespace dxmt {
constexpr int MEMOWN_INIT_UPLOAD=0;
uint64_t zero_released=0;
void mem_census_sub(int,uint64_t bytes) { zero_released+=bytes; }
class ResourceInitializer {
public:
  static constexpr size_t kResourceInitializerGpuUploadHeapAlignment=16;
  uint64_t flushInternal();
  uint64_t flushToWait();
  uint64_t refreshCompletedLocked(bool trim, bool release_warm = false);
  uint64_t trimMemoryPressure(bool release_warm = false);
  MemoryPressureDecision transientMemoryPressureDecision();
  size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0);
  uint64_t initializationFence();
  void prepareUploadLocked(size_t size);
  uint64_t current_seq_id_=1, cached_coherent_seq_id=0;
  size_t upload_bytes_since_flush_=0;
  WMT::EventState upload_queue_event_;
  WMT::Queue upload_queue_{&upload_queue_event_};
  std::shared_ptr<std::vector<uint8_t>> zero_buffer_;
  uint64_t zero_buffer_census_=0;
  size_t zero_buffer_size_=0;
  bool pending=false;
  bool idle() { return !pending; }
  void reset() { pending=false; upload_bytes_since_flush_=0; }
  void encode(WMT::CommandBuffer) {}
  std::mutex mutex_;
  MemoryPressureController transient_pressure_controller_;
  RingBumpState<CountingAllocator,256> gpu_command_heap_allocator{CountingAllocator{}};
};
}
'''


INITIALIZER_MAIN = r'''
int main() {
  using namespace dxmt;
  {
    ResourceInitializer init;
    pressure.available=1000000;
    init.gpu_command_heap_allocator.allocate(1,0,256,16);
    init.current_seq_id_=2;
    init.upload_queue_event_.value=1;
    require(init.flushToWait()==0, "idle flush failed to observe fresh GPU completion");
    require(init.cached_coherent_seq_id==1, "idle coherence frontier stayed stale");
    require(counts.bytes==256, "normal mode discarded warm backing");
    init.zero_buffer_=std::make_shared<std::vector<uint8_t>>(64);
    init.zero_buffer_census_=init.zero_buffer_size_=64;
    pressure.available=0;
    require(init.trimMemoryPressure()==320, "completed upload/zero storage was retained");
    require(!init.zero_buffer_ && init.zero_buffer_size_==0, "zero cache remains alive after complete/idle trim");
    require(counts.bytes==0, "completed GPU ring storage remains live");
  }
  {
    ResourceInitializer init;
    pressure.available=768; // Soft pressure: reserve=1024, emergency at256.
    init.gpu_command_heap_allocator.allocate(1,0,256,16);
    init.gpu_command_heap_allocator.allocate(2,0,256,16);
    init.current_seq_id_=3;
    init.upload_queue_event_.value=2;
    require(init.trimMemoryPressure()==256, "soft pressure did not reclaim excess completed upload blocks");
    require(counts.bytes==256, "soft pressure did not preserve bounded warm upload backing");
    const size_t before=counts.allocated;
    init.prepareUploadLocked(16);
    auto [backing, offset]=init.gpu_command_heap_allocator.allocate(3,2,16,16);
    backing.payload->data[offset]=0x73;
    require(counts.allocated==before, "soft pressure caused unnecessary upload allocation churn");
    init.pending=true;
    require(init.trimMemoryPressure(true)==0 && counts.bytes==256,
            "allocation-denial trim released a pending upload");
    require(backing.payload->data[offset]==0x73, "allocation-denial trim corrupted pending upload bytes");
    init.pending=false;
    init.current_seq_id_=4;
    require(init.trimMemoryPressure(true)==0 && counts.bytes==256,
            "allocation-denial trim released an in-flight upload");
    require(backing.payload->data[offset]==0x73, "allocation-denial trim corrupted in-flight upload bytes");
    init.upload_queue_event_.value=3;
    require(init.trimMemoryPressure()==0 && counts.bytes==256,
            "ordinary soft-pressure trim discarded completed warm upload backing");
    require(init.trimMemoryPressure(true)==256 && counts.bytes==0,
            "allocation-denial trim retained completed warm upload backing at soft pressure");
    require(init.trimMemoryPressure(true)==0, "repeated allocation-denial trim released storage twice");
    require(init.upload_queue_event_.waits==0 && init.upload_queue_event_.commits==0,
            "completed-only allocation-denial trim submitted or waited for pending GPU work");
    pressure.available=0;
  }
  {
    ResourceInitializer init;
    pressure.available=1000000;
    init.gpu_command_heap_allocator.allocate(1,0,256,16);
    init.current_seq_id_=2;
    init.upload_queue_event_.value=1;
    require(init.trimMemoryPressure()==0 && counts.bytes==256,
            "healthy ordinary trim discarded warm upload backing");
    require(init.trimMemoryPressure(true)==256 && counts.bytes==0,
            "allocation-denial trim ignored real completed backing without measured pressure");
    pressure.available=0;
  }
  {
    ResourceInitializer init;
    init.zero_buffer_=std::make_shared<std::vector<uint8_t>>(64);
    init.zero_buffer_census_=init.zero_buffer_size_=64;
    init.current_seq_id_=2;
    init.upload_queue_event_.value=1;
    init.pending=true;
    init.gpu_command_heap_allocator.allocate(2,1,256,16);
    require(init.trimMemoryPressure()==0, "pending uploads were reclaimed");
    require(bool(init.zero_buffer_), "zero backing referenced by pending commands was reclaimed");
    init.pending=false;
    init.current_seq_id_=4; // other submitted GPU work can still use zero
    require(init.trimMemoryPressure()==0 && bool(init.zero_buffer_), "in-flight zero buffer was released");
    init.upload_queue_event_.value=3;
    require(init.trimMemoryPressure()==320, "completed ring/zero cache was not reclaimed");
  }
  {
    ResourceInitializer init;
    init.gpu_command_heap_allocator.allocate(1,0,256,16);
    init.current_seq_id_=2;
    init.upload_queue_event_.value=1;
    init.prepareUploadLocked(16);
    require(init.upload_queue_event_.waits==0 && init.upload_queue_event_.commits==0,
            "existing reusable backing caused an unnecessary upload wait");
    const size_t before=counts.allocated;
    init.gpu_command_heap_allocator.allocate(2,1,16,16);
    require(counts.allocated==before, "growth admission missed genuine completed reuse");
  }
  require(counts.bytes==0, "initializer case leaked backing");
  for (bool completes: {false,true}) {
    ResourceInitializer init;
    init.pending=true;
    auto &live=init.gpu_command_heap_allocator.allocate(1,0,256,16).first;
    live.payload->data[0]=0x5a;
    init.upload_queue_event_.complete_on_wait=completes;
    init.prepareUploadLocked(16);
    require(init.upload_queue_event_.commits==1, "pressure did not flush actual pending upload commands");
    require(init.upload_queue_event_.waits==1 && init.upload_queue_event_.timeout==50,
            "private upload wait was not bounded to one 50ms attempt");
    require(init.cached_coherent_seq_id==(completes?1u:0u), "failed/timed-out GPU work was invented as complete");
    require(counts.bytes==(completes?0u:256u), "reclaim ignored real GPU completion");
    if (!completes) require(live.payload->data[0]==0x5a, "in-flight upload data was destroyed");
    auto [backing,offset]=init.gpu_command_heap_allocator.allocate(2,init.cached_coherent_seq_id,16,16);
    backing.payload->data[offset]=0x17;
    require(backing.payload->data[offset]==0x17, "pressure admitted an upload without real backing");
    require(counts.bytes==(completes?256u:512u), "actual owned backing count is incorrect");
  }
  require(counts.bytes==0, "initializer pressure path leaked backing");
  {
    ResourceInitializer init;
    pressure.available=400;
    pressure.sampled_ns=1;
    require(init.forecastUploadGrowth(0)==0 && init.forecastUploadGrowth(16)==256,
            "empty upload forecast did not report real new block cost");
    require(counts.bytes==0 && init.upload_queue_event_.commits==0 && init.upload_queue_event_.waits==0,
            "empty upload forecast allocated or submitted work");
    auto &backing=init.gpu_command_heap_allocator.allocate(1,0,256,16).first;
    backing.payload->data[0]=0x35;
    require(init.forecastUploadGrowth(16)==256, "pending full block was forecast as reusable");
    init.current_seq_id_=2;
    init.upload_queue_event_.value=1;
    const size_t before=counts.allocated;
    require(init.forecastUploadGrowth(16)==0, "fresh real GPU frontier was not used by forecast");
    require(init.cached_coherent_seq_id==0 && counts.bytes==256 && backing.payload->data[0]==0x35,
            "forecast mutated ownership, coherence or backing bytes");
    require(init.forecastUploadGrowth(1024)==1024, "oversized upload forecast ignored real block growth");
    require(init.forecastUploadGrowth(std::numeric_limits<size_t>::max())==std::numeric_limits<size_t>::max(),
            "oversized upload forecast overflowed into fictitious existing capacity");
    std::atomic<bool> bad{false};
    std::vector<std::thread> callers;
    for (unsigned n=0;n<8;++n) callers.emplace_back([&] {
      for (unsigned i=0;i<1000;++i)
        if (init.forecastUploadGrowth(16)!=0) bad=true;
    });
    for (auto &caller:callers) caller.join();
    require(!bad && counts.allocated==before && counts.bytes==256,
            "concurrent forecasts changed block ownership or accounting");
    require(init.upload_queue_event_.commits==0 && init.upload_queue_event_.waits==0,
            "forecast flushed or waited for GPU work");
    require(init.trimMemoryPressure()==0 && counts.bytes==256,
            "noncritical completed cache was lost below the old half-reserve boundary");
    pressure.available=256;
    pressure.sampled_ns=2;
    require(init.trimMemoryPressure()==256 && counts.bytes==0, "emergency entry retained completed warm backing");
    init.gpu_command_heap_allocator.allocate(2,1,256,16);
    init.current_seq_id_=3;
    init.upload_queue_event_.value=2;
    pressure.available=400;
    pressure.sampled_ns=3;
    require(init.trimMemoryPressure()==256 && counts.bytes==0,
            "emergency cache recovered before the separate half-reserve boundary");
    init.gpu_command_heap_allocator.allocate(3,2,256,16);
    init.current_seq_id_=4;
    init.upload_queue_event_.value=3;
    pressure.available=512;
    pressure.sampled_ns=4;
    require(init.trimMemoryPressure()==0 && counts.bytes==256,
            "completed warm cache did not recover at half reserve");
    require(init.trimMemoryPressure(true)==256 && counts.bytes==0,
            "explicit allocation-denial recovery did not override warm retention");
  }
  pressure.sampled_ns=0;
  require(counts.bytes==0, "forecast/hysteresis cases leaked backing");
  for (unsigned layout=0;layout<5;++layout) {
    ResourceInitializer init;
    pressure.available=1000000;
    const bool separate_front=layout>=3;
    if (separate_front) {
      init.gpu_command_heap_allocator.allocate(1,0,256,16);
      init.gpu_command_heap_allocator.allocate(2,0,128,16);
      init.current_seq_id_=3;
      init.upload_queue_event_.value=layout==4 ? 0 : 2;
    } else {
      init.gpu_command_heap_allocator.allocate(1,0,layout==1 ? 224 : 128,16);
      init.current_seq_id_=2;
      init.upload_queue_event_.value=1;
    }
    const size_t first=layout==2 ? 64 : 96;
    const size_t total=first*2;
    const size_t expected_growth=(layout==0 || layout==4) ? 256 : 0;
    const size_t before=counts.allocated;
    const size_t bytes_before=counts.bytes;
    const uint64_t completed=init.upload_queue_event_.value;
    if (layout==0)
      require(init.gpu_command_heap_allocator.allocation_growth(completed,total,16)==0,
              "negative control did not reproduce single-size forecast undercharge");
    require(init.forecastUploadGrowth(total,first)==expected_growth,
            "batch forecast misclassified partial latest/front rotation");
    require(counts.allocated==before && counts.bytes==bytes_before && init.cached_coherent_seq_id==0 &&
            init.upload_queue_event_.commits==0 && init.upload_queue_event_.waits==0,
            "batch forecast changed ownership, completion or submission");
    auto [first_backing, first_offset]=init.gpu_command_heap_allocator.allocate(
        init.current_seq_id_,completed,first,16);
    for (size_t i=0;i<first;++i) first_backing.payload->data[first_offset+i]=uint8_t(i+17);
    auto [second_backing, second_offset]=init.gpu_command_heap_allocator.allocate(
        init.current_seq_id_,completed,first,16);
    for (size_t i=0;i<first;++i) second_backing.payload->data[second_offset+i]=uint8_t(i+81);
    for (size_t i=0;i<first;++i) {
      require(first_backing.payload->data[first_offset+i]==uint8_t(i+17), "batch rotation corrupted first mip");
      require(second_backing.payload->data[second_offset+i]==uint8_t(i+81), "batch rotation corrupted second mip");
    }
    require(counts.allocated-before==(expected_growth ? 1u : 0u) && counts.bytes-bytes_before==expected_growth,
            "batch forecast differs from actual successive mip-allocation cost");
    require(init.forecastUploadGrowth(32,64)==std::numeric_limits<size_t>::max(),
            "invalid first-subresource size created fictitious batch capacity");
  }
  require(counts.bytes==0, "batch forecast cases leaked backing");
  {
    ResourceInitializer init;
    pressure.available=1000000;
    const size_t before=counts.allocated;
    require(init.initializationFence()==0, "unused initializer invented a submitted initialization fence");
    init.pending=true;
    require(init.initializationFence()==1 && init.pending && init.current_seq_id_==1,
            "pending initialization fence did not cover the current command sequence");
    require(init.upload_queue_event_.commits==0 && init.upload_queue_event_.waits==0 && counts.allocated==before,
            "pending initialization fence flushed, waited or allocated");
    require(init.flushToWait()==1, "fence fixture did not actually submit pending initialization");
    require(init.initializationFence()==1 && init.current_seq_id_==2 && init.upload_queue_event_.value==0,
            "idle initialization fence discarded still in-flight submitted work");
    init.pending=true;
    require(init.initializationFence()==2 && init.upload_queue_event_.submitted==1,
            "next pending initialization fence omitted concurrent creator commands");
    require(init.flushToWait()==2, "fence fixture lost the next real initialization submission");
    const auto commits=init.upload_queue_event_.commits;
    require(init.initializationFence()==2 && commits==2 && init.upload_queue_event_.waits==0 && counts.allocated==before,
            "idle initialization fence mutated submission, waiting or ownership");
    require(init.upload_queue_event_.commits==commits && init.upload_queue_event_.value==0,
            "initialization fence fabricated GPU completion");
  }
  std::cout << "PASS real initializer methods: fresh idle completion, bounded warm-cache reuse, allocation-denial release only after GPU completion, safe zero-cache retirement, bounded wait, honest backing\n";
  std::cout << "PASS real upload forecast: empty/warm/pending/oversize/concurrent queries do not allocate, trim, publish completion, flush or wait; emergency/recovery hysteresis retained\n";
  std::cout << "PASS actual successive-mip ring costs: partial completed latest-block counterexample, forced first-mip rotation, whole-tail reuse, distinct completed FIFO front and pending-front refusal; forecast has no allocation side effects\n";
  std::cout << "PASS real initialization fence: pending/current and idle/last-submitted sequences cover in-flight work without flushing, waiting, allocating or inventing GPU completion\n";
}
'''


UPLOAD_STRESS = r'''
int main() {
  using namespace dxmt;
  const size_t allocations_before=counts.allocated;
  uint64_t checksum=0;
  {
    ResourceInitializer init;
    pressure.reserve=1024;
    pressure.valid=true;
    for (uint64_t seq=1;seq<=1000;++seq) {
      // These inputs scale the device's 768MiB reserve and 256..384MiB
      // observed headroom. The controlled backend publishes completion only
      // after consuming the actual uploaded bytes, never by a CPU wait.
      pressure.available=360+(seq%5)*24;
      pressure.sampled_ns=seq;
      init.prepareUploadLocked(16);
      auto [backing, offset]=init.gpu_command_heap_allocator.allocate(
          seq,init.cached_coherent_seq_id,16,16);
      init.pending=true;
      for (size_t n=0;n<16;++n) backing.payload->data[offset+n]=uint8_t(seq+n);
      for (size_t n=0;n<16;++n) {
        require(backing.payload->data[offset+n]==uint8_t(seq+n), "stress upload byte changed before consumption");
        checksum+=backing.payload->data[offset+n];
      }
      // The submission event itself remains distinct from completion.
      init.flushToWait();
      require(init.upload_queue_event_.submitted==seq && init.upload_queue_event_.value==seq-1,
              "submission fabricated GPU completion");
      init.upload_queue_event_.value=seq;
      require(init.flushToWait()==0, "completed stress submission stayed pending");
      require(counts.bytes<=256, "stress retained more than one warm normal block");
    }
    require(init.upload_queue_event_.waits==0 && init.upload_queue_event_.commits==1000,
            "warm stress added waits or lost genuine upload submissions");
    init.trimMemoryPressure(true);
  }
  require(counts.bytes==0 && counts.allocated==counts.freed, "stress upload backing leaked");
  std::cout << "upload-stress allocations=" << counts.allocated-allocations_before
            << " checksum=" << checksum << " uploads=1000 peak-normal-blocks=1\n";
}
'''


QUEUE_BACKEND = r'''
class CompletionQueue {
public:
  dxmt::ResourceInitializer initializer;
  dxmt::RingBumpState<CountingAllocator,256> staging_allocator{CountingAllocator{}};
  dxmt::RingBumpState<CountingAllocator,256> copy_temp_allocator{CountingAllocator{}};
  dxmt::RingBumpState<CountingAllocator,256> argbuf_allocator{CountingAllocator{}};
  void finish(uint64_t internal_seq) {
/* ACTUAL_COMPLETION_RING_TRIM */
  }
  void allocate(uint64_t seq,uint64_t completed) {
    staging_allocator.allocate(seq,completed,256,16);
    copy_temp_allocator.allocate(seq,completed,256,16);
    argbuf_allocator.allocate(seq,completed,256,16);
  }
};
'''


QUEUE_MAIN = r'''
int main() {
  using namespace dxmt;
  CompletionQueue queue;
  pressure.reserve=1024;
  pressure.available=400;
  pressure.sampled_ns=1;
  queue.allocate(1,0);
  queue.initializer.gpu_command_heap_allocator.allocate(1,0,256,16);
  queue.initializer.current_seq_id_=2;
  queue.initializer.upload_queue_event_.value=1;
  queue.finish(1);
  require(counts.bytes==1024, "completion rings discarded normal warm blocks at noncritical pressure");
  pressure.available=256;
  pressure.sampled_ns=2;
  queue.initializer.pending=true;
  auto &pending=queue.initializer.gpu_command_heap_allocator.allocate(2,1,256,16).first;
  pending.payload->data[0]=0x63;
  queue.finish(1);
  require(counts.bytes==256 && pending.payload->data[0]==0x63,
          "emergency trim destroyed pending initializer backing or retained completed main-ring caches");
  queue.initializer.pending=false;
  queue.initializer.current_seq_id_=3;
  queue.initializer.upload_queue_event_.value=2;
  pressure.available=400;
  pressure.sampled_ns=3;
  queue.allocate(2,1);
  queue.finish(2);
  require(counts.bytes==0, "shared emergency history recovered a completion ring below half reserve");
  pressure.available=512;
  pressure.sampled_ns=4;
  queue.allocate(3,2);
  queue.initializer.gpu_command_heap_allocator.allocate(3,2,256,16);
  queue.initializer.current_seq_id_=4;
  queue.initializer.upload_queue_event_.value=3;
  queue.finish(3);
  require(counts.bytes==1024, "shared completion-ring cache did not recover at half reserve");
  queue.staging_allocator.trim_completed(3,false);
  queue.copy_temp_allocator.trim_completed(3,false);
  queue.argbuf_allocator.trim_completed(3,false);
  queue.initializer.trimMemoryPressure(true);
  require(counts.bytes==0 && counts.allocated==counts.freed, "completion-ring test leaked backing");
  std::cout << "PASS actual completion-ring paths: initializer/shared emergency hysteresis, three bounded warm blocks, live upload protection and separated recovery\n";
}
'''


def ring_code(source):
    start = source.index("template <typename Allocator, size_t BlockSize =")
    end = source.index("\nclass GpuPrivateBufferBlockAllocator", start)
    methods = source.index("template <typename Allocator, size_t BlockSize, class mutex>\nstd::pair", end)
    return "namespace dxmt {\n" + source[start:end] + source[methods:]


def compile_and_run(directory, name, source, main):
    cpp = directory / (name + ".cpp")
    exe = directory / name
    cpp.write_text(PRELUDE + ring_code(source) + ALLOCATOR + main)
    subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread", "-fsanitize=address,undefined",
                    str(cpp), "-o", str(exe)], check=True)
    return subprocess.run([str(exe)], text=True, capture_output=True)


def initializer_methods(source):
    methods = []
    for name in ("flushInternal", "flushToWait", "refreshCompletedLocked", "trimMemoryPressure",
                 "transientMemoryPressureDecision", "forecastUploadGrowth", "initializationFence", "prepareUploadLocked"):
        match = re.search(r"(?:std::)?(?:uint64_t|size_t|void|MemoryPressureDecision)\nResourceInitializer::" + name + r"\(", source)
        assert match, name
        opening = source.index("{", match.start())
        depth, end = 1, opening+1
        while depth:
            depth += (source[end]=="{") - (source[end]=="}")
            end += 1
        methods.append(source[match.start():end])
    return "namespace dxmt {\n" + "\n".join(methods) + "\n}\n"


def initializer_backend():
    # Compile the shared production snapshot/controller, not a model of its
    # pressure thresholds. Only native measurement/event inputs are controlled.
    source = (ROOT / "build/dxmt-ios/memory_pressure.hpp").read_text()
    start = source.index("struct MemoryPressureSnapshot")
    end = source.index("namespace memory_pressure_detail", start)
    return INITIALIZER_BACKEND.replace("/* ACTUAL_MEMORY_PRESSURE_POLICY */", source[start:end])


def compile_initializer(directory, name, ring, source, main):
    cpp = directory / (name + ".cpp")
    exe = directory / name
    cpp.write_text(PRELUDE + ring_code(ring) + ALLOCATOR + initializer_backend() +
                   initializer_methods(source) + main)
    subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread", "-fsanitize=address,undefined",
                    str(cpp), "-o", str(exe)], check=True)
    result = subprocess.run([str(exe)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def main():
    original = (SOURCE / "dxmt_ring_bump_allocator.hpp").read_text()
    staged = STAGE.stage_ring(original)
    with tempfile.TemporaryDirectory(prefix="dxmt-upload-memory-") as directory:
        directory = Path(directory)
        before = compile_and_run(directory, "before", original, OLD_MAIN)
        assert before.returncode != 0 and "redundant live block" in before.stderr, before.stderr
        print("BEFORE: reproduced redundant block at exact completed frontier")
        after = compile_and_run(directory, "after", staged, NEW_MAIN)
        assert after.returncode == 0, after.stdout + after.stderr
        print("AFTER:", after.stdout.strip())
        init_source = STAGE.stage_initializer((SOURCE / "dxmt_resource_initializer.cpp").read_text())
        print(compile_initializer(directory, "initializer", staged, init_source, INITIALIZER_MAIN))
        warm_policy = """    const auto decision = transient_pressure_controller_.evaluate(memoryPressureSnapshot());
    const bool keep_warm = !release_warm && decision.valid && !decision.critical;"""
        old_policy = """    const auto pressure = memoryPressureSnapshot();
    const bool keep_warm = !release_warm && pressure.valid && pressure.available >= pressure.reserve / 2;"""
        assert init_source.count(warm_policy) == 1
        baseline = compile_initializer(directory, "old-warm-stress", staged,
                                       init_source.replace(warm_policy, old_policy, 1), UPLOAD_STRESS)
        candidate = compile_initializer(directory, "new-warm-stress", staged, init_source, UPLOAD_STRESS)
        old_counts = re.search(r"allocations=(\d+) checksum=(\d+)", baseline)
        new_counts = re.search(r"allocations=(\d+) checksum=(\d+)", candidate)
        assert old_counts and new_counts and old_counts[1] == "1000" and new_counts[1] == "1", (baseline, candidate)
        assert old_counts[2] == new_counts[2], (baseline, candidate)
        print("BEFORE old production warm threshold:", baseline)
        print("AFTER shared production hysteresis:", candidate)
        queue = STAGE.stage_queue((SOURCE / "dxmt_command_queue.cpp").read_text())
        start = queue.index("    const auto pressure = initializer.transientMemoryPressureDecision();")
        end = queue.index("    // Dynamic caches", start)
        completion_backend = QUEUE_BACKEND.replace("/* ACTUAL_COMPLETION_RING_TRIM */", queue[start:end])
        print(compile_initializer(directory, "completion-rings", staged, init_source,
                                  completion_backend + QUEUE_MAIN))
    init = STAGE.stage_initializer((SOURCE / "dxmt_resource_initializer.cpp").read_text())
    queue = STAGE.stage_queue((SOURCE / "dxmt_command_queue.cpp").read_text())
    # These guard wiring into production callers; GPU behavior is not simulated.
    idle = init[init.index("ResourceInitializer::flushToWait()"):init.index("ResourceInitializer::refreshCompletedLocked")]
    assert "refreshCompletedLocked" in idle and "free_blocks(cached_coherent_seq_id)" not in idle
    assert "waitUntilSignaledValue(submitted, 50)" in init
    assert "trim && idle() && cached_coherent_seq_id >= current_seq_id_ - 1" in init
    assert queue.index("chunk.reset();\n    cpu_coherent.signal") < queue.index("staging_allocator.trim_completed")
    assert "cpu_command_allocator.trim_completed" not in queue
    assert "DynamicBuffer::TrimCompletedForQueue(memoryDomain(), internal_seq, false)" in queue
    for name, transform in STAGE.STAGES.items():
        first = transform((SOURCE / name).read_text())
        try:
            transform(first)
        except ValueError:
            continue
        raise AssertionError(f"stager accepted already staged {name}")
    print("PASS production initializer/queue wiring, bounded private-event wait, immutable fail-closed staging")


if __name__ == "__main__":
    main()
