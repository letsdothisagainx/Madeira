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
struct MemoryPressureSnapshot {
  uint64_t available=0, reserve=1024;
  bool valid=true;
  bool needsReclaim(uint64_t upcoming=0) const {
    return valid && (available < reserve || upcoming > available-reserve);
  }
};
MemoryPressureSnapshot pressure;
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
  uint64_t refreshCompletedLocked(bool trim);
  uint64_t trimMemoryPressure();
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
    pressure.available=768; // Soft pressure: reserve=1024, critical below512.
    init.gpu_command_heap_allocator.allocate(1,0,256,16);
    init.gpu_command_heap_allocator.allocate(2,0,256,16);
    init.current_seq_id_=3;
    init.upload_queue_event_.value=2;
    require(init.trimMemoryPressure()==256, "soft pressure did not reclaim excess completed upload blocks");
    require(counts.bytes==256, "soft pressure did not preserve bounded warm upload backing");
    const size_t before=counts.allocated;
    init.prepareUploadLocked(16);
    init.gpu_command_heap_allocator.allocate(3,2,16,16);
    require(counts.allocated==before, "soft pressure caused unnecessary upload allocation churn");
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
  std::cout << "PASS real initializer methods: fresh idle completion, safe zero-cache retirement, bounded wait, honest backing\n";
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
    for name in ("flushInternal", "flushToWait", "refreshCompletedLocked", "trimMemoryPressure", "prepareUploadLocked"):
        match = re.search(r"(?:std::)?(?:uint64_t|void)\nResourceInitializer::" + name + r"\(", source)
        assert match, name
        opening = source.index("{", match.start())
        depth, end = 1, opening+1
        while depth:
            depth += (source[end]=="{") - (source[end]=="}")
            end += 1
        methods.append(source[match.start():end])
    return "namespace dxmt {\n" + "\n".join(methods) + "\n}\n"


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
        cpp = directory / "initializer.cpp"
        exe = directory / "initializer"
        cpp.write_text(PRELUDE + ring_code(staged) + ALLOCATOR + INITIALIZER_BACKEND +
                       initializer_methods(init_source) + INITIALIZER_MAIN)
        subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread", "-fsanitize=address,undefined",
                        str(cpp), "-o", str(exe)], check=True)
        actual = subprocess.run([str(exe)], text=True, capture_output=True)
        assert actual.returncode==0, actual.stdout + actual.stderr
        print(actual.stdout.strip())
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
