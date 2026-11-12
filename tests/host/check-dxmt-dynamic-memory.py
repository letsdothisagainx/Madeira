#!/usr/bin/env python3
"""Execute pinned/staged DynamicBuffer methods with real intrusive Rc ownership.

The fake native allocation owns bytes and counts destruction. It does not
replace DynamicBuffer's production FIFO, retirement, registry or locking code.
Queue completion is supplied explicitly; Metal execution/footprint still need
the iPhone. A popped Rc is never reported as physical memory recovered here.
"""
import importlib.util
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "dxmt/src/dxmt"


PRELUDE = r'''
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>
#include "rc/util_rc_ptr.hpp"
#define ERR(...) ((void)0)
#define WARN(...) ((void)0)
namespace dxmt {
using mutex = std::mutex;
namespace env { std::string getEnvVar(const char *) { return {}; } }
namespace Logger { template<class... T> void info(T&&...) {} }
template<class T> struct Flags {};
enum class BufferAllocationFlag { GpuReadonly };
struct Pressure { uint64_t available=1000000000,reserve=1000; bool needsReclaim(uint64_t=0) const {return false;} };
Pressure memoryPressureSnapshot() {return {}; }
}
'''


COUNTERS = r'''
namespace dxmt {
MemCensus g_mem_census{};
DynStat g_dyn_stats[DYN_CENSUS_SLOTS]{};
std::atomic<uint32_t> g_dyn_next_id{0};
LiveCount g_live_dynbuf{}, g_live_buffer{}, g_live_bufalloc{};
std::atomic<uint64_t> g_trim_total_n{0}, g_trim_total_bytes{0}, g_trim_regret{0};
void mem_census_report(const char *) {}
struct BackingCounts {
  std::atomic<uint64_t> allocated{0}, destroyed{0}, bytes{0};
} backing;
void (*release_probe)()=nullptr;
struct BufferAllocation {
  std::atomic<unsigned> refs{0};
  uint64_t census_bytes_;
  std::vector<uint8_t> data;
  explicit BufferAllocation(uint64_t bytes) : census_bytes_(bytes), data(bytes,0) {
    ++backing.allocated; backing.bytes += bytes;
  }
  void incRef() { ++refs; }
  void decRef() { if (refs.fetch_sub(1)==1) delete this; }
  ~BufferAllocation() {
    ++backing.destroyed; backing.bytes -= census_bytes_;
    if (release_probe) {
      auto probe=release_probe; release_probe=nullptr; probe();
    }
  }
  bool hasSuballocatoin(uint32_t sub) const { return sub < 4; }
  void *mappedMemory(uint32_t sub) { return data.data()+sub*16; }
};
struct Buffer {
  uint64_t size;
  Rc<BufferAllocation> current_;
  explicit Buffer(uint64_t bytes=256) : size(bytes), current_(new BufferAllocation(bytes)) {}
  BufferAllocation *current() { return current_.ptr(); }
  uint64_t length() const { return size; }
  Rc<BufferAllocation> allocate(Flags<BufferAllocationFlag>, const char *) {
    return new BufferAllocation(size);
  }
  Rc<BufferAllocation> rename(Rc<BufferAllocation> &&replacement) {
    Rc<BufferAllocation> old=std::move(current_);
    current_=std::move(replacement);
    return old;
  }
};
}
void require(bool ok,const char *message) {
  if (!ok) { std::cerr << message << '\n'; std::exit(1); }
}
'''


OLD_MAIN = r'''
int main() {
  using namespace dxmt;
  Buffer buffer;
  Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{});
  dynamic->updateImmediateName(10,dynamic->allocate(0),0,false);
  auto encoded_old=buffer.rename(dynamic->immediateName());
  encoded_old=nullptr;
  // No further rename occurs: production's old allocate-only trim is never run.
  require(g_dyn_stats[dynamic->census_id_].depth==1,
          "BEFORE reproduced: one-shot retired backing retained while census depth is zero");
  require(backing.bytes==256,"BEFORE reproduced: one-shot retired backing retained");
}
'''


NEW_MAIN = r'''
dxmt::DynamicBuffer *probe_dynamic=nullptr;
int main() {
  using namespace dxmt;
  const uint64_t q1=0x1110;
  const uint64_t q2=0x2220;
  {
    // Internal D3D children may survive a Device. Reusing the queue object's
    // address must not grant a fresh queue authority over the old completion IDs.
    alignas(QueueDomainFixture) unsigned char location[sizeof(QueueDomainFixture)];
    auto *first_queue=new(location) QueueDomainFixture;
    const auto old_domain=first_queue->memoryDomain();
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},old_domain);
    dynamic->updateImmediateName(33,dynamic->allocate(0),0,false);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    first_queue->~QueueDomainFixture();
    auto *replacement=new(location) QueueDomainFixture;
    require(replacement->memoryDomain()!=old_domain,"recreated queue reused retirement domain");
    DynamicBuffer::TrimCompletedForQueue(replacement->memoryDomain(),1000,true);
    require(backing.bytes==512,"queue at reused address stole old-domain backing");
    DynamicBuffer::TrimCompletedForQueue(old_domain,33,true);
    require(backing.bytes==256,"original domain could not retire its completed cache");
    replacement->~QueueDomainFixture();
  }
  {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
    Rc<BufferAllocation> queued=buffer.current();
    Rc<BufferAllocation> gpu=queued;
    queued->data[0]=0xac;
    dynamic->updateImmediateName(10,dynamic->allocate(0),0,false);
    require(g_dyn_stats[dynamic->census_id_].depth==1,"rename census omitted retained backing");
    DynamicBuffer::TrimCompletedForQueue(q1,9,true);
    require(backing.bytes==512,"pending generation was reclaimed before completion");
    DynamicBuffer::TrimCompletedForQueue(q2,100,true);
    require(g_dyn_stats[dynamic->census_id_].depth==1,"another queue's frontier reclaimed backing");
    DynamicBuffer::TrimCompletedForQueue(q1,10,true);
    require(g_dyn_stats[dynamic->census_id_].depth==0,"completed one-shot cache not trimmed");
    require(backing.bytes==512,"trim discarded queued/GPU/current ownership");
    require(queued->data[0]==0xac && gpu->data[0]==0xac,"queued allocation data changed");
    auto encoded_old=buffer.rename(dynamic->immediateName());
    encoded_old=nullptr; queued=nullptr;
    require(backing.bytes==512,"GPU-owned allocation was released");
    gpu=nullptr;
    require(backing.bytes==256,"completed backing remains live after last real owner released");
    dynamic->immediateName()->data[0]=0x43;
    DynamicBuffer::TrimCompletedForQueue(q1,100,true);
    require(dynamic->immediateName()->data[0]==0x43,"current mapped name was reclaimed");
  }
  require(backing.bytes==0,"current/queued fixture leaked");
  {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
    dynamic->updateImmediateName(12,dynamic->allocate(0),0,false);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    DynamicBuffer::TrimCompletedForQueue(q1,12,false);
    DynamicBuffer::TrimCompletedForQueue(q1,13,false);
    require(backing.bytes==512,"normal pressure discarded hot rename reserve");
    probe_dynamic=dynamic.ptr();
    release_probe=+[] {
      require(g_dynamic_registry_mutex.try_lock(),"native destruction held registry mutex");
      g_dynamic_registry_mutex.unlock();
      require(probe_dynamic->mutex_.try_lock(),"native destruction held instance mutex");
      probe_dynamic->mutex_.unlock();
    };
    DynamicBuffer::TrimCompletedForQueue(q1,14,false);
    require(backing.bytes==256 && release_probe==nullptr,"normal pressure failed to trim dormant cache");
    probe_dynamic=nullptr;
  }
  {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{}); // D3D9/unregistered
    dynamic->updateImmediateName(15,dynamic->allocate(0),0,false);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    require(DynamicBuffer::TrimCompletedForQueue(0,100,true)==0,"zero domain was registered");
    DynamicBuffer::TrimCompletedForQueue(q1,100,true);
    require(backing.bytes==512,"registered queue stole unregistered buffer cache");
    bool minted=true;
    auto reused=dynamic->allocate(15,&minted);
    require(!minted && reused.ptr()!=dynamic->immediateName().ptr(),"ordinary safe rename reuse regressed");
  }
  {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
    Rc<BufferAllocation> deferred=dynamic->allocate(0);
    deferred->data[0]=0xd7;
    dynamic->updateImmediateName(20,Rc<BufferAllocation>(deferred),0,true);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    DynamicBuffer::TrimCompletedForQueue(q1,20,true);
    const uint64_t allocated=backing.allocated;
    dynamic->recycle(21,Rc<BufferAllocation>(deferred));
    DynamicBuffer::TrimCompletedForQueue(q1,21,true);
    require(deferred->data[0]==0xd7 && dynamic->immediateName().ptr()==deferred.ptr(),
            "reusable command-list/current name was discarded");
    require(backing.allocated==allocated,"trim minted unexpected backing");
    // A separately retained command-list allocation also survives cache retirement.
    Rc<BufferAllocation> spare=buffer.allocate({},"deferred list");
    spare->data[0]=0x87;
    dynamic->recycle(22,Rc<BufferAllocation>(spare));
    DynamicBuffer::TrimCompletedForQueue(q1,21,true);
    require(g_dyn_stats[dynamic->census_id_].depth==1,"pending recycle lost its FIFO owner");
    DynamicBuffer::TrimCompletedForQueue(q1,22,true);
    require(spare->data[0]==0x87,"application-held command list data was destroyed");
  }
  require(backing.bytes==0,"deferred fixture leaked");
  {
    Buffer first,second;
    Rc<DynamicBuffer> a=new DynamicBuffer(&first,{},q1);
    Rc<DynamicBuffer> b=new DynamicBuffer(&second,{},q2);
    a->updateImmediateName(30,a->allocate(0),0,false);
    b->updateImmediateName(30,b->allocate(0),0,false);
    auto aold=first.rename(a->immediateName()); aold=nullptr;
    auto bold=second.rename(b->immediateName()); bold=nullptr;
    DynamicBuffer::TrimCompletedForQueue(q1,30,true);
    require(backing.bytes==768,"queue-domain isolation failed");
    DynamicBuffer::TrimCompletedForQueue(q2,29,true);
    require(backing.bytes==768,"future sequence was reclaimed");
    DynamicBuffer::TrimCompletedForQueue(q2,30,true);
    require(backing.bytes==512,"second queue completed cache was not trimmed");
  }
  {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
    dynamic->updateImmediateName(40,dynamic->allocate(0),0,false);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    // The pressure hook must skip an actively mutating FIFO, not invert locks.
    std::atomic<bool> entered{false},finished{false};
    std::unique_lock<mutex> lock(dynamic->mutex_);
    std::thread trim([&] {
      entered=true;
      DynamicBuffer::TrimCompletedForQueue(q1,40,true);
      finished=true;
    });
    while (!entered) std::this_thread::yield();
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (!finished && std::chrono::steady_clock::now()<deadline) std::this_thread::yield();
    require(finished,"pressure trim blocked on busy instance mutex");
    lock.unlock(); trim.join();
    DynamicBuffer::TrimCompletedForQueue(q1,40,true);
    require(backing.bytes==256,"skipped instance never reclaimed after unlock");
  }
  {
    // Real log has thousands of resources renamed only once. The old per-object
    // 64-entry cache cap cannot reclaim even one entry from this workload.
    constexpr size_t count=6000;
    std::vector<std::unique_ptr<Buffer>> buffers;
    std::vector<Rc<DynamicBuffer>> dynamics;
    for (size_t i=0;i<count;++i) {
      buffers.push_back(std::make_unique<Buffer>());
      dynamics.emplace_back(new DynamicBuffer(buffers.back().get(),{},q1));
      auto &d=dynamics.back();
      d->updateImmediateName(50,d->allocate(0),0,false);
      auto old=buffers.back()->rename(d->immediateName()); old=nullptr;
    }
    require(backing.bytes==count*512,"one-shot workload setup did not retain two allocations");
    DynamicBuffer::TrimCompletedForQueue(q1,49,true);
    require(backing.bytes==count*512,"one-shot pending allocation was freed");
    DynamicBuffer::TrimCompletedForQueue(q1,50,true);
    require(backing.bytes==count*256,"one-shot cache failed to return completed backing");
    for (auto &d:dynamics) require(g_dyn_stats[d->census_id_].depth==0,"post-trim depth is stale");
  }
  require(backing.bytes==0,"one-shot workload leaked");
  {
    std::atomic<bool> done{false};
    std::atomic<uint64_t> completed{0};
    std::thread scanner([&] {
      while (!done.load(std::memory_order_acquire))
        DynamicBuffer::TrimCompletedForQueue(q1,completed.load(std::memory_order_acquire),true);
    });
    for (uint64_t seq=1;seq<=10000;++seq) {
      Buffer buffer;
      Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
      dynamic->updateImmediateName(seq,dynamic->allocate(0),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
      completed.store(seq,std::memory_order_release);
      dynamic=nullptr; // unregister must precede delete; scanner never resurrects.
    }
    done.store(true,std::memory_order_release); scanner.join();
    DynamicBuffer::TrimCompletedForQueue(q1,completed.load(),true);
  }
  require(backing.bytes==0 && backing.allocated==backing.destroyed,"registry lifetime race leaked backing");
  std::cout << "PASS actual DynamicBuffer: one-shot completed trim, pending/current/queued/GPU/deferred Rc pins, "
               "queue isolation, normal-age retention, native release outside locks, busy skip, "
               "6000 resources, 10000 concurrent unregister/delete cycles\n";
}
'''


def dynamic_header(source):
    start = source.index("class DynamicBuffer {")
    end = source.index("class DynamicLinearTexture", start)
    return "#define private public\nnamespace dxmt {\n" + source[start:end] + "}\n#undef private\n"


def dynamic_methods(source):
    start = source.index("namespace dxmt {")
    end = source.index("DynamicLinearTexture::DynamicLinearTexture", start)
    return source[start:end] + "}\n"


def census_types():
    source = (SOURCE / "dxmt_mem_census.hpp").read_text()
    start = source.index("enum MemOwner")
    end = source.index("inline BufSizeBucket", start)
    return "namespace dxmt {\n" + source[start:end] + "}\n"


PLACED_PRELUDE = r'''
namespace dxmt {
LiveCount g_live_bufalloc{};
void mem_census_sub(MemOwner,uint64_t) {}
void mem_census_buffer_detail(uint64_t,uint32_t,uint32_t,int) {}
void buf_site_sub(uint64_t,uint64_t) {}
std::vector<std::string> released;
struct NativeReference {
  const char *kind;
  uint8_t *backing;
  void reset() {
    if (backing) {
      // The native wrapper may flush/read its CPU shadow on release.
      require(backing[0]==0x5a,"native wrapper read damaged CPU backing");
      released.emplace_back(kind);
      backing=nullptr;
    }
  }
  NativeReference& operator=(std::nullptr_t) { reset(); return *this; }
  ~NativeReference() { reset(); }
};
namespace wsi {
void aligned_free(void *ptr) { released.emplace_back("cpu"); std::free(ptr); }
}
struct BufferAllocation {
  NativeReference obj_;
  std::vector<std::unique_ptr<NativeReference>> cached_view_;
  void *placed_buffer;
  uint64_t census_bytes_=8;
  uint32_t census_storage_=0,census_flags_=0;
  const char *census_site_=nullptr;
  explicit BufferAllocation(bool placed) :
    obj_{"buffer",nullptr},placed_buffer(placed?std::malloc(8):nullptr) {
    if (placed_buffer) {
      auto bytes=static_cast<uint8_t *>(placed_buffer);
      bytes[0]=0x5a; obj_.backing=bytes;
      cached_view_.push_back(std::make_unique<NativeReference>(NativeReference{"view",nullptr}));
      cached_view_.back()->backing=bytes;
    }
  }
  ~BufferAllocation();
};
}
'''


PLACED_MAIN = r'''
int main() {
  using namespace dxmt;
  { BufferAllocation allocation(true); }
  require(released==std::vector<std::string>{"view","buffer","cpu"},
          "CPU-placed backing was freed before native views/buffer");
  released.clear();
  { BufferAllocation allocation(false); }
  require(released.empty(),"nonplaced destructor freed nonexistent CPU backing");
  std::cout << "PASS actual BufferAllocation destructor: views -> Metal buffer -> CPU backing\n";
}
'''


def allocation_destructor(source):
    start = source.index("BufferAllocation::~BufferAllocation()")
    opening = source.index("{", start)
    depth = 0
    for offset in range(opening, len(source)):
        depth += (source[offset] == "{") - (source[offset] == "}")
        if depth == 0:
            return "namespace dxmt {\n" + source[start:offset+1] + "\n}\n"
    raise ValueError("unterminated production destructor")


def compile_placed(directory, name, source):
    cpp = directory / (name + ".cpp")
    exe = directory / name
    cpp.write_text(PRELUDE + census_types()
                   + 'void require(bool ok,const char *s) { if (!ok) { std::cerr<<s; std::exit(1); } }\n'
                   + PLACED_PRELUDE + allocation_destructor(source) + PLACED_MAIN)
    subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-I", str(ROOT / "dxmt/src/util"), str(cpp), "-o", str(exe)], check=True)
    return subprocess.run([str(exe)], text=True, capture_output=True, timeout=30)


def compile_and_run(directory, name, header, implementation, main):
    cpp = directory / (name + ".cpp")
    exe = directory / name
    cpp.write_text(PRELUDE + census_types() + COUNTERS + dynamic_header(header)
                   + dynamic_methods(implementation) + queue_domain_fixture() + main)
    subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-I", str(ROOT / "dxmt/src/util"), str(cpp), "-o", str(exe)], check=True)
    return subprocess.run([str(exe)], text=True, capture_output=True, timeout=60)


def queue_domain_fixture():
    spec = importlib.util.spec_from_file_location("upload_stage", ROOT / "tools/build/stage-dxmt-upload-memory.py")
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    source = stage.stage_queue_header((SOURCE / "dxmt_command_queue.hpp").read_text())
    start = source.index("  static uint64_t NextMemoryDomain()")
    end = source.index("  const uint64_t memory_domain_ = NextMemoryDomain();", start)
    end += len("  const uint64_t memory_domain_ = NextMemoryDomain();")
    getter = "  uint64_t memoryDomain() const { return memory_domain_; }"
    assert getter in source
    return "struct QueueDomainFixture {\n" + source[start:end] + "\n" + getter + "\n};\n"


def main():
    spec = importlib.util.spec_from_file_location("dynamic_stage", ROOT / "tools/build/stage-dxmt-dynamic-memory.py")
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    old_h = (SOURCE / "dxmt_dynamic.hpp").read_text()
    old_c = (SOURCE / "dxmt_dynamic.cpp").read_text()
    new_h = stage.STAGES["src/dxmt/dxmt_dynamic.hpp"](old_h)
    new_c = stage.STAGES["src/dxmt/dxmt_dynamic.cpp"](old_c)
    old_buffer = (SOURCE / "dxmt_buffer.cpp").read_text()
    new_buffer = stage.STAGES["src/dxmt/dxmt_buffer.cpp"](old_buffer)
    with tempfile.TemporaryDirectory(prefix="dxmt-dynamic-memory-") as directory:
        directory = Path(directory)
        before = compile_and_run(directory,"before",old_h,old_c,OLD_MAIN)
        assert before.returncode != 0 and "one-shot retired backing retained" in before.stderr, before.stderr
        print(before.stderr.strip())
        after = compile_and_run(directory,"after",new_h,new_c,NEW_MAIN)
        assert after.returncode == 0, after.stdout + after.stderr
        print(after.stdout.strip())
        placed_before=compile_placed(directory,"placed-before",old_buffer)
        assert placed_before.returncode != 0, "old placed-buffer release order unexpectedly passed"
        assert "heap-use-after-free" in placed_before.stderr or "CPU-placed backing" in placed_before.stderr, placed_before.stderr
        print("BEFORE reproduced: native release reads already freed CPU-placed backing")
        placed_after=compile_placed(directory,"placed-after",new_buffer)
        assert placed_after.returncode == 0, placed_after.stdout + placed_after.stderr
        print(placed_after.stdout.strip())
    # Registry erase must happen before the lifetime ends at delete, and without
    # resurrecting an object whose intrusive reference count already reached zero.
    dec = new_c[new_c.index("DynamicBuffer::decRef()"):new_c.index("DynamicBuffer::allocate(")]
    assert dec.index("g_dynamic_registry_mutex") < dec.index("delete this"), "unregister after object lifetime ended"
    assert dec.index("registry_prev_->registry_next_") < dec.index("delete this")
    trim = new_c[new_c.index("DynamicBuffer::TrimCompletedForQueue"):new_c.index("DynamicBuffer::incRef()")]
    assert "incRef" not in trim, "pressure scanner must not resurrect a zero-ref object"
    print("PASS source lifetime contract: unregister precedes delete; scanner cannot resurrect")


if __name__ == "__main__":
    main()
