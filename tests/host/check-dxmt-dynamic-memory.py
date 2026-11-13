#!/usr/bin/env python3
"""Execute pinned/staged DynamicBuffer methods with real intrusive Rc ownership.

The fake native allocation owns bytes and counts destruction. It does not
replace DynamicBuffer's production FIFO, retirement, registry or locking code.
Queue completion is supplied explicitly; Metal execution/footprint still need
the iPhone. A popped Rc is never reported as physical memory recovered here.
"""
import importlib.util
import hashlib
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
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
struct MemoryPressureSnapshot {
  uint64_t available=0, reserve=0, limit=0, footprint=0, sampled_ns=0;
  bool valid=false, enabled=false;
  bool needsReclaim(uint64_t=0) const { return enabled; }
};
MemoryPressureSnapshot g_pressure=[] {
  MemoryPressureSnapshot p;
  p.available=p.reserve=uint64_t{256}<<20;
  p.limit=uint64_t{6}<<30;
  p.footprint=p.limit-p.available;
  p.sampled_ns=1;
  p.valid=true;
  return p;
}();
MemoryPressureSnapshot memoryPressureSnapshot(bool=false) {return g_pressure; }
// Snapshot inputs are controlled; the actual shared pressure controller is
// inserted here, so the cache tests do not substitute a separate budget policy.
/* ACTUAL_MEMORY_PRESSURE_CONTROLLER */
}
'''


def prelude():
    source=(ROOT/"build/dxmt-ios/memory_pressure.hpp").read_text()
    start=source.index("struct MemoryPressureDecision")
    end=source.index("namespace memory_pressure_detail",start)
    return PRELUDE.replace("/* ACTUAL_MEMORY_PRESSURE_CONTROLLER */",source[start:end])


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
std::atomic<uint64_t> registry_node_visits{0};
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
    for (unsigned rename=0;rename<2;++rename) {
      dynamic->updateImmediateName(12,dynamic->allocate(11),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    }
    DynamicBuffer::TrimCompletedForQueue(q1,12,false);
    DynamicBuffer::TrimCompletedForQueue(q1,13,false);
    require(backing.bytes==768,"normal pressure discarded bounded hot rename reserve");
    probe_dynamic=dynamic.ptr();
    release_probe=+[] {
      require(dynamicRegistryState().mutex.try_lock(),"native destruction held registry mutex");
      dynamicRegistryState().mutex.unlock();
      require(probe_dynamic->mutex_.try_lock(),"native destruction held instance mutex");
      probe_dynamic->mutex_.unlock();
    };
    DynamicBuffer::TrimCompletedForQueue(q1,100,false);
    require(backing.bytes==256 && release_probe==nullptr,"normal pressure failed to trim expired dormant cache");
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
    // Emptying a reusable FIFO does not retire its warm-cache credit. The
    // pressure scan must still expire that dormant lease and return the budget.
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
    for (unsigned rename=0;rename<2;++rename) {
      dynamic->updateImmediateName(1,dynamic->allocate(0),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    }
    DynamicBuffer::TrimCompletedForQueue(q1,3,false);
    const uint64_t old_credit=dynamic->cache_credit_bytes_;
    require(old_credit>0,"hot fixture never obtained bounded cache credit");
    auto first=dynamic->allocate(3);
    auto second=dynamic->allocate(3);
    first->data[0]=0x4a; second->data[0]=0x4b;
    require(dynamic->fifo.empty() && !dynamic->has_cached_names_.load(),"consumed FIFO left a cached-name hint");
    require(dynamic->cache_credit_bytes_==old_credit,"consuming backing prematurely returned its warm credit");
    const uint64_t total_credit=dynamicRegistryState().warm_cache_credit;
    DynamicBuffer::TrimCompletedForQueue(q1,100,false);
    require(dynamic->cache_credit_bytes_==0 && dynamicRegistryState().warm_cache_credit==total_credit-old_credit,
            "empty credited owner retained its expired lease");
    require(first->data[0]==0x4a && second->data[0]==0x4b,"lease expiry reclaimed caller-owned backing");
    Buffer fresh;
    Rc<DynamicBuffer> active=new DynamicBuffer(&fresh,{},q1);
    for (unsigned rename=0;rename<2;++rename) {
      active->updateImmediateName(101,active->allocate(100),0,false);
      auto old=fresh.rename(active->immediateName()); old=nullptr;
    }
    DynamicBuffer::TrimCompletedForQueue(q1,101,false);
    require(active->cache_credit_bytes_>0,"expired empty credit was unavailable to a new active resource");
  }
  require(dynamicRegistryState().warm_cache_credit==0,"destroyed resources left orphan cache credit");
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
    auto scan=[&] {
      while (!done.load(std::memory_order_acquire))
        DynamicBuffer::TrimCompletedForQueue(q1,completed.load(std::memory_order_acquire),true);
    };
    std::thread scanner(scan),second_scanner(scan);
    for (uint64_t seq=1;seq<=10000;++seq) {
      Buffer buffer;
      Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},q1);
      dynamic->updateImmediateName(seq,dynamic->allocate(0),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
      completed.store(seq,std::memory_order_release);
      dynamic=nullptr; // unregister must precede delete; scanner never resurrects.
    }
    done.store(true,std::memory_order_release); scanner.join(); second_scanner.join();
    DynamicBuffer::TrimCompletedForQueue(q1,completed.load(),true);
  }
  require(backing.bytes==0 && backing.allocated==backing.destroyed,"registry lifetime race leaked backing");
  std::cout << "PASS actual DynamicBuffer: one-shot completed trim, pending/current/queued/GPU/deferred Rc pins, "
               "queue isolation, normal-age retention, native release outside locks, busy skip, "
               "6000 resources, 10000 concurrent unregister/delete cycles\n";
}
'''


# Synthetic bounded stress using the exact production allocation paths. The
# archive establishes severe churn, but does not expose every rename request;
# these demand/gap values are not presented as an exact CS2 scheduling replay.
HOT_WORKING_SET_MAIN = r'''
int main() {
  using namespace dxmt;
  auto exercise=[](uint64_t domain,unsigned demand,bool pressure) {
    Buffer buffer;
#ifdef VENDOR_ONLY
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{});
#else
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},domain);
#endif
    uint64_t sampled_hits=0,sampled_misses=0;
    for (unsigned frame=0;frame<20;++frame) {
      const uint64_t coherent=frame*8;
      for (unsigned draw=0;draw<demand;++draw) {
        bool minted=true;
        auto allocation=dynamic->allocate(coherent,&minted);
        dynamic->updateImmediateName(coherent+1,std::move(allocation),0,false);
        auto previous=buffer.rename(dynamic->immediateName()); previous=nullptr;
        if (frame>=4) {
          sampled_hits+=!minted;
          sampled_misses+=minted;
        }
      }
#ifndef VENDOR_ONLY
      if (pressure) DynamicBuffer::TrimCompletedForQueue(domain,coherent+3,false);
#endif
    }
    return std::pair{sampled_hits,sampled_misses};
  };
  // >64 eligible names reproduces the independent legacy allocate-time cap.
  auto burst=exercise(0x9870,80,false);
  const uint64_t burst_regret=g_trim_regret.load();
  std::cout << "hot-80 without global trim: hits=" << burst.first << " misses=" << burst.second
            << " immediate-regret=" << burst_regret << '\n';
#ifndef VENDOR_ONLY
  // The installed registry's two-submission age makes even a two-name working
  // set cold between uses. Actual future/current/GPU references are unchanged.
  auto gap=exercise(0x9871,2,true);
  std::cout << "hot-2 across completion gaps: hits=" << gap.first << " misses=" << gap.second
            << " immediate-regret=" << g_trim_regret.load()-burst_regret << '\n';
  require(gap.second==0 && gap.first==32,"completed hot working-set cache discarded by pressure sweep");
#endif
  require(burst.second==0 && burst.first==1280,"completed hot working-set cache discarded by legacy 64 cap");
  require(backing.bytes==0,"hot cache workload leaked backing");
  std::cout << "PASS actual DynamicBuffer: stable hot caches survive completion gaps and bursts\n";
}
'''


SELF_TRIM_MAIN = r'''
int main() {
  using namespace dxmt;
  Buffer buffer;
  Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},0x9879);
  dynamic->updateImmediateName(100,dynamic->allocate(0),0,false);
  auto previous=buffer.rename(dynamic->immediateName()); previous=nullptr;
  auto spare=dynamic->fifo.front().allocation.ptr();
  const uint64_t allocated=backing.allocated;
  // The completed spare already satisfies this exact request. Draining it in
  // the preceding global pressure sweep replaces backing for no memory gain.
  g_pressure.enabled=true;
  g_pressure.available=0;
  bool minted=true;
  auto replacement=dynamic->allocate(100,&minted);
  require(!minted && replacement.ptr()==spare && backing.allocated==allocated,
          "allocation pressure sweep discarded its own immediately reusable spare");
  g_pressure.enabled=false;
  std::cout << "PASS actual DynamicBuffer: requesting buffer reuses its completed spare under critical pressure\n";
}
'''


BOUNDED_CACHE_MAIN = r'''
int main() {
  using namespace dxmt;
  constexpr uint64_t domain=0x9880;
  constexpr uint64_t size=uint64_t{64}<<10;
  constexpr size_t count=600;
  std::vector<std::unique_ptr<Buffer>> buffers;
  std::vector<Rc<DynamicBuffer>> dynamics;
  auto cached=[&] {
    uint64_t bytes=0;
    for (auto &dynamic:dynamics)
      for (auto &entry:dynamic->fifo) bytes+=entry.allocation->census_bytes_;
    return bytes;
  };
  for (size_t i=0;i<count;++i) {
    buffers.push_back(std::make_unique<Buffer>(size));
    dynamics.emplace_back(new DynamicBuffer(buffers.back().get(),{},domain));
    auto &dynamic=dynamics.back();
    for (unsigned rename=0;rename<2;++rename) {
      dynamic->updateImmediateName(1,dynamic->allocate(0),0,false);
      auto old=buffers.back()->rename(dynamic->immediateName()); old=nullptr;
    }
  }
  require(cached()==count*size*2,"bounded cache workload did not create real spares");
  DynamicBuffer::TrimCompletedForQueue(domain,3,false);
  const uint64_t budget=std::min(uint64_t{128}<<20,g_pressure.reserve/8);
  const uint64_t hot=cached();
  require(hot>0 && hot<=budget,"normal warm cache exceeded queue byte budget or discarded all hot spares");
  require(backing.bytes==count*size+hot,"cache accounting confused current resources with spare capacity");
  // A new cold one-shot spare must not displace the bounded active working set.
  {
    Buffer cold(uint64_t{2}<<20);
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&cold,{},domain);
    dynamic->updateImmediateName(4,dynamic->allocate(3),0,false);
    auto old=cold.rename(dynamic->immediateName()); old=nullptr;
    // One oversized allocation cannot fit this resource's 4MiB hot-cache credit.
    Buffer oversized(uint64_t{8}<<20);
    Rc<DynamicBuffer> large=new DynamicBuffer(&oversized,{},domain);
    for (unsigned rename=0;rename<2;++rename) {
      large->updateImmediateName(4,large->allocate(3),0,false);
      auto old_large=oversized.rename(large->immediateName()); old_large=nullptr;
    }
    DynamicBuffer::TrimCompletedForQueue(domain,6,false);
    require(dynamic->fifo.empty(),"normal pressure retained a cold one-shot allocation");
    require(large->fifo.empty(),"oversized resource exceeded per-resource warm-cache byte cap");
    require(cached()==hot,"cold/oversized cache displaced smaller active working set");
  }
  DynamicBuffer::TrimCompletedForQueue(domain,100,true);
  require(cached()==0,"critical pressure retained completed warm-cache entries");
  require(backing.bytes==count*size,"critical trim released current buffers or retained unused backing");
  for (auto &dynamic:dynamics) dynamic->immediateName()->data[0]=0x7a;
  std::cout << "PASS actual DynamicBuffer: queue warm cache=" << hot << " <= budget=" << budget
            << ", cold/oversized-first, critical draining preserves current backing\n";
}
'''


MID_BATCH_PRESSURE_MAIN = r'''
int main() {
  using namespace dxmt;
  auto cold_at=[](uint64_t coherent,bool retained,const char *message) {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},0x9887);
    dynamic->updateImmediateName(coherent+1,dynamic->allocate(coherent),0,false);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    DynamicBuffer::TrimCompletedForQueue(0x9887,coherent+1,false);
    require((!dynamic->fifo.empty())==retained,message);
  };
  g_pressure.available=g_pressure.reserve*2;
  g_pressure.sampled_ns=10;
  cold_at(0,true,"healthy completion unexpectedly reclaimed cold cache");
  g_pressure.available=g_pressure.reserve;
  ++g_pressure.sampled_ns;
  cold_at(1,false,"soft high-water entry did not reclaim completed cold cache");
  g_pressure.available=g_pressure.reserve+1;
  ++g_pressure.sampled_ns;
  cold_at(2,false,"reclaim stopped before low-water recovery threshold");
  g_pressure.available=g_pressure.reserve+g_pressure.reserve/4;
  ++g_pressure.sampled_ns;
  cold_at(3,true,"low-water recovery failed to stop completion reclamation");
  g_pressure.available=g_pressure.reserve;
  ++g_pressure.sampled_ns;
  constexpr uint64_t domain=0x9888;
  std::vector<std::unique_ptr<Buffer>> buffers;
  std::vector<Rc<DynamicBuffer>> dynamics;
  auto create=[&](unsigned demand,uint64_t coherent) {
    buffers.push_back(std::make_unique<Buffer>());
    dynamics.emplace_back(new DynamicBuffer(buffers.back().get(),{},domain));
    auto &dynamic=dynamics.back();
    for (unsigned rename=0;rename<demand;++rename) {
      dynamic->updateImmediateName(coherent+1,dynamic->allocate(coherent),0,false);
      auto old=buffers.back()->rename(dynamic->immediateName()); old=nullptr;
    }
    dynamic->immediateName()->data[0]=0x67;
  };
  for (unsigned i=0;i<100;++i) create(2,0);
  DynamicBuffer::TrimCompletedForQueue(domain,3,false);
  require(dynamicRegistryState().warm_cache_credit>0,"batch fixture never obtained hot cache credit");
  for (unsigned i=0;i<70;++i) create(1,3);
  release_probe=+[] {
    const auto older_normal=g_pressure;
    g_pressure.available=0;
    g_pressure.sampled_ns=older_normal.sampled_ns+1;
    // A second caller latches a newer emergency while the outer sweep has
    // dropped both locks to release its first fixed-size native batch.
    DynamicBuffer::TrimCompletedForQueue(0x9999,4,false);
    require(dynamicRegistryState().pressure_decision.critical,"newer caller failed to latch emergency pressure");
    g_pressure=older_normal;
  };
  DynamicBuffer::TrimCompletedForQueue(domain,4,false);
  require(release_probe==nullptr,"outer trim did not reach native release batch");
  require(dynamicRegistryState().pressure_decision.critical,"older normal snapshot erased newer emergency");
  require(dynamicRegistryState().warm_cache_credit==0,"outer normal pass regranted warm credit after newer emergency");
  for (auto &dynamic:dynamics) {
    require(dynamic->fifo.empty(),"outer normal batch retained hot cache after newer emergency");
    require(dynamic->immediateName()->data[0]==0x67,"emergency batch corrupted current backing");
  }
  // Unknown snapshots must not erase the last valid emergency or authorize
  // a fresh warm-cache lease for a newly active resource.
  g_pressure.valid=false;
  create(2,5);
  DynamicBuffer::TrimCompletedForQueue(domain,6,false);
  require(dynamicRegistryState().pressure_decision.critical,"unknown snapshot erased last valid emergency");
  require(dynamicRegistryState().warm_cache_credit==0 && dynamics.back()->cache_credit_bytes_==0,
          "unknown pressure granted a new warm-cache lease");
  require(dynamics.back()->fifo.empty(),"unknown snapshot disabled the previously latched emergency drain");
  require(backing.bytes==dynamics.size()*256,"batch retirement released current or retained spare backing");
  std::cout << "PASS actual DynamicBuffer/controller: healthy/latched/recovered completion gates, newer emergency wins across native-release batches, stale/unknown readings grant no cache\n";
}
'''


LINEAR_SWEEP_MAIN = r'''
namespace {
std::vector<dxmt::Rc<dxmt::DynamicBuffer>> *probe_dynamics;
std::vector<std::unique_ptr<dxmt::Buffer>> *probe_buffers;
std::atomic<bool> busy_locked{false}, busy_release{false}, busy_unlocked{false};
uint64_t nested_retired = 0;
void delete_next_and_reenter() {
  using namespace dxmt;
  require(dynamicRegistryState().sweeps != nullptr,"outer cursor absent during native release");
  (*probe_dynamics)[35]=nullptr;
  (*probe_buffers)[35]=nullptr;
  nested_retired=DynamicBuffer::TrimCompletedForQueue(0x98a2,10,true);
}
void release_busy() {
  busy_release.store(true,std::memory_order_release);
  while (!busy_unlocked.load(std::memory_order_acquire)) std::this_thread::yield();
}
}
int main() {
  using namespace dxmt;
  {
    constexpr size_t cold_count=6000,hot_count=2000,count=cold_count+hot_count;
    std::vector<std::unique_ptr<Buffer>> buffers;
    std::vector<Rc<DynamicBuffer>> dynamics;
    for (size_t i=0;i<count;++i) {
      buffers.push_back(std::make_unique<Buffer>());
      dynamics.emplace_back(new DynamicBuffer(buffers.back().get(),{},0x98a0));
      auto &dynamic=dynamics.back();
      for (unsigned rename=0;rename<(i<cold_count?1u:2u);++rename) {
        dynamic->updateImmediateName(1,dynamic->allocate(0),0,false);
        auto old=buffers.back()->rename(dynamic->immediateName()); old=nullptr;
      }
      dynamic->immediateName()->data[0]=0x6d;
      for (auto &entry:dynamic->fifo) entry.allocation->data[0]=0x39;
    }
    registry_node_visits=0;
    const uint64_t retired=DynamicBuffer::TrimCompletedForQueue(0x98a0,3,false);
    const uint64_t visits=registry_node_visits.load();
    uint64_t retained=0;
    for (size_t i=0;i<count;++i) {
      auto &dynamic=dynamics[i];
      require(dynamic->immediateName()->data[0]==0x6d,"sweep changed current resource bytes");
      const uint64_t names=i<cold_count?0:2;
      require(dynamic->fifo.size()==names,"cursor changed cold/hot retirement decisions");
      auto &st=g_dyn_stats[dynamic->census_id_];
      require(st.depth==names && st.eligible_n==names && st.inelig_n==0,"cursor changed census eligibility");
      require(st.wfa_min==(names?1:0) && st.wfa_max==(names?1:0),"cursor changed census extrema");
      for (auto &entry:dynamic->fifo) {
        require(entry.allocation->data[0]==0x39,"sweep changed retained spare bytes");
        retained+=entry.allocation->census_bytes_;
      }
    }
    require(retired==cold_count*256 && retained==hot_count*2*256,"cursor changed returned/retained capacity");
    require(backing.bytes==count*256+retained,"cursor reports phantom memory recovery");
    std::cout << "trim-linear nodes=" << count << " visits=" << visits << " detached=" << retired
              << " retained=" << retained << " credit=" << dynamicRegistryState().warm_cache_credit << '\n';
    require(visits<=count*2,"pressure sweep repeatedly rescanned retained/trimmed registry prefixes");
  }
  require(backing.bytes==0 && dynamicRegistryState().sweeps==nullptr,"linear sweep leaked backing or cursor");
  {
    Buffer buffer;
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},0x98a1);
    for (unsigned seq=1;seq<=193;++seq) {
      dynamic->updateImmediateName(seq,buffer.allocate({},nullptr),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    }
    registry_node_visits=0;
    require(DynamicBuffer::TrimCompletedForQueue(0x98a1,150,true)==150*256,"large FIFO failed to resume after a 64-entry batch");
    require(registry_node_visits==3,"large FIFO cursor did not resume only necessary batches");
    auto &st=g_dyn_stats[dynamic->census_id_];
    require(dynamic->fifo.size()==43 && st.depth==43 && st.eligible_n==0 && st.inelig_n==43,
            "partial large FIFO changed completion eligibility");
    require(st.wfa_min==151 && st.wfa_max==193,"partial FIFO extrema changed");
    require(DynamicBuffer::TrimCompletedForQueue(0x98a1,193,true)==43*256 && dynamic->fifo.empty(),
            "large FIFO did not finish when the GPU frontier advanced");
  }
  require(backing.bytes==0,"large FIFO leaked backing");
  {
    std::vector<std::unique_ptr<Buffer>> buffers;
    std::vector<Rc<DynamicBuffer>> dynamics;
    for (unsigned i=0;i<100;++i) {
      buffers.push_back(std::make_unique<Buffer>());
      dynamics.emplace_back(new DynamicBuffer(buffers.back().get(),{},0x98a2));
      dynamics.back()->updateImmediateName(10,dynamics.back()->allocate(0),0,false);
      auto old=buffers.back()->rename(dynamics.back()->immediateName()); old=nullptr;
    }
    probe_dynamics=&dynamics; probe_buffers=&buffers;
    release_probe=delete_next_and_reenter;
    const uint64_t outer=DynamicBuffer::TrimCompletedForQueue(0x98a2,10,true);
    require(outer==64*256 && nested_retired==35*256,"reentrant retirement lost or double-counted an extent");
    require(backing.bytes==99*256 && dynamicRegistryState().sweeps==nullptr,"unregister left a dangling cursor");
  }
  require(backing.bytes==0,"reentrant deletion leaked backing");
  {
    std::vector<std::unique_ptr<Buffer>> buffers;
    std::vector<Rc<DynamicBuffer>> dynamics;
    for (unsigned i=0;i<100;++i) {
      buffers.push_back(std::make_unique<Buffer>());
      dynamics.emplace_back(new DynamicBuffer(buffers.back().get(),{},0x98a3));
      dynamics.back()->updateImmediateName(10,dynamics.back()->allocate(0),0,false);
      auto old=buffers.back()->rename(dynamics.back()->immediateName()); old=nullptr;
    }
    std::thread holder([&] {
      {
        std::lock_guard<mutex> lock(dynamics.back()->mutex_);
        busy_locked.store(true,std::memory_order_release);
        while (!busy_release.load(std::memory_order_acquire)) std::this_thread::yield();
      }
      busy_unlocked.store(true,std::memory_order_release);
    });
    while (!busy_locked.load(std::memory_order_acquire)) std::this_thread::yield();
    // Unlock completes before this callback returns; the registry and instance
    // locks must be absent while any native release callback executes.
    release_probe=release_busy;
    registry_node_visits=0;
    const uint64_t retired=DynamicBuffer::TrimCompletedForQueue(0x98a3,10,true);
    holder.join();
    require(retired==100*256 && backing.bytes==100*256,"bounded retry missed newly available completed storage");
    require(registry_node_visits<=200,"persistently busy prefix caused repeated batch rescans");
  }
  require(backing.bytes==0 && dynamicRegistryState().sweeps==nullptr,"busy retry leaked backing or cursor");
  {
    // A newer emergency can arrive during native release of the LAST hot
    // batch. The cursor must recheck the controller even after reaching end.
    Buffer buffer(uint64_t{64}<<10);
    Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},0x98a4);
    for (unsigned rename=0;rename<80;++rename) {
      dynamic->updateImmediateName(1,dynamic->allocate(0),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
    }
    dynamic->immediateName()->data[0]=0x7d;
    release_probe=+[] {
      const auto older_normal=g_pressure;
      g_pressure.available=0;
      g_pressure.sampled_ns=older_normal.sampled_ns+1;
      DynamicBuffer::TrimCompletedForQueue(0x999a,3,false);
      require(dynamicRegistryState().pressure_decision.critical,"final release failed to latch emergency");
      g_pressure=older_normal;
    };
    const uint64_t retired=DynamicBuffer::TrimCompletedForQueue(0x98a4,3,false);
    require(release_probe==nullptr && dynamic->fifo.empty() && retired==80*(uint64_t{64}<<10),
            "final hot batch missed a newer emergency during native release");
    require(dynamic->immediateName()->data[0]==0x7d,"final emergency changed current resource bytes");
  }
  require(backing.bytes==0 && dynamicRegistryState().sweeps==nullptr,"final emergency leaked backing or cursor");
  std::cout << "PASS actual trim cursor: linear cold/hot pass, large FIFO resume, exact census/bytes, cursor invalidation on delete, nested sweep, bounded busy retry\n";
}
'''


def function_body(source, signature):
    start=source.index(signature)
    opening=source.index("{",start)
    depth=0
    for offset in range(opening,len(source)):
        depth += (source[offset]=="{") - (source[offset]=="}")
        if depth==0:
            return source[start:offset+1]
    raise ValueError("unterminated production function: "+signature)


def trim_visit_instrumentation(source):
    old='for (auto *dynamic = dynamicRegistryState().head; dynamic && count < retired.size(); dynamic = dynamic->registry_next_) {'
    new='while (sweep.cursor.next && count < retired.size()) {'
    if old in source:
        return source.replace(old,old+'\n          registry_node_visits.fetch_add(1,std::memory_order_relaxed);',1)
    assert source.count(new)==1,"trim visit instrumentation anchor changed"
    return source.replace(new,new+'\n          registry_node_visits.fetch_add(1,std::memory_order_relaxed);',1)


def head_restart_trim(source):
    fixture=ROOT/'tests/host/fixtures/dxmt-trim-head-87feb2.cpp'
    contents=fixture.read_text()
    assert contents.startswith('// Captured actual production trim from Madeira 87feb2aa.')
    signature='uint64_t\nDynamicBuffer::TrimCompletedForQueue('
    old=function_body(contents,signature)
    assert hashlib.sha256((old+'\n').encode()).hexdigest()=='11bbbe4be5b4e4912539981540dd005f30f43c3299027574cbdf6f1a3721304e',\
        'captured 87feb2 trim function changed'
    return source.replace(function_body(source,signature),old,1)


def registry_storage_names(source):
    """Adapt private storage identifiers after validating pinned historical code."""
    for old, new in (
        ("g_dynamic_registry_mutex", "dynamicRegistryState().mutex"),
        ("g_dynamic_registry_head", "dynamicRegistryState().head"),
        ("g_dynamic_warm_cache_credit", "dynamicRegistryState().warm_cache_credit"),
        ("g_dynamic_pressure_controller", "dynamicRegistryState().pressure_controller"),
        ("g_dynamic_pressure_decision", "dynamicRegistryState().pressure_decision"),
    ):
        source=source.replace(old,new)
    return source


def installed_pressure_trim(source):
    fixture=ROOT/"tests/host/fixtures/dynamic-buffer-installed-pressure-trim.cpp"
    contents=fixture.read_text()
    assert "source 2059087c" in contents
    signature="uint64_t\\nDynamicBuffer::TrimCompletedForQueue(".replace("\\n","\n")
    body=function_body(contents,signature)
    expected="63f6d9097fd534eb140819a30c2ea455a2430d97c17719255d9ca765014a1005"
    assert hashlib.sha256((body+"\n").encode()).hexdigest()==expected,"installed trim fixture changed"
    # Validate the historical body before adapting only its private storage names.
    body=registry_storage_names(body)
    current=function_body(source,signature)
    if "pending_request" in current[:current.index("{")]:
        body=body.replace("bool critical) {","bool critical, const DynamicBuffer *pending_request) {",1)
    return source.replace(current,body,1)


def installed_allocate(source):
    fixture=ROOT/"tests/host/fixtures/dynamic-buffer-installed-allocate.cpp"
    contents=fixture.read_text()
    assert "source 2059087c" in contents
    signature="Rc<BufferAllocation>\nDynamicBuffer::allocate("
    body=function_body(contents,signature)
    expected="1cb3a8d162eed7dc896cea0cbaa4e0b5a136bc2ea6a3164b1fa1266df7625738"
    assert hashlib.sha256((body+"\n").encode()).hexdigest()==expected,"installed allocate fixture changed"
    current=function_body(source,signature)
    return source.replace(current,body,1)


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
    cpp.write_text(prelude() + census_types()
                   + 'void require(bool ok,const char *s) { if (!ok) { std::cerr<<s; std::exit(1); } }\n'
                   + PLACED_PRELUDE + allocation_destructor(source) + PLACED_MAIN)
    subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-I", str(ROOT / "dxmt/src/util"), str(cpp), "-o", str(exe)], check=True)
    return subprocess.run([str(exe)], text=True, capture_output=True, timeout=30)


def compile_and_run(directory, name, header, implementation, main):
    cpp = directory / (name + ".cpp")
    exe = directory / name
    cpp.write_text(prelude() + census_types() + COUNTERS + dynamic_header(header)
                   + dynamic_methods(implementation) + queue_domain_fixture() + main)
    subprocess.run(["g++", "-std=c++20", "-O1", "-g", "-pthread",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-I", str(ROOT / "dxmt/src/util"), str(cpp), "-o", str(exe)], check=True)
    return subprocess.run([str(exe)], text=True, capture_output=True, timeout=60)


REGISTRY_IMAGE_PRELUDE = r'''
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#define REGISTRY_IMAGE __attribute__((section("dynamic_registry_image"), aligned(65536), used))
extern "C" char __start_dynamic_registry_image[], __stop_dynamic_registry_image[];
static void protectRegistryImage(bool readonly) {
  const long page=sysconf(_SC_PAGESIZE);
  require(page>0 && 65536%page==0,"unsupported protection-page size");
  const auto begin=reinterpret_cast<uintptr_t>(__start_dynamic_registry_image);
  const auto end=reinterpret_cast<uintptr_t>(__stop_dynamic_registry_image);
  require(begin%page==0 && end%page==0,"registry image section shares a protection page");
  require(mprotect(reinterpret_cast<void *>(begin),end-begin,
                   PROT_READ | (readonly?PROT_EXEC:PROT_WRITE))==0,
          "could not change registry image protection");
}
'''


REGISTRY_IMAGE_MAIN = r'''
int main() {
  using namespace dxmt;
  const rlimit no_core{0,0};
  require(setrlimit(RLIMIT_CORE,&no_core)==0,"could not disable fixture core files");
  constexpr uint64_t domain=0x9890;
  Buffer buffer;
  Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},domain);
  for (unsigned rename=0;rename<2;++rename) {
    dynamic->updateImmediateName(1,dynamic->allocate(0),0,false);
    auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
  }
  DynamicBuffer::TrimCompletedForQueue(domain,3,false);
  require(dynamic->cache_credit_bytes_>0,"protected-image fixture did not earn warm credit");
#ifndef WRITABLE_IMAGE_GLOBALS
  protectRegistryImage(true);
#endif
#if defined(BEFORE_IMAGE_GLOBALS) && !defined(WRITABLE_IMAGE_GLOBALS)
  // The exact production trim now attempts its old warm-credit store in RX
  // image storage. The parent requires the resulting real protection fault.
  DynamicBuffer::TrimCompletedForQueue(domain,4,true);
  require(false,"old mutable image credit unexpectedly accepted a store");
#else
#ifndef BEFORE_IMAGE_GLOBALS
  const auto image_begin=reinterpret_cast<uintptr_t>(__start_dynamic_registry_image);
  const auto image_end=reinterpret_cast<uintptr_t>(__stop_dynamic_registry_image);
  const auto state=reinterpret_cast<uintptr_t>(&dynamicRegistryState());
  require(state<image_begin || state>=image_end,"registry state remained in protected image storage");
#endif
  // Registration, warm-credit changes, controller samples, capped report
  // counters, and unregister all execute while the real owner slot is RX.
  for (uint64_t iteration=0;iteration<128;++iteration) {
    ++g_pressure.sampled_ns;
    Buffer next;
    Rc<DynamicBuffer> active=new DynamicBuffer(&next,{},domain);
    for (unsigned rename=0;rename<2;++rename) {
      active->updateImmediateName(iteration*8+9,active->allocate(iteration*8+8),0,false);
      auto old=next.rename(active->immediateName()); old=nullptr;
    }
    DynamicBuffer::TrimCompletedForQueue(domain,iteration*8+11,false);
    require(active->cache_credit_bytes_>0,"RX owner prevented a warm-cache lease");
    DynamicBuffer::TrimCompletedForQueue(domain,iteration*8+12,true);
    require(active->cache_credit_bytes_==0,"RX owner prevented critical credit return");
  }
  require(dynamicRegistryState().warm_cache_credit==0,"protected-image stress retained orphan credit");
  require(dynamicRegistryState().reports.load()>=128,"protected-image stress omitted mutable report counter");
  protectRegistryImage(false); // Ordinary module teardown may clear its owner slot.
  std::cout << "registry-policy credit=" << dynamicRegistryState().warm_cache_credit
            << " backing=" << backing.bytes.load() << " trim-n=" << g_trim_total_n.load()
            << " trim-bytes=" << g_trim_total_bytes.load() << " reports="
            << dynamicRegistryState().reports.load() << '\n';
  std::cout << "PASS actual DynamicBuffer: RX image owner, 128 heap-state registry/lease/trim cycles without protection fault\n";
#endif
}
'''


REGISTRY_LIFETIME_MAIN = r'''
namespace dxmt {
struct LatePopulatedRegistryResource {
  std::unique_ptr<Buffer> buffer;
  Rc<DynamicBuffer> dynamic;
  ~LatePopulatedRegistryResource() {
    require(registry_state_destructions==0,"registry died before a static resource holder");
    dynamic=nullptr;
    buffer=nullptr;
  }
} late_registry_resource;
}
int main() {
  using namespace dxmt;
  require(registry_state_allocations==1,"registry owner allocated more than once during module initialization");
  require(registry_state_bytes==sizeof(DynamicRegistryState) && registry_state_bytes<=512,
          "registry metadata allocation grew beyond its fixed-size bound");
  auto *state=&dynamicRegistryState();
  std::atomic<bool> failed{false};
  std::vector<std::thread> threads;
  for (unsigned worker=0;worker<8;++worker) threads.emplace_back([&,worker] {
    if (&dynamicRegistryState()!=state) failed=true;
    for (unsigned iteration=0;iteration<32;++iteration) {
      Buffer buffer;
      Rc<DynamicBuffer> dynamic=new DynamicBuffer(&buffer,{},0x9891+worker);
      dynamic->updateImmediateName(1,dynamic->allocate(0),0,false);
      auto old=buffer.rename(dynamic->immediateName()); old=nullptr;
      DynamicBuffer::TrimCompletedForQueue(0x9891+worker,2,true);
    }
  });
  for (auto &thread:threads) thread.join();
  require(!failed && registry_state_allocations==1,"concurrent registry use created another owner");
  require(dynamicRegistryState().head==nullptr,"concurrent registry users left a registered resource");
  late_registry_resource.buffer=std::make_unique<Buffer>();
  late_registry_resource.dynamic=new DynamicBuffer(late_registry_resource.buffer.get(),{},0x9899);
  std::cout << "PASS actual DynamicBuffer: one fixed-size heap owner (" << sizeof(DynamicRegistryState)
            << " bytes), concurrent use, late-populated static resource lifetime\n";
}
'''


def registry_block(source):
    start=source.index("namespace {\nstruct DynamicRegistryState {")
    end=source.index("} // namespace",start)+len("} // namespace")
    return source[start:end]


def legacy_registry_storage_names(source):
    for old,new in (
        ("mutex","g_dynamic_registry_mutex"),
        ("head","g_dynamic_registry_head"),
        ("warm_cache_credit","g_dynamic_warm_cache_credit"),
        ("pressure_controller","g_dynamic_pressure_controller"),
        ("pressure_decision","g_dynamic_pressure_decision"),
        ("reports","g_dynamic_reports"),
    ):
        source=source.replace("dynamicRegistryState()."+old,new)
    return source


def protected_registry_source(source, before):
    owner="static const auto g_dynamic_registry = std::make_unique<DynamicRegistryState>();"
    assert source.count(owner)==1,"registry owner initialization contract changed"
    padding="\nstatic unsigned char g_registry_image_padding[65536] REGISTRY_IMAGE = {};\n"
    if not before:
        return source.replace(owner,owner.replace(" =", " REGISTRY_IMAGE =",1)+padding,1)
    # Place the observed pre-fix warm-credit member back in image storage.
    # Keep the actual registry/cursor implementation intact; only the target
    # storage differs, so native retirement and policy remain comparable.
    globals_source='static uint64_t g_dynamic_warm_cache_credit REGISTRY_IMAGE = 0;\n'+padding
    block=registry_block(source)
    assert block.count('uint64_t warm_cache_credit = 0;')==1
    proxy=block.replace('uint64_t warm_cache_credit = 0;',
                        'uint64_t &warm_cache_credit = g_dynamic_warm_cache_credit;',1)
    return source.replace(block,globals_source+proxy,1)


def compile_protected_registry(directory, name, header, implementation, before, writable=False):
    cpp=directory/(name+".cpp")
    exe=directory/name
    main=REGISTRY_IMAGE_MAIN
    if before: main="#define BEFORE_IMAGE_GLOBALS\n"+main
    if writable: main="#define WRITABLE_IMAGE_GLOBALS\n"+main
    cpp.write_text(prelude()+census_types()+COUNTERS+REGISTRY_IMAGE_PRELUDE
                   +dynamic_header(header)+dynamic_methods(protected_registry_source(implementation,before))+main)
    # ASan replaces SIGSEGV handling; use the OS's real RX-page fault here.
    subprocess.run(["g++","-std=c++20","-O1","-g","-pthread","-fno-toplevel-reorder",
                    "-I",str(ROOT/"dxmt/src/util"),str(cpp),"-o",str(exe)],check=True)
    return subprocess.run([str(exe)],text=True,capture_output=True,timeout=30)


def tracked_registry_source(source):
    start="namespace {\nstruct DynamicRegistryState {"
    assert source.count(start)==1
    tracked=r'''
namespace {
static uint64_t registry_state_allocations=0,registry_state_destructions=0;
static uint64_t registry_state_deallocations=0,registry_state_bytes=0;
struct RegistryAllocationBalance {
  ~RegistryAllocationBalance() {
    require(registry_state_allocations==1 && registry_state_destructions==1 &&
            registry_state_deallocations==1,"registry owner did not destroy and free its allocation normally");
    std::cout << "PASS registry module teardown: state destructor and ordinary delete exactly once\n";
  }
} registry_allocation_balance;
struct DynamicRegistryState {
  static void *operator new(size_t bytes) {
    ++registry_state_allocations; registry_state_bytes+=bytes;
    return ::operator new(bytes);
  }
  static void operator delete(void *pointer) {
    ++registry_state_deallocations; ::operator delete(pointer);
  }
  ~DynamicRegistryState() {
    require(head==nullptr && sweeps==nullptr && warm_cache_credit==0,"registry owner died while resources, sweep cursors or credit remained live");
    ++registry_state_destructions;
  }
'''
    return source.replace(start,tracked,1)


def check_registry_image_isolation(directory, implementation):
    block=registry_block(implementation)
    exported=r'''
extern "C" {
__attribute__((visibility("default"))) uintptr_t registry_owner_address() {
  return reinterpret_cast<uintptr_t>(&g_dynamic_registry);
}
__attribute__((visibility("default"))) uintptr_t registry_state_address() {
  return reinterpret_cast<uintptr_t>(&dynamicRegistryState());
}
__attribute__((visibility("default"))) uint64_t registry_credit() {
  return dynamicRegistryState().warm_cache_credit;
}
__attribute__((visibility("default"))) void registry_set_credit(uint64_t value) {
  dynamicRegistryState().warm_cache_credit=value;
}
}
'''
    libraries=[]
    for name in ("registry-first","registry-second"):
        cpp=directory/(name+".cpp")
        shared=directory/(name+(".dylib" if sys.platform=="darwin" else ".so"))
        cpp.write_text(prelude()+"namespace dxmt { class DynamicBuffer;\n"+block+exported+"}\n")
        shared_flag="-dynamiclib" if sys.platform=="darwin" else "-shared"
        subprocess.run(["g++","-std=c++20","-O1",shared_flag,"-fPIC","-fvisibility=hidden",
                        "-I",str(ROOT/"dxmt/src/util"),str(cpp),"-o",str(shared)],check=True)
        library=ctypes.CDLL(str(shared),mode=os.RTLD_LOCAL|os.RTLD_NOW)
        library.registry_owner_address.restype=ctypes.c_size_t
        library.registry_state_address.restype=ctypes.c_size_t
        library.registry_credit.restype=ctypes.c_uint64
        library.registry_set_credit.argtypes=[ctypes.c_uint64]
        libraries.append(library)
    first,second=libraries
    assert first.registry_owner_address()!=second.registry_owner_address(),"loaded images merged private owner slots"
    assert first.registry_state_address()!=second.registry_state_address(),"loaded images shared mutable registry state"
    first.registry_set_credit(73)
    assert first.registry_credit()==73 and second.registry_credit()==0,"one loaded image changed another's warm credit"
    second.registry_set_credit(29)
    assert first.registry_credit()==73 and second.registry_credit()==29,"loaded-image heap owners are not isolated"
    first.registry_set_credit(0)
    second.registry_set_credit(0)
    import _ctypes
    for library in libraries: _ctypes.dlclose(library._handle)
    print("PASS actual registry owner declaration: two RTLD_LOCAL images retain independent owner slots and heap state")


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
        if sys.platform=="linux":
            # Dedicated ELF sections isolate the real owner/credit storage from
            # unrelated globals. Mach-O hosts still run every ownership/cache
            # test below; this page-protection fixture needs ELF start/stop symbols.
            image_before=compile_protected_registry(directory,"before-registry-image",new_h,new_c,True)
            assert image_before.returncode==-signal.SIGSEGV, image_before.stdout+image_before.stderr
            print("BEFORE reproduced: actual trim warm-credit write faults in RX image metadata")
            image_after=compile_protected_registry(directory,"after-registry-image",new_h,new_c,False)
            assert image_after.returncode==0,image_after.stdout+image_after.stderr
            print(image_after.stdout.strip())
            image_writable=compile_protected_registry(directory,"before-registry-writable",new_h,new_c,True,True)
            assert image_writable.returncode==0,image_writable.stdout+image_writable.stderr
            policy=lambda result: next(line for line in result.stdout.splitlines() if line.startswith("registry-policy "))
            assert policy(image_writable)==policy(image_after),image_writable.stdout+image_after.stdout
            print("PASS writable old globals and RX owner/heap state preserve identical credit, live backing, trim totals and report counts")
        else:
            print("SKIP protected registry image pages: ELF-only fixture; ownership/cache tests remain enabled")
        lifecycle=compile_and_run(directory,"registry-owner-lifetime",new_h,
                                  tracked_registry_source(new_c),REGISTRY_LIFETIME_MAIN)
        assert lifecycle.returncode==0,lifecycle.stdout+lifecycle.stderr
        assert "ordinary delete exactly once" in lifecycle.stdout,lifecycle.stdout+lifecycle.stderr
        print(lifecycle.stdout.strip())
        check_registry_image_isolation(directory,new_c)
        before = compile_and_run(directory,"before",old_h,old_c,OLD_MAIN)
        assert before.returncode != 0 and "one-shot retired backing retained" in before.stderr, before.stderr
        print(before.stderr.strip())
        after = compile_and_run(directory,"after",new_h,new_c,NEW_MAIN)
        assert after.returncode == 0, after.stdout + after.stderr
        print(after.stdout.strip())
        restart=compile_and_run(directory,"before-linear-sweep",new_h,
                                trim_visit_instrumentation(head_restart_trim(new_c)),LINEAR_SWEEP_MAIN)
        assert restart.returncode!=0 and 'repeatedly rescanned' in restart.stderr,restart.stdout+restart.stderr
        print('BEFORE reproduced: '+restart.stdout.strip())
        linear=compile_and_run(directory,"after-linear-sweep",new_h,
                               trim_visit_instrumentation(new_c),LINEAR_SWEEP_MAIN)
        assert linear.returncode==0,linear.stdout+linear.stderr
        print(linear.stdout.strip())
        cap_before=compile_and_run(directory,"before-hot-cap",old_h,old_c,"#define VENDOR_ONLY\n"+HOT_WORKING_SET_MAIN)
        assert cap_before.returncode != 0 and "legacy 64 cap" in cap_before.stderr, cap_before.stdout+cap_before.stderr
        print("BEFORE reproduced: "+cap_before.stdout.strip())
        pressure_before=compile_and_run(directory,"before-hot-pressure",new_h,installed_pressure_trim(new_c),HOT_WORKING_SET_MAIN)
        assert pressure_before.returncode != 0 and "pressure sweep" in pressure_before.stderr, pressure_before.stdout+pressure_before.stderr
        print("BEFORE reproduced: "+pressure_before.stdout.strip())
        self_before=compile_and_run(directory,"before-self-trim",new_h,installed_allocate(installed_pressure_trim(new_c)),SELF_TRIM_MAIN)
        assert self_before.returncode != 0 and "its own immediately reusable spare" in self_before.stderr,self_before.stdout+self_before.stderr
        print("BEFORE reproduced: allocation pressure sweep destroys its own reusable spare")
        self_after=compile_and_run(directory,"after-self-trim",new_h,new_c,SELF_TRIM_MAIN)
        assert self_after.returncode==0,self_after.stdout+self_after.stderr
        print(self_after.stdout.strip())
        hot_after=compile_and_run(directory,"after-hot",new_h,new_c,HOT_WORKING_SET_MAIN)
        assert hot_after.returncode == 0, hot_after.stdout+hot_after.stderr
        print(hot_after.stdout.strip())
        bounded=compile_and_run(directory,"after-bounded",new_h,new_c,BOUNDED_CACHE_MAIN)
        assert bounded.returncode==0,bounded.stdout+bounded.stderr
        print(bounded.stdout.strip())
        batch=compile_and_run(directory,"after-mid-batch",new_h,new_c,MID_BATCH_PRESSURE_MAIN)
        assert batch.returncode==0,batch.stdout+batch.stderr
        print(batch.stdout.strip())
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
    assert dec.index("dynamicRegistryState().mutex") < dec.index("delete this"), "unregister after object lifetime ended"
    assert dec.index("registry_prev_->registry_next_") < dec.index("delete this")
    trim = new_c[new_c.index("DynamicBuffer::TrimCompletedForQueue"):new_c.index("DynamicBuffer::incRef()")]
    assert "incRef" not in trim, "pressure scanner must not resurrect a zero-ref object"
    print("PASS source lifetime contract: unregister precedes delete; scanner cannot resurrect")


if __name__ == "__main__":
    main()
