#!/usr/bin/env python3
"""Stage queue-scoped, GPU-complete DynamicBuffer cache pressure reclamation."""
import argparse
import hashlib
import json
from pathlib import Path

FILES = (
    'src/dxmt/dxmt_dynamic.hpp',
    'src/dxmt/dxmt_dynamic.cpp',
    'src/d3d11/d3d11_buffer.cpp',
    'src/d3d11/d3d11_texture_dynamic.cpp',
    'src/dxmt/dxmt_buffer.cpp',
)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('DXMT dynamic memory input contract changed: ' + repr(old[:100]))
    return text.replace(old, new, 1)


REGISTRY = r'''
/* Queue domains are monotonic identities, never recycled addresses: internal
 * D3D11 references may outlive their parent queue. D3D9 stays unregistered.
 * Registry -> try_lock(instance), unregister BEFORE delete, no strong registry
 * ownership. Credit accounting is protected by the registry mutex. */
namespace {
struct DynamicRegistryState {
  dxmt::mutex mutex;
  DynamicBuffer *head = nullptr;
  uint64_t warm_cache_credit = 0;
  MemoryPressureController pressure_controller;
  MemoryPressureDecision pressure_decision = pressure_controller.evaluate(MemoryPressureSnapshot{});
  std::atomic<uint64_t> reports{0};
};

// Copied native images are executable/read-only. Publish one heap owner during
// the same module initialization as the former registry globals; only its
// immutable pointer stays in image data. This preserves their destruction
// order, including resources held by statics populated after initialization.
// Publication/teardown may use existing image-write recovery once; recurring
// state mutations target heap memory. The owner releases this fixed-size
// metadata normally at module teardown; allocation failure follows C++ new.
static const auto g_dynamic_registry = std::make_unique<DynamicRegistryState>();

static DynamicRegistryState &
dynamicRegistryState() {
  return *g_dynamic_registry;
}
} // namespace

// All calls hold the registry mutex. An unknown reading grants no new credit,
// but must not erase another thread's last valid emergency decision.
static auto
pressureDecisionLocked(const MemoryPressureSnapshot &pressure, uint64_t upcoming = 0) {
  const auto decision = dynamicRegistryState().pressure_controller.evaluate(pressure, upcoming);
  if (decision.valid) dynamicRegistryState().pressure_decision = decision;
  return dynamicRegistryState().pressure_decision;
}

uint64_t
DynamicBuffer::allocationCostLocked() const {
  return name_.ptr() ? name_->census_bytes_ : (buffer ? buffer->length() : 0);
}

void
DynamicBuffer::noteRequestLocked(uint64_t coherent_seq_id) {
  if (!request_count_) {
    request_epoch_ = coherent_seq_id;
    epoch_demand_ = 1;
  } else if (request_epoch_ != coherent_seq_id) {
    const uint64_t gap = coherent_seq_id > request_epoch_ ? std::min<uint64_t>(1024, coherent_seq_id - request_epoch_) : 1;
    request_gap_ = std::max(gap, (request_gap_ * 7 + gap) / 8);
    request_epoch_ = coherent_seq_id;
    epoch_demand_ = 1;
  } else if (epoch_demand_ < 65536) {
    ++epoch_demand_;
  }
  if (request_count_ < 65536) ++request_count_;
  peak_demand_ = std::max(peak_demand_, epoch_demand_);
  // A single upload earns no persistent spare. Learning/growth is occasional;
  // do not acquire a global registry lock or write a global atomic per draw.
  if (queue_domain_ && request_count_ >= 2 && lease_attempt_epoch_ != coherent_seq_id &&
      cache_credit_bytes_ < desiredCacheBytesLocked())
    lease_pending_.store(true, std::memory_order_release);
}

bool
DynamicBuffer::hotAtLocked(uint64_t coherent_seq_id) const {
  if (request_count_ < 2)
    return false;
  const uint64_t age = coherent_seq_id > request_epoch_ ? coherent_seq_id - request_epoch_ : 0;
  const uint64_t gap = std::max(request_gap_, reuse_age_);
  const uint64_t horizon = std::max<uint64_t>(8, std::min<uint64_t>(1024, gap * 4));
  return age <= horizon;
}

uint64_t
DynamicBuffer::desiredCacheBytesLocked() const {
  const uint64_t cost = allocationCostLocked();
  constexpr uint64_t resource_cap = uint64_t{4} << 20;
  if (!cost || cost > resource_cap || request_count_ < 2)
    return 0;
  uint64_t names = 1;
  while (names < peak_demand_ && names < 65536) names <<= 1;
  return std::min(names, resource_cap / cost) * cost;
}

void
DynamicBuffer::updateLeaseLocked(uint64_t coherent_seq_id, uint64_t budget, bool critical, bool allow_new) {
  const bool hot = hotAtLocked(coherent_seq_id);
  const uint64_t desired = !critical && hot ? desiredCacheBytesLocked() : 0;
  const uint64_t others = dynamicRegistryState().warm_cache_credit - cache_credit_bytes_;
  const uint64_t capacity = budget > others ? budget - others : 0;
  const uint64_t cost = allocationCostLocked();
  const uint64_t candidate = std::min(desired, allow_new ? capacity : cache_credit_bytes_);
  const uint64_t grant = cost ? (candidate / cost) * cost : 0;
  dynamicRegistryState().warm_cache_credit = others + grant;
  cache_credit_bytes_ = grant;
  lease_attempt_epoch_ = coherent_seq_id;
  lease_pending_.store(false, std::memory_order_release);
  if (!hot && request_count_ >= 2) {
    request_count_ = 0;
    epoch_demand_ = 0;
    peak_demand_ = 1;
    request_gap_ = 1;
    reuse_age_ = 0;
  }
}

void
DynamicBuffer::EnsureWorkingSetLease(DynamicBuffer *dynamic, uint64_t coherent_seq_id, const MemoryPressureSnapshot &pressure) {
  if (!dynamic->lease_pending_.load(std::memory_order_acquire))
    return;
  std::lock_guard<dxmt::mutex> registry_lock(dynamicRegistryState().mutex);
  const auto decision = pressureDecisionLocked(pressure);
  std::unique_lock<dxmt::mutex> instance_lock(dynamic->mutex_, std::try_to_lock);
  if (instance_lock.owns_lock())
    dynamic->updateLeaseLocked(coherent_seq_id, decision.warm_cache_budget, decision.critical, pressure.valid && pressure.reserve);
}

void
DynamicBuffer::updateCensusLocked(uint64_t coherent_seq_id) {
  census_coherent_ = coherent_seq_id;
  if (census_id_ >= DYN_CENSUS_SLOTS) return;
  auto &st = g_dyn_stats[census_id_];
  uint64_t en = 0, eb = 0, in = 0, ib = 0, lo = ~0ull, hi = 0;
  for (const auto &entry : fifo) {
    const uint64_t bytes = entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
    if (entry.will_free_at <= coherent_seq_id) { ++en; eb += bytes; }
    else { ++in; ib += bytes; }
    lo = std::min(lo, entry.will_free_at);
    hi = std::max(hi, entry.will_free_at);
  }
  st.depth.store(fifo.size(), std::memory_order_relaxed);
  st.eligible_n.store(en, std::memory_order_relaxed);
  st.eligible_bytes.store(eb, std::memory_order_relaxed);
  st.inelig_n.store(in, std::memory_order_relaxed);
  st.inelig_bytes.store(ib, std::memory_order_relaxed);
  st.wfa_min.store(lo == ~0ull ? 0 : lo, std::memory_order_relaxed);
  st.wfa_max.store(hi, std::memory_order_relaxed);
}

void
DynamicBuffer::recordQueuePopLocked(uint64_t bytes, uint64_t will_free_at) {
  if (fifo.empty()) has_cached_names_.store(false, std::memory_order_release);
  if (census_id_ >= DYN_CENSUS_SLOTS) return;
  auto &st = g_dyn_stats[census_id_];
  st.depth.store(fifo.size(), std::memory_order_relaxed);
  if (will_free_at <= census_coherent_) {
    st.eligible_n.fetch_sub(1, std::memory_order_relaxed);
    st.eligible_bytes.fetch_sub(bytes, std::memory_order_relaxed);
  } else {
    st.inelig_n.fetch_sub(1, std::memory_order_relaxed);
    st.inelig_bytes.fetch_sub(bytes, std::memory_order_relaxed);
  }
  st.wfa_min.store(fifo.empty() ? 0 : fifo.front().will_free_at, std::memory_order_relaxed);
  st.wfa_max.store(fifo.empty() ? 0 : fifo.back().will_free_at, std::memory_order_relaxed);
}

void
DynamicBuffer::recordQueuePushLocked() {
  if (fifo.size() == 1) has_cached_names_.store(true, std::memory_order_release);
  g_mem_census.dyn_fifo_depth.store(fifo.size(), std::memory_order_relaxed);
  uint64_t d = fifo.size(), mx = g_mem_census.dyn_fifo_depth_max.load(std::memory_order_relaxed);
  while (d > mx && !g_mem_census.dyn_fifo_depth_max.compare_exchange_weak(mx, d, std::memory_order_relaxed)) {}
  if (census_id_ >= DYN_CENSUS_SLOTS) return;
  auto &st = g_dyn_stats[census_id_];
  const auto &entry = fifo.back();
  const uint64_t bytes = entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
  st.depth.store(fifo.size(), std::memory_order_relaxed);
  if (entry.will_free_at <= census_coherent_) {
    st.eligible_n.fetch_add(1, std::memory_order_relaxed);
    st.eligible_bytes.fetch_add(bytes, std::memory_order_relaxed);
  } else {
    st.inelig_n.fetch_add(1, std::memory_order_relaxed);
    st.inelig_bytes.fetch_add(bytes, std::memory_order_relaxed);
  }
  const uint64_t lo = st.wfa_min.load(std::memory_order_relaxed);
  const uint64_t hi = st.wfa_max.load(std::memory_order_relaxed);
  st.wfa_min.store(fifo.size() == 1 ? entry.will_free_at : std::min(lo, entry.will_free_at), std::memory_order_relaxed);
  st.wfa_max.store(std::max(hi, entry.will_free_at), std::memory_order_relaxed);
}

uint64_t
DynamicBuffer::TrimCompletedForQueue(uint64_t queue_domain, uint64_t coherent_seq_id, bool critical,
                                     const DynamicBuffer *pending_request) {
  if (!queue_domain) return 0;
  const auto pressure = memoryPressureSnapshot();
  const bool force_critical = critical;
  const uint64_t upcoming = pending_request && pending_request->buffer ? pending_request->buffer->length() : 0;
  uint64_t warm_budget = 0;
  {
    std::lock_guard<dxmt::mutex> registry_lock(dynamicRegistryState().mutex);
    // A pending requester reaches this path only after an actual reuse miss.
    // Let the controller compare its latest valid sample, not a stale caller's
    // half-reserve boolean. Explicit critical remains available for forced drain.
    const auto decision = pressureDecisionLocked(pressure, upcoming);
    critical = force_critical || decision.critical;
    if (!decision.reclaim && !critical)
      return 0; // Healthy completion: no per-resource walk or mutex writes.
    warm_budget = critical ? 0 : decision.warm_cache_budget;
  }
  uint64_t detached_bytes = 0, detached_count = 0;
  // Return cold/oversized leases before distributing the bounded hot credits.
  for (unsigned phase = 0; phase < (critical ? 1u : 2u); ++phase) {
    for (;;) {
      std::array<Rc<BufferAllocation>, 64> retired;
      size_t count = 0;
      {
        std::lock_guard<dxmt::mutex> registry_lock(dynamicRegistryState().mutex);
        // Another requester may have latched emergency while this sweep released
        // its previous batch. Never grant warm credit from an older normal pass.
        const auto decision = pressureDecisionLocked(pressure, upcoming);
        critical = force_critical || decision.critical;
        warm_budget = critical ? 0 : decision.warm_cache_budget;
        for (auto *dynamic = dynamicRegistryState().head; dynamic && count < retired.size(); dynamic = dynamic->registry_next_) {
          if (dynamic->queue_domain_ != queue_domain) continue;
          // Credit is registry-owned metadata, so this read needs no instance
          // lock. Empty-but-credited cold owners must return their lease; wholly
          // empty, uncredited resources cost no mutex writes on completion.
          if (!dynamic->has_cached_names_.load(std::memory_order_acquire) &&
              !dynamic->cache_credit_bytes_) continue;
          std::unique_lock<dxmt::mutex> instance_lock(dynamic->mutex_, std::try_to_lock);
          if (!instance_lock.owns_lock()) continue;
          const bool hot = dynamic->hotAtLocked(coherent_seq_id) && dynamic->desiredCacheBytesLocked();
          if (!critical && hot != (phase == 1)) continue;
          dynamic->updateLeaseLocked(coherent_seq_id, warm_budget, critical, pressure.valid && pressure.reserve);
          // The requester is about to consume its own genuine reusable backing.
          // Never purge it immediately before allocate checks its FIFO.
          if (dynamic == pending_request) continue;
          const uint64_t cost = dynamic->allocationCostLocked();
          const uint64_t keep_names = cost ? dynamic->cache_credit_bytes_ / cost : 0;
          uint64_t bytes = 0, n = 0;
          while (dynamic->fifo.size() > keep_names && count < retired.size() &&
                 dynamic->fifo.front().will_free_at <= coherent_seq_id) {
            auto &entry = dynamic->fifo.front();
            bytes += entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
            retired[count++] = std::move(entry.allocation);
            dynamic->fifo.pop_front();
            ++n;
          }
          if (n) {
            if (dynamic->fifo.empty()) dynamic->has_cached_names_.store(false, std::memory_order_release);
            dynamic->trimmed_last_ = true;
            if (dynamic->census_id_ < DYN_CENSUS_SLOTS) {
              g_dyn_stats[dynamic->census_id_].trimmed_n.fetch_add(n, std::memory_order_relaxed);
              g_dyn_stats[dynamic->census_id_].trimmed_bytes.fetch_add(bytes, std::memory_order_relaxed);
            }
            detached_bytes += bytes;
            detached_count += n;
          }
          if (n || (!dynamic->fifo.empty() && dynamic->census_coherent_ != coherent_seq_id))
            dynamic->updateCensusLocked(coherent_seq_id);
        }
      }
      // All native releases happen after BOTH locks, in a bounded stack batch.
      if (!count) break;
    }
  }
  if (detached_count) {
    g_trim_total_n.fetch_add(detached_count, std::memory_order_relaxed);
    g_trim_total_bytes.fetch_add(detached_bytes, std::memory_order_relaxed);
    const uint64_t report = dynamicRegistryState().reports.fetch_add(1, std::memory_order_relaxed);
    if (report < 4 || (report & 63) == 0)
      ERR("[dynamic-memory-pressure-v1] policy=bounded-hot-v2 storage=owner-heap-v1 cache-detached=", detached_bytes,
          " entries=", detached_count, " coherent=", coherent_seq_id,
          " warm-budget=", warm_budget, " physical-freed=unmeasured");
  }
  return detached_bytes;
}
'''


def stage_file(path, source):
    if '[dynamic-memory-pressure-v' in source or 'TrimCompletedForQueue' in source:
        raise ValueError('dynamic memory input is already staged')
    if path == FILES[0]:
        source = replace_once(source, 'class DynamicBuffer {', 'struct MemoryPressureSnapshot;\n\nclass DynamicBuffer {')
        source = replace_once(source,
            '  DynamicBuffer(Buffer *buffer, Flags<BufferAllocationFlag> flags);',
            '''  DynamicBuffer(Buffer *buffer, Flags<BufferAllocationFlag> flags, uint64_t queue_domain = 0);

  // Drops only this queue's GPU-complete cached names. Returned bytes are
  // detached cache capacity; other allocation owners can still retain backing.
  static uint64_t TrimCompletedForQueue(uint64_t queue_domain, uint64_t coherent_seq_id, bool critical = false, const DynamicBuffer *pending_request = nullptr);''')
        source = replace_once(source,
            '  bool trimmed_last_ = false;      /* ml685: trim-regret latch */',
            '''  bool trimmed_last_ = false;      /* ml685: trim-regret latch */
  const uint64_t queue_domain_ = 0;
  DynamicBuffer *registry_prev_ = nullptr;
  DynamicBuffer *registry_next_ = nullptr;
  uint64_t census_coherent_ = 0;
  std::atomic<bool> has_cached_names_{false};
  std::atomic<bool> lease_pending_{false};
  uint64_t cache_credit_bytes_ = 0;
  uint64_t request_epoch_ = 0, lease_attempt_epoch_ = ~0ull;
  uint64_t request_gap_ = 1, reuse_age_ = 0;
  uint32_t request_count_ = 0, epoch_demand_ = 0, peak_demand_ = 1;
  uint64_t allocationCostLocked() const;
  void noteRequestLocked(uint64_t coherent_seq_id);
  bool hotAtLocked(uint64_t coherent_seq_id) const;
  uint64_t desiredCacheBytesLocked() const;
  void updateLeaseLocked(uint64_t coherent_seq_id, uint64_t budget, bool critical, bool allow_new);
  static void EnsureWorkingSetLease(DynamicBuffer *, uint64_t coherent_seq_id, const MemoryPressureSnapshot &);
  void updateCensusLocked(uint64_t coherent_seq_id);
  void recordQueuePushLocked();
  void recordQueuePopLocked(uint64_t bytes, uint64_t will_free_at);''')
    elif path == FILES[1]:
        source = replace_once(source, '#include <algorithm>', '#include <algorithm>\n#include <array>\n#include <memory>\n#include "memory_pressure.hpp"')
        source = replace_once(source, '\nDynamicBuffer::DynamicBuffer(', '\n' + REGISTRY + '\nDynamicBuffer::DynamicBuffer(')
        source = replace_once(source,
            'DynamicBuffer::DynamicBuffer(Buffer *buffer, Flags<BufferAllocationFlag> flags) :',
            'DynamicBuffer::DynamicBuffer(Buffer *buffer, Flags<BufferAllocationFlag> flags, uint64_t queue_domain) :')
        source = replace_once(source,
            '    name_(buffer->current()) {',
            '    name_(buffer->current()),\n    queue_domain_(queue_domain) {')
        source = replace_once(source,
            '    g_dyn_stats[census_id_].length.store(buffer ? buffer->length() : 0, std::memory_order_relaxed);\n}',
            '''    g_dyn_stats[census_id_].length.store(buffer ? buffer->length() : 0, std::memory_order_relaxed);
  if (queue_domain_) {
    std::lock_guard<dxmt::mutex> registry_lock(dynamicRegistryState().mutex);
    registry_next_ = dynamicRegistryState().head;
    if (registry_next_) registry_next_->registry_prev_ = this;
    dynamicRegistryState().head = this;
  }
}''')
        source = replace_once(source,
            '    g_live_dynbuf.destroyed.fetch_add(1, std::memory_order_relaxed);   /* ml684 */\n    delete this;',
            '''    std::atomic_thread_fence(std::memory_order_acquire);
    if (queue_domain_) {
      // Remove before destructor begins: the registry pins the object lifetime.
      std::lock_guard<dxmt::mutex> registry_lock(dynamicRegistryState().mutex);
      if (registry_prev_) registry_prev_->registry_next_ = registry_next_;
      else dynamicRegistryState().head = registry_next_;
      if (registry_next_) registry_next_->registry_prev_ = registry_prev_;
      dynamicRegistryState().warm_cache_credit -= cache_credit_bytes_;
      cache_credit_bytes_ = 0;
    }
    if (census_id_ < DYN_CENSUS_SLOTS) {
      auto &st = g_dyn_stats[census_id_];
      st.depth.store(0, std::memory_order_relaxed);
      st.eligible_n.store(0, std::memory_order_relaxed);
      st.eligible_bytes.store(0, std::memory_order_relaxed);
      st.inelig_n.store(0, std::memory_order_relaxed);
      st.inelig_bytes.store(0, std::memory_order_relaxed);
      st.wfa_min.store(0, std::memory_order_relaxed);
      st.wfa_max.store(0, std::memory_order_relaxed);
    }
    g_live_dynbuf.destroyed.fetch_add(1, std::memory_order_relaxed);   /* ml684 */
    delete this;''')
        source = replace_once(source,
            'DynamicBuffer::allocate(uint64_t coherent_seq_id, bool *out_minted_fresh) {\n  std::lock_guard<dxmt::mutex> lock(mutex_);',
            '''DynamicBuffer::allocate(uint64_t coherent_seq_id, bool *out_minted_fresh) {
  Rc<BufferAllocation> pressure_reuse;
  std::unique_lock<dxmt::mutex> lock(mutex_, std::defer_lock);
  if (queue_domain_) {
    const auto pressure = memoryPressureSnapshot();
    EnsureWorkingSetLease(this, coherent_seq_id, pressure);
    const uint64_t upcoming = buffer ? buffer->length() : 0;
    if (pressure.needsReclaim(upcoming)) {
      // Reuse first: a completed name is already real backing. Do not purge it
      // and then treat this request as a fresh allocation under pressure.
      lock.lock();
      if (!fifo.empty() && fifo.front().will_free_at <= coherent_seq_id) {
        auto &entry = fifo.front();
        const uint64_t bytes = entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
        const uint64_t seq = entry.will_free_at;
        const uint64_t age = std::min<uint64_t>(1024, coherent_seq_id - seq);
        reuse_age_ = std::max(age, (reuse_age_ * 7 + age) / 8);
        pressure_reuse = std::move(entry.allocation);
        fifo.pop_front();
        recordQueuePopLocked(bytes, seq);
      } else {
        lock.unlock();
        // Upcoming can trigger emergency handling ONLY for a genuine miss.
        const bool critical = pressure.valid &&
            (pressure.available <= pressure.reserve / 4 || upcoming >= pressure.available);
        struct SweepStamp { uint64_t domain = 0, coherent = 0; bool critical = false, valid = false; };
        static thread_local SweepStamp last_sweep;
        if (!last_sweep.valid || last_sweep.domain != queue_domain_ ||
            last_sweep.coherent != coherent_seq_id || (critical && !last_sweep.critical)) {
          last_sweep = {queue_domain_, coherent_seq_id, critical, true};
          TrimCompletedForQueue(queue_domain_, coherent_seq_id, false, this);
        }
      }
    }
  }
  if (!lock.owns_lock()) lock.lock();
  noteRequestLocked(coherent_seq_id);
  // Keep the optional large rename cache free of per-draw census walks.
  if (dynKeepFor(buffer ? buffer->length() : 0) && census_coherent_ != coherent_seq_id)
    updateCensusLocked(coherent_seq_id);''')
        buffer_source, linear_source = source.split('DynamicLinearTexture::DynamicLinearTexture', 1)
        buffer_source = replace_once(buffer_source,
            '  Rc<BufferAllocation> ret;\n  for (;;) {',
            '  Rc<BufferAllocation> ret = std::move(pressure_reuse);\n  for (;;) {\n    if (ret.ptr()) break;')
        buffer_source = replace_once(buffer_source,
            '    ret = std::move(entry.allocation);\n    fifo.pop_front();\n    break;',
            '''    const uint64_t pop_bytes = entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
    const uint64_t pop_seq = entry.will_free_at;
    const uint64_t age = coherent_seq_id - pop_seq;
    reuse_age_ = std::max<uint64_t>(std::min<uint64_t>(1024, age), (reuse_age_ * 7 + std::min<uint64_t>(1024, age)) / 8);
    ret = std::move(entry.allocation);
    fifo.pop_front();
    recordQueuePopLocked(pop_bytes, pop_seq);
    break;''')
        buffer_source = replace_once(buffer_source,
            '    enum { DYN_KEEP_ELIGIBLE = 64 };',
            '    const uint64_t DYN_KEEP_ELIGIBLE = std::max<uint64_t>(64, allocationCostLocked() ? cache_credit_bytes_ / allocationCostLocked() : 0);')
        buffer_source = replace_once(buffer_source,
            '    const bool stats = census_id_ < DYN_CENSUS_SLOTS;',
            '    census_coherent_ = coherent_seq_id;\n    const bool stats = census_id_ < DYN_CENSUS_SLOTS;')
        buffer_source = replace_once(buffer_source,
            '      freed_n++;\n      fifo.pop_front();',
            '''      freed_n++;
      const uint64_t pop_bytes = f.allocation.ptr() ? f.allocation->census_bytes_ : 0;
      const uint64_t pop_seq = f.will_free_at;
      fifo.pop_front();
      recordQueuePopLocked(pop_bytes, pop_seq);''')
        buffer_source = replace_once(buffer_source,
            '        freed_n++;\n        fifo.pop_front();',
            '''        freed_n++;
        const uint64_t pop_bytes = f.allocation.ptr() ? f.allocation->census_bytes_ : 0;
        const uint64_t pop_seq = f.will_free_at;
        fifo.pop_front();
        recordQueuePopLocked(pop_bytes, pop_seq);''')
        buffer_source = replace_once(buffer_source,
            '  if (!owned_by_command_list_)\n    fifo.push_back(QueueEntry{.allocation = std::move(name_), .will_free_at = current_seq_id});',
            '''  if (!owned_by_command_list_) {
    fifo.push_back(QueueEntry{.allocation = std::move(name_), .will_free_at = current_seq_id});
    recordQueuePushLocked();
  }''')
        source = buffer_source + 'DynamicLinearTexture::DynamicLinearTexture' + linear_source
        source = replace_once(source,
            '  fifo.push_back(QueueEntry{.allocation = std::move(allocation), .will_free_at = current_seq_id});\n}\n\nuint32_t\nDynamicBuffer::nextSuballocation',
            '  fifo.push_back(QueueEntry{.allocation = std::move(allocation), .will_free_at = current_seq_id});\n  recordQueuePushLocked();\n}\n\nuint32_t\nDynamicBuffer::nextSuballocation')
    elif path == FILES[2]:
        source = replace_once(source, 'new DynamicBuffer(buffer_.ptr(), flags);',
            'new DynamicBuffer(buffer_.ptr(), flags, device->GetDXMTDevice().queue().memoryDomain());')
    elif path == FILES[3]:
        source = replace_once(source, 'new DynamicBuffer(subresource.buffer.ptr(), buffer_flags);',
            'new DynamicBuffer(subresource.buffer.ptr(), buffer_flags, pDevice->GetDXMTDevice().queue().memoryDomain());')
    elif path == FILES[4]:
        source = replace_once(source,
            '  if (placed_buffer) {\n    wsi::aligned_free(placed_buffer);',
            '''  if (placed_buffer) {
    // Metal references can synchronously drain CPU-placed writes on release.
    // Release derived views and the native buffer before its caller-owned pages.
    cached_view_.clear();
    obj_ = nullptr;
    wsi::aligned_free(placed_buffer);''')
    return source


STAGES = {path: (lambda source, path=path: stage_file(path, source)) for path in FILES}


def stage(source_dir, output_dir):
    rows = []
    for path in FILES:
        data = (source_dir / path).read_bytes()
        staged = stage_file(path, data.decode()).encode()
        target = output_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(staged)
        rows.append({'path': path, 'source_sha256': hashlib.sha256(data).hexdigest(),
                     'output_sha256': hashlib.sha256(staged).hexdigest()})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.source_dir.resolve() == args.output_dir.resolve():
        parser.error('vendor input must remain immutable')
    print(json.dumps({'stage': 'dxmt-dynamic-memory-v1', 'files': stage(args.source_dir, args.output_dir)}))


if __name__ == '__main__':
    main()
