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
 * The registry owns no reference: last decRef unregisters BEFORE delete starts.
 * Lock order is registry -> try_lock(instance); never block on an instance. */
static dxmt::mutex g_dynamic_registry_mutex;
static DynamicBuffer *g_dynamic_registry_head = nullptr;

void
DynamicBuffer::updateCensusLocked(uint64_t coherent_seq_id) {
  census_coherent_ = coherent_seq_id;
  if (census_id_ >= DYN_CENSUS_SLOTS)
    return;
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
  if (census_id_ >= DYN_CENSUS_SLOTS)
    return;
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
  /* Pushes happen AFTER allocate's snapshot. Keeping these incremental avoids
   * both a false empty-FIFO census and an O(depth) walk on every draw. */
  g_mem_census.dyn_fifo_depth.store(fifo.size(), std::memory_order_relaxed);
  uint64_t d = fifo.size(), mx = g_mem_census.dyn_fifo_depth_max.load(std::memory_order_relaxed);
  while (d > mx && !g_mem_census.dyn_fifo_depth_max.compare_exchange_weak(mx, d, std::memory_order_relaxed)) {}
  if (census_id_ >= DYN_CENSUS_SLOTS)
    return;
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
DynamicBuffer::TrimCompletedForQueue(uint64_t queue_domain, uint64_t coherent_seq_id, bool critical) {
  if (!queue_domain)
    return 0;
  // Normal pressure removes dormant spares; critical pressure can drain any
  // completed spare. Two completed submissions preserve hot rename reuse.
  const uint64_t reclaim_through = critical ? coherent_seq_id : (coherent_seq_id >= 2 ? coherent_seq_id - 2 : 0);
  if (!critical && coherent_seq_id < 2)
    return 0;
  uint64_t detached_bytes = 0, detached_count = 0;
  for (;;) {
    /* Fixed-size batches avoid heap growth during memory pressure. Rc destruction
     * (and native Metal release) happens after BOTH registry and instance locks. */
    std::array<Rc<BufferAllocation>, 64> retired;
    size_t count = 0;
    {
      std::lock_guard<dxmt::mutex> registry_lock(g_dynamic_registry_mutex);
      for (auto *dynamic = g_dynamic_registry_head; dynamic && count < retired.size(); dynamic = dynamic->registry_next_) {
        if (dynamic->queue_domain_ != queue_domain)
          continue;
        std::unique_lock<dxmt::mutex> instance_lock(dynamic->mutex_, std::try_to_lock);
        if (!instance_lock.owns_lock())
          continue;
        uint64_t bytes = 0, n = 0;
        /* Never touch name_, Buffer::current(), or a fenced entry. Other GPU,
         * command-list and queued-operation Rc owners remain independently live. */
        while (!dynamic->fifo.empty() && count < retired.size() &&
               dynamic->fifo.front().will_free_at <= reclaim_through) {
          auto &entry = dynamic->fifo.front();
          bytes += entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
          retired[count++] = std::move(entry.allocation);
          dynamic->fifo.pop_front();
          ++n;
        }
        if (n) {
          dynamic->trimmed_last_ = true;
          if (dynamic->census_id_ < DYN_CENSUS_SLOTS) {
            g_dyn_stats[dynamic->census_id_].trimmed_n.fetch_add(n, std::memory_order_relaxed);
            g_dyn_stats[dynamic->census_id_].trimmed_bytes.fetch_add(bytes, std::memory_order_relaxed);
          }
          detached_bytes += bytes;
          detached_count += n;
        }
        // Empty dormant buffers already have an exact zero snapshot. Avoid
        // protected-global atomic writes for every live resource on every GPU
        // completion. Recount only a changed cache or a nonempty new frontier.
        if (n || (!dynamic->fifo.empty() && dynamic->census_coherent_ != coherent_seq_id))
          dynamic->updateCensusLocked(coherent_seq_id);
      }
    }
    if (!count)
      break;
  }
  if (detached_count) {
    g_trim_total_n.fetch_add(detached_count, std::memory_order_relaxed);
    g_trim_total_bytes.fetch_add(detached_bytes, std::memory_order_relaxed);
    static std::atomic<uint64_t> reports{0};
    const uint64_t report = reports.fetch_add(1, std::memory_order_relaxed);
    if (report < 4 || (report & 63) == 0)
      ERR("[dynamic-memory-pressure-v1] cache-detached=", detached_bytes,
          " entries=", detached_count, " coherent=", coherent_seq_id,
          " physical-freed=unmeasured");
  }
  return detached_bytes;
}
'''


def stage_file(path, source):
    if '[dynamic-memory-pressure-v1]' in source or 'TrimCompletedForQueue' in source:
        raise ValueError('dynamic memory input is already staged')
    if path == FILES[0]:
        source = replace_once(source,
            '  DynamicBuffer(Buffer *buffer, Flags<BufferAllocationFlag> flags);',
            '''  DynamicBuffer(Buffer *buffer, Flags<BufferAllocationFlag> flags, uint64_t queue_domain = 0);

  // Drops only this queue's GPU-complete cached names. Returned bytes are
  // detached cache capacity; other allocation owners can still retain backing.
  static uint64_t TrimCompletedForQueue(uint64_t queue_domain, uint64_t coherent_seq_id, bool critical = false);''')
        source = replace_once(source,
            '  bool trimmed_last_ = false;      /* ml685: trim-regret latch */',
            '''  bool trimmed_last_ = false;      /* ml685: trim-regret latch */
  const uint64_t queue_domain_ = 0;
  DynamicBuffer *registry_prev_ = nullptr;
  DynamicBuffer *registry_next_ = nullptr;
  uint64_t census_coherent_ = 0;
  void updateCensusLocked(uint64_t coherent_seq_id);
  void recordQueuePushLocked();
  void recordQueuePopLocked(uint64_t bytes, uint64_t will_free_at);''')
    elif path == FILES[1]:
        source = replace_once(source, '#include <algorithm>', '#include <algorithm>\n#include <array>\n#include "memory_pressure.hpp"')
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
    std::lock_guard<dxmt::mutex> registry_lock(g_dynamic_registry_mutex);
    registry_next_ = g_dynamic_registry_head;
    if (registry_next_) registry_next_->registry_prev_ = this;
    g_dynamic_registry_head = this;
  }
}''')
        source = replace_once(source,
            '    g_live_dynbuf.destroyed.fetch_add(1, std::memory_order_relaxed);   /* ml684 */\n    delete this;',
            '''    std::atomic_thread_fence(std::memory_order_acquire);
    if (queue_domain_) {
      // Remove before destructor begins: the registry pins the object lifetime.
      std::lock_guard<dxmt::mutex> registry_lock(g_dynamic_registry_mutex);
      if (registry_prev_) registry_prev_->registry_next_ = registry_next_;
      else g_dynamic_registry_head = registry_next_;
      if (registry_next_) registry_next_->registry_prev_ = registry_prev_;
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
  // Before taking an instance lock, reclaim completed caches across this queue,
  // including dormant buffers which will never call allocate again.
  if (queue_domain_) {
    const auto pressure = memoryPressureSnapshot();
    const uint64_t upcoming = buffer ? buffer->length() : 0;
    if (pressure.needsReclaim(upcoming)) {
      const bool critical = pressure.available < pressure.reserve / 2 || upcoming > pressure.available;
      // Map/Update can execute thousands of times in one submission. A new
      // retirement is fenced by CurrentSeqId > CoherentSeqId, so repeating this
      // whole-domain sweep before coherence advances cannot expose new caches.
      // Bounded TLS stores one domain only; a new queue, fence or critical
      // transition always permits a fresh sweep. GPU completion also sweeps.
      struct SweepStamp { uint64_t domain = 0, coherent = 0; bool critical = false, valid = false; };
      static thread_local SweepStamp last_sweep;
      if (!last_sweep.valid || last_sweep.domain != queue_domain_ ||
          last_sweep.coherent != coherent_seq_id || (critical && !last_sweep.critical)) {
        last_sweep = {queue_domain_, coherent_seq_id, critical, true};
        TrimCompletedForQueue(queue_domain_, coherent_seq_id, critical);
      }
    }
  }
  std::lock_guard<dxmt::mutex> lock(mutex_);
  // Keep the optional large rename cache free of per-draw census walks.
  // Eligibility is refreshed only once per completed submission in that mode.
  if (dynKeepFor(buffer ? buffer->length() : 0) && census_coherent_ != coherent_seq_id)
    updateCensusLocked(coherent_seq_id);''')
        buffer_source, linear_source = source.split('DynamicLinearTexture::DynamicLinearTexture', 1)
        buffer_source = replace_once(buffer_source,
            '    ret = std::move(entry.allocation);\n    fifo.pop_front();\n    break;',
            '''    const uint64_t pop_bytes = entry.allocation.ptr() ? entry.allocation->census_bytes_ : 0;
    const uint64_t pop_seq = entry.will_free_at;
    ret = std::move(entry.allocation);
    fifo.pop_front();
    recordQueuePopLocked(pop_bytes, pop_seq);
    break;''')
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
