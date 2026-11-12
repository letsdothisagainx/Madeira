// Actual installed production function, staged from source 2059087c.
// Captured before the adaptive cache correction. Do not use for production.
// Function SHA-256: 63f6d9097fd534eb140819a30c2ea455a2430d97c17719255d9ca765014a1005
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
