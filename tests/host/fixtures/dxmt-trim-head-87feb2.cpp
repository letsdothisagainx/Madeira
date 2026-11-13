// Captured actual production trim from Madeira 87feb2aa.
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
