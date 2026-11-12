#pragma once

#include "winemetal.h"

#include <chrono>
#include <cstdint>
#include <limits>

namespace dxmt {

// Process footprint includes more than Metal resources.  This budget therefore
// comes from the native process, rather than texture-capacity counters or a
// device model's advertised RAM.  Unknown readings never invent capacity.
struct MemoryPressureSnapshot {
  uint64_t footprint = 0;
  uint64_t available = 0;
  uint64_t limit = 0;
  uint64_t reserve = 0;
  uint64_t sampled_ns = 0;
  bool valid = false;

  bool needsReclaim(uint64_t upcoming = 0) const {
    return valid && (available <= reserve || upcoming >= available - reserve);
  }
};

struct MemoryPressureDecision {
  bool valid = false;
  bool reclaim = false;
  bool critical = false;
  uint64_t warm_cache_budget = 0;
};

// Caller-serialized (the DynamicBuffer registry already supplies that lock).
// Reading a pressure snapshot does not take a new process-wide lock or write
// shared counters on every Map. Only newer measurements change the watermarks.
class MemoryPressureController {
  bool initialized_ = false;
  bool reclaim_ = false;
  bool critical_ = false;
  uint64_t sampled_ns_ = 0;
  uint64_t available_ = 0;
  uint64_t reserve_ = 0;

public:
  MemoryPressureDecision evaluate(const MemoryPressureSnapshot &snapshot, uint64_t upcoming = 0) {
    if (!snapshot.valid || !snapshot.reserve)
      return {}; // Do not revoke existing ownership or grant new credit on an unknown reading.
    const bool newer = !initialized_ || !snapshot.sampled_ns || !sampled_ns_ ||
        snapshot.sampled_ns > sampled_ns_;
    if (newer) {
      available_ = snapshot.available;
      reserve_ = snapshot.reserve;
      sampled_ns_ = snapshot.sampled_ns;
      initialized_ = true;
      // A spare is existing backing, not a new allocation. Do not drain hot
      // reuse at the old half-reserve boundary: cache refill could immediately
      // cross it again. Emergency enter/exit are separated by a full cache cap.
      if (critical_) {
        if (available_ >= reserve_ / 2) critical_ = false;
      } else if (available_ <= reserve_ / 4) {
        critical_ = true;
      }
      const uint64_t high = reserve_ > std::numeric_limits<uint64_t>::max() - reserve_ / 4
          ? std::numeric_limits<uint64_t>::max() : reserve_ + reserve_ / 4;
      if (critical_) reclaim_ = true;
      else if (reclaim_) {
        if (available_ >= high) reclaim_ = false;
      } else if (available_ <= reserve_) {
        reclaim_ = true;
      }
    }
    // Callers pass upcoming only after a genuine reuse miss. Reusing already
    // backed memory must not be classified as fresh memory growth.
    if (upcoming && upcoming >= available_) {
      critical_ = true;
      reclaim_ = true;
    }
    const bool growth_pressure = upcoming &&
        (available_ <= reserve_ || upcoming >= available_ - reserve_);
    constexpr uint64_t maximum = uint64_t{128} << 20;
    const uint64_t cache = reserve_ / 8 < maximum ? reserve_ / 8 : maximum;
    return {true, reclaim_ || growth_pressure, critical_, critical_ ? 0 : cache};
  }
};

namespace memory_pressure_detail {

inline MemoryPressureSnapshot query() {
  struct madeira_ctl_args args = {};
  args.op = 40;
  MadeiraCtl(&args);
  MemoryPressureSnapshot result;
  if (args.ret != 1 || !args.ptr ||
      args.ptr == std::numeric_limits<uint64_t>::max() ||
      args.len == std::numeric_limits<uint64_t>::max() ||
      args.len > std::numeric_limits<uint64_t>::max() - args.ptr)
    return result;

  result.footprint = args.ptr;
  result.available = args.len;
  result.limit = args.ptr + args.len;
  constexpr uint64_t minimum = uint64_t{128} << 20;
  constexpr uint64_t maximum = uint64_t{1024} << 20;
  const uint64_t fraction = result.limit / 8;
  result.reserve = fraction < minimum ? minimum : fraction > maximum ? maximum : fraction;
  result.valid = true;
  return result;
}

} // namespace memory_pressure_detail

// One inexpensive native measurement per calling thread per 100ms.  Resource
// retirement/backpressure can force a fresh measurement after freeing memory.
// No process-global mutex is taken on D3D11 allocation paths.
inline MemoryPressureSnapshot memoryPressureSnapshot(bool refresh = false) {
  using Clock = std::chrono::steady_clock;
  struct Cache {
    MemoryPressureSnapshot snapshot;
    Clock::time_point sampled;
    bool initialized = false;
  };
  thread_local Cache cache;
  const auto now = Clock::now();
  if (refresh || !cache.initialized || now - cache.sampled >= std::chrono::milliseconds(100)) {
    cache.snapshot = memory_pressure_detail::query();
    cache.snapshot.sampled_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count());
    cache.sampled = now;
    cache.initialized = true;
  }
  return cache.snapshot;
}

} // namespace dxmt
