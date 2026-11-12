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
  bool valid = false;

  bool needsReclaim(uint64_t upcoming = 0) const {
    return valid && (available <= reserve || upcoming >= available - reserve);
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
    cache.sampled = now;
    cache.initialized = true;
  }
  return cache.snapshot;
}

} // namespace dxmt
