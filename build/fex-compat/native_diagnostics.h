/* SPDX-License-Identifier: MIT
 * Madeira-owned native diagnostics. The loader binds only these explicit
 * source-built spans, in an unpublished image, to its retained writable alias.
 * The original DATA bytes and all atomic operations remain intact. Unknown
 * contracts use their canonical address and the existing fault recovery.
 */
#ifndef MADEIRA_FEX_NATIVE_DIAGNOSTICS_H
#define MADEIRA_FEX_NATIVE_DIAGNOSTICS_H
#include <atomic>
#include <cstdint>
#include <cstddef>

struct MadeiraFEXNativeWriteContract {
  uint64_t tag;
  uint32_t bytes;
  uint32_t alignment;
  const void* payload;
  uintptr_t writer;
};
static_assert(sizeof(MadeiraFEXNativeWriteContract) == 32);

constexpr uint64_t MadeiraFEXTelemetryTag = UINT64_C(0x31544d584546574d);
constexpr uint64_t MadeiraFEXIRTopoTag = UINT64_C(0x315249584546574d);
constexpr uint64_t MadeiraFEXCompileTag = UINT64_C(0x314243584546574d);
constexpr uint64_t MadeiraFEXHistoryTag = UINT64_C(0x314852584546574d);
constexpr uint64_t MadeiraFEXTransitionTag = UINT64_C(0x315058584546574d);
constexpr uint64_t MadeiraFEXSyscallTag = UINT64_C(0x315359584546574d);

extern "C" {
extern MadeiraFEXNativeWriteContract MadeiraFEXTelemetryWriteContract;
extern MadeiraFEXNativeWriteContract MadeiraFEXIRTopoWriteContract;
extern MadeiraFEXNativeWriteContract MadeiraFEXCompileWriteContract;
extern MadeiraFEXNativeWriteContract MadeiraFEXHistoryWriteContract;
extern MadeiraFEXNativeWriteContract MadeiraFEXTransitionWriteContract;
extern MadeiraFEXNativeWriteContract MadeiraFEXSyscallWriteContract;
}

template<typename T>
inline T& MadeiraFEXNativeWriter(MadeiraFEXNativeWriteContract& contract, T& canonical) {
  const uintptr_t writer = __atomic_load_n(&contract.writer, __ATOMIC_ACQUIRE);
  return writer ? *reinterpret_cast<T*>(writer) : canonical;
}

namespace MadeiraFEXDiagnostics {
/* Preserve the existing four-slot diagnostic history, including its volatile
 * accesses and collision behavior. This is image-owned DATA, not thread TLS
 * or guest state. Only its native writer address changes after loader binding.
 */
struct CallRetHistoryState {
  volatile uint64_t key[4] {0,0,0,0};
  volatile uint64_t crsp_min[4] {UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX};
  volatile uint64_t crsp_max[4] {0,0,0,0};
  volatile uint64_t crsp_last[4] {0,0,0,0};
  volatile uint64_t count[4] {0,0,0,0};
  volatile uint64_t last_rip[4] {0,0,0,0};
};
static_assert(sizeof(CallRetHistoryState) == 192 && alignof(CallRetHistoryState) == 8);

struct CompileState {
  std::atomic<uint64_t> total {0};
  std::atomic<uint64_t> real_compiles {0};
  std::atomic<uint64_t> hot_rip {0};
  std::atomic<uint64_t> hot_balance {0};
  std::atomic<uint64_t> sample_skips {0};
  std::atomic<uint32_t> sampling {0};
  uint32_t reserved {0};
};
static_assert(sizeof(CompileState) == 48 && alignof(CompileState) == 8);

/* The hot-RIP value is an approximate Boyer-Moore candidate, not a repeat
 * count. Never spin or block execution for this diagnostic. A contending
 * observer skips only the estimator sample; exact dispatch/compile totals are
 * always counted. Exclusive ownership of the candidate/balance pair prevents
 * two mismatches from decrementing a balance of one through zero.
 */
inline uint64_t RecordDispatch(CompileState& state, uint64_t rip) {
  const uint64_t total = state.total.fetch_add(1, std::memory_order_seq_cst) + 1;
  uint32_t expected = 0;
  if (state.sampling.compare_exchange_strong(expected, 1, std::memory_order_acquire, std::memory_order_relaxed)) {
    const uint64_t balance = state.hot_balance.load(std::memory_order_relaxed);
    if (!balance) {
      state.hot_rip.store(rip, std::memory_order_relaxed);
      state.hot_balance.store(1, std::memory_order_relaxed);
    } else if (state.hot_rip.load(std::memory_order_relaxed) == rip) {
      state.hot_balance.store(balance + 1, std::memory_order_relaxed);
    } else {
      state.hot_balance.store(balance - 1, std::memory_order_relaxed);
    }
    state.sampling.store(0, std::memory_order_release);
  } else {
    state.sample_skips.fetch_add(1, std::memory_order_relaxed);
  }
  return total;
}

inline void RecordCompile(CompileState& state) {
  state.real_compiles.fetch_add(1, std::memory_order_seq_cst);
}

/* Unique dispatch tickets replace the old racy last-summary store. The
 * caller captures its scalar report before formatting, without holding a
 * diagnostic lock or invoking the allocator from inside one.
 */
inline bool SummaryDue(uint64_t total) { return total && !(total & UINT64_C(16383)); }

struct IRTopoState {
  std::atomic<uint64_t> checked {0}, tripped {0}, repaired {0}, declined {0};
};
static_assert(sizeof(IRTopoState) == 32 && alignof(IRTopoState) == 8);
}
#endif
