#ifndef MADEIRA_NATIVE_HEAP_RELIEF_H
#define MADEIRA_NATIVE_HEAP_RELIEF_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <mach/mach.h>
#include <malloc/malloc.h>
#include <os/proc.h>
#include <sys/sysctl.h>

/* The renderer only requests work. The existing pool-warmer calls poll before
 * taking any pool/VM lock. Public libmalloc relief releases allocator-owned
 * FREE pages, never live guest/JIT/Metal resources. Its returned byte count is
 * not a measurement of this task's physical-footprint reduction.
 *
 * No new thread, graphics-path lock, allocation or per-request syscall is
 * needed. A pending request is a coalesced hint; the worker must remeasure.
 */
static unsigned md_native_heap_relief_pending, md_native_heap_relief_running;
static uint64_t md_native_heap_relief_next_ns;
static uint64_t md_native_heap_relief_last_log_ns;
static unsigned md_native_heap_relief_reports;
static const volatile char md_native_heap_relief_contract[] = "[native-heap-relief-v1]";

static inline uint64_t md_native_heap_relief_reserve(uint64_t limit) {
  const uint64_t minimum = UINT64_C(128) << 20, maximum = UINT64_C(1024) << 20;
  const uint64_t value = limit / 8;
  return value < minimum ? minimum : value > maximum ? maximum : value;
}

#ifdef __cplusplus
extern "C" {
#endif
void madeira_native_memory_relief_request(uint64_t, uint64_t) __attribute__((visibility("default")));
void madeira_native_memory_relief_request(uint64_t footprint, uint64_t available) {
  unsigned expected = 0;
  /* Called only for a validated native reading. Reject invalid direct callers,
   * including overflow; zero available is genuine emergency pressure. */
  if (!footprint || available > UINT64_MAX - footprint ||
      available > md_native_heap_relief_reserve(footprint + available)) return;
  if (__atomic_load_n(&md_native_heap_relief_pending, __ATOMIC_RELAXED)) return;
  (void)__atomic_compare_exchange_n(&md_native_heap_relief_pending, &expected, 1, 0,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
#ifdef __cplusplus
}
#endif

struct md_native_heap_reading { uint64_t footprint, available; int valid; };

static inline struct md_native_heap_reading md_native_heap_relief_measure(void) {
  struct md_native_heap_reading result = {0, 0, 0};
  task_vm_info_data_t info = {0};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  uint64_t installed = 0;
  size_t length = sizeof(installed);
  if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) != KERN_SUCCESS ||
      count < TASK_VM_INFO_REV1_COUNT || !info.phys_footprint ||
      sysctlbyname("hw.memsize", &installed, &length, NULL, 0) ||
      length != sizeof(installed) || !installed) return result;
  result.footprint = (uint64_t)info.phys_footprint;
  result.available = (uint64_t)os_proc_available_memory();
  if (result.available > installed || result.available > UINT64_MAX - result.footprint)
    return result;
  result.valid = 1;
  return result;
}

static inline uint64_t md_native_heap_relief_clock(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 || now.tv_nsec < 0 ||
      now.tv_nsec >= 1000000000L ||
      (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / UINT64_C(1000000000)) return 0;
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

#ifdef __cplusplus
extern "C" {
#endif
void madeira_native_memory_relief_poll(void) __attribute__((visibility("default")));
void madeira_native_memory_relief_poll(void) {
  const int saved_errno = errno;
  const uint64_t interval = UINT64_C(2000000000), backoff = UINT64_C(8000000000);
  uint64_t now, finished, next, reserve, target, goal, drop = 0;
  size_t allocator_returned = 0;
  unsigned expected = 0;
  struct md_native_heap_reading before, after;

  if (!__atomic_load_n(&md_native_heap_relief_pending, __ATOMIC_ACQUIRE)) goto done;
  now = md_native_heap_relief_clock();
  next = __atomic_load_n(&md_native_heap_relief_next_ns, __ATOMIC_RELAXED);
  if (!now || now < next) goto done;
  if (!__atomic_compare_exchange_n(&md_native_heap_relief_running, &expected, 1, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) goto done;
  next = __atomic_load_n(&md_native_heap_relief_next_ns, __ATOMIC_RELAXED);
  if (now < next) goto unlock; /* Another poll may have finished since our first check. */
  if (!__atomic_exchange_n(&md_native_heap_relief_pending, 0, __ATOMIC_ACQ_REL)) goto unlock;
  before = md_native_heap_relief_measure();
  if (!before.valid) {
    next = now > UINT64_MAX - backoff ? UINT64_MAX : now + backoff;
    __atomic_store_n(&md_native_heap_relief_next_ns, next, __ATOMIC_RELAXED);
    goto unlock;
  }
  reserve = md_native_heap_relief_reserve(before.footprint + before.available);
  if (before.available > reserve) goto unlock; /* Pressure disappeared before polling. */
  target = reserve + reserve / 4;
  goal = target > before.available ? target - before.available : 0;
  if (goal < (UINT64_C(16) << 20)) goal = UINT64_C(16) << 20;
  if (goal > (UINT64_C(64) << 20)) goal = UINT64_C(64) << 20;
  (void)md_native_heap_relief_contract[0];
  allocator_returned = malloc_zone_pressure_relief(NULL, (size_t)goal);
  after = md_native_heap_relief_measure();
  if (after.valid && before.footprint > after.footprint)
    drop = before.footprint - after.footprint;
  /* libmalloc may spend longer than the throttle interval walking zones.
   * Start backoff after that work, so a slow pass cannot cause another pass
   * immediately. An unavailable/backward clock retains the original bound. */
  finished = md_native_heap_relief_clock();
  if (finished < now) finished = now;
  next = drop ? interval : backoff;
  next = finished > UINT64_MAX - next ? UINT64_MAX : finished + next;
  __atomic_store_n(&md_native_heap_relief_next_ns, next, __ATOMIC_RELAXED);
  /* Four initial reports, then at most one every 30s. Log actual observations,
   * including zero reduction; allocator-returned is never called physical. */
  if (md_native_heap_relief_reports < 4 ||
      (finished >= md_native_heap_relief_last_log_ns &&
       finished - md_native_heap_relief_last_log_ns >= UINT64_C(30000000000))) {
    if (md_native_heap_relief_reports != UINT32_MAX) ++md_native_heap_relief_reports;
    md_native_heap_relief_last_log_ns = finished;
    dprintf(2, "[native-heap-relief-v1] goal=%llu allocator-returned=%llu "
               "footprint-before=%llu footprint-after=%llu available-before=%llu available-after=%llu "
               "after-valid=%d observed-footprint-drop=%llu next-ms=%u\n",
            (unsigned long long)goal, (unsigned long long)allocator_returned,
            (unsigned long long)before.footprint, (unsigned long long)after.footprint,
            (unsigned long long)before.available, (unsigned long long)after.available,
            after.valid, (unsigned long long)drop, drop ? 2000 : 8000);
  }
unlock:
  __atomic_store_n(&md_native_heap_relief_running, 0, __ATOMIC_RELEASE);
done:
  errno = saved_errno;
}
#ifdef __cplusplus
}
#endif
#endif
