#ifndef MADEIRA_MEMORY_PRESSURE_NATIVE_H
#define MADEIRA_MEMORY_PRESSURE_NATIVE_H

#include <errno.h>
#include <stdint.h>
#include <mach/mach.h>
#include <os/proc.h>
#include <pthread.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>

// Volatile read retains the producer's contract marker in the packaged native
// image without logging, file I/O, or changing the pointer-free control ABI.
static const volatile char md_memory_pressure_contract[] = "[madeira-memory-pressure-v1]";

static inline void md_memory_pressure_query(struct madeira_ctl_args *args) {
  const int saved_errno = errno;
  task_vm_info_data_t info = {0};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  uint64_t installed = 0;
  size_t installed_size = sizeof(installed);
  uint64_t available, footprint;
  (void)md_memory_pressure_contract[0];
  args->ret = 0;
  args->ptr = 0;
  args->len = 0;

  if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) != KERN_SUCCESS ||
      count < TASK_VM_INFO_REV1_COUNT)
    goto done;
  footprint = (uint64_t)info.phys_footprint;
  if (sysctlbyname("hw.memsize", &installed, &installed_size, NULL, 0) != 0 ||
      installed_size != sizeof(installed) || !installed || !footprint)
    goto done;
  available = (uint64_t)os_proc_available_memory();
  // os_proc_available_memory() can expose an unknown/sentinel value on an
  // unsupported platform.  A genuine zero, with valid task data, is critical
  // pressure and MUST NOT be treated as an unknown/successfully free budget.
  if (available > installed || footprint > UINT64_MAX - available)
    goto done;
  args->ptr = footprint;
  args->len = available;
  args->ret = 1;
done:
  errno = saved_errno;
}

/* Admission is shared by all PE/native callers of the one in-process Metal
 * backend. These receipts cover prospective resource backing through CPU creation and
 * real GPU initialization. Completed residency belongs to the OS footprint,
 * not a cumulative allocation ledger. Never retire GPU work by age or CPU exit.
 */
#define MD_RESOURCE_GROWTH_RECEIPTS 256
#ifdef __cplusplus
extern "C" {
#endif
extern void *ios_jit_current_peb(void) __attribute__((weak));
extern unsigned long long ios_thread_process_snapshot(void *, unsigned *, int *, int *) __attribute__((weak));
extern unsigned long long ios_thread_process_quiescent_lease(void *) __attribute__((weak));
extern uint64_t madeira_growth_event_retain(uint64_t, void *, unsigned long long);
extern int madeira_growth_event_value(uint64_t, uint64_t *);
extern void madeira_growth_event_release(uint64_t);
void madeira_resource_growth_retire(void *, unsigned long long) __attribute__((visibility("default")));
#ifdef __cplusplus
}
#endif
static const volatile char md_resource_growth_contract[] = "[texture-growth-budget-v1]";
static const volatile char md_resource_live_contract[] = "[texture-live-budget-v2]";
static pthread_mutex_t md_resource_growth_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t md_resource_growth_condition = PTHREAD_COND_INITIALIZER;
static struct { uint64_t token, bytes, lease, event_handle, event_cookie, target; void *owner; unsigned phase; }
    md_resource_growth_receipts[MD_RESOURCE_GROWTH_RECEIPTS];
static uint64_t md_resource_growth_held, md_resource_growth_next = 1;
static unsigned md_resource_growth_waiters;
static int md_resource_growth_pressure;

/* A passive generation snapshot must not create or relink a Wine thread.
 * Caller owns its registered Wine CPU lifetime; unknown/foreign host contexts
 * cannot acquire a receipt on behalf of the last selected pseudo-process. */
static inline int md_resource_growth_identity(void **owner, uint64_t *lease, int allow_exiting) {
  unsigned threads = 0;
  int exiting = 0, reclaimed = 0;
  if (!ios_jit_current_peb || !ios_thread_process_snapshot || !ios_thread_process_quiescent_lease)
    return -1;
  *owner = ios_jit_current_peb();
  if (!*owner) return 0;
  *lease = ios_thread_process_snapshot(*owner, &threads, &exiting, &reclaimed);
  return *lease && threads && !reclaimed && (allow_exiting || !exiting);
}

static inline uint64_t md_resource_growth_reserve(uint64_t limit) {
  const uint64_t minimum = UINT64_C(128) << 20, maximum = UINT64_C(1024) << 20;
  uint64_t reserve = limit / 8;
  return reserve < minimum ? minimum : reserve > maximum ? maximum : reserve;
}

static inline uint64_t md_resource_growth_floor(uint64_t reserve) {
  const uint64_t minimum = UINT64_C(128) << 20, maximum = UINT64_C(256) << 20;
  uint64_t floor = reserve / 4;
  return floor < minimum ? minimum : floor > maximum ? maximum : floor;
}

/* The first 32 bytes of the existing pointer-free name payload contain the exact
 * decision's footprint, outstanding credits, floor and denial kind. */
static inline void md_resource_growth_diagnostics(struct madeira_ctl_args *args, uint64_t footprint,
                                                  uint64_t held, uint64_t floor, uint64_t reason) {
  const uint64_t values[4] = {footprint, held, floor, reason};
  memcpy(args->name, values, sizeof(values));
}

static inline void md_resource_growth_notify_locked(void) {
  if (md_resource_growth_waiters) pthread_cond_broadcast(&md_resource_growth_condition);
}

static inline uint64_t md_resource_growth_drop_locked(unsigned slot) {
  const uint64_t cookie = md_resource_growth_receipts[slot].event_cookie;
  md_resource_growth_held -= md_resource_growth_receipts[slot].bytes;
  memset(&md_resource_growth_receipts[slot], 0, sizeof(md_resource_growth_receipts[slot]));
  return cookie;
}

static inline void md_resource_growth_release_events(const uint64_t *cookies, unsigned count) {
  unsigned i;
  for (i = 0; i < count; ++i) madeira_growth_event_release(cookies[i]);
}

/* Initialized resident backing is already counted by the OS. Until its real
 * initialization event completes, retain the prospective credit independently
 * of the producer's CPU/process lifetime. Cache one read per native event in
 * this sweep; several textures commonly share the same private upload event. */
static inline unsigned md_resource_growth_poll_gpu_locked(uint64_t *cookies) {
  struct {uint64_t handle, value; int known;} cache[16];
  unsigned cached = 0, slot, i, count = 0;
  int released = 0;
  for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot) {
    uint64_t value = 0;
    int known = 0;
    if (md_resource_growth_receipts[slot].phase != 3) continue;
    for (i = 0; i < cached; ++i)
      if (cache[i].handle == md_resource_growth_receipts[slot].event_handle) break;
    if (i < cached) {value = cache[i].value; known = cache[i].known;}
    else {
      known = madeira_growth_event_value(md_resource_growth_receipts[slot].event_cookie, &value);
      if (cached < sizeof(cache)/sizeof(cache[0])) {
        cache[cached].handle = md_resource_growth_receipts[slot].event_handle;
        cache[cached].value = value; cache[cached++].known = known;
      }
    }
    if (!known || value < md_resource_growth_receipts[slot].target) continue;
    cookies[count++] = md_resource_growth_drop_locked(slot);
    released = 1;
  }
  if (released) md_resource_growth_notify_locked();
  return count;
}

static inline uint64_t md_resource_growth_clock_ns(void) {
  struct timespec now;
#ifdef __APPLE__
  if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
#else
  /* Non-Darwin hosts only execute policy fixtures. The iOS producer uses a
   * monotonic deadline and Darwin's relative condition wait below. */
  if (timespec_get(&now, TIME_UTC) != TIME_UTC) return 0;
#endif
  if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
      (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / UINT64_C(1000000000)) return 0;
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static inline int md_resource_growth_condition_wait(uint64_t remaining) {
  struct timespec timeout;
  /* GPU event progress need not produce a CPU-credit notification. Poll only
   * while blocked, in bounded 10ms sleeps, rather than stalling 250ms per batch. */
  if (remaining > UINT64_C(10000000)) remaining = UINT64_C(10000000);
  timeout.tv_sec = remaining / UINT64_C(1000000000);
  timeout.tv_nsec = remaining % UINT64_C(1000000000);
#ifdef __APPLE__
  return pthread_cond_timedwait_relative_np(&md_resource_growth_condition, &md_resource_growth_mutex, &timeout);
#else
  {
    struct timespec now;
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return EINVAL;
    timeout.tv_sec += now.tv_sec;
    timeout.tv_nsec += now.tv_nsec;
    if (timeout.tv_nsec >= 1000000000L) {++timeout.tv_sec; timeout.tv_nsec -= 1000000000L;}
  }
  return pthread_cond_timedwait(&md_resource_growth_condition, &md_resource_growth_mutex, &timeout);
#endif
}

static void md_resource_growth_wait_canceled(void *unused) {
  (void)unused;
  if (md_resource_growth_waiters) --md_resource_growth_waiters;
  pthread_mutex_unlock(&md_resource_growth_mutex);
}

/* op41 input ptr=prospective destination plus actual NEW upload growth;
 * len0/1 remain accepted for old callers. There is no historical-spend ledger
 * or texture-size exception. Initialized residency is counted by the OS.
 * Output ret0 means measurement unavailable,
 * ret1 granted, ret2 granted/reclaim recommended, ret3 denied measured pressure,
 * ret4 denied counter overflow or invalid/retiring owner.
 * A grant returns ptr=token and
 * len=actual measured physical headroom. No successful allocation is implied.
 */
static inline void md_resource_growth_acquire(struct madeira_ctl_args *args) {
  const int saved_errno = errno;
  const uint64_t bytes = args->ptr, completion_retry = args->len;
  struct madeira_ctl_args measurement = {0, 0, 0, 0, {0}};
  uint64_t available, reserve, floor, effective, recovery, now, deadline = 0;
  uint64_t lease = 0, current_lease = 0;
  void *owner = NULL, *current_owner = NULL;
  int identity, wait_status, cancel_state;
  uint64_t cookies[MD_RESOURCE_GROWTH_RECEIPTS];
  unsigned slot, cookie_count;
  (void)md_resource_growth_contract[0];
  (void)md_resource_live_contract[0];
  args->ret = 0; args->ptr = 0; args->len = 0;
  md_resource_growth_diagnostics(args, 0, 0, 0, 0);
  if (completion_retry > 1) {
    md_resource_growth_diagnostics(args, 0, 0, 0, 4); args->ret = 4; goto done;
  }
  if (!bytes) goto done;
  identity = md_resource_growth_identity(&owner, &lease, 0);
  if (identity < 0) goto done;
  if (!identity) {
    md_resource_growth_diagnostics(args, 0, 0, 0, 3); args->ret = 4; goto done;
  }
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  pthread_mutex_lock(&md_resource_growth_mutex);
 retry:
  cookie_count = md_resource_growth_poll_gpu_locked(cookies);
  if (cookie_count) {
    pthread_mutex_unlock(&md_resource_growth_mutex);
    md_resource_growth_release_events(cookies, cookie_count);
    pthread_mutex_lock(&md_resource_growth_mutex);
  }
  if (md_resource_growth_identity(&current_owner, &current_lease, 0) != 1 ||
      current_owner != owner || current_lease != lease) {
    md_resource_growth_diagnostics(args, 0, md_resource_growth_held, 0, 3); args->ret = 4; goto unlock;
  }
  /* Every admission samples the real task. A per-thread 100ms cache is not a
   * physical allocation guarantee when several streaming workers grow at once. */
  md_memory_pressure_query(&measurement);
  if (measurement.ret != 1) goto unlock;
  available = measurement.len;
  reserve = md_resource_growth_reserve(measurement.ptr + available);
  floor = md_resource_growth_floor(reserve);
  effective = available > md_resource_growth_held ? available - md_resource_growth_held : 0;
  recovery = reserve + reserve / 4;
  if (effective >= recovery) {
    md_resource_growth_pressure = 0;
  }
  if (!md_resource_growth_pressure &&
      (effective <= reserve || bytes >= effective - reserve)) {
    md_resource_growth_pressure = 1;
  }
  args->len = available;
  md_resource_growth_diagnostics(args, measurement.ptr, md_resource_growth_held, floor, 0);
  for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot)
    if (!md_resource_growth_receipts[slot].token) break;
  if (available <= floor || bytes > available - floor) {
    md_resource_growth_pressure = 1;
    md_resource_growth_diagnostics(args, measurement.ptr, md_resource_growth_held, floor, 1);
    args->ret = 3; goto unlock;
  }
  if (effective <= floor || bytes > effective - floor || slot == MD_RESOURCE_GROWTH_RECEIPTS) {
    md_resource_growth_pressure = 1;
    /* The first request must return to the PE producer so it can submit a
     * private initializer batch. Only its explicit post-flush retry may wait
     * for CPU/GPU receipts; otherwise an unsubmitted batch could deadlock. */
    if (!completion_retry || !md_resource_growth_held) {
      md_resource_growth_diagnostics(args, measurement.ptr, md_resource_growth_held, floor,
                                     md_resource_growth_held ? 2 : 4);
      args->ret = 3; goto unlock;
    }
    /* The request fits genuine physical capacity; another pending creator
     * temporarily owns it. Do not hold the mutex or block unrelated threads
     * while waiting, and revalidate both ownership and physical memory. */
    md_resource_growth_diagnostics(args, measurement.ptr, md_resource_growth_held, floor, 2);
    now = md_resource_growth_clock_ns();
    if (!now || (!deadline && now > UINT64_MAX - UINT64_C(250000000))) {
      args->ret = 3; goto unlock;
    }
    if (!deadline) deadline = now + UINT64_C(250000000);
    if (now >= deadline) {
      md_resource_growth_diagnostics(args, measurement.ptr, md_resource_growth_held, floor, 2);
      args->ret = 3; goto unlock;
    }
    ++md_resource_growth_waiters;
    pthread_cleanup_push(md_resource_growth_wait_canceled, NULL);
    pthread_setcancelstate(cancel_state, NULL);
    /* Darwin's relative_np condition wait is explicitly NOCANCEL. Test at
     * both owned-mutex boundaries while cleanup is registered; a deferred
     * cancellation then retires this waiter within one bounded sleep slice. */
    pthread_testcancel();
    wait_status = md_resource_growth_condition_wait(deadline - now);
    pthread_testcancel();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    --md_resource_growth_waiters;
    pthread_cleanup_pop(0);
    if (wait_status && wait_status != ETIMEDOUT && wait_status != EINTR) {
      args->ret = 3; goto unlock;
    }
    goto retry;
  }
  if (!md_resource_growth_next ||
      bytes > UINT64_MAX - md_resource_growth_held) {
    md_resource_growth_diagnostics(args, measurement.ptr, md_resource_growth_held, floor, 4);
    args->ret = 4;
    goto unlock;
  }
  args->ptr = md_resource_growth_next++;
  md_resource_growth_receipts[slot].token = args->ptr;
  md_resource_growth_receipts[slot].bytes = bytes;
  md_resource_growth_receipts[slot].owner = owner;
  md_resource_growth_receipts[slot].lease = lease;
  md_resource_growth_receipts[slot].phase = 1;
  md_resource_growth_held += bytes;
  args->ret = md_resource_growth_pressure ? 2 : 1;
unlock:
  pthread_mutex_unlock(&md_resource_growth_mutex);
  pthread_setcancelstate(cancel_state, NULL);
done:
  errno = saved_errno;
}

/* op43 begins GPU ownership BEFORE the first initializer operation with the
 * sentinel UINT64_MAX. The same creator finalizes that intent exactly once
 * with its real fence (<UINT64_MAX), or0 for a proven no-work scope. A canceled
 * intent remains conservatively charged; CPU exit cannot guess its GPU fence. */
static inline void md_resource_growth_handoff(struct madeira_ctl_args *args) {
  const int saved_errno = errno;
  const uint64_t token = args->ptr, handle = args->len;
  uint64_t target, lease = 0, cookie = 0, value = 0;
  void *owner = NULL, *current_owner = NULL;
  uint64_t current_lease = 0;
  int identity, cancel_state;
  unsigned slot;
  memcpy(&target, args->name, sizeof(target));
  args->ret = 0; args->ptr = 0; args->len = 0;
  md_resource_growth_diagnostics(args, 0, 0, 0, 0);
  if (!token || !handle) {args->ret = 4; goto done;}
  identity = md_resource_growth_identity(&owner, &lease, 1);
  if (identity < 0) goto done;
  if (!identity) {args->ret = 4; goto done;}
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  pthread_mutex_lock(&md_resource_growth_mutex);
  if (md_resource_growth_identity(&current_owner, &current_lease, 1) != 1 ||
      current_owner != owner || current_lease != lease) {args->ret = 4; goto unlock;}
  for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot)
    if (md_resource_growth_receipts[slot].token == token &&
        md_resource_growth_receipts[slot].owner == owner &&
        md_resource_growth_receipts[slot].lease == lease) break;
  if (slot == MD_RESOURCE_GROWTH_RECEIPTS) {args->ret = 4; goto unlock;}
  if (md_resource_growth_receipts[slot].phase == 1) {
    if (target != UINT64_MAX) {args->ret = 4; goto unlock;}
    cookie = madeira_growth_event_retain(handle, owner, lease);
    if (!cookie) {args->ret = 4; goto unlock;}
    md_resource_growth_receipts[slot].event_handle = handle;
    md_resource_growth_receipts[slot].event_cookie = cookie;
    md_resource_growth_receipts[slot].target = UINT64_MAX;
    md_resource_growth_receipts[slot].phase = 2;
    cookie = 0; /* Native loan is now receipt-owned, independent of the CPU. */
    args->ret = 1;
  } else if (md_resource_growth_receipts[slot].phase == 2 && target != UINT64_MAX &&
             md_resource_growth_receipts[slot].event_handle == handle) {
    if (target && !madeira_growth_event_value(md_resource_growth_receipts[slot].event_cookie, &value)) {
      args->ret = 4; goto unlock;
    }
    if (!target || value >= target) {
      cookie = md_resource_growth_drop_locked(slot);
      md_resource_growth_notify_locked();
    } else {
      md_resource_growth_receipts[slot].target = target;
      md_resource_growth_receipts[slot].phase = 3;
    }
    args->ret = 1;
  } else args->ret = 4; /* No foreign event, duplicate begin or fence downgrade. */
 unlock:
  pthread_mutex_unlock(&md_resource_growth_mutex);
  if (cookie) madeira_growth_event_release(cookie);
  pthread_setcancelstate(cancel_state, NULL);
 done:
  errno = saved_errno;
}

/* op42 releases exactly one live CPU creation receipt. Duplicate/foreign tokens
 * cannot underflow held bytes or release another caller's credit. */
static inline void md_resource_growth_release(struct madeira_ctl_args *args) {
  const int saved_errno = errno;
  const uint64_t token = args->ptr;
  uint64_t lease = 0;
  uint64_t cookies[MD_RESOURCE_GROWTH_RECEIPTS];
  void *owner = NULL;
  unsigned slot, cookie_count;
  int cancel_state;
  args->ret = 0; args->ptr = 0; args->len = 0;
  if (!token) goto done;
  if (md_resource_growth_identity(&owner, &lease, 1) != 1) goto done;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  pthread_mutex_lock(&md_resource_growth_mutex);
  cookie_count = md_resource_growth_poll_gpu_locked(cookies);
  for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot) {
    if (md_resource_growth_receipts[slot].token != token ||
        md_resource_growth_receipts[slot].owner != owner ||
        md_resource_growth_receipts[slot].lease != lease ||
        md_resource_growth_receipts[slot].phase != 1) continue;
    (void)md_resource_growth_drop_locked(slot);
    md_resource_growth_notify_locked();
    args->ret = 1;
    break;
  }
  pthread_mutex_unlock(&md_resource_growth_mutex);
  md_resource_growth_release_events(cookies, cookie_count);
  pthread_setcancelstate(cancel_state, NULL);
done:
  errno = saved_errno;
}

/* Metadata-only cancellation cleanup, invoked by Wine only after its complete
 * native-thread quiescence proof and before the generation/window is recycled.
 * Live GPU/guest allocations are neither freed nor declared physically free.
 */
#ifdef __cplusplus
extern "C"
#endif
void madeira_resource_growth_retire(void *owner, unsigned long long lease) {
  const int saved_errno = errno;
  unsigned slot, cookie_count;
  uint64_t cookies[MD_RESOURCE_GROWTH_RECEIPTS];
  int released = 0, cancel_state;
  if (!owner || !lease || !ios_thread_process_quiescent_lease ||
      ios_thread_process_quiescent_lease(owner) != lease) goto done;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  pthread_mutex_lock(&md_resource_growth_mutex);
  cookie_count = md_resource_growth_poll_gpu_locked(cookies);
  if (ios_thread_process_quiescent_lease(owner) == lease) {
    for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot) {
      if (md_resource_growth_receipts[slot].owner != owner ||
          md_resource_growth_receipts[slot].lease != lease ||
          md_resource_growth_receipts[slot].phase != 1) continue;
      (void)md_resource_growth_drop_locked(slot);
      released = 1;
    }
  }
  if (released) md_resource_growth_notify_locked();
  pthread_mutex_unlock(&md_resource_growth_mutex);
  md_resource_growth_release_events(cookies, cookie_count);
  pthread_setcancelstate(cancel_state, NULL);
done:
  errno = saved_errno;
}

#endif
