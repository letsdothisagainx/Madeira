#ifndef MADEIRA_MEMORY_PRESSURE_NATIVE_H
#define MADEIRA_MEMORY_PRESSURE_NATIVE_H

#include <errno.h>
#include <stdint.h>
#include <mach/mach.h>
#include <os/proc.h>
#include <pthread.h>
#include <sys/sysctl.h>

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
 * backend. These receipts cover CPU-side resource creation and its initial
 * upload encoding, not persistent Metal residency or unrelated guest heaps.
 * Never retire a receipt by age: only its matching owner token may release it.
 */
#define MD_RESOURCE_GROWTH_RECEIPTS 256
#ifdef __cplusplus
extern "C" {
#endif
extern void *ios_jit_current_peb(void) __attribute__((weak));
extern unsigned long long ios_thread_process_snapshot(void *, unsigned *, int *, int *) __attribute__((weak));
extern unsigned long long ios_thread_process_quiescent_lease(void *) __attribute__((weak));
void madeira_resource_growth_retire(void *, unsigned long long) __attribute__((visibility("default")));
#ifdef __cplusplus
}
#endif
static const volatile char md_resource_growth_contract[] = "[texture-growth-budget-v1]";
static pthread_mutex_t md_resource_growth_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct { uint64_t token, bytes, lease; void *owner; } md_resource_growth_receipts[MD_RESOURCE_GROWTH_RECEIPTS];
static uint64_t md_resource_growth_held, md_resource_growth_next = 1;
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
  const uint64_t minimum = UINT64_C(128) << 20, maximum = UINT64_C(512) << 20;
  uint64_t floor = reserve / 2;
  return floor < minimum ? minimum : floor > maximum ? maximum : floor;
}

/* op41 input ptr=prospective bytes. Output ret0 means measurement unavailable,
 * ret1 granted, ret2 granted/reclaim recommended, ret3 denied measured pressure,
 * ret4 denied finite receipt capacity/overflow or invalid/retiring owner.
 * A grant returns ptr=token and
 * len=actual measured physical headroom. No successful allocation is implied.
 */
static inline void md_resource_growth_acquire(struct madeira_ctl_args *args) {
  const int saved_errno = errno;
  const uint64_t bytes = args->ptr;
  struct madeira_ctl_args measurement = {0, 0, 0, 0, {0}};
  uint64_t available, reserve, floor, effective, recovery;
  uint64_t lease = 0, current_lease = 0;
  void *owner = NULL, *current_owner = NULL;
  int identity;
  unsigned slot;
  (void)md_resource_growth_contract[0];
  args->ret = 0; args->ptr = 0; args->len = 0;
  if (!bytes) goto done;
  identity = md_resource_growth_identity(&owner, &lease, 0);
  if (identity < 0) goto done;
  if (!identity) { args->ret = 4; goto done; }
  pthread_mutex_lock(&md_resource_growth_mutex);
  if (md_resource_growth_identity(&current_owner, &current_lease, 0) != 1 ||
      current_owner != owner || current_lease != lease) { args->ret = 4; goto unlock; }
  /* Every admission samples the real task. A per-thread100ms cache is not a
   * physical allocation guarantee when several streaming workers grow at once. */
  md_memory_pressure_query(&measurement);
  if (measurement.ret != 1) goto unlock;
  available = measurement.len;
  reserve = md_resource_growth_reserve(measurement.ptr + available);
  floor = md_resource_growth_floor(reserve);
  effective = available > md_resource_growth_held ? available - md_resource_growth_held : 0;
  recovery = reserve + reserve / 4;
  if (md_resource_growth_pressure) {
    if (effective >= recovery) md_resource_growth_pressure = 0;
  }
  if (!md_resource_growth_pressure &&
      (effective <= reserve || bytes >= effective - reserve)) {
    md_resource_growth_pressure = 1;
  }
  args->len = available;
  /* The reserve is the early reclaim watermark, not an unconditional denial
   * of useful work. The separate floor preserves a practical physical margin
   * while allowing modest allocations in the reclaim/recovery band. */
  if (effective <= floor || bytes > effective - floor) {
    md_resource_growth_pressure = 1;
    args->ret = 3;
    goto unlock;
  }
  for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot)
    if (!md_resource_growth_receipts[slot].token) break;
  if (slot == MD_RESOURCE_GROWTH_RECEIPTS || !md_resource_growth_next ||
      bytes > UINT64_MAX - md_resource_growth_held) {
    args->ret = 4;
    goto unlock;
  }
  args->ptr = md_resource_growth_next++;
  md_resource_growth_receipts[slot].token = args->ptr;
  md_resource_growth_receipts[slot].bytes = bytes;
  md_resource_growth_receipts[slot].owner = owner;
  md_resource_growth_receipts[slot].lease = lease;
  md_resource_growth_held += bytes;
  args->ret = md_resource_growth_pressure ? 2 : 1;
unlock:
  pthread_mutex_unlock(&md_resource_growth_mutex);
done:
  errno = saved_errno;
}

/* op42 releases exactly one live creation receipt. Duplicate/foreign tokens
 * cannot underflow held bytes or release another caller's credit. */
static inline void md_resource_growth_release(struct madeira_ctl_args *args) {
  const int saved_errno = errno;
  const uint64_t token = args->ptr;
  uint64_t lease = 0;
  void *owner = NULL;
  unsigned slot;
  args->ret = 0; args->ptr = 0; args->len = 0;
  if (!token) goto done;
  if (md_resource_growth_identity(&owner, &lease, 1) != 1) goto done;
  pthread_mutex_lock(&md_resource_growth_mutex);
  for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot) {
    if (md_resource_growth_receipts[slot].token != token ||
        md_resource_growth_receipts[slot].owner != owner ||
        md_resource_growth_receipts[slot].lease != lease) continue;
    md_resource_growth_held -= md_resource_growth_receipts[slot].bytes;
    md_resource_growth_receipts[slot].token = 0;
    md_resource_growth_receipts[slot].bytes = 0;
    md_resource_growth_receipts[slot].owner = NULL;
    md_resource_growth_receipts[slot].lease = 0;
    args->ret = 1;
    break;
  }
  pthread_mutex_unlock(&md_resource_growth_mutex);
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
  unsigned slot;
  if (!owner || !lease || !ios_thread_process_quiescent_lease ||
      ios_thread_process_quiescent_lease(owner) != lease) goto done;
  pthread_mutex_lock(&md_resource_growth_mutex);
  if (ios_thread_process_quiescent_lease(owner) == lease) {
    for (slot = 0; slot < MD_RESOURCE_GROWTH_RECEIPTS; ++slot) {
      if (md_resource_growth_receipts[slot].owner != owner ||
          md_resource_growth_receipts[slot].lease != lease) continue;
      md_resource_growth_held -= md_resource_growth_receipts[slot].bytes;
      md_resource_growth_receipts[slot].token = 0;
      md_resource_growth_receipts[slot].bytes = 0;
      md_resource_growth_receipts[slot].owner = NULL;
      md_resource_growth_receipts[slot].lease = 0;
    }
  }
  pthread_mutex_unlock(&md_resource_growth_mutex);
done:
  errno = saved_errno;
}

#endif
