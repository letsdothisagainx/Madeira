#ifndef MADEIRA_MEMORY_PRESSURE_NATIVE_H
#define MADEIRA_MEMORY_PRESSURE_NATIVE_H

#include <errno.h>
#include <stdint.h>
#include <mach/mach.h>
#include <os/proc.h>
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

#endif
