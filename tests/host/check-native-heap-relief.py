#!/usr/bin/env python3
"""Exercise the actual native free-heap relief helper, without guest/JIT purges.

Portable fixtures control only OS observations and libmalloc's response. Darwin
also exercises the real public API with real footprint measurements and live
data checks. Neither fixture is an iPhone memory/performance acceptance test.
"""
from pathlib import Path
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'build/dxmt-ios/native_heap_relief.h'

FIXTURE = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static int fixture_clock_gettime(clockid_t, struct timespec *);
static int fixture_dprintf(int, const char *, ...);
#define clock_gettime fixture_clock_gettime
#define dprintf fixture_dprintf
#include "native_heap_relief.h"
#undef clock_gettime
#undef dprintf
static const uint64_t MiB = UINT64_C(1) << 20;
static uint64_t stamp = UINT64_C(1000000000), foot, avail, returned, reduction, goal_seen, relief_elapsed;
static unsigned measure_calls, relief_calls, logs;
static int task_failure, short_count, sysctl_failure, clock_failure, after_failure;
static uint64_t installed = UINT64_C(7672) << 20;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int block_relief, entered, release_relief;
static int fixture_clock_gettime(clockid_t which, struct timespec *out) {
  assert(which == CLOCK_MONOTONIC);
  errno = 51;
  if (clock_failure) return -1;
  out->tv_sec = (time_t)(stamp / UINT64_C(1000000000));
  out->tv_nsec = (long)(stamp % UINT64_C(1000000000));
  return 0;
}
static int fixture_dprintf(int fd, const char *format, ...) {
  assert(fd == 2 && strstr(format, "observed-footprint-drop="));
  ++logs; errno = 52; return 0;
}
int mach_task_self(void) { return 1; }
int task_info(int task, int flavor, task_info_t data, mach_msg_type_number_t *count) {
  assert(task == 1 && flavor == TASK_VM_INFO);
  ++measure_calls; errno = 53;
  ((task_vm_info_data_t *)data)->phys_footprint = foot;
  *count = short_count ? TASK_VM_INFO_REV1_COUNT - 1 : TASK_VM_INFO_COUNT;
  return task_failure || (after_failure && relief_calls);
}
size_t os_proc_available_memory(void) { errno = 54; return (size_t)avail; }
int sysctlbyname(const char *name, void *value, size_t *length, void *input, size_t size) {
  assert(!strcmp(name, "hw.memsize") && !input && !size);
  *(uint64_t *)value = installed; *length = sizeof(installed); errno = 55;
  return sysctl_failure;
}
size_t malloc_zone_pressure_relief(malloc_zone_t *zone, size_t goal) {
  assert(!zone && goal >= 16 * MiB && goal <= 64 * MiB);
  pthread_mutex_lock(&gate);
  ++relief_calls; goal_seen = goal;
  if (block_relief) {
    entered = 1; pthread_cond_broadcast(&condition);
    while (!release_relief) pthread_cond_wait(&condition, &gate);
  }
  pthread_mutex_unlock(&gate);
  assert(reduction <= foot);
  foot -= reduction; avail += reduction; stamp += relief_elapsed; errno = 56;
  return (size_t)returned;
}
static void reset(void) {
  md_native_heap_relief_pending = md_native_heap_relief_running = 0;
  md_native_heap_relief_next_ns = md_native_heap_relief_last_log_ns = 0;
  md_native_heap_relief_reports = 0;
  stamp = UINT64_C(1000000000); foot = 6000 * MiB; avail = 144 * MiB;
  returned = reduction = goal_seen = relief_elapsed = 0; measure_calls = relief_calls = logs = 0;
  task_failure = short_count = sysctl_failure = clock_failure = after_failure = 0;
  block_relief = entered = release_relief = 0;
}
static void request(void) {
  errno = 71; madeira_native_memory_relief_request(foot, avail); assert(errno == 71);
}
static void poll(void) {
  errno = 72; madeira_native_memory_relief_poll(); assert(errno == 72);
}
static void *request_thread(void *unused) {
  (void)unused;
  for (unsigned n = 0; n < 100000; ++n) {
    errno = 73; madeira_native_memory_relief_request(6000 * MiB, 144 * MiB); assert(errno == 73);
  }
  return NULL;
}
static void *poll_thread(void *unused) { (void)unused; poll(); return NULL; }
int main(void) {
  reset();
  for (unsigned n = 0; n < 10000; ++n) poll();
  assert(!measure_calls && !relief_calls && !logs); /* Truly idle background path. */
  madeira_native_memory_relief_request(4096 * MiB, 2048 * MiB);
  madeira_native_memory_relief_request(0, 0);
  madeira_native_memory_relief_request(UINT64_MAX - 3, 4);
  poll(); assert(!measure_calls && !relief_calls);

  pthread_t threads[8];
  for (unsigned n = 0; n < 8; ++n) assert(!pthread_create(&threads[n], NULL, request_thread, NULL));
  for (unsigned n = 0; n < 8; ++n) assert(!pthread_join(threads[n], NULL));
  assert(md_native_heap_relief_pending == 1 && !measure_calls && !relief_calls);
  returned = 512 * MiB; /* Allocator may claim bytes without lowering charged footprint. */
  poll(); assert(relief_calls == 1 && measure_calls == 2 && goal_seen == 64 * MiB);
  assert(md_native_heap_relief_next_ns == stamp + UINT64_C(8000000000));
  request();
  for (unsigned n = 0; n < 10000; ++n) poll();
  assert(relief_calls == 1 && md_native_heap_relief_pending == 1);
  stamp += UINT64_C(7999999999); poll(); assert(relief_calls == 1);
  stamp++; reduction = 32 * MiB; poll();
  assert(relief_calls == 2 && md_native_heap_relief_next_ns == stamp + UINT64_C(2000000000));
  request(); stamp += UINT64_C(2000000000); poll(); assert(relief_calls == 3);

  reset(); request(); relief_elapsed = UINT64_C(3000000000); poll();
  assert(stamp == UINT64_C(4000000000));
  assert(md_native_heap_relief_next_ns == stamp + UINT64_C(8000000000));
  request(); stamp += UINT64_C(7999999999); poll(); assert(relief_calls == 1);
  stamp++; reduction = MiB; poll(); assert(relief_calls == 2);
  assert(md_native_heap_relief_next_ns == stamp + UINT64_C(2000000000));

  reset(); request(); foot = 4096 * MiB; avail = 2048 * MiB;
  poll(); assert(measure_calls == 1 && !relief_calls && !md_native_heap_relief_pending);
  reset(); foot = 128 * MiB; avail = 128 * MiB; request(); poll();
  assert(relief_calls == 1 && goal_seen == 32 * MiB); /* Device-adaptive goal, no fixed 6GiB limit. */
  reset(); avail = 0; request(); poll(); assert(relief_calls == 1);

  for (unsigned bad = 0; bad < 7; ++bad) {
    reset(); request();
    if (bad == 0) task_failure = 1;
    if (bad == 1) short_count = 1;
    if (bad == 2) sysctl_failure = 1;
    if (bad == 3) installed = 0;
    if (bad == 4) avail = UINT64_MAX;
    if (bad == 5) { foot = UINT64_MAX - 3; avail = 4; }
    if (bad == 6) foot = 0;
    poll(); assert(!relief_calls && md_native_heap_relief_next_ns == stamp + UINT64_C(8000000000));
    installed = 7672 * MiB;
  }
  reset(); request(); after_failure = 1; returned = 64 * MiB; reduction = MiB;
  poll(); assert(relief_calls == 1 && md_native_heap_relief_next_ns == stamp + UINT64_C(8000000000));
  reset(); request(); clock_failure = 1; poll();
  assert(!measure_calls && !relief_calls && md_native_heap_relief_pending == 1);

  /* Reentrant/concurrent polls cannot run another allocator sweep. Requests
   * during the first sweep remain pending; the next poll respects backoff. */
  reset(); request(); block_relief = 1;
  assert(!pthread_create(&threads[0], NULL, poll_thread, NULL));
  pthread_mutex_lock(&gate);
  while (!entered) pthread_cond_wait(&condition, &gate);
  pthread_mutex_unlock(&gate);
  request(); poll(); assert(relief_calls == 1);
  pthread_mutex_lock(&gate); release_relief = 1; pthread_cond_broadcast(&condition); pthread_mutex_unlock(&gate);
  assert(!pthread_join(threads[0], NULL)); poll(); assert(relief_calls == 1);
  assert(md_native_heap_relief_pending == 1 && !md_native_heap_relief_running);
  stamp += UINT64_C(8000000000); poll(); assert(relief_calls == 2);

  reset();
  for (unsigned n = 0; n < 40; ++n) { request(); poll(); stamp += UINT64_C(8000000000); }
  assert(relief_calls == 40 && logs <= 14); /* Bounded reporting, not per-allocation diagnostics. */
  puts("PASS actual native heap helper: coalesced lock-free requests, bounded goals, fresh pressure checks, 2s/8s backoff, zero/unknown headroom, errno, concurrent polls, bounded reporting.");
}
'''

DARWIN = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "native_heap_relief.h"
int main(void) {
  const size_t length = (size_t)32 << 20;
  unsigned char *live = malloc(length), *temporary = malloc(length);
  assert(live && temporary);
  memset(live, 0x6d, length); memset(temporary, 0xc3, length);
  volatile unsigned char *touch = temporary;
  unsigned sum = 0;
  for (size_t n = 0; n < length; n += 4096) sum += touch[n];
  assert(sum);
  free(temporary);
  struct md_native_heap_reading before = md_native_heap_relief_measure();
  assert(before.footprint); /* macOS may have no finite per-process headroom. */
  const size_t allocator_returned = malloc_zone_pressure_relief(NULL, (size_t)64 << 20);
  struct md_native_heap_reading after = md_native_heap_relief_measure();
  assert(after.footprint);
  for (size_t n = 0; n < length; ++n) assert(live[n] == 0x6d);
  errno = 77;
  madeira_native_memory_relief_request(before.footprint, before.available);
  madeira_native_memory_relief_poll();
  assert(errno == 77);
  printf("DARWIN public malloc relief: allocator-returned=%zu actual-footprint-before=%llu after=%llu "
         "available-before=%llu after=%llu headroom-valid-before=%d after=%d; "
         "live32MiB contents intact. No required positive physical saving assumed.\n",
         allocator_returned, (unsigned long long)before.footprint, (unsigned long long)after.footprint,
         (unsigned long long)before.available, (unsigned long long)after.available, before.valid, after.valid);
  free(live);
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-native-heap-relief-') as directory:
    temp = Path(directory)
    for name in ('mach', 'os', 'sys', 'malloc'):
        (temp / name).mkdir()
    (temp / 'mach/mach.h').write_text('''#pragma once
#include <stdint.h>
typedef struct { uint64_t phys_footprint; } task_vm_info_data_t;
typedef unsigned mach_msg_type_number_t;
typedef int *task_info_t;
#define TASK_VM_INFO_COUNT 42
#define TASK_VM_INFO_REV1_COUNT 12
#define TASK_VM_INFO 22
#define KERN_SUCCESS 0
int mach_task_self(void);
int task_info(int, int, task_info_t, mach_msg_type_number_t *);
''')
    (temp / 'os/proc.h').write_text('#pragma once\n#include <stddef.h>\nsize_t os_proc_available_memory(void);\n')
    (temp / 'sys/sysctl.h').write_text('#pragma once\n#include <stddef.h>\nint sysctlbyname(const char *, void *, size_t *, void *, size_t);\n')
    (temp / 'malloc/malloc.h').write_text('''#pragma once
#include <stddef.h>
typedef struct malloc_zone_t malloc_zone_t;
size_t malloc_zone_pressure_relief(malloc_zone_t *, size_t);
''')
    source = temp / 'fixture.c'
    source.write_text(FIXTURE)
    executable = temp / 'fixture'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                    '-I', str(temp), '-I', str(HEADER.parent), str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
    if platform.system() == 'Darwin':
        source = temp / 'darwin.c'
        source.write_text(DARWIN)
        executable = temp / 'darwin'
        # Deliberately no mock include directory or ASan allocator: this path
        # measures genuine Darwin task data and calls the real libmalloc API.
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-I', str(HEADER.parent), str(source), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, timeout=30)
    else:
        print('SKIP Darwin real libmalloc/task-footprint exercise: this host is not Darwin.')
