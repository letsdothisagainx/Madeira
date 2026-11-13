#!/usr/bin/env python3
"""Execute the production recursive lock; measure CPU cost, not iPhone FPS.

The NT delay shim uses a real host sleep. CMake stages the complete pinned
rpmalloc source; lock functions are extracted verbatim for the host executable.
Optional LLVM_MINGW also compiles that complete source for both real PE ABIs.
"""
from pathlib import Path
import os
import runpy
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ns = runpy.run_path(str(ROOT / 'tests/host/check-fex-owner-allocator-config.py'))
COMPAT = ROOT / 'build/fex-compat'
ORIGINAL = ns['ORIGINAL']

def lock_body(text):
    start = text.index('static _Atomic(uintptr_t) fex_ios_rpm_owner;')
    end = text.index('\n#endif', start)
    return text[start:end]

WINDOWS = '''#pragma once
#include <stdint.h>
#define NTSYSAPI
#define NTAPI
#define FALSE 0
typedef int32_t NTSTATUS;
typedef unsigned char BOOLEAN;
typedef union { int64_t QuadPart; } LARGE_INTEGER;
'''
PRELUDE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "windows.h"
#define NOINLINE __attribute__((noinline))
static _Thread_local uintptr_t identity;
static uintptr_t get_thread_id(void) { return (uintptr_t)&identity; }
static void wait_spin(void) { __asm__ __volatile__("" ::: "memory"); }
static _Atomic unsigned delays, failed_delay, attempted, entered;
NTSTATUS NtDelayExecution(BOOLEAN,const LARGE_INTEGER*);
'''
HARNESS = r'''
static uint64_t ticks(clockid_t c) { struct timespec t;assert(!clock_gettime(c,&t));return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }
static void sleep_ns(long n) { struct timespec t={0,n};nanosleep(&t,0); }
NTSTATUS NtDelayExecution(BOOLEAN alertable,const LARGE_INTEGER* time) {
 assert(!alertable && time->QuadPart==-1000);
 assert(atomic_load(&fex_ios_rpm_owner)!=(get_thread_id()|1));
 atomic_fetch_add(&delays,1);
 if(atomic_exchange(&failed_delay,0))return (NTSTATUS)0xc0000002;
 sleep_ns(100000);return 0;
}
static void* waiter(void* ignored) {
 (void)ignored;atomic_store(&attempted,1);fex_ios_rpm_lock();
 atomic_store(&entered,1);fex_ios_rpm_unlock();return 0;
}
static void held_test(int ready) {
 pthread_t thread;atomic_store(&attempted,0);atomic_store(&entered,0);
 unsigned before=atomic_load(&delays);fex_ios_rpm_lock();
 assert(!pthread_create(&thread,0,waiter,0));
 uint64_t deadline=ticks(CLOCK_MONOTONIC)+3000000000ULL;
 while(!atomic_load(&attempted)){assert(ticks(CLOCK_MONOTONIC)<deadline);sleep_ns(100000);}
 if(ready)while(atomic_load(&delays)==before){assert(ticks(CLOCK_MONOTONIC)<deadline);sleep_ns(100000);}
 else sleep_ns(2000000);
 assert(!atomic_load(&entered));
 if(ready)assert(atomic_load(&delays)>before);else assert(atomic_load(&delays)==before);
 fex_ios_rpm_unlock();assert(!pthread_join(thread,0));assert(atomic_load(&entered));
}
static pthread_mutex_t barrier_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cond=PTHREAD_COND_INITIALIZER;
static unsigned barrier_arrivals,barrier_total,barrier_generation;
static void barrier_wait(void) {
 pthread_mutex_lock(&barrier_mutex);unsigned generation=barrier_generation;
 if(++barrier_arrivals==barrier_total){barrier_arrivals=0;++barrier_generation;pthread_cond_broadcast(&barrier_cond);}
 else while(generation==barrier_generation)pthread_cond_wait(&barrier_cond,&barrier_mutex);
 pthread_mutex_unlock(&barrier_mutex);
}
static unsigned iterations,hold_us;
static uint64_t counter,max_wait;
static void* bench(void* ignored) {
 (void)ignored;barrier_wait();
 for(unsigned i=0;i<iterations;i++) {
  uint64_t begin=ticks(CLOCK_MONOTONIC);fex_ios_rpm_lock();
  uint64_t wait=ticks(CLOCK_MONOTONIC)-begin;if(wait>max_wait)max_wait=wait;
  ++counter;if(hold_us)sleep_ns(hold_us*1000);
  fex_ios_rpm_unlock();
 }return 0;
}
int main(void) {
 held_test(0); /* Early entries must not enter any NT/CRT call. */
#if NEW_LOCK
 fex_ios_rpm_enable_backoff();
 unsigned before=atomic_load(&delays);
 fex_ios_rpm_lock();fex_ios_rpm_lock();fex_ios_rpm_unlock();
 assert(fex_ios_rpm_depth==1 && atomic_load(&delays)==before);
 fex_ios_rpm_unlock();assert(!atomic_load(&fex_ios_rpm_owner));
 atomic_store(&failed_delay,1);held_test(1); /* Failed delay never grants ownership. */
 pthread_t canceled;atomic_store(&attempted,0);atomic_store(&entered,0);
 fex_ios_rpm_lock();assert(!pthread_create(&canceled,0,waiter,0));
 before=atomic_load(&delays);uint64_t deadline=ticks(CLOCK_MONOTONIC)+3000000000ULL;
 while(atomic_load(&delays)==before){assert(ticks(CLOCK_MONOTONIC)<deadline);sleep_ns(100000);}
 assert(!pthread_cancel(canceled));void* result;assert(!pthread_join(canceled,&result));
 assert(result==PTHREAD_CANCELED && !atomic_load(&entered));
 fex_ios_rpm_unlock();fex_ios_rpm_lock();fex_ios_rpm_unlock();
#endif
 const unsigned holds[]={0,0,100,500},counts[]={1,4,4,4};
 for(unsigned mode=0;mode<4;mode++) {
  hold_us=holds[mode];iterations=hold_us?100:50000;counter=0;max_wait=0;
  pthread_t threads[4];barrier_total=counts[mode];assert(!barrier_arrivals);
  uint64_t wall=ticks(CLOCK_MONOTONIC),cpu=ticks(CLOCK_PROCESS_CPUTIME_ID);
  for(unsigned i=0;i<counts[mode];i++)assert(!pthread_create(&threads[i],0,bench,0));
  for(unsigned i=0;i<counts[mode];i++)assert(!pthread_join(threads[i],0));
  cpu=ticks(CLOCK_PROCESS_CPUTIME_ID)-cpu;wall=ticks(CLOCK_MONOTONIC)-wall;
  assert(counter==(uint64_t)counts[mode]*iterations);
  printf("host-lock-benchmark (not iPhone FPS) %s threads=%u hold-us=%u entries=%llu wall-ms=%.3f cpu-ms=%.3f max-wait-us=%.3f\n",
   NEW_LOCK?"backoff":"original",counts[mode],hold_us,(unsigned long long)counter,wall/1e6,cpu/1e6,max_wait/1e3);
 }
 puts("PASS real recursive-owner lock: early no-NT entry, exact counter/exclusion, recursive reentry, failed delay and pre-acquisition cancellation");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-owner-backoff-') as tmp:
    d = Path(tmp)
    source = ns['fixture'](d / 'production')
    build = d / 'production/build'
    ns['configure'](source, build)
    checked = (build / 'madeira-fex-compat/rpmalloc-checked.c').read_text()
    for name in ('windows.h', 'winternl.h'):
        (d / name).write_text(WINDOWS)
    cc = shlex.split(os.environ.get('CC', 'cc'))
    for label, text in (('original', ORIGINAL), ('backoff', checked)):
        path = d / (label + '.c')
        path.write_text(PRELUDE + lock_body(text) + HARNESS)
        binary = d / label
        subprocess.run(cc + ['-std=gnu11', '-O3', '-pthread', '-I' + str(d), '-I' + str(COMPAT),
                            '-DNEW_LOCK=' + str(int(label == 'backoff')), str(path), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=30)
    # The separate cross-compiled planner test accepts these files or stages its
    # own copy. Setting this variable is useful when reviewing exact linked PCs.
    keep = os.environ.get('MADEIRA_OWNER_BACKOFF_STAGE')
    if keep:
        Path(keep).write_text(checked)
