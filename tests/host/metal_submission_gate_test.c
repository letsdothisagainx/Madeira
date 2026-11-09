#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "metal_submission_gate.h"

static struct md_metal_gate gate = MD_METAL_GATE_INITIALIZER;
static unsigned ledger[20000];
static _Atomic unsigned submitted;

static void record(void *payload)
{
  /* Called by the production admission policy, not a synthetic GPU completion.
   * No API status/event/HRESULT is supplied by this fixture. */
  assert(gate.active);
  unsigned n = atomic_load_explicit(&submitted, memory_order_relaxed);
  assert(n < sizeof(ledger) / sizeof(ledger[0]));
  ledger[n] = (unsigned)(uintptr_t)payload;
  atomic_store_explicit(&submitted, n + 1, memory_order_release);
}

static void *producer(void *payload)
{
  md_metal_gate_submit_wait(&gate, record, payload);
  return 0;
}

static void wait_queued(unsigned expected)
{
  struct timespec started, now, delay = {0, 1000000};
  clock_gettime(CLOCK_MONOTONIC, &started);
  for (;;) {
    pthread_mutex_lock(&gate.lock);
    unsigned queued = 0;
    for (struct md_metal_work *work = gate.head; work; work = work->next) queued++;
    pthread_mutex_unlock(&gate.lock);
    if (queued == expected) return;
    clock_gettime(CLOCK_MONOTONIC, &now);
    assert(now.tv_sec - started.tv_sec < 5);
    nanosleep(&delay, 0);
  }
}

static void *stress(void *payload)
{
  for (unsigned i = 0; i < 1000; ++i)
    md_metal_gate_submit_wait(&gate, record, payload);
  return 0;
}

int main(void)
{
  pthread_t first, third, sixth;
  struct md_metal_work second = {0, record, (void *)2, 1};
  struct md_metal_work fifth = {0, record, (void *)5, 1};
  assert(!md_metal_gate_try_submit(&gate, record, (void *)99));
  assert(!atomic_load(&submitted));
  assert(!pthread_create(&first, 0, producer, (void *)1));
  wait_queued(1);
  /* The main-thread-style deferred call returns while inactive and never
   * overtakes an earlier producer when activation arrives. */
  md_metal_gate_defer(&gate, &second);
  assert(!pthread_create(&third, 0, producer, (void *)3));
  wait_queued(3);
  pthread_mutex_lock(&gate.lock);
  pthread_cond_broadcast(&gate.ready); /* a wake alone cannot admit GPU work */
  pthread_mutex_unlock(&gate.lock);
  assert(!atomic_load(&submitted));
  assert(md_metal_gate_set_active(&gate, 1));
  assert(!pthread_join(first, 0) && !pthread_join(third, 0));
  assert(atomic_load(&submitted) == 3);
  assert(ledger[0] == 1 && ledger[1] == 2 && ledger[2] == 3);
  assert(md_metal_gate_try_submit(&gate, record, (void *)4));
  assert(ledger[3] == 4);

  /* A cancelled blocked thread must not leave a dead stack node or a locked
   * mutex that prevents foreground notification and later queued work. */
  assert(md_metal_gate_set_active(&gate, 0));
  assert(!pthread_create(&first, 0, producer, (void *)99));
  wait_queued(1);
  md_metal_gate_defer(&gate, &fifth);
  assert(!pthread_create(&sixth, 0, producer, (void *)6));
  wait_queued(3);
  assert(!pthread_cancel(first));
  void *cancelled;
  assert(!pthread_join(first, &cancelled) && cancelled == PTHREAD_CANCELED);
  wait_queued(2);
  assert(atomic_load(&submitted) == 4);
  assert(md_metal_gate_set_active(&gate, 1));
  assert(!pthread_join(sixth, 0));
  assert(atomic_load(&submitted) == 6 && ledger[4] == 5 && ledger[5] == 6);

  pthread_t producers[8];
  for (uintptr_t i = 0; i < 8; ++i)
    assert(!pthread_create(&producers[i], 0, stress, (void *)(i + 10)));
  for (unsigned i = 0; i < 10000; ++i) md_metal_gate_set_active(&gate, i & 1);
  md_metal_gate_set_active(&gate, 1);
  for (unsigned i = 0; i < 8; ++i) assert(!pthread_join(producers[i], 0));
  assert(atomic_load(&submitted) == 8006);
  assert(!gate.head && !gate.tail);
  unsigned counts[8] = {0};
  for (unsigned i = 6; i < 8006; ++i) {
    assert(ledger[i] >= 10 && ledger[i] < 18);
    counts[ledger[i] - 10]++;
  }
  for (unsigned i = 0; i < 8; ++i) assert(counts[i] == 1000);
  puts("PASS production Metal submission policy: paused work retained, no callback while inactive, FIFO mixed worker/main deferral, cancellation cleanup, 8000 exact-once submissions across 10000 lifecycle transitions; no GPU/completion emulation");
  return 0;
}
