#ifndef MADEIRA_METAL_SUBMISSION_GATE_H
#define MADEIRA_METAL_SUBMISSION_GATE_H

/* Admission controls actual submission, never completion. Paused producers
 * retain their encoded work; a deferred main-thread item retains its payload
 * in the Objective-C adapter. No UIKit callback waits on this condition. */
#include <pthread.h>

struct md_metal_work {
  struct md_metal_work *next;
  void (*submit)(void *);
  void *payload;
  int deferred;
};
struct md_metal_gate {
  pthread_mutex_t lock;
  pthread_cond_t ready;
  struct md_metal_work *head, *tail;
  int active;
};
#define MD_METAL_GATE_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0}

static inline void md_metal_append(struct md_metal_gate *gate, struct md_metal_work *work)
{
  work->next = 0;
  if (gate->tail) gate->tail->next = work;
  else gate->head = work;
  gate->tail = work;
}

static inline void md_metal_run_head(struct md_metal_gate *gate)
{
  struct md_metal_work *work = gate->head;
  gate->head = work->next;
  if (!gate->head) gate->tail = 0;
  /* The callback may release a deferred node. Do not access it afterwards. */
  work->submit(work->payload);
}

static inline void md_metal_drain_deferred(struct md_metal_gate *gate)
{
  while (gate->active && gate->head && gate->head->deferred)
    md_metal_run_head(gate);
}

static inline int md_metal_gate_set_active(struct md_metal_gate *gate, int active)
{
  pthread_mutex_lock(&gate->lock);
  int changed = gate->active != !!active;
  gate->active = !!active;
  md_metal_drain_deferred(gate);
  pthread_cond_broadcast(&gate->ready);
  pthread_mutex_unlock(&gate->lock);
  return changed;
}

struct md_metal_cancel { struct md_metal_gate *gate; struct md_metal_work *work; };
static inline void md_metal_cancel_wait(void *argument)
{
  struct md_metal_cancel *cancel = argument;
  struct md_metal_gate *gate = cancel->gate;
  struct md_metal_work **cursor = &gate->head, *previous = 0;
  while (*cursor && *cursor != cancel->work) {
    previous = *cursor;
    cursor = &(*cursor)->next;
  }
  if (*cursor) {
    *cursor = cancel->work->next;
    if (gate->tail == cancel->work) gate->tail = previous;
  }
  md_metal_drain_deferred(gate);
  pthread_cond_broadcast(&gate->ready);
  pthread_mutex_unlock(&gate->lock);
}

static inline void md_metal_gate_submit_wait(struct md_metal_gate *gate, void (*submit)(void *), void *payload)
{
  struct md_metal_work work = {0, submit, payload, 0};
  struct md_metal_cancel cancel = {gate, &work};
  pthread_mutex_lock(&gate->lock);
  md_metal_append(gate, &work);
  pthread_cleanup_push(md_metal_cancel_wait, &cancel);
  while (!gate->active || gate->head != &work)
    pthread_cond_wait(&gate->ready, &gate->lock);
  md_metal_run_head(gate);
  md_metal_drain_deferred(gate);
  pthread_cond_broadcast(&gate->ready);
  pthread_cleanup_pop(0);
  pthread_mutex_unlock(&gate->lock);
}

/* UIKit's main thread never waits for didBecomeActive on its own run loop. */
static inline int md_metal_gate_try_submit(struct md_metal_gate *gate, void (*submit)(void *), void *payload)
{
  pthread_mutex_lock(&gate->lock);
  int accepted = gate->active && !gate->head;
  if (accepted) submit(payload);
  pthread_mutex_unlock(&gate->lock);
  return accepted;
}

static inline void md_metal_gate_defer(struct md_metal_gate *gate, struct md_metal_work *work)
{
  pthread_mutex_lock(&gate->lock);
  work->deferred = 1;
  md_metal_append(gate, work);
  md_metal_drain_deferred(gate);
  pthread_cond_broadcast(&gate->ready);
  pthread_mutex_unlock(&gate->lock);
}
#endif
