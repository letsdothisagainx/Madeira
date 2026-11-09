#ifndef MADEIRA_METAL_LIFECYCLE_H
#define MADEIRA_METAL_LIFECYCLE_H

#include <TargetConditionals.h>
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include "metal_submission_gate.h"

#if TARGET_OS_IOS
static struct md_metal_gate md_metal_submission = MD_METAL_GATE_INITIALIZER;

/* The root UIKit lifecycle calls this before games can launch, at
 * willResignActive/didEnterBackground, and at didBecomeActive. It never waits
 * on the activation condition or GPU completion; its mutex covers just native
 * commit calls, so an already-entered native commit can briefly hold it.
 * Default paused also covers an initial session started before activation. */
void madeira_metal_set_active(int active)
{
  if (md_metal_gate_set_active(&md_metal_submission, active)) {
    static _Atomic unsigned transitions;
    unsigned n = atomic_fetch_add_explicit(&transitions, 1, memory_order_relaxed) + 1;
    if (n <= 8 || !(n & (n - 1)))
      fprintf(stderr, "[metal-lifecycle-v1] transition=%u active=%d policy=preserve-encoded-work-until-active\n", n, !!active);
  }
}

static void md_metal_submit_now(void *payload)
{
  [(id<MTLCommandBuffer>)payload commit];
}

struct md_metal_deferred {
  struct md_metal_work work;
  id<MTLCommandBuffer> buffer;
};
static void md_metal_submit_deferred(void *payload)
{
  struct md_metal_deferred *pending = payload;
  [pending->buffer commit];
  [pending->buffer release];
  free(pending);
}

static void md_metal_commit(id<MTLCommandBuffer> buffer)
{
  if (![NSThread isMainThread]) {
    md_metal_gate_submit_wait(&md_metal_submission, md_metal_submit_now, (void *)buffer);
    return;
  }
  if (md_metal_gate_try_submit(&md_metal_submission, md_metal_submit_now, (void *)buffer)) return;
  struct md_metal_deferred *pending = calloc(1, sizeof(*pending));
  if (!pending) {
    /* No submission or completion can be invented after an allocation failure.
     * This follows the existing process-fatal allocation contract of the port. */
    fputs("[metal-lifecycle-v1] cannot retain a main-thread deferred submission\n", stderr);
    abort();
  }
  pending->buffer = [buffer retain];
  pending->work.submit = md_metal_submit_deferred;
  pending->work.payload = pending;
  md_metal_gate_defer(&md_metal_submission, &pending->work);
}
#else
void madeira_metal_set_active(int active) { (void)active; }
static void md_metal_commit(id<MTLCommandBuffer> buffer) { [buffer commit]; }
#endif
#endif
