#ifndef MADEIRA_RESOURCE_GROWTH_EVENT_NATIVE_H
#define MADEIRA_RESOURCE_GROWTH_EVENT_NATIVE_H

/* This header belongs only to the native Objective-C WMT translation unit.
 * Public Foundation zeroing-weak values validate a genuine device-created
 * event without retaining every event for the lifetime of the application.
 * Opaque, bounded strong loans separately cover GPU-pending growth receipts.
 */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif
extern void *ios_jit_current_peb(void) __attribute__((weak));
extern unsigned long long ios_thread_process_snapshot(void *, unsigned *, int *, int *) __attribute__((weak));

#define MD_GROWTH_EVENT_SLOTS 256
#define MD_GROWTH_EVENT_LOANS 256
static const volatile char md_growth_event_contract[] = "[texture-gpu-events-v1]";
static pthread_mutex_t md_growth_event_mutex = PTHREAD_MUTEX_INITIALIZER;
static NSMapTable *md_growth_event_map;
static struct {
  uint64_t handle;
  void *owner;
  unsigned long long lease;
} md_growth_events[MD_GROWTH_EVENT_SLOTS];
static struct {
  uint64_t cookie;
  id event; /* Exactly one owned retain while this opaque loan is live. */
} md_growth_event_loans[MD_GROWTH_EVENT_LOANS];
static uint64_t md_growth_event_next_cookie = 1;

/* No growth-budget callback or mutex is entered here. Native budget callers
 * may already own their growth mutex: ordering is growth -> event registry.
 * Registry callers capture the passive Wine identity before entering it.
 */
static int md_growth_event_identity(void **owner, unsigned long long *lease) {
  unsigned threads = 0;
  int exiting = 0, reclaimed = 0;
  if (!ios_jit_current_peb || !ios_thread_process_snapshot) return 0;
  *owner = ios_jit_current_peb();
  if (!*owner) return 0;
  *lease = ios_thread_process_snapshot(*owner, &threads, &exiting, &reclaimed);
  return *lease && threads && !exiting && !reclaimed;
}

/* Only _MTLDevice_newSharedEvent invokes this with its real native +1 result.
 * Remote handles and caller-supplied private control values never register.
 * A full/failed registry leaves ordinary WMT event creation unchanged; the
 * private GPU-credit handoff then fails conservatively instead of trusting
 * an arbitrary Objective-C address.
 */
static void madeira_growth_event_register_created(id<MTLSharedEvent> event) {
  const int saved_errno = errno;
  void *owner = NULL;
  unsigned long long lease = 0;
  (void)md_growth_event_contract[0];
  if (!event || !md_growth_event_identity(&owner, &lease)) goto done;
  @autoreleasepool {
    const uint64_t handle = (uint64_t)(uintptr_t)event;
    NSNumber *key = [NSNumber numberWithUnsignedLongLong:handle];
    unsigned free_slot = MD_GROWTH_EVENT_SLOTS, match = MD_GROWTH_EVENT_SLOTS;
    pthread_mutex_lock(&md_growth_event_mutex);
    if (!md_growth_event_map)
      md_growth_event_map = [[NSMapTable alloc] initWithKeyOptions:NSPointerFunctionsStrongMemory
          valueOptions:NSPointerFunctionsWeakMemory capacity:MD_GROWTH_EVENT_SLOTS];
    if (!md_growth_event_map) { pthread_mutex_unlock(&md_growth_event_mutex); goto done; }
    for (unsigned i = 0; i < MD_GROWTH_EVENT_SLOTS; ++i) {
      if (md_growth_events[i].handle) {
        NSNumber *old_key = [NSNumber numberWithUnsignedLongLong:md_growth_events[i].handle];
        if (![md_growth_event_map objectForKey:old_key]) {
          [md_growth_event_map removeObjectForKey:old_key];
          md_growth_events[i].handle = 0;
          md_growth_events[i].owner = NULL;
          md_growth_events[i].lease = 0;
        }
      }
      if (md_growth_events[i].handle == handle) match = i;
      if (!md_growth_events[i].handle && free_slot == MD_GROWTH_EVENT_SLOTS) free_slot = i;
    }
    unsigned slot = match == MD_GROWTH_EVENT_SLOTS ? free_slot : match;
    if (slot < MD_GROWTH_EVENT_SLOTS &&
        (!md_growth_events[slot].handle ||
         (md_growth_events[slot].owner == owner && md_growth_events[slot].lease == lease))) {
      [md_growth_event_map setObject:event forKey:key];
      md_growth_events[slot].handle = handle;
      md_growth_events[slot].owner = owner;
      md_growth_events[slot].lease = lease;
    }
    pthread_mutex_unlock(&md_growth_event_mutex);
  }
done:
  errno = saved_errno;
}

uint64_t madeira_growth_event_retain(uint64_t handle, void *owner, unsigned long long lease) {
  const int saved_errno = errno;
  uint64_t cookie = 0;
  void *current_owner = NULL;
  unsigned long long current_lease = 0;
  if (!handle || !owner || !lease || !md_growth_event_identity(&current_owner, &current_lease) ||
      current_owner != owner || current_lease != lease) goto done;
  @autoreleasepool {
    pthread_mutex_lock(&md_growth_event_mutex);
    for (unsigned i = 0; i < MD_GROWTH_EVENT_SLOTS; ++i) {
      if (md_growth_events[i].handle != handle || md_growth_events[i].owner != owner ||
          md_growth_events[i].lease != lease) continue;
      /* NSMapTable's zeroing-weak lookup is the only source of this object.
       * No caller handle is cast and messaged. The normal MRC +0 result is
       * retained before this autorelease pool can drain.
       */
      id event = [md_growth_event_map objectForKey:[NSNumber numberWithUnsignedLongLong:handle]];
      if (!event || !md_growth_event_next_cookie) break;
      for (unsigned j = 0; j < MD_GROWTH_EVENT_LOANS; ++j) {
        if (md_growth_event_loans[j].cookie) continue;
        cookie = md_growth_event_next_cookie++;
        md_growth_event_loans[j].event = [event retain];
        md_growth_event_loans[j].cookie = cookie;
        break;
      }
      break;
    }
    pthread_mutex_unlock(&md_growth_event_mutex);
  }
done:
  errno = saved_errno;
  return cookie;
}

int madeira_growth_event_value(uint64_t cookie, uint64_t *value) {
  const int saved_errno = errno;
  id event = nil;
  int known = 0;
  if (value) *value = 0;
  if (!cookie || !value) goto done;
  pthread_mutex_lock(&md_growth_event_mutex);
  for (unsigned i = 0; i < MD_GROWTH_EVENT_LOANS; ++i)
    if (md_growth_event_loans[i].cookie == cookie) {
      event = [md_growth_event_loans[i].event retain];
      break;
    }
  pthread_mutex_unlock(&md_growth_event_mutex);
  if (event) {
    *value = [(id<MTLSharedEvent>)event signaledValue];
    known = 1;
    [event release];
  }
done:
  errno = saved_errno;
  return known;
}

void madeira_growth_event_release(uint64_t cookie) {
  const int saved_errno = errno;
  id event = nil;
  if (!cookie) goto done;
  pthread_mutex_lock(&md_growth_event_mutex);
  for (unsigned i = 0; i < MD_GROWTH_EVENT_LOANS; ++i)
    if (md_growth_event_loans[i].cookie == cookie) {
      event = md_growth_event_loans[i].event;
      md_growth_event_loans[i].cookie = 0;
      md_growth_event_loans[i].event = nil;
      break;
    }
  pthread_mutex_unlock(&md_growth_event_mutex);
  /* Destruction is outside the registry mutex. This private loan has no
   * relationship to generic public WMT retain/release bookkeeping.
   */
  [event release];
done:
  errno = saved_errno;
}
#ifdef __cplusplus
}
#endif
#endif
