/* Native thread history for the existing crossing-store check. A whole task
 * snapshot is retained without evicting an earlier entry during enumeration.
 * This changes neither store eligibility nor completion/fault semantics. */
#ifndef MADEIRA_STUCK_STORE_HISTORY_H
#define MADEIRA_STUCK_STORE_HISTORY_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef IOS_STUCK_HISTORY_CALLOC
#define IOS_STUCK_HISTORY_CALLOC calloc
#endif
#ifndef IOS_STUCK_HISTORY_FREE
#define IOS_STUCK_HISTORY_FREE free
#endif

/* Above this bound the check declines; it never samples an arbitrary subset.
 * Normal task snapshots need only tens of KiB. Both tables together are
 * bounded below 1 MiB even at this limit. */
#define IOS_STUCK_HISTORY_MAX_THREADS 4096u

struct ios_stuck_entry
{
    uint64_t tid, pc, ea, seen_ms, sys_us, user_us;
    unsigned hits;
};
struct ios_stuck_table
{
    struct ios_stuck_entry *entries;
    size_t capacity, count;
};
struct ios_stuck_history
{
    struct ios_stuck_table tables[2];
    size_t limit;
    unsigned current, active;
};

static void ios_stuck_history_reset(struct ios_stuck_history *history)
{
    history->tables[0].count = history->tables[1].count = 0;
    history->active = 0;
}

static size_t ios_stuck_history_bucket(uint64_t tid, size_t capacity)
{
    /* The key is THREAD_IDENTIFIER_INFO.thread_id, not a recyclable Mach
     * port name, Windows TID, TEB address or position in task_threads(). */
    tid ^= tid >> 33;
    tid *= UINT64_C(0xff51afd7ed558ccd);
    tid ^= tid >> 33;
    return (size_t)tid & (capacity - 1);
}

static struct ios_stuck_entry *ios_stuck_history_find(struct ios_stuck_table *table,
                                                      uint64_t tid)
{
    size_t index, scanned;
    if (!tid || !table->count) return NULL;
    index = ios_stuck_history_bucket(tid, table->capacity);
    for (scanned = 0; scanned < table->capacity; ++scanned)
    {
        struct ios_stuck_entry *entry = table->entries + index;
        if (entry->tid == tid) return entry;
        if (!entry->tid) return NULL;
        index = (index + 1) & (table->capacity - 1);
    }
    return NULL;
}

static int ios_stuck_history_begin(struct ios_stuck_history *history, size_t threads)
{
    struct ios_stuck_table *next = history->tables + (history->current ^ 1);
    size_t capacity = 8;
    if (history->active || threads > IOS_STUCK_HISTORY_MAX_THREADS)
    {
        ios_stuck_history_reset(history);
        return 0;
    }
    while (capacity < threads * 2) capacity *= 2;
    if (next->capacity < capacity)
    {
        struct ios_stuck_entry *entries = IOS_STUCK_HISTORY_CALLOC(capacity, sizeof(*entries));
        if (!entries)
        {
            /* No stale PC/EA may survive a pass whose coverage was lost. */
            ios_stuck_history_reset(history);
            return 0;
        }
        IOS_STUCK_HISTORY_FREE(next->entries);
        next->entries = entries;
        next->capacity = capacity;
    }
    else memset(next->entries, 0, next->capacity * sizeof(*next->entries));
    next->count = 0;
    history->limit = threads;
    history->active = 1;
    return 1;
}

/* Wall timestamps are milliseconds; CPU counters/deltas are microseconds.
 * The caller pairs user_us with the same native CPU sample as sys_us.
 * Return this pass's owned entry and its valid elapsed counters. A new native
 * identity, duplicate enumeration, zero interval or regressing counter cannot
 * qualify a store. The caller keeps the existing CPU gate and PC/EA checks. */
static struct ios_stuck_entry *ios_stuck_history_observe(struct ios_stuck_history *history,
    uint64_t tid, uint64_t now, uint64_t sys, uint64_t *dt, uint64_t *dsys)
{
    struct ios_stuck_table *previous = history->tables + history->current;
    struct ios_stuck_table *next = history->tables + (history->current ^ 1);
    struct ios_stuck_entry *old, *entry;
    size_t index;
    *dt = *dsys = 0;
    if (!history->active || !tid || next->count >= history->limit ||
        ios_stuck_history_find(next, tid)) return NULL;
    index = ios_stuck_history_bucket(tid, next->capacity);
    while (next->entries[index].tid) index = (index + 1) & (next->capacity - 1);
    entry = next->entries + index;
    old = ios_stuck_history_find(previous, tid);
    if (old) *entry = *old;
    else *entry = (struct ios_stuck_entry){0};
    entry->tid = tid;
    ++next->count;
    if (old && now > old->seen_ms && sys >= old->sys_us)
    {
        *dt = now - old->seen_ms;
        *dsys = sys - old->sys_us;
    }
    else entry->pc = entry->ea = entry->hits = 0;
    entry->seen_ms = now;
    entry->sys_us = sys;
    return entry;
}

static void ios_stuck_history_end(struct ios_stuck_history *history)
{
    if (history->active)
    {
        history->current ^= 1;
        history->active = 0;
    }
}

static inline void ios_stuck_history_destroy(struct ios_stuck_history *history)
{
    IOS_STUCK_HISTORY_FREE(history->tables[0].entries);
    IOS_STUCK_HISTORY_FREE(history->tables[1].entries);
    *history = (struct ios_stuck_history){0};
}
#endif
