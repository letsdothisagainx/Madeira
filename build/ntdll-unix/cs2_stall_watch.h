/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded, passive identities for the Run13 evidence gap. No guest addresses
 * are guessed, no native thread rights are retained, and nothing here changes
 * scheduling, suspension counts, memory protection or store completion. */
#ifndef MADEIRA_CS2_STALL_WATCH_H
#define MADEIRA_CS2_STALL_WATCH_H
#include <stdint.h>
#include <pthread.h>

#define IOS_CS2_STALL_PROCESSES 4
#define IOS_CS2_STALL_WORKERS 2
#define IOS_CS2_STALL_SAMPLES 1200
struct ios_cs2_stall_target
{
    uint64_t native_id, teb;
    unsigned tid;
};
struct ios_cs2_stall_watch
{
    uint64_t owner, lease;
    unsigned pid;
    struct ios_cs2_stall_target main, worker[IOS_CS2_STALL_WORKERS];
};
static struct ios_cs2_stall_watch ios_cs2_stall_watches[IOS_CS2_STALL_PROCESSES];
static pthread_mutex_t ios_cs2_stall_mutex = PTHREAD_MUTEX_INITIALIZER;

/* All identity fields are immutable after publishing the native ID/owner.
 * Slots are never recycled. Native thread IDs, unlike port names and TEBs,
 * identify a single native lifetime. The native adapter also rechecks the
 * process lease before observing; termination is a missed sample. */
static struct ios_cs2_stall_watch *ios_cs2_stall_find(uint64_t owner, unsigned pid, uint64_t lease)
{
    unsigned i;
    for (i = 0; i < IOS_CS2_STALL_PROCESSES; ++i)
        if (__atomic_load_n(&ios_cs2_stall_watches[i].owner, __ATOMIC_ACQUIRE) == owner && owner &&
            ios_cs2_stall_watches[i].pid == pid && ios_cs2_stall_watches[i].lease == lease)
            return ios_cs2_stall_watches + i;
    return 0;
}

static void ios_cs2_stall_register_main(uint64_t owner, unsigned pid, uint64_t lease,
                                      unsigned tid, uint64_t teb, uint64_t native_id)
{
    unsigned i;
    if (!owner || !pid || !lease || !tid || !teb || !native_id ||
        pthread_mutex_trylock(&ios_cs2_stall_mutex)) return;
    if (!ios_cs2_stall_find(owner, pid, lease))
        for (i = 0; i < IOS_CS2_STALL_PROCESSES; ++i)
            if (!ios_cs2_stall_watches[i].owner)
            {
                struct ios_cs2_stall_watch *watch = ios_cs2_stall_watches + i;
                watch->pid = pid; watch->lease = lease;
                watch->main = (struct ios_cs2_stall_target){native_id, teb, tid};
                __atomic_store_n(&watch->owner, owner, __ATOMIC_RELEASE);
                break;
            }
    pthread_mutex_unlock(&ios_cs2_stall_mutex);
}

/* Called only after an existing CS2 copy-loop capture has been validated and
 * its sampler-owned suspension balanced. No new worker discovery scan. */
static void ios_cs2_stall_register_worker(uint64_t owner, unsigned pid, uint64_t lease,
                                        unsigned tid, uint64_t teb, uint64_t native_id)
{
    struct ios_cs2_stall_watch *watch;
    unsigned i;
    if (!tid || !teb || !native_id || pthread_mutex_trylock(&ios_cs2_stall_mutex)) return;
    watch = ios_cs2_stall_find(owner, pid, lease);
    if (watch && watch->main.native_id != native_id)
    {
        for (i = 0; i < IOS_CS2_STALL_WORKERS; ++i)
        {
            if (watch->worker[i].native_id == native_id) break;
            if (!watch->worker[i].native_id)
            {
                watch->worker[i].tid = tid; watch->worker[i].teb = teb;
                __atomic_store_n(&watch->worker[i].native_id, native_id, __ATOMIC_RELEASE);
                break;
            }
        }
    }
    pthread_mutex_unlock(&ios_cs2_stall_mutex);
}

static struct ios_cs2_stall_watch *ios_cs2_stall_for_native(uint64_t native_id, int main_only,
                                                          unsigned *slot)
{
    unsigned i, j;
    if (!native_id) return 0;
    for (i = 0; i < IOS_CS2_STALL_PROCESSES; ++i)
    {
        struct ios_cs2_stall_watch *watch = ios_cs2_stall_watches + i;
        if (!__atomic_load_n(&watch->owner, __ATOMIC_ACQUIRE)) continue;
        if (watch->main.native_id == native_id) { *slot = i * 3; return watch; }
        if (!main_only)
            for (j = 0; j < IOS_CS2_STALL_WORKERS; ++j)
                if (__atomic_load_n(&watch->worker[j].native_id, __ATOMIC_ACQUIRE) == native_id)
                { *slot = i * 3 + j + 1; return watch; }
    }
    return 0;
}

struct ios_cs2_stall_rate { uint64_t next_us; unsigned samples; };
static int ios_cs2_stall_due(struct ios_cs2_stall_rate *rate, uint64_t now_us)
{
    if (now_us < rate->next_us) return 0;
    rate->next_us = now_us > UINT64_MAX - 1000000 ? UINT64_MAX : now_us + 1000000;
    ++rate->samples;
    return 1;
}
#endif
