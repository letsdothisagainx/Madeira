/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Diagnostic counters only. These never select addresses, retain reservations,
 * cache an NTSTATUS, or change whether an allocation is attempted. */
#ifndef MADEIRA_VM_FAILURE_TRACE_H
#define MADEIRA_VM_FAILURE_TRACE_H

#include <stdint.h>
#include <string.h>

#define MADEIRA_VM_FAILURE_KEYS 8
#define MADEIRA_VM_FAILURE_THREAD_DETAILS 16
#define MADEIRA_VM_FAILURE_GLOBAL_DETAILS 128

struct madeira_vm_failure_key
{
    uint64_t owner, window, generation, size, zero_bits, limit, alignment;
    uint32_t status, type, protect;
};

struct madeira_vm_failure_entry
{
    struct madeira_vm_failure_key key;
    uint64_t matches, first_hint, last_hint, hint_changes;
};

struct madeira_vm_failure_trace
{
    struct madeira_vm_failure_entry entries[MADEIRA_VM_FAILURE_KEYS];
    unsigned next;
    uint64_t total;
    unsigned detail_reports;
};

struct madeira_vm_failure_global
{
    uint64_t total;
    unsigned detail_reports;
};

struct madeira_vm_failure_report
{
    uint64_t thread_total, global_total;
    unsigned detail, aggregate;
};

/* After the initial records, logarithmic sampling has a fixed upper bound for
 * a uint64_t counter. Unlike a modulo sample it cannot flood an infinite loop. */
static inline int madeira_vm_count_sample( uint64_t count, unsigned initial )
{
    return count && (count <= initial || !(count & (count - 1)));
}

static inline int madeira_vm_failure_key_equal( const struct madeira_vm_failure_key *a,
                                                const struct madeira_vm_failure_key *b )
{
    return a->owner == b->owner && a->window == b->window && a->generation == b->generation &&
           a->size == b->size && a->zero_bits == b->zero_bits && a->limit == b->limit &&
           a->alignment == b->alignment && a->status == b->status && a->type == b->type &&
           a->protect == b->protect;
}

/* One instance belongs to one native thread. A bounded table permits interleaved
 * request shapes. "matches" is cumulative matching failures, not a claim that
 * these calls came from one guest operation. Hint addresses are observations;
 * every original request must still run against the current VAD tree. */
static inline struct madeira_vm_failure_entry *madeira_vm_failure_note(
    struct madeira_vm_failure_trace *trace, const struct madeira_vm_failure_key *key, uint64_t hint )
{
    struct madeira_vm_failure_entry *entry = 0;
    unsigned i;
    if (trace->total != UINT64_MAX) trace->total++;
    for (i = 0; i < MADEIRA_VM_FAILURE_KEYS; i++)
    {
        if (!trace->entries[i].matches) continue;
        if (madeira_vm_failure_key_equal( &trace->entries[i].key, key ))
        {
            entry = &trace->entries[i];
            break;
        }
    }
    if (!entry)
    {
        entry = &trace->entries[trace->next];
        trace->next = (trace->next + 1) % MADEIRA_VM_FAILURE_KEYS;
        memset( entry, 0, sizeof(*entry) );
        entry->key = *key;
        entry->first_hint = hint;
    }
    if (entry->matches && entry->last_hint != hint && entry->hint_changes != UINT64_MAX)
        entry->hint_changes++;
    entry->last_hint = hint;
    if (entry->matches != UINT64_MAX) entry->matches++;
    return entry;
}

/* Call exactly once after note(), even when a signature is not sampled. The
 * table can evict signatures; its bounded size alone does NOT bound output:
 * nine cyclic keys would all have matches=1. Independent thread/global detail
 * budgets close that hole. Overall failures keep counting after either budget
 * is used, with at most 64 additional power-of-two aggregate records globally.
 * If both flags are set, print one detail record containing the total counts.
 * This state is diagnostics only and must never gate an allocation attempt. */
static inline struct madeira_vm_failure_report madeira_vm_failure_gate(
    struct madeira_vm_failure_trace *trace, const struct madeira_vm_failure_entry *entry,
    struct madeira_vm_failure_global *global )
{
    struct madeira_vm_failure_report report = { .thread_total = trace->total };
    uint64_t before = __atomic_load_n( &global->total, __ATOMIC_RELAXED );
    unsigned details;
    while (before != UINT64_MAX &&
           !__atomic_compare_exchange_n( &global->total, &before, before + 1, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED )) {}
    report.global_total = before == UINT64_MAX ? before : before + 1;
    report.aggregate = before != UINT64_MAX && madeira_vm_count_sample( report.global_total, 0 );
    if (trace->detail_reports >= MADEIRA_VM_FAILURE_THREAD_DETAILS ||
        !madeira_vm_count_sample( entry->matches, 4 )) return report;
    details = __atomic_load_n( &global->detail_reports, __ATOMIC_RELAXED );
    while (details < MADEIRA_VM_FAILURE_GLOBAL_DETAILS)
    {
        if (__atomic_compare_exchange_n( &global->detail_reports, &details, details + 1, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
        {
            trace->detail_reports++;
            report.detail = 1;
            break;
        }
    }
    return report;
}

#endif
