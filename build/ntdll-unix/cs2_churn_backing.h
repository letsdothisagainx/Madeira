/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Allocation policy, not a sampler: virtual_mutex serializes every operation.
 * Learn from completed whole private-view lifetimes; never migrate live bytes.
 * The live bitmap keeps the full anonymous cost charged through decommit and
 * partial view splits, until successful native unmapping proves it is gone.
 */
#ifndef MADEIRA_CS2_CHURN_BACKING_H
#define MADEIRA_CS2_CHURN_BACKING_H
#include <stdint.h>
#include <string.h>

#define MD_CHURN_CLASSES 64
#define MD_CHURN_VIEWS 512
#define MD_CHURN_PAGE 16384u
#define MD_CHURN_MIN (256u << 10)
#define MD_CHURN_MAX (4u << 20)
#define MD_CHURN_CAP (UINT64_C(32) << 20)
#define MD_CHURN_YOUNG_NS UINT64_C(3000000000)

struct md_churn_class {
    uintptr_t owner;
    uint64_t lease, bytes, allocations, young;
};
struct md_churn_view {
    uintptr_t base;
    uint64_t bytes, generation, born, pages[4];
    unsigned class_index, charged, learned;
};
static struct md_churn_class md_churn_classes[MD_CHURN_CLASSES];
static struct md_churn_view md_churn_views[MD_CHURN_VIEWS];
struct md_churn_counters {
    uint64_t tracked, hot, bypasses, bytes, held, peak, cap_denied,
             pressure_denied, tracking_denied, retired, query_ns, queries, budget_unavailable,
             active, learning_evicted;
};
static struct md_churn_counters md_churn_stats;
#define MD_CHURN_ADD(field,n) __atomic_add_fetch(&md_churn_stats.field,(uint64_t)(n),__ATOMIC_RELAXED)
#define MD_CHURN_GET(field) __atomic_load_n(&md_churn_stats.field,__ATOMIC_RELAXED)

static int md_churn_hot(const struct md_churn_view *v)
{
    const struct md_churn_class *c = &md_churn_classes[v->class_index];
    return c->young >= 8 && c->young >= (c->allocations + 1) / 2;
}

/* Called once for an eligible fresh, whole, host-aligned private commit.
 * Uncharged old learning records may rotate; charged records never do. A full
 * charged table or overlapping lifetime fails closed to the file policy.
 */
static struct md_churn_view *md_churn_begin(uintptr_t owner, uint64_t lease,
    uint64_t generation, uintptr_t base, uint64_t bytes, uint64_t now)
{
    unsigned i, ci = MD_CHURN_CLASSES, free_ci = MD_CHURN_CLASSES, vi = MD_CHURN_VIEWS, evict = MD_CHURN_VIEWS;
    struct md_churn_view *v;
    if (!owner || !lease || !generation || !now || bytes < MD_CHURN_MIN || bytes > MD_CHURN_MAX ||
        (base & (MD_CHURN_PAGE - 1)) || (bytes & (MD_CHURN_PAGE - 1)) ||
        base > UINTPTR_MAX - bytes) return NULL;
    for (i = 0; i < MD_CHURN_VIEWS; ++i) {
        v = &md_churn_views[i];
        if (!v->bytes) { if (vi == MD_CHURN_VIEWS) vi = i; continue; }
        if (base < v->base + v->bytes && v->base < base + bytes) return NULL;
        if (!v->charged && (evict == MD_CHURN_VIEWS || v->born < md_churn_views[evict].born)) evict = i;
    }
    for (i = 0; i < MD_CHURN_CLASSES; ++i) {
        struct md_churn_class *c = &md_churn_classes[i];
        if (!c->owner) { if (free_ci == MD_CHURN_CLASSES) free_ci = i; continue; }
        if (c->owner == owner && c->lease == lease && c->bytes == bytes) { ci = i; break; }
    }
    if (ci == MD_CHURN_CLASSES) ci = free_ci;
    if (ci == MD_CHURN_CLASSES || (vi == MD_CHURN_VIEWS && evict == MD_CHURN_VIEWS)) {
        MD_CHURN_ADD(tracking_denied,1); return NULL;
    }
    if (vi == MD_CHURN_VIEWS) {
        /* This is only an uncharged learning observation. Its real file
         * ownership remains in the backing ledger. Never evict a charged
         * commitment, and never count an unknown lifetime as a young death. */
        vi = evict; MD_CHURN_ADD(learning_evicted,1);
    } else MD_CHURN_ADD(active,1);
    struct md_churn_class *c = &md_churn_classes[ci];
    c->owner = owner; c->lease = lease; c->bytes = bytes;
    ++c->allocations;
    v = &md_churn_views[vi];
    memset(v,0,sizeof(*v));
    v->base = base; v->bytes = bytes; v->generation = generation; v->born = now; v->class_index = ci;
    for (i = 0; i < bytes / MD_CHURN_PAGE; ++i) v->pages[i / 64] |= UINT64_C(1) << (i % 64);
    MD_CHURN_ADD(tracked,1);
    return v;
}

/* No native memory query for cold classes or an exhausted aggregate budget. */
static int md_churn_needs_budget(struct md_churn_view *v)
{
    if (!v || !md_churn_hot(v)) return 0;
    MD_CHURN_ADD(hot,1);
    if (v->bytes > MD_CHURN_CAP - MD_CHURN_GET(held)) { MD_CHURN_ADD(cap_denied,1); return 0; }
    return 1;
}

/* available/floor are fresh native measurements, not diagnostic snapshots.
 * Retain TWO existing safety floors plus the entire outstanding committed
 * charge and this request. Double counting resident charged pages is deliberate
 * conservatism; no virtual reservation is claimed to be physically resident.
 */
static int md_churn_admit(struct md_churn_view *v, uint64_t available, uint64_t floor)
{
    uint64_t held = MD_CHURN_GET(held), next;
    if (!v || v->charged || !md_churn_hot(v) || v->bytes > MD_CHURN_CAP - held) return 0;
    next = held + v->bytes;
    if (!floor || floor > UINT64_MAX / 2 || next > UINT64_MAX - 2 * floor || available < 2 * floor + next) {
        MD_CHURN_ADD(pressure_denied,1); return 0;
    }
    v->charged = 1;
    v->learned = 1;
    MD_CHURN_ADD(held,v->bytes); MD_CHURN_ADD(bytes,v->bytes); MD_CHURN_ADD(bypasses,1);
    if (next > MD_CHURN_GET(peak)) __atomic_store_n(&md_churn_stats.peak,next,__ATOMIC_RELAXED);
    return 1;
}

/* A successful native unmap/PROT_NONE replacement, not guest decommit, is
 * the receipt. Partial releases clear only whole host pages actually removed.
 * Failed native operations and process quarantine never call this function.
 */
static void md_churn_unmapped(uintptr_t base, uint64_t bytes, uint64_t now)
{
    unsigned i, p;
    if (!bytes || base > UINTPTR_MAX - bytes) return;
    for (i = 0; i < MD_CHURN_VIEWS; ++i) {
        struct md_churn_view *v = &md_churn_views[i];
        uintptr_t lo, hi;
        uint64_t removed = 0;
        if (!v->bytes || base >= v->base + v->bytes || v->base >= base + bytes) continue;
        lo = base > v->base ? base : v->base;
        hi = base + bytes < v->base + v->bytes ? base + bytes : v->base + v->bytes;
        lo = (lo + MD_CHURN_PAGE - 1) & ~(uintptr_t)(MD_CHURN_PAGE - 1);
        hi &= ~(uintptr_t)(MD_CHURN_PAGE - 1);
        for (p = (unsigned)((lo - v->base) / MD_CHURN_PAGE); lo < hi; ++p, lo += MD_CHURN_PAGE) {
            uint64_t bit = UINT64_C(1) << (p % 64);
            if (v->pages[p / 64] & bit) { v->pages[p / 64] &= ~bit; removed += MD_CHURN_PAGE; }
        }
        if (v->charged && removed) __atomic_sub_fetch(&md_churn_stats.held,removed,__ATOMIC_RELAXED);
        if (!(v->pages[0] | v->pages[1] | v->pages[2] | v->pages[3])) {
            if (v->learned && now >= v->born && now - v->born < MD_CHURN_YOUNG_NS)
                ++md_churn_classes[v->class_index].young;
            MD_CHURN_ADD(retired,1);
            __atomic_sub_fetch(&md_churn_stats.active,1,__ATOMIC_RELAXED);
            memset(v,0,sizeof(*v));
        }
    }
}

/* Avoid adding the old payload-reading zero probe to a bypassed commit or
 * decommit. It is zero by the unchanged anonymous-map producer, like a fresh
 * file hole; this function never reads or changes guest bytes. */
static int md_churn_charged_range(uintptr_t base, uint64_t bytes, uint64_t generation)
{
    unsigned i;
    if (base > UINTPTR_MAX - bytes) return 0;
    for (i = 0; i < MD_CHURN_VIEWS; ++i) {
        const struct md_churn_view *v = &md_churn_views[i];
        if (v->bytes && v->charged && v->generation == generation && base >= v->base &&
            bytes <= v->bytes && base - v->base <= v->bytes - bytes) {
            unsigned first=(unsigned)((base-v->base)/MD_CHURN_PAGE);
            unsigned end=(unsigned)((base-v->base+bytes+MD_CHURN_PAGE-1)/MD_CHURN_PAGE),p;
            for(p=first;p<end;++p)if(!(v->pages[p/64] & (UINT64_C(1)<<(p%64))))return 0;
            return 1;
        }
    }
    return 0;
}
#endif
