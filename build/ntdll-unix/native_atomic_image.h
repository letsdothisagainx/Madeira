/* Madeira native-image lowering. Run only on an unpublished, private pool copy.
 * Guest PE/JIT code is never passed here. The planner changes only a proven
 * transient address producer; atomics, values, flags and ordering stay intact.
 */
#ifndef MADEIRA_NATIVE_ATOMIC_IMAGE_H
#define MADEIRA_NATIVE_ATOMIC_IMAGE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "native_atomic_alias.h"

struct ios_native_atomic_image_stats { size_t planned, lse, exclusive, ranges; };
static uint16_t ios_native_u16(const unsigned char *p) { uint16_t n; memcpy(&n,p,2); return n; }
static uint32_t ios_native_u32(const unsigned char *p) { uint32_t n; memcpy(&n,p,4); return n; }
static uint64_t ios_native_u64(const unsigned char *p) { uint64_t n; memcpy(&n,p,8); return n; }
static int ios_native_span(size_t at, size_t n, size_t size) { return at <= size && n <= size-at; }

/* The original (unrelocated) header, copied header, and pool image may each
 * supply the CHPE pointer, depending on whether Wine has applied DIR64 yet. */
static size_t ios_native_meta_rva(uint64_t pointer, uint64_t preferred,
                                uintptr_t source, uintptr_t rx, uintptr_t rw, size_t size)
{
    const uint64_t bases[4] = { preferred, source, rx, rw };
    unsigned i;
    for (i=0;i<4;i++) if (pointer>=bases[i] && pointer-bases[i]<size) return (size_t)(pointer-bases[i]);
    return size;
}

struct ios_native_atomic_data_bounds {
    uintptr_t rx;
    intptr_t delta;
    size_t size;
    const unsigned char *sections;
    unsigned section_count;
};
static int ios_native_atomic_data_allowed(void *context, uintptr_t rx, uintptr_t rw, size_t bytes)
{
    const struct ios_native_atomic_data_bounds *b=context;
    size_t offset;
    unsigned i;
    if (!bytes || rx<b->rx || rx-b->rx>b->size || bytes>b->size-(rx-b->rx) ||
        (rx & (bytes-1)) || rw!=rx+(uintptr_t)b->delta) return 0;
    offset=rx-b->rx;
    for (i=0;i<b->section_count;i++)
    {
        const unsigned char *s=b->sections+i*40;
        size_t a=ios_native_u32(s+12), n=ios_native_u32(s+8);
        uint32_t flags=ios_native_u32(s+36);
        if (!n) n=ios_native_u32(s+16);
        if ((flags & 0xa2000000u)==0x80000000u && offset>=a &&
            offset-a<=n && bytes<=n-(offset-a)) return 1;
    }
    return 0;
}

static void ios_native_atomic_range(unsigned char *image, size_t image_size,
                                    uintptr_t rx, intptr_t delta, size_t start, size_t bytes,
                                    const unsigned char *sections, unsigned section_count,
                                    struct ios_native_atomic_image_stats *stats)
{
    struct ios_native_atomic_data_bounds bounds={rx,delta,image_size,sections,section_count};
    size_t i, count=bytes/4;
    uint32_t *words;
    if ((start & 3) || (bytes & 3) || !bytes || !ios_native_span(start,bytes,image_size)) return;
    words=(uint32_t *)(image+start);
    stats->ranges++;
    for (i=0;i<count;i++)
    {
        struct madeira_native_atomic_alias_plan plan;
        if ((words[i]&0x9f000000u)!=0x90000000u) continue;
        if (!madeira_native_atomic_alias_plan(words,count,rx+start,delta,i,
                                              ios_native_atomic_data_allowed,&bounds,&plan)) continue;
        /* The planner returns exactly one immutable producer rewrite. None of
         * the original memory instructions or their retry branches change. */
        if (plan.producer_index!=i || plan.original!=words[i] ||
            plan.consumer_index>=count) continue;
        words[i]=plan.replacement;
        stats->planned++;
        if (plan.kind==MADEIRA_NATIVE_ATOMIC_ALIAS_EXCLUSIVE) stats->exclusive++;
        else stats->lse++;
    }
}

static struct ios_native_atomic_image_stats ios_native_atomic_image_lower(
    unsigned char *image, size_t image_size, uintptr_t rx, uintptr_t source, intptr_t delta)
{
    struct ios_native_atomic_image_stats stats = {0};
    size_t pe, opt, section_at, meta, map_at, count, i;
    unsigned machine, section_count, opt_size;
    uint64_t preferred, pointer;
    if (!image || delta <= 0 || (delta & 0xfff) || !rx || (rx & 3) ||
        image_size<0x40 || image[0]!='M' || image[1]!='Z' ||
        rx>UINTPTR_MAX-image_size || (uintptr_t)delta>UINTPTR_MAX-rx-image_size) return stats;
    pe=ios_native_u32(image+0x3c);
    if (!ios_native_span(pe,24,image_size) || memcmp(image+pe,"PE\0\0",4)) return stats;
    machine=ios_native_u16(image+pe+4); section_count=ios_native_u16(image+pe+6);
    opt_size=ios_native_u16(image+pe+20); opt=pe+24;
    if (!section_count || section_count>96 || opt_size<0x70 ||
        !ios_native_span(opt,opt_size,image_size) || ios_native_u16(image+opt)!=0x20b ||
        ios_native_u32(image+opt+56)!=image_size) return stats;
    section_at=opt+opt_size;
    if (!ios_native_span(section_at,40u*section_count,image_size)) return stats;
    /* Validate ALL section extents before making any change. Overlapping
     * writable/executable ownership is ineligible, not a reason to broaden it. */
    for (i=0;i<section_count;i++)
    {
        const unsigned char *s=image+section_at+40*i;
        size_t a=ios_native_u32(s+12), n=ios_native_u32(s+8), j;
        if (!n) n=ios_native_u32(s+16);
        if (!ios_native_span(a,n,image_size)) return stats;
        for (j=0;j<i;j++)
        {
            const unsigned char *t=image+section_at+40*j;
            size_t b=ios_native_u32(t+12), m=ios_native_u32(t+8);
            if (!m) m=ios_native_u32(t+16);
            if (n && m && a<b+m && b<a+n) return stats;
        }
    }
    if (machine==0xaa64)
    {
        for (i=0;i<section_count;i++)
        {
            const unsigned char *s=image+section_at+40*i;
            size_t a=ios_native_u32(s+12), n=ios_native_u32(s+8);
            if (!n) n=ios_native_u32(s+16);
            if ((ios_native_u32(s+36)&0xa0000000u)==0x20000000u)
                ios_native_atomic_range(image,image_size,rx,delta,a,n,image+section_at,section_count,&stats);
        }
        return stats;
    }
    /* ARM64EC uses AMD64 machine ID. NEVER scan x64 thunks as ARM64. */
    if ((machine!=0x8664 && machine!=0xa641) || opt_size<0x70+11*8 ||
        ios_native_u32(image+opt+108)<11) return stats;
    map_at=ios_native_u32(image+opt+0x70+10*8);
    count=ios_native_u32(image+opt+0x70+10*8+4);
    if (count<0xd0 || !ios_native_span(map_at,count,image_size)) return stats;
    pointer=ios_native_u64(image+map_at+0xc8); preferred=ios_native_u64(image+opt+24);
    meta=ios_native_meta_rva(pointer,preferred,source,rx,(uintptr_t)(rx+delta),image_size);
    if (!ios_native_span(meta,12,image_size)) return stats;
    map_at=ios_native_u32(image+meta+4); count=ios_native_u32(image+meta+8);
    if (!count || count>image_size/8 || !ios_native_span(map_at,count*8,image_size)) return stats;
    /* Complete metadata validation precedes ALL mutation. CodeMap is an
     * ordered partition; reject overlaps, wrapping and unknown range kinds. */
    {
        size_t previous_end=0;
        for (i=0;i<count;i++)
        {
            uint32_t entry=ios_native_u32(image+map_at+i*8);
            size_t a=entry&~3u, n=ios_native_u32(image+map_at+i*8+4);
            if ((entry&3)>2 || !n || !ios_native_span(a,n,image_size) ||
                ((entry&3)<=1 && (n&3)) || (i && a<previous_end)) return stats;
            previous_end=a+n;
        }
    }
    for (i=0;i<count;i++)
    {
        uint32_t entry=ios_native_u32(image+map_at+i*8);
        size_t a=entry&~3u, n=ios_native_u32(image+map_at+i*8+4), j;
        int executable=0;
        if ((entry&3)>1 || !n || (a&3) || (n&3)) continue;
        for (j=0;j<section_count;j++)
        {
            const unsigned char *s=image+section_at+40*j;
            size_t lo=ios_native_u32(s+12), len=ios_native_u32(s+8);
            if (!len) len=ios_native_u32(s+16);
            if ((ios_native_u32(s+36)&0xa0000000u)==0x20000000u &&
                a>=lo && a-lo<=len && n<=len-(a-lo)) executable=1;
        }
        if (executable) ios_native_atomic_range(image,image_size,rx,delta,a,n,image+section_at,section_count,&stats);
    }
    return stats;
}
#endif
