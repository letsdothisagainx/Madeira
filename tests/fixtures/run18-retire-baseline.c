static uint64_t ios_swap_take( size_t len )
{
    unsigned i, best = ~0u;
    for (i = 0; i < ios_swap_nfree; i++)
        if (ios_swap_free[i].len >= len && (best == ~0u || ios_swap_free[i].len < ios_swap_free[best].len)) best = i;
    if (best != ~0u)
    {
        uint64_t off = ios_swap_free[best].off;
        if (ios_swap_free[best].len > len) { ios_swap_free[best].off += len; ios_swap_free[best].len -= len; }
        else ios_swap_free[best] = ios_swap_free[--ios_swap_nfree];
        return off;
    }
    if (ios_swap_bump + len > ios_swap_logical) return (uint64_t)-1;
    ios_swap_bump += len;
    return ios_swap_bump - len;
}

static void ios_swap_free_add( uint64_t off, uint64_t len )
{
    unsigned i;
    int merged = 1;
    if (!ios_swap_v2)
    {
        if (ios_swap_nfree < 8192) { ios_swap_free[ios_swap_nfree].off = off; ios_swap_free[ios_swap_nfree].len = len; ios_swap_nfree++; }
        return;
    }
    while (merged)
    {
        merged = 0;
        for (i = 0; i < ios_swap_nfree; i++)
        {
            if (ios_swap_free[i].off + ios_swap_free[i].len == off) off = ios_swap_free[i].off;
            else if (off + len != ios_swap_free[i].off) continue;
            len += ios_swap_free[i].len;
            ios_swap_free[i] = ios_swap_free[--ios_swap_nfree];
            ios_swap_merges++;
            merged = 1;
            break;
        }
    }
    if (off + len == ios_swap_bump) { ios_swap_bump = off; ios_swap_bump_back++; return; }
    if (ios_swap_nfree < 8192) { ios_swap_free[ios_swap_nfree].off = off; ios_swap_free[ios_swap_nfree].len = len; ios_swap_nfree++; }
    else ios_swap_free_drop++;   /* leaked offset space: later backings may be refused, never wrong */
}

static void ios_swap_give( uint64_t off, size_t len )
{
    struct fpunchhole ph;
    if (ios_swap_punch_defer( off, len )) return;   /* ml1291: punched and freed off the virtual lock */
    memset( &ph, 0, sizeof(ph) );
    ph.fp_offset = (off_t)off; ph.fp_length = (off_t)len;
    if (fcntl( ios_swap_fd, F_PUNCHHOLE, &ph ))
    {
        static int said;
        if (said++ < 8) dprintf( 2, "[swap] ml1077 F_PUNCHHOLE off=%llu len=%zu failed errno=%d (range not reused, ml1297)\n", (unsigned long long)off, len, errno );
        ios_swap_punch_leaks++;
        return;
    }
    ios_swap_free_add( off, len );
}

static void ios_swap_release_range( void *base, size_t size, int copy_back )
{
    char *lo = (char *)base, *hi = (char *)base + size;
    unsigned i = 0;
    unsigned long long releases_before = ios_swap_releases;
    uint64_t noted_born = 0;   /* ml1258: pieces of one split extent are one death */
    if (ios_swap_fd < 0 || !ios_swap_n) return;
    __atomic_add_fetch(&ios_ev_vm_generation,1,__ATOMIC_RELEASE);
    if (copy_back)
    {
        lo = (char *)((uintptr_t)lo & ~(uintptr_t)host_page_mask);
        hi = (char *)(((uintptr_t)hi + host_page_mask) & ~(uintptr_t)host_page_mask);
    }
    while (i < ios_swap_n)
    {
        char *a = ios_swap_ext[i].va, *b = a + ios_swap_ext[i].len;
        char *oa = a > lo ? a : lo, *ob = b < hi ? b : hi;
        if (oa >= ob) { i++; continue; }
        {
            uint64_t ooff = ios_swap_ext[i].off + (oa - a);
            size_t olen = ob - oa;
            if (copy_back)
            {
                size_t copied;
                /* An interior start needs a ledger slot for its suffix if a
                 * later chunk fails. Refuse before touching unrecordable backing. */
                if (oa > a && ios_swap_n == 16384) { i++; continue; }
                copied = ios_swap_copyback( oa, olen );
                if (copied != olen)
                {
                    static int said;
                    if (said++ < 8)
                        dprintf( 2, "[swap] copy-back of %p+0x%zx: moved 0x%zx, suffix stays file-backed errno=%d\n",
                                 oa, olen, copied, errno );
                    if (!copied) { i++; continue; }
                    olen = copied;
                    ob = oa + copied;
                }
                ios_swap_unbacks++;
            }
            /* ml1293: the range's contents are dead (decommit/release), but its dirty pages would
             * still be written to the file by the pageout daemon -- I/O that slowed every other
             * fault on the file and the punch behind it. Discard them first: no writeback. */
            if (!copy_back) ios_ev_discard( oa, olen, MS_KILLPAGES );
            ios_swap_give( ooff, olen );
            ios_swap_bytes -= olen;
            if (ios_swap_ext[i].img) ios_swap_img_bytes -= olen;   /* madeira-bcd swap-images */
            ios_swap_releases++;
            /* trim the extent: up to two remaining pieces */
            if (oa == a && ob == b)
            {
                if (!copy_back && ios_swap_broad && ios_swap_ext[i].born != noted_born)   /* ml1258: freed whole; how long did it live? */
                {
                    uint64_t lived = ios_swap_now_ns() - ios_swap_ext[i].born;
                    noted_born = ios_swap_ext[i].born;
                    if (lived < IOS_SWAP_CHURN_NS) ios_swap_churn_note( ios_swap_ext[i].key, lived );
                }
                ios_swap_ext[i] = ios_swap_ext[--ios_swap_n];
                continue;
            }
            if (oa == a) { ios_swap_ext[i].va = ob; ios_swap_ext[i].off += olen; ios_swap_ext[i].len -= olen; i++; continue; }
            if (ob == b) { ios_swap_ext[i].len = oa - a; i++; continue; }
            if (ios_swap_n < 16384)
            {
                ios_swap_ext[ios_swap_n] = ios_swap_ext[i];   /* resv, key, born carry over */
                ios_swap_ext[ios_swap_n].va = ob; ios_swap_ext[ios_swap_n].off = ios_swap_ext[i].off + (ob - a);
                ios_swap_ext[ios_swap_n].len = b - ob; ios_swap_n++;
            }
            ios_swap_ext[i].len = oa - a; i++;
        }
    }
    if (ios_swap_releases != releases_before && (ios_swap_releases <= 16 || (ios_swap_releases % 64) == 0))
        dprintf( 2, "[swap] ml1077 released %p+0x%zx%s: %llu MB in %u extents, %llu releases, %llu unbacks\n",
                 base, size, copy_back ? " (copied back to anonymous)" : "", ios_swap_bytes >> 20, ios_swap_n, ios_swap_releases, ios_swap_unbacks );
}

static int ios_swap_punch_resv( char *lo, size_t len )
{
    char *hi;
    size_t covered = 0;
    unsigned i, parts = 0, extra = 0, original_n = ios_swap_n;
    uint64_t fresh;
    struct ios_swap_extent merged = {0};
    int same_metadata = 1;
    if (ios_swap_fd < 0 || !ios_swap_n) return 0;
    if (!len || ((uintptr_t)lo & host_page_mask) || (len & host_page_mask) ||
        len > UINTPTR_MAX - (uintptr_t)lo) return 0;
    hi = lo + len;
    for (i = 0; i < original_n; i++)
    {
        char *a = ios_swap_ext[i].va, *b = a + ios_swap_ext[i].len;
        char *oa = a > lo ? a : lo, *ob = b < hi ? b : hi;
        if (oa >= ob) continue;
        if (!ios_swap_ext[i].resv || ios_swap_ext[i].img) return 0;
        if (!parts) merged = ios_swap_ext[i];
        else if (merged.key != ios_swap_ext[i].key || merged.born != ios_swap_ext[i].born)
            same_metadata = 0;
        covered += ob - oa;
        parts++;
        extra += (oa > a) + (ob < b);
    }
    if (covered != len) return 0;
    __atomic_add_fetch(&ios_ev_vm_generation,1,__ATOMIC_RELEASE);

    if (extra <= 16384 - original_n && ios_swap_punch_room( parts ) &&
        (fresh = ios_swap_take( len )) != (uint64_t)-1)
    {
        /* Only dead full host pages are discarded. Never touch replacement
         * pages: the worker receives old file offsets, not these addresses. */
        if (!ios_ev_discard( lo, len, MS_KILLPAGES ) &&
            ios_ev_swap_map( lo, len, PROT_READ | PROT_WRITE, fresh ) != MAP_FAILED)
        {
            for (i = 0; i < original_n; i++)
            {
                struct ios_swap_extent old = ios_swap_ext[i];
                char *a = old.va, *b = a + old.len;
                char *oa = a > lo ? a : lo, *ob = b < hi ? b : hi;
                size_t dead;
                if (oa >= ob) continue;
                dead = ob - oa;
                if (oa > a)
                {
                    ios_swap_ext[ios_swap_n] = old;
                    ios_swap_ext[ios_swap_n++].len = oa - a;
                }
                if (ob < b)
                {
                    ios_swap_ext[ios_swap_n] = old;
                    ios_swap_ext[ios_swap_n].va = ob;
                    ios_swap_ext[ios_swap_n].off += ob - a;
                    ios_swap_ext[ios_swap_n++].len = b - ob;
                }
                ios_swap_ext[i].va = oa;
                ios_swap_ext[i].len = dead;
                ios_swap_ext[i].off = fresh + (oa - lo);
                ios_swap_ext[i].evidence_id = ++ios_ev_extent_id;
                /* Queue room was reserved by the producer's virtual lock.
                 * If its invariant is ever violated, leak/quarantine the old
                 * offset honestly rather than reusing dirty or live backing. */
                if (!ios_swap_punch_defer( old.off + (oa - a), dead )) ios_swap_punch_leaks++;
            }
            /* Repeated overlapping decommits must not accumulate every old
             * split boundary. A replacement is one contiguous file mapping;
             * coalesce its pieces when their reservation metadata agrees. */
            if (parts > 1 && same_metadata)
            {
                unsigned out = 0;
                for (i = 0; i < ios_swap_n; i++)
                {
                    char *a = ios_swap_ext[i].va, *b = a + ios_swap_ext[i].len;
                    if (a >= lo && b <= hi) continue;
                    ios_swap_ext[out++] = ios_swap_ext[i];
                }
                merged.evidence_id = ++ios_ev_extent_id;
                merged.va = lo; merged.len = len; merged.off = fresh;
                ios_swap_ext[out++] = merged;
                ios_swap_n = out;
            }
            ios_swap_holes++;
            /* The low-frequency native census reads these without the VM
             * lock. Keep its counters atomic; they never govern ownership. */
            {
                unsigned long long remaps = __atomic_add_fetch( &ios_swap_decommit_remaps, 1, __ATOMIC_RELAXED );
                if (remaps <= 8 || !(remaps % 1024))
                    dprintf( 2, "[swap-decommit-remap-v1] bytes=%zu old-parts=%u live-bytes=%llu result=zero-file-backed\n",
                             len, parts, ios_swap_bytes );
            }
            return 1;
        }
        /* Failed discard stays synchronous to avoid retaining old dirty pages
         * alongside a fresh mapping. No writer has used this zeroed offset,
         * and Darwin's failed fixed map leaves the prior mapping intact. */
        ios_swap_free_add( fresh, len );
    }

    __atomic_fetch_add( &ios_swap_decommit_fallbacks, 1, __ATOMIC_RELAXED );
    for (i = 0; i < original_n; i++)
    {
        char *a = ios_swap_ext[i].va, *b = a + ios_swap_ext[i].len;
        char *oa = a > lo ? a : lo, *ob = b < hi ? b : hi;
        if (oa >= ob) continue;
        ios_ev_discard( oa, ob - oa, MS_KILLPAGES );
        if (ios_swap_punch_timed( ios_swap_ext[i].off + (oa - a), ob - oa, "decommit" )) return 0;
    }
    if (mprotect( lo, len, PROT_READ | PROT_WRITE )) return 0;
    if (++ios_swap_holes <= 8 || !(ios_swap_holes % 1024))
        dprintf( 2, "[swap] ml1257 decommit %p+0x%zx punched in place (%llu holes)\n", lo, len, ios_swap_holes );
    return 1;
}
