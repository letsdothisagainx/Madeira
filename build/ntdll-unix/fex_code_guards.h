/* Madeira-owned permanent CodeBuffer guards. Include after the pool globals.
 * Bits are published before protection changes and never cleared. Three
 * bitmap levels give a bounded, lock-free range query for fault handlers. */
#ifndef MADEIRA_FEX_CODE_GUARDS_H
#define MADEIRA_FEX_CODE_GUARDS_H

#include "fex_code_buffer_abi.h"

#define IOS_CODE_GUARD_MAX_POOL (UINT64_C(4) << 30)
#define IOS_CODE_GUARD_WORDS 4096
static uint64_t ios_code_guard_pages[IOS_CODE_GUARD_WORDS];
static uint64_t ios_code_guard_summary[64];
static uint64_t ios_code_guard_root;

static uint64_t ios_code_guard_mask( unsigned first, unsigned last )
{
    return (UINT64_MAX << first) & (UINT64_MAX >> (63 - last));
}

static int ios_code_guard_pages_contain( size_t first, size_t last )
{
    const uint64_t *levels[3] = { ios_code_guard_pages, ios_code_guard_summary, &ios_code_guard_root };
    unsigned level;

    for (level = 0; level < 3; level++)
    {
        size_t lo = first / 64, hi = last / 64;
        uint64_t left = __atomic_load_n( levels[level] + lo, __ATOMIC_ACQUIRE );
        if (lo == hi) return !!(left & ios_code_guard_mask( first % 64, last % 64 ));
        if ((left & (UINT64_MAX << (first % 64))) ||
            (__atomic_load_n( levels[level] + hi, __ATOMIC_ACQUIRE ) &
             (UINT64_MAX >> (63 - last % 64)))) return 1;
        if (hi - lo <= 1) return 0;
        first = lo + 1;
        last = hi - 1;
    }
    return 0;
}

/* An intersection query, not permission to access the rest of the range.
 * Both aliases share page bits. Overflow is refused conservatively. */
int ios_jit_code_guard_contains( uintptr_t addr, size_t size )
{
    uintptr_t bases[2] = { (uintptr_t)ios_jit_rx_base_global, (uintptr_t)ios_jit_rw_base_global };
    uintptr_t end;
    size_t total = ios_jit_pool_size_global;
    unsigned alias;

    if (!size) return 0;
    if (size > UINTPTR_MAX - addr) return 1;
    if (!total || total > IOS_CODE_GUARD_MAX_POOL) return 0;
    end = addr + size;
    for (alias = 0; alias < 2; alias++)
    {
        uintptr_t base = bases[alias], limit, lo, hi;
        if (!base || total > UINTPTR_MAX - base) continue;
        limit = base + total;
        if (addr >= limit || end <= base) continue;
        lo = addr > base ? addr : base;
        hi = end < limit ? end : limit;
        if (ios_code_guard_pages_contain( (lo - base) / MADEIRA_FEX_CODE_GUARD_BYTES,
                                         (hi - base - 1) / MADEIRA_FEX_CODE_GUARD_BYTES )) return 1;
    }
    return 0;
}

static uint64_t ios_code_guard_armed[IOS_CODE_GUARD_WORDS];

/* The caller owns an unpublished, tracked carve. A partial protection failure
 * remains quarantined with these bits set; it is never returned or recycled. */
static int ios_fex_code_guard_arm( size_t off, size_t size )
{
    size_t guard, page, word;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global, rw = (uintptr_t)ios_jit_rw_base_global;

    if (!madeira_fex_code_buffer_class_valid( size ) || !rx || !rw || rx == rw ||
        ((rx | rw) & (MADEIRA_FEX_CODE_GUARD_BYTES - 1)) ||
        ios_jit_pool_size_global > IOS_CODE_GUARD_MAX_POOL ||
        ios_jit_pool_size_global > UINTPTR_MAX - rx || ios_jit_pool_size_global > UINTPTR_MAX - rw ||
        (rx < rw ? ios_jit_pool_size_global > rw - rx : ios_jit_pool_size_global > rx - rw) ||
        off > ios_jit_pool_size_global || size > ios_jit_pool_size_global - off ||
        (off & (MADEIRA_FEX_CODE_GUARD_BYTES - 1)) ||
        off > UINTPTR_MAX - rx || size > UINTPTR_MAX - rx - off ||
        off > UINTPTR_MAX - rw || size > UINTPTR_MAX - rw - off) return 0;
    guard = off + size - MADEIRA_FEX_CODE_GUARD_BYTES;
    page = guard / MADEIRA_FEX_CODE_GUARD_BYTES;
    word = page / 64;
    __atomic_fetch_or( ios_code_guard_pages + word, UINT64_C(1) << (page % 64), __ATOMIC_RELEASE );
    __atomic_fetch_or( ios_code_guard_summary + word / 64, UINT64_C(1) << (word % 64), __ATOMIC_RELEASE );
    __atomic_fetch_or( &ios_code_guard_root, UINT64_C(1) << (word / 64), __ATOMIC_RELEASE );
    if (mach_vm_protect( mach_task_self(), rx + guard, MADEIRA_FEX_CODE_GUARD_BYTES,
                         0, VM_PROT_NONE ) != KERN_SUCCESS) return 0;
    if (mach_vm_protect( mach_task_self(), rw + guard, MADEIRA_FEX_CODE_GUARD_BYTES,
                         0, VM_PROT_NONE ) != KERN_SUCCESS) return 0;
    __atomic_fetch_or( ios_code_guard_armed + word, UINT64_C(1) << (page % 64), __ATOMIC_RELEASE );
    return 1;
}

static int ios_fex_code_guard_is_armed( size_t guard )
{
    size_t page = guard / MADEIRA_FEX_CODE_GUARD_BYTES;
    return guard < IOS_CODE_GUARD_MAX_POOL && !(guard & (MADEIRA_FEX_CODE_GUARD_BYTES - 1)) &&
           !!(__atomic_load_n( ios_code_guard_armed + page / 64, __ATOMIC_ACQUIRE ) &
              (UINT64_C(1) << (page % 64)));
}

#endif
