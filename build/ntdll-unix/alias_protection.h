/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_ALIAS_PROTECTION_H
#define MADEIRA_ALIAS_PROTECTION_H
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>

/* Callers hold the VM lock, which also serializes alias retirement/reuse.
 * Query a whole host page, not a 4 KiB guest subpage. Apply never receives a
 * writable alias page, including transiently during a W->X transition. */
static inline int madeira_protect_alias_writes(uintptr_t base, size_t size, size_t page,
        int prot, int (*owned)(uintptr_t, size_t, void *),
        int (*apply)(uintptr_t, size_t, int, int, void *), void *context)
{
    uintptr_t end, cursor, run;
    int previous = -1;
    if (!page || (page & (page-1)) || (base & (page-1)) || !size ||
        size > UINTPTR_MAX-base || size > SIZE_MAX-(page-1)) { errno=EINVAL; return -1; }
    size = (size+page-1) & ~(page-1);
    if (size > UINTPTR_MAX-base) { errno=EINVAL; return -1; }
    end=base+size; run=base;
    for (cursor=base; cursor<end; cursor+=page)
    {
        int alias = (prot & PROT_WRITE) && owned(cursor,page,context);
        if (previous != -1 && alias != previous)
        {
            if (apply(run,cursor-run,previous ? PROT_READ|PROT_EXEC : prot,previous,context)) return -1;
            run=cursor;
        }
        previous=alias;
    }
    return apply(run,end-run,previous ? PROT_READ|PROT_EXEC : prot,previous,context);
}
#endif
