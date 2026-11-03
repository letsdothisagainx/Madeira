/* SPDX-License-Identifier: MIT.
 * Bounded PE DATA export lookup. Native code reads bytes; it never invokes a
 * guest export or guesses an execution-view address from a guest base. */
#ifndef MADEIRA_HTMLIPC_READY_READER_H
#define MADEIRA_HTMLIPC_READY_READER_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "htmlipc_ready_abi.h"

typedef int (*madeira_htmlipc_read_fn)(void *, uint64_t, void *, size_t);

static inline uint16_t madeira_htmlipc_u16(const unsigned char *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static inline uint32_t madeira_htmlipc_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline int madeira_htmlipc_pe_read(madeira_htmlipc_read_fn read, void *ctx,
                                         uint64_t base, uint32_t image_size,
                                         uint32_t offset, void *out, size_t size)
{
    return offset <= image_size && size <= image_size - offset &&
           read(ctx, base + offset, out, size);
}

/* `base` is the mapped execution-view DllBase from THIS owner's fresh loader
 * list. The caller owns process/lease checks and must revalidate them after
 * lookup and after reading the result. An answer is never safe to cache across
 * calls or process leases. Only the 80-byte public DATA object is admitted. */
static inline int madeira_htmlipc_find_ready_export(madeira_htmlipc_read_fn read,
        void *ctx, uint64_t base, uint32_t image_size, uint64_t *address)
{
    static const char wanted[] = "MadeiraRuntimeReady";
    unsigned char dos[64], nt[24], opt[120], exp[40], section[40], word[4];
    uint32_t pe, optional, section_table, headers, export_rva, export_size;
    uint32_t functions, names, ordinals, nfunctions, nnames, ready_rva = 0;
    uint16_t nsections, optional_size;
    unsigned i;
    int found = 0, data_section = 0;
    if (address) *address = 0;
    if (!address || !read || !base || image_size < sizeof(dos) ||
        image_size > (UINT32_C(512) << 20) || base > UINT64_MAX - image_size ||
        !madeira_htmlipc_pe_read(read,ctx,base,image_size,0,dos,sizeof(dos)) ||
        madeira_htmlipc_u16(dos) != 0x5a4d) return 0;
    pe = madeira_htmlipc_u32(dos + 60);
    if (pe < sizeof(dos) || pe > image_size ||
        !madeira_htmlipc_pe_read(read,ctx,base,image_size,pe,nt,sizeof(nt)) ||
        madeira_htmlipc_u32(nt) != UINT32_C(0x00004550) ||
        madeira_htmlipc_u16(nt + 4) != 0x8664) return 0;
    nsections = madeira_htmlipc_u16(nt + 6);
    optional_size = madeira_htmlipc_u16(nt + 20);
    if (!nsections || nsections > 96 || optional_size < sizeof(opt) || optional_size > 4096 ||
        image_size - pe < sizeof(nt) || optional_size > image_size - pe - sizeof(nt)) return 0;
    optional = pe + sizeof(nt);
    section_table = optional + optional_size;
    if (!madeira_htmlipc_pe_read(read,ctx,base,image_size,optional,opt,sizeof(opt)) ||
        madeira_htmlipc_u16(opt) != 0x20b || madeira_htmlipc_u32(opt + 56) != image_size ||
        madeira_htmlipc_u32(opt + 108) < 1 || madeira_htmlipc_u32(opt + 108) > 16 ||
        112 + madeira_htmlipc_u32(opt + 108) * 8 > optional_size) return 0;
    headers = madeira_htmlipc_u32(opt + 60);
    if (headers > image_size || section_table > headers ||
        (uint32_t)nsections * sizeof(section) > headers - section_table) return 0;
    export_rva = madeira_htmlipc_u32(opt + 112);
    export_size = madeira_htmlipc_u32(opt + 116);
    if (!export_rva || export_size < sizeof(exp) || export_rva > image_size ||
        export_size > image_size - export_rva ||
        !madeira_htmlipc_pe_read(read,ctx,base,image_size,export_rva,exp,sizeof(exp))) return 0;
    nfunctions = madeira_htmlipc_u32(exp + 20);
    nnames = madeira_htmlipc_u32(exp + 24);
    functions = madeira_htmlipc_u32(exp + 28);
    names = madeira_htmlipc_u32(exp + 32);
    ordinals = madeira_htmlipc_u32(exp + 36);
    if (!nfunctions || nfunctions > 4096 || !nnames || nnames > 4096 ||
        !functions || functions > image_size || nfunctions * 4 > image_size - functions ||
        !names || names > image_size || nnames * 4 > image_size - names ||
        !ordinals || ordinals > image_size || nnames * 2 > image_size - ordinals) return 0;
    for (i = 0; i < nnames; ++i)
    {
        char name[64];
        uint32_t rva;
        uint16_t ordinal;
        unsigned n;
        if (!madeira_htmlipc_pe_read(read,ctx,base,image_size,names + i * 4,word,4)) return 0;
        rva = madeira_htmlipc_u32(word);
        if (!rva || !madeira_htmlipc_pe_read(read,ctx,base,image_size,ordinals + i * 2,word,2)) return 0;
        ordinal = madeira_htmlipc_u16(word);
        if (ordinal >= nfunctions) return 0;
        for (n = 0; n < sizeof(name); ++n)
        {
            if (rva >= image_size || n >= image_size - rva ||
                !madeira_htmlipc_pe_read(read,ctx,base,image_size,rva + n,name + n,1)) return 0;
            if (!name[n]) break;
        }
        if (n == sizeof(name)) return 0;
        if (strcmp(name,wanted)) continue;
        if (found++ || !madeira_htmlipc_pe_read(read,ctx,base,image_size,
                                               functions + ordinal * 4,word,4)) return 0;
        ready_rva = madeira_htmlipc_u32(word);
        if (!ready_rva || ready_rva > image_size ||
            sizeof(struct madeira_htmlipc_ready) > image_size - ready_rva ||
            (ready_rva >= export_rva && ready_rva - export_rva < export_size)) return 0;
    }
    if (!found) return 0;
    for (i = 0; i < nsections; ++i)
    {
        uint32_t start, extent, raw, flags;
        if (!madeira_htmlipc_pe_read(read,ctx,base,image_size,section_table + i * 40,
                                     section,sizeof(section))) return 0;
        extent = madeira_htmlipc_u32(section + 8);
        start = madeira_htmlipc_u32(section + 12);
        raw = madeira_htmlipc_u32(section + 16);
        flags = madeira_htmlipc_u32(section + 36);
        if (raw > extent) extent = raw;
        if (start > image_size || extent > image_size - start) return 0;
        if (!extent || start >= ready_rva + sizeof(struct madeira_htmlipc_ready) ||
            (start <= ready_rva && ready_rva - start >= extent)) continue;
        /* Reject overlapping/ambiguous membership, executable data, shared
         * state, and a DATA object truncated at its section boundary. */
        if (data_section++ || start > ready_rva || start < headers || !(flags & UINT32_C(0x40000000)) ||
            !(flags & UINT32_C(0x000000c0)) || (flags & UINT32_C(0x32000020)) ||
            sizeof(struct madeira_htmlipc_ready) > extent - (ready_rva - start)) return 0;
    }
    if (!data_section) return 0;
    *address = base + ready_rva;
    return 1;
}
#endif
