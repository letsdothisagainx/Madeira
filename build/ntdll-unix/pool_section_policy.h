/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_POOL_SECTION_POLICY_H
#define MADEIRA_POOL_SECTION_POLICY_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* A PE section is 4 KB aligned; the host page may contain several sections.
 * Fail closed on malformed metadata. Never remove EXEC from a page containing
 * any executable section, including an executable+writable section. */
enum { IOS_POOL_PAGE_CODE = 1, IOS_POOL_PAGE_DATA = 2 };
static uint32_t ios_pool_u32( const unsigned char *p )
{
    uint32_t n;
    memcpy( &n, p, sizeof(n) );
    return n;
}
static unsigned ios_pool_page_policy( const void *image, size_t size, size_t pe,
                                      uintptr_t rx, uintptr_t page, size_t host_page )
{
    const unsigned char *b = image;
    size_t table, count, opt, i;
    unsigned flags = 0;
    if (!image || !host_page || (host_page & (host_page - 1)) ||
        page % host_page || size > UINTPTR_MAX - rx || page > UINTPTR_MAX - host_page ||
        pe > size || size - pe < 24) return IOS_POOL_PAGE_CODE;
    count = (size_t)b[pe + 6] | (size_t)b[pe + 7] << 8;
    opt = (size_t)b[pe + 20] | (size_t)b[pe + 21] << 8;
    if (opt > size - pe - 24) return IOS_POOL_PAGE_CODE;
    table = pe + 24 + opt;
    if (!count || count > 4096 || count > (size - table) / 40) return IOS_POOL_PAGE_CODE;
    for (i = 0; i < count; i++)
    {
        const unsigned char *s = b + table + i * 40;
        size_t rva = ios_pool_u32( s + 12 ), len = ios_pool_u32( s + 8 );
        size_t raw = ios_pool_u32( s + 16 );
        uint32_t attrs = ios_pool_u32( s + 36 );
        if (raw > len) len = raw;
        if (rva > size || len > size - rva) return IOS_POOL_PAGE_CODE;
        if (!len || page >= rx + rva + len || page + host_page <= rx + rva) continue;
        if (attrs & 0x20000000u) flags |= IOS_POOL_PAGE_CODE;
        if (attrs & 0x80000000u) flags |= IOS_POOL_PAGE_DATA;
    }
    /* Padding belongs to the pool allocator, not to this image's data. */
    if (page < rx || page + host_page > rx + size) flags &= ~IOS_POOL_PAGE_DATA;
    return flags;
}
#endif
