/* SPDX-License-Identifier: MIT. Bounded diagnostic parsing; no launch gate. */
#ifndef MADEIRA_NATIVE_BUILD_PROVENANCE_H
#define MADEIRA_NATIVE_BUILD_PROVENANCE_H
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
struct madeira_build_component { char source[65], revision[41]; };
static int madeira_build_hex(const char *value, size_t length)
{
    if (!value) return 0;
    for (size_t i=0; i<length; ++i)
        if (!((value[i]>='0' && value[i]<='9') || (value[i]>='a' && value[i]<='f'))) return 0;
    return 1;
}
static int madeira_build_component_read(const char *value, const char *prefix,
                                        struct madeira_build_component *out)
{
    size_t n = strlen(prefix);
    if (!value || strnlen(value,n+107)!=n+105 || strncmp(value,prefix,n) ||
        !madeira_build_hex(value+n,64) || value[n+64]!=':' ||
        !madeira_build_hex(value+n+65,40)) return 0;
    memcpy(out->source,value+n,64);out->source[64]=0;
    memcpy(out->revision,value+n+65,40);out->revision[40]=0;
    return 1;
}
/* These are bounded environment INPUT observations. The native allocator logs
 * its parsed/effective values separately; this parser never changes them. */
static int madeira_build_env_number(const char *value, uint64_t *out)
{
    char *end; unsigned long long number; int saved_errno;
    if (!value) return 0;
    size_t n = strnlen(value,33);
    if (!n || n>32 || value[0]=='-' || value[0]=='+' || value[0]<=' ') return -1;
    saved_errno=errno;errno=0;number=strtoull(value,&end,0);
    int valid=!errno && *end==0;errno=saved_errno;
    if (!valid) return -1;
    *out=number;return 1;
}
#endif
