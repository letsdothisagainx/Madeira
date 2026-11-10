/* SPDX-License-Identifier: MIT
 * Madeira-owned native FEX code-buffer contract. This is not a guest API.
 * A successful tagged allocation already owns a permanent terminal guard in
 * both aliases. Its class includes that guard; the guard is never executable
 * image capacity and must never be restored for reuse. */
#ifndef MADEIRA_FEX_CODE_BUFFER_ABI_H
#define MADEIRA_FEX_CODE_BUFFER_ABI_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MADEIRA_FEX_CODE_GUARD_BYTES 0x4000u
#define MADEIRA_FEX_CODE_PARAMETER_TYPE 31u
#define MADEIRA_FEX_CODE_GUARD_ABI_V1 UINT64_C(0x4d41444547524401)
#define IOS_FEX_CODE_GUARDED_ATTRIBUTE 0x80000000u
#define MADEIRA_FEX_CODE_GUARD_ENV "WINE_IOS_FEX_CODE_GUARD_V1"
#define MADEIRA_FEX_CODE_MIN_CLASS 0x100000u
#define MADEIRA_FEX_CODE_INITIAL_CLASS 0x1000000u
#define MADEIRA_FEX_CODE_MAX_CLASS 0x8000000u

static inline int madeira_fex_code_guard_enabled(void)
{
    const char *value = getenv(MADEIRA_FEX_CODE_GUARD_ENV);
    return value && value[0] == '1' && !value[1];
}

static inline int madeira_fex_code_buffer_class_valid(size_t size)
{
    return size >= MADEIRA_FEX_CODE_MIN_CLASS && size <= MADEIRA_FEX_CODE_MAX_CLASS &&
           !(size & (size - 1));
}

/* Grow from the previous actual grant, including a genuinely degraded grant.
 * Clamping before multiplication avoids overflow for malformed state. */
static inline size_t madeira_fex_code_buffer_next_size(size_t previous)
{
    if (previous < MADEIRA_FEX_CODE_INITIAL_CLASS / 2) return MADEIRA_FEX_CODE_INITIAL_CLASS;
    if (previous >= MADEIRA_FEX_CODE_MAX_CLASS / 2) return MADEIRA_FEX_CODE_MAX_CLASS;
    return previous * 2;
}

#endif
