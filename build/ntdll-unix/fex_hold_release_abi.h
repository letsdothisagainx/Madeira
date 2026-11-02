/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Madeira's private native-ARM64 CPU-backend hold-release registration.
 * This is a separate operation; it does not extend an existing Unix-call ABI. */
#ifndef MADEIRA_FEX_HOLD_RELEASE_ABI_H
#define MADEIRA_FEX_HOLD_RELEASE_ABI_H

#include <stddef.h>
#include <stdint.h>

#define MADEIRA_FEX_HOLD_REGISTER_CLASS 1011
#define MADEIRA_FEX_HOLD_REGISTER_VERSION 1
#define MADEIRA_FEX_JIT_POOL_ADDRESS_CLASS 1005

struct madeira_fex_hold_registration
{
    uint32_t size;
    uint32_t version;
    void *peb;
    void *callback;
};

enum madeira_fex_hold_release_result
{
    MADEIRA_FEX_HOLD_RELEASE_SHARED = 1,
    MADEIRA_FEX_HOLD_RELEASE_FOREIGN_STAMP = 4,
    MADEIRA_FEX_HOLD_RELEASE_NO_CONTEXT = 8,
    MADEIRA_FEX_HOLD_RELEASE_SELFTEST = 16,
    MADEIRA_FEX_HOLD_RELEASE_FOREIGN_THREAD = 32,
    MADEIRA_FEX_HOLD_RELEASE_FOREIGN_PROCESS = 64,
    MADEIRA_FEX_HOLD_RELEASE_INVALID_DEPTH = 128
};

#ifdef __cplusplus
static_assert(sizeof(madeira_fex_hold_registration) == 24);
static_assert(offsetof(madeira_fex_hold_registration, peb) == 8);
static_assert(offsetof(madeira_fex_hold_registration, callback) == 16);
#else
_Static_assert(sizeof(struct madeira_fex_hold_registration) == 24, "native 64-bit registration ABI");
_Static_assert(offsetof(struct madeira_fex_hold_registration, peb) == 8, "registration owner offset");
_Static_assert(offsetof(struct madeira_fex_hold_registration, callback) == 16, "registration callback offset");
#endif

#endif
