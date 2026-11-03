/* SPDX-License-Identifier: MIT. Shared DATA ABI: no guest function invocation. */
#ifndef MADEIRA_HTMLIPC_READY_ABI_H
#define MADEIRA_HTMLIPC_READY_ABI_H
#include <stdint.h>
#define MADEIRA_HTMLIPC_OWNER_LEASE_CLASS UINT32_C(0x4d480001)
#define MADEIRA_HTMLIPC_READY_MAGIC UINT64_C(0x314452504948444d)
#define MADEIRA_HTMLIPC_READY_VERSION 1u
#define MADEIRA_HTMLIPC_READY_PREPARED 1u
#define MADEIRA_HTMLIPC_READY_CACHE_VERIFIED 2u
#define MADEIRA_HTMLIPC_READY_INSTALLED 4u
#define MADEIRA_HTMLIPC_READY_FLAGS 7u
/* Export as `MadeiraRuntimeReady DATA`. An odd sequence means publication in
 * progress. Publish an even nonzero sequence last, with release ordering.
 * Clear installed before reporting any provider/installer failure or detach.
 * owner_lease comes from the private NtQueryInformationProcess query above;
 * Windows/stock Wine need not implement it and must then leave native ready off.
 * Never fill owner_lease from the PID or owner PEB, or use a fixture value. */
struct madeira_htmlipc_ready {
    uint64_t magic;
    uint32_t size, version;
    uint32_t sequence, flags;
    uint32_t pid, provider_error;
    uint32_t installer_error, reserved;
    uint64_t owner_peb, owner_lease;
    uint64_t self_module, installed_module, generation;
};
#if defined(__cplusplus)
static_assert(sizeof(madeira_htmlipc_ready)==80,"HTMLIPC ready DATA ABI");
#else
_Static_assert(sizeof(struct madeira_htmlipc_ready)==80,"HTMLIPC ready DATA ABI");
#endif
#endif
