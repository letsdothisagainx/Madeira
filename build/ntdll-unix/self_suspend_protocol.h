#ifndef MADEIRA_SELF_SUSPEND_PROTOCOL_H
#define MADEIRA_SELF_SUSPEND_PROTOCOL_H

#include <stdint.h>

/* Heap-free internal capability in the existing four reserved reply bytes.
 * Count offset and fixed packet length stay unchanged; old clients ignore the
 * bytes and old servers leave them zero. Low bit identifies the exact object
 * resolved by THIS operation as the requester itself. No second handle lookup
 * and no allocation while a target may hold the native allocator lock. */
#define MADEIRA_SUSPEND_IDENTITY_MAGIC UINT32_C(0x53555330)
/* Decoded observer input, NOT a wire structure. Foreign target IDs are not
 * carried in the reserved bytes; the server observer supplies them directly. */
struct madeira_suspend_identity_reply
{
    uint32_t magic;
    uint32_t self;
    uint32_t tid;
    uint32_t pid;
};

#ifdef __cplusplus
static_assert(sizeof(struct madeira_suspend_identity_reply) == 16, "suspend identity ABI");
#else
_Static_assert(sizeof(struct madeira_suspend_identity_reply) == 16, "suspend identity ABI");
#endif

#endif
