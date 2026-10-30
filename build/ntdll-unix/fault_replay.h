/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_FAULT_REPLAY_H
#define MADEIRA_FAULT_REPLAY_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Only used for FEX's explicit guest-fault trampoline, after normal page and
 * instruction emulation. Each thread retains a small bounded set: an invalid
 * exception dispatcher can alternate with the original invalid entry point. */
struct ios_fault_signature
{
    uint64_t owner, teb, pc, addr, rip, rsp, sp;
};
struct ios_fault_replay
{
    struct { struct ios_fault_signature key; uint64_t since_ms; unsigned count; } slot[8];
    unsigned next, stopped, logs;
};

/* 1 = original-state diagnostic; 2 = repeated failure; 0 = no new message.
 * Recovered alignment, SMC writes, and ordinary native faults never call this.
 * A later occurrence starts a fresh budget rather than accumulating across
 * frames or across a recycled process/thread identity. */
static int ios_fault_replay_note(struct ios_fault_replay *replay,
                                 const struct ios_fault_signature *key, uint64_t now_ms)
{
    unsigned i;
    if (replay->stopped) return 0;
    for (i = 0; i < 8; ++i)
        if (!memcmp(&replay->slot[i].key, key, offsetof(struct ios_fault_signature, rsp))) break;
    if (i == 8) i = replay->next++ % 8;
    if (memcmp(&replay->slot[i].key, key, offsetof(struct ios_fault_signature, rsp)) ||
        now_ms - replay->slot[i].since_ms > 500 || !replay->slot[i].count)
    {
        replay->slot[i].key = *key;
        replay->slot[i].since_ms = now_ms;
        replay->slot[i].count = 1;
        return replay->logs++ < 8 ? 1 : 0;
    }
    if (++replay->slot[i].count == 256)
    {
        replay->stopped = 1;
        return 2;
    }
    return 0;
}
#endif
