/* Read-only recognition of the sampled vector copy loop. This does not replace
 * guest code, infer memcpy semantics, or inspect copied data. The caller takes
 * the register snapshot during its existing thread-sampling suspension. */
#ifndef MADEIRA_COPY_LOOP_TRACE_H
#define MADEIRA_COPY_LOOP_TRACE_H

#include <stddef.h>
#include <stdint.h>

enum { IOS_COPY_TRACE_KEYS = 8, IOS_COPY_TRACE_PER_KEY = 4, IOS_COPY_TRACE_LIMIT = 32 };
struct ios_copy_loop_sample
{
    uint64_t loop, src, dst, end, remaining;
    unsigned slot, src_reg, dst_reg, end_reg, have_remaining;
};

/* Accept only the observed eleven-instruction forward loop, with arbitrary
 * working-register allocation. Its x28 frame doorbell at +0x5e8 and real
 * back-edge are part of the match; another state word is not a suspend check.
 * A register value sampled after its increment is normalized to iteration entry;
 * this is remaining loop span, never the caller's original requested length. */
static int ios_copy_loop_decode(const uint32_t *code, size_t words, uint64_t base,
                                uint64_t pc, const uint64_t regs[29],
                                struct ios_copy_loop_sample *out)
{
    size_t i;
    if ((base | pc) & 3 || pc < base || words > (UINT64_MAX - base) / 4 ||
        (pc - base) / 4 >= words) return 0;
    for (i = 0; i + 11 <= words; ++i)
    {
        const uint32_t *p = code + i;
        uint64_t loop = base + i * 4;
        unsigned v = p[0] & 31, src = (p[0] >> 5) & 31;
        unsigned dst = (p[2] >> 5) & 31, end = (p[6] >> 16) & 31;
        unsigned state = (p[7] >> 5) & 31, tmp = p[7] & 31, slot;
        int32_t branch;
        if (pc < loop || pc >= loop + 44 || src >= 29 || dst >= 29 || end >= 29 ||
            state >= 29 || tmp >= 29 || src == dst || src == end || dst == end ||
            tmp == src || tmp == dst || tmp == end || state == tmp ||
            state == src || state == dst || state == end) continue;
        if (p[0] != (0x3dc00000u | src << 5 | v) ||
            p[1] != (0x91008000u | src << 5 | src) ||
            p[2] != (0x3d800000u | dst << 5 | v) ||
            p[3] != (0x3cdf0000u | src << 5 | v) ||
            p[4] != (0x3d800400u | dst << 5 | v) ||
            p[5] != (0x91008000u | dst << 5 | dst) ||
            p[6] != (0xeb00001fu | end << 16 | dst << 5) ||
            p[7] != (0xb945eb80u | tmp) || state != 28 ||
            p[8] != (0x34000040u | tmp) || p[9] != 0xd4395fc0u ||
            (p[10] & 0xff00001fu) != 0x54000003u) continue;
        branch = (int32_t)(p[10] << 8) >> 13;
        if (branch != -10) continue;
        slot = (unsigned)((pc - loop) / 4);
        if ((slot >= 2 && regs[src] < 32) || (slot >= 6 && regs[dst] < 32)) continue;
        *out = (struct ios_copy_loop_sample){0};
        out->loop = loop; out->src_reg = src; out->dst_reg = dst; out->end_reg = end;
        out->slot = slot;
        out->src = regs[src] - (slot >= 2 ? 32 : 0);
        out->dst = regs[dst] - (slot >= 6 ? 32 : 0);
        out->end = regs[end];
        if ((out->have_remaining = out->end >= out->dst)) out->remaining = out->end - out->dst;
        return 1;
    }
    return 0;
}

struct ios_copy_trace_key
{
    uint64_t owner, tid, teb, block, loop, src, dst, end;
    unsigned samples;
};
struct ios_copy_trace_state
{
    struct ios_copy_trace_key key[IOS_COPY_TRACE_KEYS];
    unsigned keys, total;
};
struct ios_copy_trace_progress
{
    uint64_t src_delta, dst_delta;
    unsigned sample, same_span, forward;
};

/* Single sampler thread owns this bounded ledger. Different process/thread/block
 * addresses are never compared. Deltas describe observed progress and
 * cannot establish that two snapshots belong to the same caller invocation. */
static int ios_copy_trace_note(struct ios_copy_trace_state *state, uint64_t owner,
                              uint64_t tid, uint64_t teb, uint64_t block,
                              const struct ios_copy_loop_sample *now,
                              struct ios_copy_trace_progress *out)
{
    struct ios_copy_trace_key *key;
    unsigned i;
    if (!owner || !tid || !teb || !block || state->total >= IOS_COPY_TRACE_LIMIT) return 0;
    for (i = 0; i < state->keys; ++i)
    {
        key = state->key + i;
        if (key->owner == owner && key->tid == tid && key->teb == teb &&
            key->block == block && key->loop == now->loop) break;
    }
    if (i == state->keys)
    {
        if (state->keys >= IOS_COPY_TRACE_KEYS) return 0;
        key = state->key + state->keys++;
        *key = (struct ios_copy_trace_key){0};
        key->owner = owner; key->tid = tid; key->teb = teb;
        key->block = block; key->loop = now->loop;
    }
    key = state->key + i;
    if (key->samples >= IOS_COPY_TRACE_PER_KEY) return 0;
    *out = (struct ios_copy_trace_progress){0};
    if (key->samples && key->end == now->end)
    {
        out->same_span = 1;
        if (now->src >= key->src && now->dst >= key->dst)
        {
            out->src_delta = now->src - key->src;
            out->dst_delta = now->dst - key->dst;
            out->forward = out->src_delta == out->dst_delta;
        }
    }
    out->sample = ++key->samples; ++state->total;
    key->src = now->src; key->dst = now->dst; key->end = now->end;
    return 1;
}
#endif
