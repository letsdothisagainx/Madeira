#!/usr/bin/env python3
"""Exercise the production read-only generated-copy recognizer and bounded ledger.

These are captured instruction fixtures and synthetic register snapshots. They do
not execute Valve code, replace a copy, or measure iPhone loading performance.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "copy_loop_trace.h"

/* Exact eleven instructions in both daf3dcec exported generated-code windows:
 * src=x0, dst=x8, end=x1, vector=q0, doorbell=w11 at [x28,#0x5e8]. */
static const uint32_t observed[] = {
    0x3dc00000, 0x91008000, 0x3d800100, 0x3cdf0000, 0x3d800500,
    0x91008108, 0xeb01011f, 0xb945eb8b, 0x3400004b, 0xd4395fc0, 0x54fffec3
};
static void encode(uint32_t p[11], unsigned src, unsigned dst, unsigned end,
                   unsigned state, unsigned tmp, unsigned vector)
{
    p[0] = 0x3dc00000 | src << 5 | vector;
    p[1] = 0x91008000 | src << 5 | src;
    p[2] = 0x3d800000 | dst << 5 | vector;
    p[3] = 0x3cdf0000 | src << 5 | vector;
    p[4] = 0x3d800400 | dst << 5 | vector;
    p[5] = 0x91008000 | dst << 5 | dst;
    p[6] = 0xeb00001f | end << 16 | dst << 5;
    p[7] = 0xb945e800 | state << 5 | tmp;
    p[8] = 0x34000040 | tmp;
    p[9] = 0xd4395fc0;
    p[10] = 0x54fffec3;
}

int main(void)
{
    uint32_t p[21] = {0}, variant[11];
    uint64_t regs[29] = {0};
    struct ios_copy_loop_sample sample;
    struct ios_copy_trace_state ledger = {0};
    struct ios_copy_trace_progress progress;
    unsigned matches = 0;
    memcpy(p + 5, observed, sizeof(observed));
    /* Sampling before/after increments describes the same iteration, rather
     * than inventing a backwards copy at a mid-iteration PC. */
    for (unsigned slot = 0; slot < 11; ++slot)
    {
        regs[0] = 0x100003 + (slot >= 2 ? 32 : 0);
        regs[8] = 0x200007 + (slot >= 6 ? 32 : 0);
        regs[1] = 0x280007;
        assert(ios_copy_loop_decode(p, 21, 0x1000, 0x1014 + slot * 4, regs, &sample));
        assert(sample.loop == 0x1014 && sample.src == 0x100003 && sample.dst == 0x200007);
        assert(sample.end == 0x280007 && sample.have_remaining && sample.remaining == 0x80000);
        ++matches;
    }
    /* Arbitrary legal register allocation and different virtual placement. */
    for (unsigned reg = 0; reg < 24; ++reg)
    {
        unsigned src = reg, dst = reg + 1, end = reg + 2, state = 28, tmp = reg + 4;
        for (unsigned vector = 0; vector < 32; ++vector)
        {
            encode(variant, src, dst, end, state, tmp, vector);
            regs[src] = 0x100000000 + 32; regs[dst] = 0x300000000 + 32; regs[end] = 0x400000000;
            assert(ios_copy_loop_decode(variant, 11, 0x7000000000, 0x7000000028, regs, &sample));
            assert(sample.src_reg == src && sample.dst_reg == dst && sample.end_reg == end);
            assert(sample.src == 0x100000000 && sample.dst == 0x300000000);
            assert(sample.remaining == 0x100000000);
            ++matches;
        }
    }
    /* Every instruction matters: another vector operation, wrong stride,
     * missing safepoint, signed back-edge or different condition is refused. */
    regs[0] = 0x100020; regs[8] = 0x200020; regs[1] = 0x280000;
    for (unsigned word = 0; word < 11; ++word)
    {
        memcpy(variant, observed, sizeof(variant));
        variant[word] ^= word == 7 ? 0x00400000 : 0x1;
        assert(!ios_copy_loop_decode(variant, 11, 0x1000, 0x1028, regs, &sample));
    }
    assert(!ios_copy_loop_decode(observed, 10, 0x1000, 0x1020, regs, &sample));
    assert(!ios_copy_loop_decode(observed, 11, 0x1000, 0xffc, regs, &sample));
    assert(!ios_copy_loop_decode(observed, 11, 0x1000, 0x102c, regs, &sample));
    assert(!ios_copy_loop_decode(observed, 11, 0x1000, 0x1001, regs, &sample));
    assert(!ios_copy_loop_decode(observed, 11, UINT64_MAX - 3, UINT64_MAX - 3, regs, &sample));
    /* Other frame words or another base register are not this suspend doorbell. */
    memcpy(variant, observed, sizeof(variant));
    variant[7] ^= 0x400;
    assert(!ios_copy_loop_decode(variant, 11, 0x1000, 0x1028, regs, &sample));
    memcpy(variant, observed, sizeof(variant));
    variant[7] ^= 0x20;
    assert(!ios_copy_loop_decode(variant, 11, 0x1000, 0x1028, regs, &sample));
    regs[0] = 8;
    assert(!ios_copy_loop_decode(observed, 11, 0x1000, 0x1028, regs, &sample));
    regs[0] = 0x100020; regs[1] = 0x1ffff0;
    assert(ios_copy_loop_decode(observed, 11, 0x1000, 0x1028, regs, &sample));
    assert(!sample.have_remaining); /* no unsigned-underflow invented length */
    regs[1] = 0x280000;
    assert(ios_copy_loop_decode(observed, 11, 0x1000, 0x1028, regs, &sample));
    assert(ios_copy_trace_note(&ledger, 1, 2, 3, 4, &sample, &progress));
    assert(progress.sample == 1 && !progress.same_span);
    sample.src += 64; sample.dst += 64;
    assert(ios_copy_trace_note(&ledger, 1, 2, 3, 4, &sample, &progress));
    assert(progress.same_span && progress.forward && progress.src_delta == 64 && progress.dst_delta == 64);
    sample.end += 32;
    assert(ios_copy_trace_note(&ledger, 1, 2, 3, 4, &sample, &progress));
    assert(!progress.same_span && !progress.forward);
    assert(ios_copy_trace_note(&ledger, 1, 2, 3, 4, &sample, &progress));
    assert(progress.same_span && progress.forward && !progress.src_delta);
    assert(!ios_copy_trace_note(&ledger, 1, 2, 3, 4, &sample, &progress));
    /* Same TID/addresses in another process must start an independent record. */
    assert(ios_copy_trace_note(&ledger, 11, 2, 3, 4, &sample, &progress));
    assert(progress.sample == 1 && !progress.same_span);
    assert(ios_copy_trace_note(&ledger, 1, 12, 3, 4, &sample, &progress));
    assert(progress.sample == 1 && !progress.same_span);
    assert(ios_copy_trace_note(&ledger, 1, 2, 13, 4, &sample, &progress));
    assert(ios_copy_trace_note(&ledger, 1, 2, 3, 14, &sample, &progress));
    for (unsigned key = ledger.keys; key < IOS_COPY_TRACE_KEYS; ++key)
        assert(ios_copy_trace_note(&ledger, 100 + key, 2, 3, 4, &sample, &progress));
    assert(!ios_copy_trace_note(&ledger, 200, 2, 3, 4, &sample, &progress));
    memset(&ledger, 0, sizeof(ledger));
    for (unsigned key = 0; key < IOS_COPY_TRACE_KEYS; ++key)
        for (unsigned n = 0; n < IOS_COPY_TRACE_PER_KEY; ++n)
            assert(ios_copy_trace_note(&ledger, key + 1, 2, 3, 4, &sample, &progress));
    assert(ledger.total == IOS_COPY_TRACE_LIMIT);
    assert(!ios_copy_trace_note(&ledger, 1, 2, 3, 4, &sample, &progress));
    printf("copy observer: %u valid generated-loop snapshots; malformed/boundary/register/progression/ownership/cap cases passed; no guest copy substituted\n", matches);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-copy-loop-') as work:
    source = Path(work) / 'fixture.c'
    binary = Path(work) / 'fixture'
    source.write_text(FIXTURE)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I', str(ROOT / 'build/ntdll-unix'), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

native = (ROOT / 'build/ntdll-unix/server_ios.c').read_text()
capture = native.split('static void ios_ts_capture_copy(', 1)[1].split('\nstatic void ', 1)[0]
assert 'thread_suspend' not in capture and 'thread_resume' not in capture and 'malloc(' not in capture
assert 'ios_ts_read(pc - 40, code, sizeof(code))' in capture
assert 'ios_native_rip_from_hostpc' not in capture and 'ios_ts_saved_guest64' not in capture
assert 'ios_copy_trace_note' not in capture and 'out->rip' not in capture
finished = native.split('static void ios_ts_print_copy(', 1)[1].split('\nstatic void ', 1)[0]
assert 'identity.frame != copy->frame' in finished and 'identity.owner != map->peb' in finished
assert finished.index('strcasecmp(map->m[0].name, "cs2.exe")') < finished.index('ios_copy_trace_note')
assert 'copy->rip = mapped_rip' in finished
assert 'original-request=unmeasured' in native and 'invocation-identity=unmeasured' in native
sampler = native.split('static void ios_thread_sampler_pass(int burst)', 1)[1].split('\n/*', 1)[0]
assert sampler.index('ios_ts_capture_copy(&st') < sampler.index('thread_resume(tlist[k]);\n        if (have_bb)')
assert sampler.index('ios_ts_print_copy(&copy') > sampler.index('thread_resume(tlist[k]);\n        if (have_bb)')
print('copy observer integration: existing-suspension capture, post-resume logging, no payload reads or new guest execution')
