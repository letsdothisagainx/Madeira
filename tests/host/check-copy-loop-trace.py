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

# Compile and execute the actual production formatter, not a reimplementation.
# The typed capture struct and printf attribute also catch invalid struct casts
# and argument/format mismatches before an expensive iOS build is dispatched.
def production_block(marker, trailing_semicolon=False):
    start = native.index(marker)
    opening = native.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (native[end] == '{') - (native[end] == '}')
        end += 1
    if trailing_semicolon:
        assert native[end] == ';'
        end += 1
    return native[start:end]

declarations = '\n'.join(production_block(marker, True) for marker in (
    'struct ios_ts_mod {', 'struct ios_ts_map {',
    'struct ios_ts_hot_context\n', 'struct ios_ts_copy_capture\n'))
printer = production_block('static void ios_ts_print_copy(')
FORMAT_PRELUDE = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "copy_loop_trace.h"
'''
FORMAT_ADAPTERS = r'''
static struct ios_copy_trace_state ios_ts_copy_ledger;
static struct ios_ts_hot_context fixture_identity;
static unsigned fixture_identity_reads, fixture_code_reads, fixture_logs;
static char fixture_output[32768];
static size_t fixture_used;
static void ios_ts_saved_guest64(uint64_t teb, struct ios_ts_hot_context *identity)
{
    assert(teb == 0x7000000000);
    ++fixture_identity_reads;
    *identity = fixture_identity;
}
static const char *ios_ts_mod_for(struct ios_ts_map *map, uint64_t va, uint64_t *rva)
{
    for (int i = 0; i < map->n; ++i)
        if (va >= map->m[i].base && va - map->m[i].base < map->m[i].size)
        { *rva = va - map->m[i].base; return map->m[i].name; }
    return NULL;
}
static int ios_ts_read(uint64_t address, void *out, size_t bytes)
{
    /* The formatter may read a bounded guest-code window, never the source or
     * destination payload. These assertions catch any change to that boundary. */
    assert(address == 0x71d510fa2a && bytes == 64);
    ++fixture_code_reads;
    memset(out, 0xa5, bytes);
    return 1;
}
static void wine_log_write(const char *, ...) __attribute__((format(printf, 1, 2)));
static void wine_log_write(const char *format, ...)
{
    char line[1024]; /* Match the real logger's line-size bound. */
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    assert(length >= 0 && (size_t)length < sizeof(line));
    assert((size_t)length + 2 < sizeof(fixture_output) - fixture_used);
    memcpy(fixture_output + fixture_used, line, length);
    fixture_used += length;
    fixture_output[fixture_used++] = '\n';
    fixture_output[fixture_used] = 0;
    ++fixture_logs;
}
'''
FORMAT_MAIN = r'''
int main(void)
{
    const uint32_t observed[] = {
        0x3dc00000, 0x91008000, 0x3d800100, 0x3cdf0000, 0x3d800500,
        0x91008108, 0xeb01011f, 0xb945eb8b, 0x3400004b, 0xd4395fc0, 0x54fffec3
    };
    uint64_t regs[29] = {0};
    struct ios_ts_copy_capture copy = {0};
    struct ios_ts_map map = {0};
    map.peb = 0x118db8000;
    map.n = 2;
    strcpy(map.m[0].name, "steam.exe");
    strcpy(map.m[1].name, "tier0.dll");
    map.m[1].base = 0x71d4e80000; map.m[1].size = 0x400000;
    copy.captured = 1; copy.teb = 0x7000000000;
    copy.frame = 0x7e7d405140; copy.block = 0x7c3226a000;
    copy.pc = 0x7c3226ad60; copy.lr = 0x7c322377cc;
    regs[0] = 0x100003 + 32; regs[8] = 0x200007 + 32; regs[1] = 0x280007;
    assert(ios_copy_loop_decode(observed, 11, 0x7c3226ad38, copy.pc, regs, &copy.loop));
    ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    assert(!fixture_logs && !fixture_identity_reads && !ios_ts_copy_ledger.total);
    strcpy(map.m[0].name, "CS2.EXE");
    fixture_identity.have_guest = 1;
    fixture_identity.pid = 0x38c; fixture_identity.tid = 0x390;
    fixture_identity.owner = map.peb;
    fixture_identity.frame = copy.frame + 16; /* stale frame */
    ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    assert(!fixture_logs && !ios_ts_copy_ledger.total);
    fixture_identity.frame = copy.frame;
    fixture_identity.owner = map.peb + 16; /* wrong process */
    ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    assert(!fixture_logs && !ios_ts_copy_ledger.total);
    fixture_identity.owner = map.peb;
    copy.captured = 0;
    ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    assert(!fixture_logs && !ios_ts_copy_ledger.total);
    copy.captured = 1;
    ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    assert(ios_ts_copy_ledger.total == 1 && fixture_logs == 2 && fixture_code_reads == 1);
    assert(strstr(fixture_output, "pid=038c tid=0390 owner=0x118db8000"));
    assert(strstr(fixture_output, "loop=0x7c3226ad38 host-pc=0x7c3226ad60"));
    assert(strstr(fixture_output, "module=tier0.dll rva=0x28fa2a"));
    assert(strstr(fixture_output, "slot=10 src-reg=0 dst-reg=8 end-reg=1"));
    assert(strstr(fixture_output, "iteration-src=0x100003 iteration-dst=0x200007"));
    assert(strstr(fixture_output, "remaining-valid=1 remaining=524288 original-request=unmeasured"));
    assert(strstr(fixture_output, "invocation-identity=unmeasured"));
    assert(strstr(fixture_output, "guest-code=0x71d510fa2a bytes=a5 a5 a5"));
    for (unsigned i = 0; i < 3; ++i)
    {
        copy.loop.src += 32; copy.loop.dst += 32; copy.loop.remaining -= 32;
        ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    }
    assert(ios_ts_copy_ledger.total == 4);
    assert(strstr(fixture_output, "same-span=1 forward-deltas=1 src-delta=32 dst-delta=32"));
    unsigned logs = fixture_logs;
    ios_ts_print_copy(&copy, 0x71d510fa2a, &map);
    assert(ios_ts_copy_ledger.total == 4 && fixture_logs == logs);
    puts("actual production copy formatter: typed printf compilation, live loop/RVA/register/progression fields, Steam/stale-identity gates and per-key cap passed");
    return 0;
}
'''
FORMAT_ADAPTERS += r'''
static unsigned long long ios_thread_process_try_observation_lease(void *owner, unsigned pid)
{ assert(owner && pid); return 1; }
static void ios_cs2_stall_register_worker(uint64_t owner, unsigned pid, uint64_t lease,
                                        unsigned tid, uint64_t teb, uint64_t native)
{ (void)owner; (void)pid; (void)lease; (void)tid; (void)teb; (void)native; }
'''
with tempfile.TemporaryDirectory(prefix='madeira-copy-format-') as work:
    source = Path(work) / 'formatter.c'
    binary = Path(work) / 'formatter'
    compile_command = [os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra',
                       '-Werror', '-Wformat=2', '-I', str(ROOT / 'build/ntdll-unix'),
                       str(source), '-o', str(binary)]
    source.write_text(FORMAT_PRELUDE + declarations + FORMAT_ADAPTERS + printer + FORMAT_MAIN)
    subprocess.run(compile_command, check=True)
    subprocess.run([str(binary)], check=True)
    # Reproduce the invalid production struct cast as a negative control. The
    # same typed fixture must reject it rather than passing substring checks.
    assert '(unsigned long long)copy->loop.loop' in printer
    broken = printer.replace('(unsigned long long)copy->loop.loop', '(unsigned long long)copy->loop')
    source.write_text(FORMAT_PRELUDE + declarations + FORMAT_ADAPTERS + broken + FORMAT_MAIN)
    failed = subprocess.run(compile_command, text=True, capture_output=True)
    assert failed.returncode, 'actual production formatter struct-cast negative control compiled'
    print('actual production formatter negative control: invalid struct-to-integer cast rejected by compiler')
