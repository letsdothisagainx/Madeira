#!/usr/bin/env python3
"""Compile the production GPR STR immediate helper, routing and PC epilogue.

Replays e08dcae's rejected STR XZR,[X8,#16]! (0xf8010d1f) with real
RX/RW file aliases. An isolated old bit-11 guard is a control, not a
replacement validator. Every verdict/write/writeback in the corrected path
comes from production source. No historical git checkout is needed by CI.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(name):
    import re
    found = re.search(r'(?m)^static (?:int|uintptr_t) ' + name + r'\(', source)
    assert found, name
    return source[found.start():source.index('\n}', found.start()) + 2] + '\n'


start = source.index('                    /* GPR STR immediate:')
route = source[start:source.index('                    /* SIMD/FP STR (immediate, post/pre-index, D-reg', start)]
unsigned_start = source.index('                    /* STR (immediate, unsigned offset, 64-bit):')
unsigned_end = source.index('                    /* STR (immediate, unsigned offset, 32-bit):', unsigned_start)
route = source[unsigned_start:unsigned_end] + route
start = source.index('                        /* Advance PC past the emulated instruction */')
advance = source[start:source.index('                        static volatile int emul_count', start)]
assert 'ios_alias_store_immediate(' in route

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
enum { PAGE = 0x4000, RX_SIZE = 2 * PAGE, RW_SIZE = 3 * PAGE };
static unsigned char *rx, *rw;
static int second_present = 1;
static uintptr_t protected_page;
void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
static int capture(int fd, const char *fmt, ...) { (void)fd; (void)fmt; return 0; }
#define dprintf capture
static int ios_jit_low_contains(uintptr_t addr) { (void)addr; return 0; }
uintptr_t ios_jit_anon_alias_lookup(uintptr_t addr)
{
    uintptr_t base = (uintptr_t)rx;
    if (addr >= base && addr - base < PAGE) return (uintptr_t)rw + addr - base;
    if (second_present && addr >= base + PAGE && addr - base - PAGE < PAGE)
        return (uintptr_t)rw + 2 * PAGE + addr - base - PAGE;
    return 0;
}
int ios_page_expected_prot(const void *addr)
{
    return protected_page && ((uintptr_t)addr & ~(uintptr_t)0xfff) == protected_page
        ? PROT_READ | PROT_EXEC : PROT_READ | PROT_WRITE;
}
struct state { uint64_t __x[29], __fp, __lr, __sp, __pc; };
#define IOS_STORE_SRC(r) ((r) == 31 ? 0ull : state.__x[r])
'''
helpers = ''.join(function(name) for name in (
    'ios_write_alias', 'ios_alias_write_is_trapped', 'ios_alias_write', 'ios_alias_store_immediate'))

# Restore the former bit-11 guard inside the actual helper for an isolated
# old-policy control. It rejects precisely the captured pre-index mode before
# any access; the corrected helper and complete route below are unchanged.
old_helper = function('ios_alias_store_immediate').replace('ios_alias_store_immediate(', 'old_store_immediate(', 1)
old_helper = old_helper.replace('{\n', '{\n    if (insn & 0x800u) return 0; /* previous scalar guards */\n', 1)
code = prefix + helpers + old_helper + r'''
static int old_route(uint32_t insn, uintptr_t fault_addr, struct state *input)
{
    uint64_t gpr[32]; uintptr_t blocked = 0;
    memcpy(gpr, input->__x, sizeof(input->__x));
    gpr[29] = input->__fp; gpr[30] = input->__lr; gpr[31] = input->__sp;
    return old_store_immediate(insn, fault_addr, gpr, &blocked, 1);
}
#undef __darwin_arm_thread_state64_set_pc_fptr
#define __darwin_arm_thread_state64_set_pc_fptr(st, p) ((st).__pc = (uintptr_t)(p))
static int actual_route(uint32_t insn, uintptr_t fault_addr, struct state *input,
                        uintptr_t *blocked, int honor_guest_prot)
{
    struct state state = *input;
    uint64_t fault_pc = state.__pc;
    uintptr_t alias_fault = 0;
    int emulated = 0, handled = 0;
    if (0) {}
''' + route + r'''
    if (emulated)
    {
''' + advance + r'''
    }
    *input = state; *blocked = alias_fault; assert(handled == emulated); return handled;
}
static void initial(struct state *s)
{
    for (unsigned i = 0; i < 29; i++) s->__x[i] = 0xfeed000000000000ull + i;
    s->__fp = 0xfeed000000000029ull; s->__lr = 0xfeed000000000030ull;
    s->__sp = (uintptr_t)rx + 0x1800; s->__pc = (uintptr_t)rx + 0x300;
}
static uint64_t get(const struct state *s, unsigned r)
{ return r == 31 ? s->__sp : r == 30 ? s->__lr : r == 29 ? s->__fp : s->__x[r]; }
static void set(struct state *s, unsigned r, uint64_t value)
{
    if (r == 31) s->__sp = value;
    else if (r == 30) s->__lr = value;
    else if (r == 29) s->__fp = value;
    else s->__x[r] = value;
}
static uint32_t store(unsigned size, unsigned mode, int imm, unsigned rn, unsigned rt)
{ return 0x38000000u | size << 30 | ((unsigned)imm & 0x1ff) << 12 | mode << 10 | rn << 5 | rt; }
static void reset_bytes(void) { memset(rw, 0xa5, RW_SIZE); }
static void assert_canaries(uintptr_t ea, unsigned width, uint64_t value)
{
    for (unsigned i = 0; i < RX_SIZE; i++)
    {
        uintptr_t a = (uintptr_t)rx + i;
        unsigned char want = a >= ea && a - ea < width ? (unsigned char)(value >> ((a - ea) * 8)) : 0xa5;
        assert(rx[i] == want);
    }
    for (unsigned i = PAGE; i < 2 * PAGE; i++) assert(rw[i] == 0xa5);
}
static void assert_permissions(void)
{
#ifdef __APPLE__
    for (unsigned i = 0; i < RX_SIZE; i += PAGE)
    {
        mach_vm_address_t a = (uintptr_t)rx + i; mach_vm_size_t n = 0;
        vm_region_basic_info_data_64_t info; mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        assert(mach_vm_region(mach_task_self(), &a, &n, VM_REGION_BASIC_INFO_64,
                              (vm_region_info_t)&info, &count, &object) == KERN_SUCCESS);
        assert((info.protection & (VM_PROT_READ | VM_PROT_EXECUTE)) == (VM_PROT_READ | VM_PROT_EXECUTE));
        assert(!(info.protection & VM_PROT_WRITE));
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    }
#else
    FILE *maps = fopen("/proc/self/maps", "r"); assert(maps); char line[512]; unsigned found = 0;
    while (fgets(line, sizeof line, maps))
    {
        unsigned long long lo, hi; char perm[5];
        if (sscanf(line, "%llx-%llx %4s", &lo, &hi, perm) != 3) continue;
        for (unsigned i = 0; i < RX_SIZE; i += PAGE)
            if ((uintptr_t)rx + i >= lo && (uintptr_t)rx + i < hi)
            { assert(perm[0] == 'r' && perm[1] == '-' && perm[2] == 'x'); found |= 1u << (i / PAGE); }
    }
    fclose(maps); assert(found == 3);
#endif
}
static void check(unsigned size, unsigned mode, int imm, unsigned rn, unsigned rt, unsigned far_delta)
{
    struct state s, before, expected; uintptr_t blocked = 0;
    reset_bytes(); initial(&s); set(&s, rn, (uintptr_t)rx + 0x1800);
    if (rt != 31 && rt != rn) set(&s, rt, 0x8877665544332211ull);
    before = s; expected = s;
    uintptr_t base = get(&s, rn), ea = mode == 1 ? base : base + imm;
    uint64_t value = rt == 31 ? 0 : get(&s, rt);
    if (mode == 1 || mode == 3) set(&expected, rn, base + imm);
    expected.__pc += 4;
    assert(actual_route(store(size, mode, imm, rn, rt), ea + far_delta, &s, &blocked, 1));
    assert(!blocked && !memcmp(&s, &expected, sizeof s));
    assert_canaries(ea, 1u << size, value);
    (void)before;
}
static void refused(uint32_t insn, uintptr_t target, struct state *state, uintptr_t wanted_block)
{
    unsigned char bytes[RW_SIZE]; memcpy(bytes, rw, sizeof bytes);
    struct state before = *state; uintptr_t blocked = 0;
    assert(!actual_route(insn, target, state, &blocked, 1));
    assert(blocked == wanted_block && !memcmp(state, &before, sizeof before) && !memcmp(bytes, rw, sizeof bytes));
}
int main(void)
{
    assert(sysconf(_SC_PAGESIZE) <= PAGE && PAGE % sysconf(_SC_PAGESIZE) == 0);
    FILE *file = tmpfile(); assert(file && !ftruncate(fileno(file), RW_SIZE));
    rw = mmap(0, RW_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    void *reservation = mmap(0, RX_SIZE + PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(rw != MAP_FAILED && reservation != MAP_FAILED);
    /* Linux only promises 4 KiB mmap alignment. Model the production 16 KiB
     * host-page geometry explicitly before splitting the alias backing. */
    rx = (unsigned char *)(((uintptr_t)reservation + PAGE - 1) & ~(uintptr_t)(PAGE - 1));
    size_t leading = (uintptr_t)rx - (uintptr_t)reservation;
    size_t trailing = RX_SIZE + PAGE - leading - RX_SIZE;
    if (leading) assert(!munmap(reservation, leading));
    if (trailing) assert(!munmap(rx + RX_SIZE, trailing));
    assert(!((uintptr_t)rx & (PAGE - 1)));
    assert(mmap(rx, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fileno(file), 0) == rx);
    assert(mmap(rx + PAGE, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fileno(file), 2 * PAGE) == rx + PAGE);
    assert_permissions(); reset_bytes();
    struct state s, before; uintptr_t blocked = 0;
    initial(&s); s.__x[8] = (uintptr_t)rx + 0x8e8; before = s;
    assert(store(3, 3, 16, 8, 31) == 0xf8010d1fu);
    assert(!old_route(0xf8010d1fu, (uintptr_t)rx + 0x8f8, &s));
    assert(!memcmp(&s, &before, sizeof s)); assert_canaries(0, 0, 0);
    puts("PASS previous production guard rejects captured STR XZR,[X8,#16]!; no bytes, writeback or PC changed");
    /* Exact native-pool case. The remaining cases exercise guest alias
     * protection metadata and nonadjacent backing within 16 KiB host pages. */
    ios_jit_rx_base_global = rx; ios_jit_rw_base_global = rw; ios_jit_pool_size_global = PAGE;
    assert(actual_route(0xf8010d1fu, (uintptr_t)rx + 0x8f8, &s, &blocked, 1));
    assert(!blocked && s.__x[8] == (uintptr_t)rx + 0x8f8 && s.__pc == before.__pc + 4);
    before.__x[8] += 16; before.__pc += 4; assert(!memcmp(&s, &before, sizeof s));
    assert_canaries((uintptr_t)rx + 0x8f8, 8, 0);
    /* Replay the immediately following f9000688 (STR X8,[X20,#8]).
     * The capture later dereferenced X20+8's stale 0x101; this sequence proves
     * the valid pointer initializer can complete once pre-index writeback is
     * restored. It does not prove the on-device secondary fault disappears. */
    reset_bytes(); initial(&s); s.__x[20] = s.__x[8] = (uintptr_t)rx + 0x8e8;
    uint64_t stale = 0x101; memcpy(rw + 0x8f0, &stale, 8);
    assert(actual_route(0xf8010d1fu, (uintptr_t)rx + 0x8f8, &s, &blocked, 1));
    assert(s.__x[8] == (uintptr_t)rx + 0x8f8);
    assert(actual_route(0xf9000688u, (uintptr_t)rx + 0x8f0, &s, &blocked, 1));
    uint64_t field = 0; memcpy(&field, rx + 0x8f0, 8);
    assert(field == (uintptr_t)rx + 0x8f8 && s.__x[20] == (uintptr_t)rx + 0x8e8);
    puts("PASS captured two-instruction initializer replaces stale0x101 at X20+8 with the correctly advanced X8 through real aliases");
    ios_jit_rx_base_global = ios_jit_rw_base_global = 0; ios_jit_pool_size_global = 0;
    unsigned count = 0;
    for (unsigned size = 0; size < 4; size++)
    for (unsigned mode = 0; mode < 4; mode++) if (mode != 2)
    for (int imm = -256; imm <= 255; imm++)
    {
        check(size, mode, imm, 8, 9, (1u << size) - 1); count++;
    }
    for (unsigned size = 0; size < 4; size++)
    for (unsigned mode = 0; mode < 4; mode++) if (mode != 2)
    for (unsigned rn = 29; rn < 32; rn++)
    for (unsigned rt = 29; rt < 32; rt++) if (rt != rn || mode == 0 || rn == 31)
        check(size, mode, -16, rn, rt, 0);
    reset_bytes(); initial(&s); s.__x[8] = (uintptr_t)rx + 0x200;
    for (unsigned size = 0; size < 4; size++)
    {
        refused(store(size, 2, 16, 8, 31), s.__x[8] + 16, &s, 0); /* STTR */
        refused(store(size, 3, 16, 8, 31) | 0x400000u, s.__x[8] + 16, &s, 0); /* load */
        refused(store(size, 3, 16, 8, 31) | 0x04000000u, s.__x[8] + 16, &s, 0); /* SIMD */
        refused(store(size, 3, 16, 8, 31) | 0x200000u, s.__x[8] + 16, &s, 0); /* register-offset family */
        refused(store(size, 3, 16, 8, 8), s.__x[8] + 16, &s, 0); /* unpredictable overlap */
    }
    refused(0xf8010d1fu, s.__x[8] + 24, &s, 0); /* FAR outside store */
    s.__x[8] = 0; refused(store(3, 0, 0, 8, 31), 0, &s, 0);
    s.__x[8] = (uintptr_t)rx + RX_SIZE; refused(store(3, 0, 0, 8, 31), s.__x[8], &s, 0);
    s.__x[8] = UINTPTR_MAX - 3; refused(store(3, 0, 0, 8, 31), s.__x[8], &s, 0);
    /* Validate both fragments before touching either, and commit writeback
     * exactly once after FEX clears a real guest protection fault. */
    for (unsigned boundary = 0x1000; boundary <= PAGE; boundary += PAGE - 0x1000)
    {
        reset_bytes(); initial(&s); s.__x[8] = (uintptr_t)rx + boundary - 20;
        uintptr_t ea = s.__x[8] + 16;
        protected_page = ((uintptr_t)rx + boundary) & ~(uintptr_t)0xfff;
        refused(0xf8010d1fu, ea, &s, protected_page);
        protected_page = 0;
        if (boundary == PAGE)
        {
            second_present = 0; refused(0xf8010d1fu, ea, &s, 0); second_present = 1;
        }
        before = s;
        assert(actual_route(0xf8010d1fu, ea + 7, &s, &blocked, 1));
        assert(!blocked && s.__x[8] == ea && s.__pc == before.__pc + 4);
        assert_canaries(ea, 8, 0);
    }
    assert_permissions();
    printf("PASS production STR immediate decoder/route: exact f8010d1f, %u width/mode/signed-offset cases, FP/LR/SP/XZR, invalid family/alias/protection refusal, full-span atomicity, writeback/PC and unchanged RX permissions\n", count);
    munmap(rx, RX_SIZE); munmap(rw, RW_SIZE); fclose(file);
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-str-immediate-') as temp:
    src = Path(temp) / 'check.c'
    binary = Path(temp) / 'check'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(src), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
