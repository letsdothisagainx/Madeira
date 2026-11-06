#!/usr/bin/env python3
"""Replay same-image and cross-module exclusive loops through production recovery.

The old inline handler is compiled as a control and refuses 0xc80afd28 when
its LDAXR destination is XZR. The new helper, alias/ownership validation and
shared successful-emulation PC advance are compiled unchanged. Real RX/RW
file aliases model the live debugger pool; no fixture writes through RX.
The captured ntdll 0x8809fc08 loop runs against a second FEX PE mapping, with
the actual production generation-token accessor and executable-code bounds.
Independent ownership, retired/unmapped slots, executable protections and
generation changes during host queries are checked before atomic completion.
Apple ARM64 executes the production exclusive primitive. Other hosts use a
fresh acquire-load/release-CAS abstraction solely for portable validation;
the IPA gate supplies the actual ARM64 acquire/exclusive/release coverage.
"""
from pathlib import Path
import os
import platform
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
virtual = (root / 'build/ntdll-unix/virtual_ios.c').read_text()


def function(text, name):
    import re
    found = re.search(r'(?m)^(?:static )?(?:int|unsigned(?: long long)?|uintptr_t|void \*)\s*' + re.escape(name) + r'\s*\(', text)
    assert found, name
    return text[found.start():text.index('\n}', found.start()) + 2] + '\n'


# The existing retained-value algorithm is unchanged by this fix, so its
# current source is also the prior-build control (no historical checkout or
# synthetic copy of that decoder is needed in a shallow Actions checkout).
previous = source
start = previous.index('                    else if ((insn & 0x3fe07c00) == 0x08007c00)')
old_case = previous[start:previous.index('                    /* iOS-Madeira ml626: SWP', start)]
start = source.index('                    /* Aligned load-discard exclusive loop:')
route_case = source[start:source.index("                    /* FEX's native backpatch lock uses CASAL", start)]
pc_start = source.index('                        /* Advance PC past the emulated instruction */')
pc_end = source.index('                        static volatile int emul_count', pc_start)
pc_advance = source[pc_start:pc_end]

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef unsigned mach_msg_type_number_t;
typedef unsigned mach_port_t;
typedef int kern_return_t;
typedef int *vm_region_info_t;
typedef struct { int protection, max_protection; } vm_region_basic_info_data_64_t;
#define VM_REGION_BASIC_INFO_COUNT_64 1
#define VM_REGION_BASIC_INFO_64 1
#define MACH_PORT_NULL 0
#define KERN_SUCCESS 0
#define VM_PROT_READ PROT_READ
#define VM_PROT_WRITE PROT_WRITE
#define VM_PROT_EXECUTE PROT_EXEC
static int mach_task_self(void) { return 0; }
static int capture(int fd, const char *fmt, ...) { (void)fd; (void)fmt; return 0; }
#define dprintf capture
static unsigned char *rx, *rw;
static size_t mapped_size;
static int permit_read = 1, permit_write = 1, permit_code = 1;
static int code_nx, data_nx;
static unsigned mutate_generation;
static void change_generation(void);
static unsigned fail_read;
typedef struct { unsigned char padding[0x60]; void *Peb; } TEB;
static _Thread_local TEB fixture_teb;
static int permit_teb = 1;
void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
static int ios_jit_low_contains(uintptr_t address) { (void)address; return 0; }
uintptr_t ios_jit_anon_alias_lookup(uintptr_t address) { (void)address; return 0; }
int ios_page_expected_prot(const void *address) { (void)address; return PROT_READ | PROT_WRITE; }
static int inside(uintptr_t address, size_t length, const void *base)
{
    uintptr_t start = (uintptr_t)base;
    return address >= start && address - start <= mapped_size && length <= mapped_size - (address - start);
}
static int mach_vm_read_overwrite(int task, uintptr_t address, size_t length, uintptr_t out, size_t *got)
{
    (void)task; *got = 0;
    if (permit_teb && address == (uintptr_t)&fixture_teb.Peb && length == sizeof(void *))
    { memcpy((void *)out, &fixture_teb.Peb, length); *got = length; return 0; }
    if (fail_read || !permit_read || !inside(address, length, rx)) return 1;
    memcpy((void *)out, (const void *)address, length); *got = length; return 0;
}
static int mach_vm_region(int task, uintptr_t *address, size_t *length, int flavor,
                          int *raw, unsigned *count, mach_port_t *object)
{
    (void)task; (void)count; assert(flavor == VM_REGION_BASIC_INFO_64);
    if (mutate_generation) change_generation();
    vm_region_basic_info_data_64_t *info = (void *)raw;
    if (inside(*address, 1, rx))
    {
        unsigned data = *address - (uintptr_t)rx >= mapped_size / 2;
        *address = (uintptr_t)rx + (data ? mapped_size / 2 : 0); *length = mapped_size / 2;
        info->protection = (permit_read ? PROT_READ : 0) |
            (permit_code && !(data ? data_nx : code_nx) ? PROT_EXEC : 0);
    }
    else if (inside(*address, 1, rw))
    {
        *address = (uintptr_t)rw; *length = mapped_size;
        info->protection = PROT_READ | (permit_write ? PROT_WRITE : 0);
    }
    else return 1;
    info->max_protection = info->protection; *object = MACH_PORT_NULL; return 0;
}
static int mach_port_deallocate(int task, int object) { (void)task; (void)object; return 0; }
MAPPINGS
'''

decl_start = virtual.index('#define IOS_JIT_MAX_MAPPINGS')
decl_end = virtual.index('static int ios_jit_mapping_count = 0;', decl_start) + len('static int ios_jit_mapping_count = 0;')
prefix = prefix.replace('MAPPINGS', virtual[decl_start:decl_end])

helpers = ''.join(function(source, name) for name in (
    'ios_write_alias', 'ios_alias_write_is_trapped', 'ios_fault_read_insn'))
helpers += ''.join(function(virtual, name) for name in ('ios_jit_new_generation', 'ios_jit_code_bounds', 'ios_jit_pool_access_token'))
helpers += r'''
static void change_generation(void)
{
    unsigned index = mutate_generation - 1; mutate_generation = 0;
    assert(index < (unsigned)ios_jit_mapping_count);
    ios_jit_mappings[index].generation = ios_jit_new_generation();
}
'''
helpers += function(source, 'ios_exclusive_code_readable')
helpers += function(source, 'ios_alias_exclusive_span')
primitive = function(source, 'ios_mach_alias_exclusive_store')
if platform.machine().lower() in ('aarch64', 'arm64'):
    primitive = primitive.replace('ios_mach_alias_exclusive_store(', 'exclusive_primitive_actual(', 1)
else:
    primitive = r'''
/* Portable host model only; Apple ARM64 compiles and executes the actual
 * production ldaxr/stlxr primitive above, without this abstraction. */
static unsigned exclusive_primitive_actual(uintptr_t address, uint64_t value, unsigned size)
{
#define ATTEMPT(T) do { T seen = __atomic_load_n((T *)address, __ATOMIC_ACQUIRE); \
    return !__atomic_compare_exchange_n((T *)address, &seen, (T)value, 1, __ATOMIC_RELEASE, __ATOMIC_RELAXED); } while (0)
    switch (size) { case 0: ATTEMPT(uint8_t); case 1: ATTEMPT(uint16_t); case 2: ATTEMPT(uint32_t); default: ATTEMPT(uint64_t); }
#undef ATTEMPT
}
'''

code = prefix + helpers + primitive + r'''
static _Thread_local unsigned injected_failure;
static unsigned primitive_calls, primitive_failures;
static unsigned ios_mach_alias_exclusive_store(uintptr_t address, uint64_t value, unsigned size)
{
    __atomic_add_fetch(&primitive_calls, 1, __ATOMIC_RELAXED);
    if (injected_failure)
    {
        injected_failure--;
        __atomic_add_fetch(&primitive_failures, 1, __ATOMIC_RELAXED); return 1;
    }
    unsigned status = exclusive_primitive_actual(address, value, size);
    if (status) __atomic_add_fetch(&primitive_failures, 1, __ATOMIC_RELAXED);
    return status;
}
''' + function(source, 'ios_mach_emulate_exclusive_loop') + function(source, 'ios_mach_emulate_exclusive_add_loop') + function(source, 'ios_mach_emulate_exclusive_conditional_loop') + r'''
struct state { uint64_t __x[29], __fp, __lr, __sp, __pc; uint32_t __cpsr; };
static pthread_mutex_t route_lock = PTHREAD_MUTEX_INITIALIZER;
#define IOS_STORE_SRC(r) ((r) == 31 ? 0ull : state.__x[r])
static int old_route(uint32_t insn, uintptr_t rw_addr, uintptr_t fault_addr, struct state *input)
{
    struct state state = *input; uint64_t fault_pc = state.__pc; int emulated = 0;
    if (0) {}
''' + old_case + r'''
    *input = state; return emulated;
}
/* This route uses the fixture's standalone state, not Darwin's state type. */
#ifdef __darwin_arm_thread_state64_set_pc_fptr
#undef __darwin_arm_thread_state64_set_pc_fptr
#endif
#define __darwin_arm_thread_state64_set_pc_fptr(st, value) ((st).__pc = (uintptr_t)(value))
static int route(uint32_t insn, uintptr_t fault_addr, struct state *input, void *owner)
{
    /* Production uses one Mach exception server. Native writers to the
     * shared RW backing can still race the real exclusive primitive. */
    assert(!pthread_mutex_lock(&route_lock));
    struct state state = *input;
    uint64_t fault_pc = state.__pc; int handled = 0, emulated = 0, in_jit = 1;
    uintptr_t thread_teb = (uintptr_t)&fixture_teb;
    fixture_teb.Peb = owner ? owner : (void *)0x1111;
''' + route_case + r'''
    if (emulated)
    {
''' + pc_advance + r'''
    }
    *input = state; assert(handled == emulated);
    assert(!pthread_mutex_unlock(&route_lock)); return handled;
}
static uintptr_t code_pc(void) { return (uintptr_t)rx + 0x104; }
static uint32_t load_insn(unsigned size, unsigned acquire, unsigned rn)
{ return 0x085f7c1fu | size << 30 | acquire << 15 | rn << 5; }
static uint32_t store_insn(unsigned size, unsigned release, unsigned status, unsigned rn, unsigned rt)
{ return 0x08007c00u | size << 30 | release << 15 | status << 16 | rn << 5 | rt; }
static uint32_t retry_insn(unsigned status) { return 0x35000000u | ((unsigned)-2 & 0x7ffff) << 5 | status; }
static void set_code(uint32_t load, uint32_t store, uint32_t retry)
{
    uint32_t words[4] = {load, store, retry, 0xd5033bbfu};
    memcpy(rw + 0x100, words, sizeof words);
}
static uint64_t read_cell(unsigned size)
{
    uint64_t value = 0; memcpy(&value, rx + 0x200, 1u << size); return value;
}
static uint64_t reg(const struct state *state, unsigned r)
{ return r < 29 ? state->__x[r] : r == 29 ? state->__fp : r == 30 ? state->__lr : state->__sp; }
static int retry_branch(struct state *state)
{
    uint32_t branch; memcpy(&branch, (const void *)state->__pc, 4);
    assert((branch & 0xff000000u) == 0x35000000u);
    if ((uint32_t)reg(state, branch & 31))
    {
        int32_t offset = (int32_t)(branch << 8) >> 13;
        state->__pc += (int64_t)offset * 4; return 1;
    }
    state->__pc += 4; return 0;
}
static void initial(struct state *state, uint64_t value)
{
    for (unsigned i = 0; i < 29; i++) state->__x[i] = 0xfeed000000000000ull | i;
    state->__fp = 0xfeed000000000029ull; state->__lr = 0xfeed000000000030ull;
    state->__x[8] = value; state->__x[9] = (uintptr_t)rx + 0x200;
    state->__pc = code_pc(); state->__sp = 0x100000000ull;
}
static void complete(uint32_t insn, struct state *state)
{
    for (unsigned attempts = 0;; attempts++)
    {
        assert(attempts < 100000);
        state->__pc = code_pc();
        assert(route(insn, reg(state, (insn >> 5) & 31), state, 0));
        assert(state->__pc == code_pc() + 4 && reg(state, (insn >> 16) & 31) <= 1);
        if (!retry_branch(state)) break;
        assert(state->__pc == code_pc() - 4);
        /* Native retry executes the already validated discarded load. */
    }
    assert(state->__pc == code_pc() + 8);
}
enum { THREADS = 8, ROUNDS = 5000 };
static unsigned completed, torn, native_done;
static void *native_contend(void *arg)
{
    (void)arg;
    for (unsigned i = 1; !__atomic_load_n(&native_done, __ATOMIC_RELAXED); i = i % ROUNDS + 1)
    {
        uint64_t token = ((uint64_t)(THREADS + 1) << 56) | ((uint64_t)i << 24) | ((i ^ 0x5a5a5a) & 0xffffff);
        __atomic_exchange_n((uint64_t *)(rw + 0x200), token, __ATOMIC_ACQ_REL);
    }
    return 0;
}
static void *contend(void *arg)
{
    uintptr_t id = (uintptr_t)arg;
    for (unsigned i = 1; i <= ROUNDS; i++)
    {
        uint64_t token = ((id + 1) << 56) | ((uint64_t)i << 24) | ((i ^ 0x5a5a5a) & 0xffffff);
        struct state state; initial(&state, token); complete(0xc80afd28u, &state);
        __atomic_add_fetch(&completed, 1, __ATOMIC_RELAXED);
        uint64_t seen = __atomic_load_n((uint64_t *)(rx + 0x200), __ATOMIC_ACQUIRE);
        unsigned seq = (seen >> 24) & 0xffffffffu;
        if (!(seen >> 56) || (seen >> 56) > THREADS + 1 || !seq || seq > ROUNDS ||
            (seen & 0xffffff) != ((seq ^ 0x5a5a5a) & 0xffffff))
            __atomic_add_fetch(&torn, 1, __ATOMIC_RELAXED);
    }
    return 0;
}
static unsigned payload;
static void *publish(void *arg)
{
    (void)arg;
    for (unsigned i = 1; i <= ROUNDS; i++)
    {
        while (__atomic_load_n((uint64_t *)(rx + 0x200), __ATOMIC_ACQUIRE)) sched_yield();
        payload = i; struct state state; initial(&state, 1); complete(0xc80afd28u, &state);
    }
    return 0;
}
static void *consume(void *arg)
{
    (void)arg;
    for (unsigned i = 1; i <= ROUNDS; i++)
    {
        while (!__atomic_load_n((uint64_t *)(rx + 0x200), __ATOMIC_ACQUIRE)) sched_yield();
        assert(payload == i); __atomic_store_n((uint64_t *)(rw + 0x200), 0, __ATOMIC_RELEASE);
    }
    return 0;
}
static unsigned cross_counter;
static size_t cross_offset;
static uint64_t cross_read(unsigned size)
{ uint64_t value = 0; memcpy(&value, rx + cross_offset, 1u << size); return value; }
static void *cross_module_counter(void *argument)
{
    (void)argument;
    for (unsigned i = 0; i < ROUNDS; i++)
    {
        uint32_t expected;
        do
        {
            expected = 0;
            if (__atomic_compare_exchange_n((uint32_t *)(rw + cross_offset), &expected, 1,
                                            0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) break;
            sched_yield();
        } while (1);
        /* The normal lock owner releases its own acquired lock through the
         * captured ntdll store loop. This is not a forced recovery unlock. */
        cross_counter++;
        struct state state; initial(&state, 0); state.__x[0] = (uintptr_t)rx + cross_offset;
        complete(0x8809fc08u, &state);
    }
    return 0;
}
static void cross_module_refuse(void *owner)
{
    struct state state, before;
    initial(&state, 0x11223344u); state.__x[0] = (uintptr_t)rx + cross_offset; before = state;
    uint64_t data = cross_read(3); unsigned calls = primitive_calls;
    assert(!route(0x8809fc08u, state.__x[0], &state, owner));
    assert(!memcmp(&state, &before, sizeof state) && cross_read(3) == data && primitive_calls == calls);
}
static void cross_module_accept(void *owner)
{
    struct state state;
    do
    {
        initial(&state, 0x11223344u); state.__x[0] = (uintptr_t)rx + cross_offset;
        assert(route(0x8809fc08u, state.__x[0], &state, owner));
        assert(state.__pc == code_pc() + 4 && state.__x[9] <= 1);
    } while (state.__x[9]);
    assert(cross_read(2) == 0x11223344u);
}
/* ntdll's 32-bit discard-load loop writes a live critical-section field in
 * libarm64ecfex. Both images are shared, but their PE identities differ. */
static void cross_module_captured(void)
{
    struct state state, before;
    ios_jit_mapping_count = 2; cross_offset = mapped_size / 2 + 0x200;
    ios_jit_mappings[0].pe_base = (void *)0x100000000ull; /* ntdll */
    ios_jit_mappings[0].jit_base = rx;
    ios_jit_mappings[0].size = mapped_size / 2;
    ios_jit_mappings[0].owner_peb = 0;
    ios_jit_mappings[1].pe_base = (void *)0x200000000ull; /* libarm64ecfex */
    ios_jit_mappings[1].jit_base = rx + mapped_size / 2;
    ios_jit_mappings[1].size = mapped_size / 2;
    ios_jit_mappings[1].owner_peb = 0;
    ios_jit_mappings[1].generation = ios_jit_new_generation();
    set_code(0x885ffc1fu, 0x8809fc08u, 0x35ffffc9u);
    assert(load_insn(2, 1, 0) == 0x885ffc1fu &&
           store_insn(2, 1, 9, 0, 8) == 0x8809fc08u && retry_insn(9) == 0x35ffffc9u);
    memset(rw + cross_offset, 0xa5, 16);
    initial(&state, 1); state.__x[0] = (uintptr_t)rx + cross_offset; before = state;
    fprintf(stderr, "Replaying captured cross-module ntdll -> FEX STLXR 8809fc08 with shared live owners\n");
    injected_failure = 1;
    assert(route(0x8809fc08u, state.__x[0], &state, 0));
    assert(state.__x[9] == 1 && cross_read(2) == 0xa5a5a5a5u && state.__pc == code_pc() + 4);
    assert(retry_branch(&state) && state.__pc == code_pc() - 4);
    for (unsigned attempts = 0;; attempts++)
    {
        assert(attempts < 100000); state.__pc = code_pc();
        assert(route(0x8809fc08u, state.__x[0], &state, 0));
        assert(state.__pc == code_pc() + 4 && state.__x[9] <= 1);
        if (!retry_branch(&state)) break;
        assert(state.__pc == code_pc() - 4);
    }
    assert(state.__x[9] == 0 && cross_read(2) == 1 && state.__pc == code_pc() + 8);
    for (unsigned r = 0; r < 29; r++) if (r != 9) assert(state.__x[r] == before.__x[r]);
    assert(state.__fp == before.__fp && state.__lr == before.__lr && state.__sp == before.__sp);
    uint32_t saved_code[4]; memcpy(saved_code, rx + 0x100, sizeof saved_code);
    memset(rw + cross_offset, 0, 4); pthread_t threads[THREADS];
    for (unsigned i = 0; i < THREADS; i++) assert(!pthread_create(&threads[i], 0, cross_module_counter, 0));
    for (unsigned i = 0; i < THREADS; i++) assert(!pthread_join(threads[i], 0));
    assert(cross_counter == THREADS * ROUNDS && !cross_read(2));
    assert(!memcmp(saved_code, rx + 0x100, sizeof saved_code));
    for (unsigned i = 4; i < 16; i++) assert(rx[cross_offset + i] == 0xa5);
    /* Shared images and images owned by the actual calling process are
     * independently authorized. Neither can authorize a foreign peer. */
    ios_jit_mappings[0].owner_peb = (void *)0x1234;
    cross_module_refuse((void *)0x5678);
    cross_module_accept((void *)0x1234);
    ios_jit_mappings[1].owner_peb = (void *)0x1234;
    cross_module_refuse((void *)0x5678);
    cross_module_accept((void *)0x1234);
    ios_jit_mappings[0].owner_peb = 0;
    cross_module_accept((void *)0x1234);
    ios_jit_mappings[1].owner_peb = (void *)0x5678;
    cross_module_refuse((void *)0x1234);
    ios_jit_mappings[1].owner_peb = 0;
    /* Retirement tombstones and an instruction sequence straddling an
     * unregistered code range do not inherit the pool's arithmetic alias. */
    ios_jit_mappings[0].size = 0; cross_module_refuse(0); ios_jit_mappings[0].size = mapped_size / 2;
    ios_jit_mappings[1].size = 0; cross_module_refuse(0); ios_jit_mappings[1].size = mapped_size / 2;
    ios_jit_mappings[0].pe_base = 0; cross_module_refuse(0); ios_jit_mappings[0].pe_base = (void *)0x100000000ull;
    ios_jit_mappings[1].pe_base = 0; cross_module_refuse(0); ios_jit_mappings[1].pe_base = (void *)0x200000000ull;
    ios_jit_mappings[0].size = 0x108; cross_module_refuse(0); ios_jit_mappings[0].size = mapped_size / 2;
    ios_jit_mappings[0].text_size = 8; cross_module_refuse(0); ios_jit_mappings[0].text_size = 0x10;
    ios_jit_mappings[0].text_size = 0; cross_module_refuse(0); ios_jit_mappings[0].text_size = 0x10;
    for (unsigned i = 0; i < 2; i++)
    {
        ios_jit_mappings[i].generation = 0; cross_module_refuse(0);
        ios_jit_mappings[i].generation = ios_jit_new_generation();
        ios_jit_mappings[i].unmapped = 1; cross_module_refuse(0);
        ios_jit_mappings[i].unmapped = 0;
        ios_jit_mappings[i].generation = ios_jit_new_generation();
        /* Replace a slot with the same PE, owner and VA while a Mach query
         * is in progress. The old token must not authorize the new image
         * incarnation, even though all pointer arithmetic still agrees. */
        mutate_generation = i + 1; cross_module_refuse(0);
        assert(!mutate_generation); cross_module_accept(0);
    }
    code_nx = 1; cross_module_refuse(0); code_nx = 0;
    data_nx = 1; cross_module_refuse(0); data_nx = 0;
    permit_write = 0; cross_module_refuse(0); permit_write = 1;
    cross_module_accept(0);
    printf("PASS captured cross-module ntdll code / FEX data exclusive loop: status/PC/register preservation, %u lock-protected increments without lost updates, shared/private ownership, retirement and generation-race rejection, unchanged adjacent code/data\n", cross_counter);
}
int main(void)
{
    mapped_size = 2 * (size_t)sysconf(_SC_PAGESIZE);
    FILE *file = tmpfile(); assert(file && !ftruncate(fileno(file), mapped_size));
    rw = mmap(0, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    rx = mmap(0, mapped_size, PROT_READ | PROT_EXEC, MAP_SHARED, fileno(file), 0);
    assert(rw != MAP_FAILED && rx != MAP_FAILED);
    memset(rw, 0xa5, mapped_size);
    ios_jit_rx_base_global = rx; ios_jit_rw_base_global = rw; ios_jit_pool_size_global = mapped_size;
    ios_jit_mappings[0].pe_base = (void *)0x100000000ull; ios_jit_mappings[0].jit_base = rx;
    ios_jit_mappings[0].size = mapped_size; ios_jit_mapping_count = 1;
    ios_jit_mappings[0].generation = ios_jit_new_generation();
    ios_jit_mappings[0].text_offset = 0x100; ios_jit_mappings[0].text_size = 0x10;
    assert(load_insn(3, 1, 9) == 0xc85ffd3fu && store_insn(3, 1, 10, 9, 8) == 0xc80afd28u && retry_insn(10) == 0x35ffffcau);
    set_code(0xc85ffd3fu, 0xc80afd28u, 0x35ffffcau);
    struct state state, before; initial(&state, 0x1122334455667788ull); before = state;
    assert(!old_route(0xc80afd28u, (uintptr_t)rw + 0x200, state.__x[9], &state));
    assert(!memcmp(&state, &before, sizeof state) && read_cell(3) == 0xa5a5a5a5a5a5a5a5ull);
    puts("PASS old production control reproduces captured shcore STLXR refusal without modifying registers or data");
    injected_failure = 1;
    assert(route(0xc80afd28u, state.__x[9], &state, 0));
    assert(state.__x[10] == 1 && state.__pc == code_pc() + 4 && read_cell(3) == 0xa5a5a5a5a5a5a5a5ull);
    assert(retry_branch(&state) && state.__pc == code_pc() - 4);
    complete(0xc80afd28u, &state); assert(read_cell(3) == before.__x[8]);
    for (unsigned r = 0; r < 29; r++) if (r != 10) assert(state.__x[r] == before.__x[r]);
    assert(state.__sp == before.__sp && state.__fp == before.__fp && state.__lr == before.__lr);
    for (unsigned size = 0; size < 4; size++)
    for (unsigned acquire = 0; acquire < 2; acquire++)
    for (unsigned release = 0; release < 2; release++)
    {
        uint32_t store = store_insn(size, release, 10, 9, 8);
        set_code(load_insn(size, acquire, 9), store, retry_insn(10));
        memset(rw + 0x200, 0xa5, 16); initial(&state, 0x1122334455667788ull); complete(store, &state);
        uint64_t mask = size == 3 ? ~0ull : (1ull << (8u << size)) - 1;
        assert(read_cell(size) == (0x1122334455667788ull & mask));
        for (unsigned i = 1u << size; i < 16; i++) assert(rx[0x200 + i] == 0xa5);
    }
    /* FP/LR are outside Darwin's __x[29], but remain legal source/status
     * encodings; Ws writes must zero-extend and must never overwrite SP. */
    for (unsigned r = 29; r <= 30; r++)
    {
        uint32_t store = store_insn(3, 1, 10, 9, r);
        set_code(load_insn(3, 1, 9), store, retry_insn(10));
        initial(&state, 1); uint64_t value = reg(&state, r); before = state;
        complete(store, &state); assert(read_cell(3) == value && state.__fp == before.__fp && state.__lr == before.__lr);
        store = store_insn(3, 1, r, 9, 8);
        set_code(load_insn(3, 1, 9), store, retry_insn(r));
        initial(&state, value); before = state; complete(store, &state);
        assert(read_cell(3) == value && !reg(&state, r) && state.__sp == before.__sp);
    }
    {
        uint32_t store = store_insn(3, 1, 10, 9, 31);
        set_code(load_insn(3, 1, 9), store, retry_insn(10));
        initial(&state, 1); complete(store, &state); assert(!read_cell(3));
    }
    set_code(0xc85ffd3fu, 0xc80afd28u, 0x35ffffcau);
    /* Every invalid input must leave all registers, PC and target bytes alone. */
#define REFUSE(expression) do { initial(&state, 7); before = state; uint64_t value = read_cell(3); \
    assert(!(expression)); assert(!memcmp(&state, &before, sizeof state) && read_cell(3) == value); } while (0)
    REFUSE(route(0xc80afd28u, (uintptr_t)rx + 0x204, &state, 0));
    initial(&state, 7); state.__x[9]++; before = state;
    assert(!route(0xc80afd28u, state.__x[9], &state, 0) && !memcmp(&state, &before, sizeof state));
    permit_write = 0; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); permit_write = 1;
    permit_read = 0; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); permit_read = 1;
    permit_code = 0; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); permit_code = 1;
    fail_read = 1; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); fail_read = 0;
    permit_teb = 0; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); permit_teb = 1;
    ios_jit_mappings[0].pe_base = 0; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); ios_jit_mappings[0].pe_base = (void *)0x100000000ull;
    ios_jit_mappings[0].owner_peb = (void *)0x1234; REFUSE(route(0xc80afd28u, state.__x[9], &state, (void *)0x5678));
    do { initial(&state, 9); assert(route(0xc80afd28u, state.__x[9], &state, (void *)0x1234)); } while(state.__x[10]);
    assert(read_cell(3) == 9);
    ios_jit_mappings[0].owner_peb = 0;
    ios_jit_pool_size_global = 0x204; REFUSE(route(0xc80afd28u, state.__x[9], &state, 0)); ios_jit_pool_size_global = mapped_size;
    initial(&state, 7); state.__x[9] = (uintptr_t)rx + mapped_size; before = state;
    assert(!route(0xc80afd28u, state.__x[9], &state, 0) && !memcmp(&state, &before, sizeof state));
    uint32_t broken[][3] = {
        {0xc85ffd28u, 0xc80afd28u, 0x35ffffcau}, /* retained-load loop belongs to existing CAS path */
        {0x885ffd3fu, 0xc80afd28u, 0x35ffffcau}, /* wrong load width */
        {0xc85ffd3fu, 0xc80afd28u, 0x35ffffeau}, /* retry does not return to load */
        {0xc85ffd3fu, 0xc80afd28u, 0x34ffffcau}, /* CBZ reverses retry condition */
        {0xc85ffd3fu, 0xc80afd28u, 0x35ffffcbu}, /* retry uses wrong status */
        {0xc85ffd3fu, 0xc809fd28u, 0x35ffffc9u}, /* status overlaps base */
        {0xc85ffd3fu, 0xc808fd28u, 0x35ffffc8u}, /* status overlaps source */
    };
    for (unsigned i = 0; i < sizeof broken / sizeof broken[0]; i++)
    { set_code(broken[i][0], broken[i][1], broken[i][2]); REFUSE(route(broken[i][1], state.__x[9], &state, 0)); }
#undef REFUSE
    set_code(0xc85ffd3fu, 0xc80afd28u, 0x35ffffcau);
    uint32_t saved_code[4]; memcpy(saved_code, rx + 0x100, sizeof saved_code);
    memset(rw + 0x200, 0, 16); pthread_t threads[THREADS], native_thread;
    assert(!pthread_create(&native_thread, 0, native_contend, 0));
    for (uintptr_t i = 0; i < THREADS; i++) assert(!pthread_create(&threads[i], 0, contend, (void *)i));
    for (unsigned i = 0; i < THREADS; i++) assert(!pthread_join(threads[i], 0));
    __atomic_store_n(&native_done, 1, __ATOMIC_RELAXED); assert(!pthread_join(native_thread, 0));
    assert(completed == THREADS * ROUNDS && !torn);
    __atomic_store_n((uint64_t *)(rw + 0x200), 0, __ATOMIC_RELAXED);
    assert(!pthread_create(&threads[0], 0, publish, 0) && !pthread_create(&threads[1], 0, consume, 0));
    assert(!pthread_join(threads[0], 0) && !pthread_join(threads[1], 0));
    assert(!memcmp(saved_code, rx + 0x100, sizeof saved_code));
    for (unsigned i = 0; i < mapped_size; i++)
        if (!(i >= 0x100 && i < 0x110) && !(i >= 0x200 && i < 0x210)) assert(rx[i] == 0xa5);
    cross_module_captured();
    printf("PASS production exclusive recovery: exact shcore instruction, widths/orderings, status/retry/PC, invalid owner/mapping/code rejection, %u concurrent completions, no tearing, release/acquire publication; primitive failures=%u\n", completed, primitive_failures);
    munmap(rx, mapped_size); munmap(rw, mapped_size); fclose(file);
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='madeira-alias-exclusive-') as temp:
        file = Path(temp) / 'check.c'
        binary = Path(temp) / 'check'
        file.write_text(code)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread', str(file), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print('ARM64 production exclusive primitive' if platform.machine().lower() in ('arm64', 'aarch64') else
          'Portable primitive abstraction; actual ARM64 instructions run in the IPA regression gate')


if __name__ == '__main__':
    main()
