#!/usr/bin/env python3
"""Production retained register-add exclusive recovery, including its old failure.

Reuse the complete mapping/alias fixture without executing its independent
suite. Both helpers, the dispatch block and PC advancement are production
source. This test never replaces the corrected decoder with a model.
"""
from pathlib import Path
import os
import runpy
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
shared = runpy.run_path(str(root / 'tests/host/check-jit-alias-exclusive.py'))
base = shared['code'].replace('int main(void)',
    'static void previous_fixture_main(void) __attribute__((unused));\nstatic void previous_fixture_main(void)', 1)
base = base.replace('static unsigned mutate_generation;', 'static unsigned mutate_generation, mutation_queries;')
# The production OR route first tries its discard-load helper, which rejects
# this retained-load shape. Mutate during the second (register-add) helper's
# code query, rather than before that helper takes its initial snapshot.
base = base.replace('if (mutate_generation) change_generation();',
                    'if (mutate_generation && ++mutation_queries == 2) change_generation();')
code = base + r'''
static uintptr_t add_pc(void) { return (uintptr_t)rx + 0x108; }
static uint64_t add_mask(unsigned size) { return size == 3 ? ~0ull : 0xffffffffu; }
static uint32_t add_store(unsigned size, unsigned release)
{ return 0x08007c00u | size << 30 | release << 15 | 16 << 16 | 12 << 5 | 15; }
static uint32_t add_load(unsigned size, unsigned acquire)
{ return 0x085f7c00u | size << 30 | acquire << 15 | 12 << 5 | 15; }
static uint32_t add_math(unsigned size, unsigned sub, unsigned rm)
{ return 0x0b000000u | (size == 3 ? 0x80000000u : 0) | sub << 30 | rm << 16 | 15 << 5 | 15; }
static void add_code(unsigned size, unsigned sub, unsigned acquire, unsigned release)
{
    uint32_t words[] = {add_load(size, acquire), add_math(size, sub, 10),
                        add_store(size, release), 0x35ffffb0u, 0xd5033bbfu};
    memcpy(rw + 0x100, words, sizeof words);
}
static void add_initial(struct state *s, unsigned size, unsigned sub, uint64_t seen, uint64_t delta)
{
    initial(s, 0); s->__pc = add_pc();
    s->__x[10] = delta; s->__x[12] = (uintptr_t)rx + 0x200;
    s->__x[15] = (sub ? seen - delta : seen + delta) & add_mask(size);
}
static void add_put(unsigned size, uint64_t v) { memcpy(rw + 0x200, &v, 1u << size); }
static void add_preserve(const struct state *s, const struct state *old)
{
    for (unsigned i = 0; i < 29; i++) if (i != 16) assert(s->__x[i] == old->__x[i]);
    assert(s->__fp == old->__fp && s->__lr == old->__lr && s->__sp == old->__sp);
}
static void add_refuse(uint32_t insn, uintptr_t address, void *owner)
{
    struct state s, old; add_initial(&s, 3, 0, 0, 1); old = s;
    uint64_t value = read_cell(3);
    assert(!route(insn, address, &s, owner));
    assert(!memcmp(&s, &old, sizeof s) && read_cell(3) == value);
}
enum { ADD_THREADS = 8, ADD_ROUNDS = 4000 };
static unsigned add_size, add_failures;
static void *add_counter(void *argument)
{
    (void)argument;
    for (unsigned i = 0; i < ADD_ROUNDS; i++)
    for (unsigned attempt = 0;; attempt++)
    {
        assert(attempt < 100000);
        uint64_t loaded = add_size == 3
            ? __atomic_load_n((uint64_t *)(rw + 0x200), __ATOMIC_ACQUIRE)
            : __atomic_load_n((uint32_t *)(rw + 0x200), __ATOMIC_ACQUIRE);
        struct state s; add_initial(&s, add_size, 0, loaded, 1);
        assert(route(add_store(add_size, 1), s.__x[12], &s, 0));
        assert(s.__pc == add_pc() + 4 && s.__x[16] <= 1);
        if (!retry_branch(&s)) break;
        assert(s.__pc == add_pc() - 8);
        __atomic_add_fetch(&add_failures, 1, __ATOMIC_RELAXED);
    }
    return 0;
}
static void *add_native_counter(void *argument)
{
    (void)argument;
    for (unsigned i = 0; i < ADD_ROUNDS; i++)
        if (add_size == 3) __atomic_fetch_add((uint64_t *)(rw + 0x200), 1, __ATOMIC_ACQ_REL);
        else __atomic_fetch_add((uint32_t *)(rw + 0x200), 1, __ATOMIC_ACQ_REL);
    return 0;
}
int main(void)
{
    mapped_size = 2 * (size_t)sysconf(_SC_PAGESIZE);
    FILE *file = tmpfile(); assert(file && !ftruncate(fileno(file), mapped_size));
    rw = mmap(0, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
    rx = mmap(0, mapped_size, PROT_READ | PROT_EXEC, MAP_SHARED, fileno(file), 0);
    assert(rw != MAP_FAILED && rx != MAP_FAILED); memset(rw, 0xa5, mapped_size);
    ios_jit_rx_base_global = rx; ios_jit_rw_base_global = rw; ios_jit_pool_size_global = mapped_size;
    ios_jit_mappings[0].pe_base = (void *)0x100000000ull;
    ios_jit_mappings[0].jit_base = rx; ios_jit_mappings[0].size = mapped_size;
    ios_jit_mappings[0].generation = ios_jit_new_generation();
    ios_jit_mappings[0].text_offset = 0x100; ios_jit_mappings[0].text_size = 0x14;
    ios_jit_mapping_count = 1;
    add_code(3, 0, 1, 1); add_put(3, 0);
    uint32_t words[4]; memcpy(words, rx + 0x100, sizeof words);
    assert(words[0] == 0xc85ffd8fu && words[1] == 0x8b0a01efu &&
           words[2] == 0xc810fd8fu && words[3] == 0x35ffffb0u);
    struct state s, old; add_initial(&s, 3, 0, 0, 0x1257c7); old = s;
    assert(!old_route(0xc810fd8fu, (uintptr_t)rw + 0x200, s.__x[12], &s));
    assert(!memcmp(&s, &old, sizeof s) && !read_cell(3));
    puts("PASS old production branch refuses exact c810fd8f retained LDAXR/ADD-register/STLXR");
    assert(route(0xc810fd8fu, s.__x[12], &s, 0));
    assert(read_cell(3) == 0x1257c7 && !s.__x[16] && s.__pc == add_pc() + 4); add_preserve(&s, &old);
    assert(!retry_branch(&s) && s.__pc == add_pc() + 8);
    for (unsigned size = 2; size <= 3; size++)
    for (unsigned sub = 0; sub <= 1; sub++)
    for (unsigned acquire = 0; acquire <= 1; acquire++)
    for (unsigned release = 0; release <= 1; release++)
    {
        add_code(size, sub, acquire, release);
        uint64_t seen = add_mask(size) - 2, delta = 7; add_put(size, seen);
        add_initial(&s, size, sub, seen, delta); old = s;
        assert(route(add_store(size, release), s.__x[12], &s, 0));
        assert(read_cell(size) == old.__x[15] && !s.__x[16] && s.__pc == add_pc() + 4); add_preserve(&s, &old);
        add_put(size, 19); add_initial(&s, size, sub, 17, delta); old = s;
        assert(route(add_store(size, release), s.__x[12], &s, 0));
        assert(read_cell(size) == 19 && s.__x[16] == 1 && s.__pc == add_pc() + 4); add_preserve(&s, &old);
        assert(retry_branch(&s) && s.__pc == add_pc() - 8);
    }
    /* SUB underflow and W arithmetic's truncation of high source bits are
     * independent of the successful rollover and stale-CAS checks above. */
    for (unsigned size = 2; size <= 3; size++)
    {
        add_code(size, 1, 1, 1); add_put(size, 2);
        add_initial(&s, size, 1, 2, size == 2 ? 0xfeed000000000007ull : 7); old = s;
        assert(route(add_store(size, 1), s.__x[12], &s, 0));
        assert(!s.__x[16] && read_cell(size) == ((2ull - 7) & add_mask(size))); add_preserve(&s, &old);
        add_code(size, 0, 1, 1); uint32_t zr_math = add_math(size, 0, 31);
        memcpy(rw + 0x104, &zr_math, 4); add_put(size, 23);
        add_initial(&s, size, 0, 23, 0); old = s;
        assert(route(add_store(size, 1), s.__x[12], &s, 0));
        assert(!s.__x[16] && read_cell(size) == 23); add_preserve(&s, &old);
    }
    for (add_size = 2; add_size <= 3; add_size++)
    {
        add_code(add_size, 0, 1, 1); add_put(add_size, 0);
        pthread_t threads[ADD_THREADS], native; assert(!pthread_create(&native, 0, add_native_counter, 0));
        for (unsigned i = 0; i < ADD_THREADS; i++) assert(!pthread_create(&threads[i], 0, add_counter, 0));
        for (unsigned i = 0; i < ADD_THREADS; i++) assert(!pthread_join(threads[i], 0));
        assert(!pthread_join(native, 0)); assert(read_cell(add_size) == (ADD_THREADS + 1) * ADD_ROUNDS);
    }
    add_code(3, 0, 1, 1); add_put(3, 0);
    permit_write = 0; add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0); permit_write = 1;
    code_nx = 1; add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0); code_nx = 0;
    fail_read = 1; add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0); fail_read = 0;
    add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x201, 0);
    ios_jit_mappings[0].owner_peb = (void *)0x1234;
    add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, (void *)0x5678); ios_jit_mappings[0].owner_peb = 0;
    ios_jit_mappings[0].generation = 0; add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0);
    ios_jit_mappings[0].generation = ios_jit_new_generation();
    ios_jit_mappings[0].unmapped = 1; add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0);
    ios_jit_mappings[0].unmapped = 0;
    mutate_generation = 1; add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0); assert(!mutate_generation);
    static const uint32_t bad_math[] = {
        0x8b0a05efu, /* shifted register */ 0xab0a01efu, /* flags */
        0x0b0a01efu, /* wrong width */ 0x8b0f01efu, /* operand overlaps loaded value */
        0x8b1001efu, /* operand overlaps status */ 0x8b0a01eeu, /* other destination */
        0x910005efu, /* immediate belongs to prior path */
    };
    for (unsigned i = 0; i < sizeof bad_math / sizeof bad_math[0]; i++)
    { memcpy(rw + 0x104, &bad_math[i], 4); add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0); }
    add_code(3, 0, 1, 1);
    uint32_t wrong_retry = 0x35ffffd0u; memcpy(rw + 0x10c, &wrong_retry, 4);
    add_refuse(0xc810fd8fu, (uintptr_t)rx + 0x200, 0); add_code(3, 0, 1, 1);
    for (unsigned i = 0; i < mapped_size; i++)
        if (!(i >= 0x100 && i < 0x114) && !(i >= 0x200 && i < 0x208)) assert(rx[i] == 0xa5);
    printf("PASS production register-add exclusive recovery: c810fd8f; ADD/SUB32/64, ordering, success/failure/retry/PC/registers; %u updates per width without loss; invalid transforms/owners/generations/protections rejected; CAS retries=%u\n", (ADD_THREADS + 1) * ADD_ROUNDS, add_failures);
    munmap(rx, mapped_size); munmap(rw, mapped_size); fclose(file);
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-exclusive-add-') as temp:
    file, binary = Path(temp) / 'check.c', Path(temp) / 'check'
    file.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread', str(file), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
