#!/usr/bin/env python3
"""Check MAIN retired-code transfer guards and actual concurrent ownership.

Compile the production allocator/reclaim fixture used by the captured CS2
replay. Darwin permission/thread answers are controlled; both aliases use real
shared backing. This tests allocator ownership, not execution of Wine or CS2.
"""
from pathlib import Path
import os
import runpy
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
shared = runpy.run_path(str(root / 'tests/host/check-pool-cs2-budget.py'))
if 'static int ios_pool_recycle_main_code_range(' not in shared['native']:
    print('SKIP: this source predates MAIN retired-code transfer')
    raise SystemExit(0)

fixture = shared['fixture'].replace('int main(void)', 'int captured_replay_main(void)', 1)
# Request identity and the loader failure flag belong to the calling thread.
# Lease/provider configuration stays immutable throughout each concurrent run.
fixture = fixture.replace('static uintptr_t owner;', 'static __thread uintptr_t owner;')
fixture = fixture.replace('static int ios_jit_anon_alias_count, ios_jit_mapping_count, ios_jit_copy_refused;',
                          'static int ios_jit_anon_alias_count, ios_jit_mapping_count;\n'
                          'static __thread int ios_jit_copy_refused;')
fixture = fixture.replace('static int region_bad_alias;', 'static int region_bad_alias, main_region_gap;')
fixture = fixture.replace('uintptr_t base = alias == 1 ? rx : rw, query = *address;',
                          'uintptr_t base = alias == 1 ? rx : rw, query = *address;\n'
                          '    if (main_region_gap && region_bad_alias == alias &&\n'
                          '        query >= base + region_bad_off && query < base + region_bad_off + region_bad_size)\n'
                          '    { *address = query + 0x4000; *size = 0x4000; *object = MACH_PORT_NULL; return KERN_SUCCESS; }')
# Observe all three competitors reaching genuine production mutex operations
# while the first recycler owns carve -> pool. This only controls scheduling.
fixture = fixture.replace('static int schedule_mode, tiny_has_pool, other_waiting, release_tiny;',
                          'static int schedule_mode, tiny_has_pool, other_waiting, release_tiny;\n'
                          'static unsigned main_waiters;')
fixture = fixture.replace('static int scheduled_mutex_lock(pthread_mutex_t *lock)\n{',
                          'static int scheduled_mutex_lock(pthread_mutex_t *lock)\n{\n'
                          '    if (schedule_mode && ((schedule_role == 2 && lock == &ios_pool_lock) ||\n'
                          '        (schedule_role == 3 && lock == &ios_tail_carve_lock) ||\n'
                          '        (schedule_role == 4 && lock == &ios_pool_lock)))\n'
                          '    {\n'
                          '        pthread_mutex_lock(&schedule_lock); main_waiters |= 1u << schedule_role;\n'
                          '        pthread_cond_broadcast(&schedule_cond); pthread_mutex_unlock(&schedule_lock);\n'
                          '    }')

fixture += r'''

static const size_t main_off = 128 * MB, main_bytes = 48 * MB, client_bytes = 0x29a8000;
static const uintptr_t old_owner = 0x9000, image_a = 0xa001, image_b = 0xa002, code_owner = 0xc001;

static void main_setup(int frontier)
{
    reset(256 * MB, 48 * MB);
    fake_now = 90; owner = old_owner;
    jit_pool_offset = 128 * MB; ios_jit_tail_reserved = 128 * MB;
    ios_pool_free_count = ios_pool_ledger_count = ios_jit_mapping_count = ios_jit_anon_alias_count = 0;
    memset(ios_pool_freelist, 0, sizeof ios_pool_freelist);
    memset(ios_pool_ledger, 0, sizeof ios_pool_ledger);
    memset(ios_jit_mappings, 0, sizeof ios_jit_mappings);
    memset(ios_jit_anon_aliases, 0, sizeof ios_jit_anon_aliases);
    memset(ios_tail_carves, 0, sizeof ios_tail_carves);
    memset((char *)rw_memory + main_off, 0xa5, main_bytes);
    set_process_lease((void *)old_owner, 41, 1);
    set_process_lease((void *)image_a, 51, 0);
    set_process_lease((void *)image_b, 52, 0);
    set_process_lease((void *)code_owner, 61, 0);
    ios_tail_carve_n = 4 + frontier;
    for (unsigned i = 0; i < 3; ++i)
        ios_tail_carves[i] = (struct ios_tail_carve){.off=main_off+i*16*MB, .size=16*MB,
                                                  .peb=(void *)old_owner, .allocation_lease=41};
    ios_tail_carves[3] = (struct ios_tail_carve){.off=224*MB, .size=16*MB, .peb=(void *)steam_owner};
    if (frontier)
        ios_tail_carves[4] = (struct ios_tail_carve){.off=176*MB, .size=32*MB, .free=1,
                                                  .freed_at=90, .allocation_lease=24};
    ios_tail_carves_owner_died((void *)old_owner);
    for (unsigned i = 0; i < 3; ++i)
        CHECK(ios_tail_carves[i].free && ios_tail_carves[i].retired && ios_tail_carves[i].retired_lease == 41);
    fake_now = 100; owner = image_a;
    main_region_gap = 0; schedule_mode = 0; schedule_role = 0;
}

struct main_snapshot {
    unsigned char carves[sizeof ios_tail_carves], free[sizeof ios_pool_freelist], ledger[sizeof ios_pool_ledger];
    unsigned char mappings[sizeof ios_jit_mappings], aliases[sizeof ios_jit_anon_aliases];
    unsigned char bytes[48 * 1024 * 1024];
    size_t head, tail, low;
    unsigned carves_n;
    int free_n, ledger_n, mappings_n, aliases_n;
};
static struct main_snapshot before;
static void main_snapshot(void)
{
    memcpy(before.carves, ios_tail_carves, sizeof ios_tail_carves);
    memcpy(before.free, ios_pool_freelist, sizeof ios_pool_freelist);
    memcpy(before.ledger, ios_pool_ledger, sizeof ios_pool_ledger);
    memcpy(before.mappings, ios_jit_mappings, sizeof ios_jit_mappings);
    memcpy(before.aliases, ios_jit_anon_aliases, sizeof ios_jit_anon_aliases);
    memcpy(before.bytes, (char *)rx_memory + main_off, main_bytes);
    before.head = jit_pool_offset; before.tail = ios_jit_tail_reserved; before.low = ios_jit_low_reserved;
    before.carves_n = ios_tail_carve_n; before.free_n = ios_pool_free_count; before.ledger_n = ios_pool_ledger_count;
    before.mappings_n = ios_jit_mapping_count; before.aliases_n = ios_jit_anon_alias_count;
}
static void main_unchanged(void)
{
    CHECK(!memcmp(before.carves, ios_tail_carves, sizeof ios_tail_carves));
    CHECK(!memcmp(before.free, ios_pool_freelist, sizeof ios_pool_freelist));
    CHECK(!memcmp(before.ledger, ios_pool_ledger, sizeof ios_pool_ledger));
    CHECK(!memcmp(before.mappings, ios_jit_mappings, sizeof ios_jit_mappings));
    CHECK(!memcmp(before.aliases, ios_jit_anon_aliases, sizeof ios_jit_anon_aliases));
    CHECK(!memcmp(before.bytes, (char *)rx_memory + main_off, main_bytes));
    CHECK(before.head == jit_pool_offset && before.tail == ios_jit_tail_reserved && before.low == ios_jit_low_reserved);
    CHECK(before.carves_n == ios_tail_carve_n && before.free_n == ios_pool_free_count && before.ledger_n == ios_pool_ledger_count);
    CHECK(before.mappings_n == ios_jit_mapping_count && before.aliases_n == ios_jit_anon_alias_count);
}

static void check_main_transfer(void)
{
    main_setup(1);
    struct ios_tail_carve foreign = ios_tail_carves[3], frontier = ios_tail_carves[4];
    main_snapshot();
    CHECK(ios_pool_recycle_code_range(client_bytes));
    CHECK(ios_tail_carve_n == 2 && ios_pool_free_count == 1 && !ios_pool_ledger_count);
    CHECK(ios_pool_freelist[0].off == main_off && ios_pool_freelist[0].size == main_bytes);
    CHECK(jit_pool_offset == 128*MB && ios_jit_tail_reserved == 128*MB);
    CHECK(!memcmp(&ios_tail_carves[find_carve(foreign.off)], &foreign, sizeof foreign));
    CHECK(!memcmp(&ios_tail_carves[find_carve(frontier.off)], &frontier, sizeof frontier));
    CHECK(!memcmp(before.bytes, (char *)rx_memory + main_off, main_bytes));
    size_t got = (size_t)-1;
    CHECK(!allocate_image(client_bytes, &got) && got == main_off);
    CHECK(ios_pool_ledger_holds(got, client_bytes, (void *)image_a));
    CHECK(ios_pool_free_count == 1 && ios_pool_freelist[0].off == main_off + client_bytes);
    CHECK(ios_pool_freelist[0].size == main_bytes - client_bytes && ios_pool_ledger_count == 1);
    memset((char *)rw_memory + got, 0x39, client_bytes);
    CHECK(*(unsigned char *)((char *)rx_memory + got) == 0x39);
    CHECK(*(unsigned char *)((char *)rx_memory + got + client_bytes - 1) == 0x39);
    puts("PASS: three certified 16MiB MAIN carves transfer 48MiB for client.dll's 0x29a8000 request; remainder, ledger, foreign code and ordinary FREE frontier stay distinct");
}

static void bad_page(int alias, unsigned prot, unsigned max)
{
    region_bad_alias = alias; region_bad_off = main_off + main_bytes - 0x4000;
    region_bad_size = 0x4000; region_bad_prot = prot; region_bad_max = max;
}

static void check_main_guards(void)
{
    for (unsigned test = 0; test < 33; ++test)
    {
        main_setup(1);
        size_t want = client_bytes;
        switch (test)
        {
        case 0: ios_tail_carves[1].allocation_lease = 0; break;
        case 1: ios_tail_carves[1].retired_lease = 0; break;
        case 2: ios_tail_carves[1].retired_lease = 42; break;
        case 3: ios_tail_carves[1].retired = 0; break;
        case 4: ios_tail_carves[1].free = 0; break;
        case 5: ios_tail_carves[1].freed_at = fake_now - 2; break;
        case 6: ios_tail_carves[1].freed_at = fake_now + 1; break;
        case 7: ios_tail_carves[1].freed_at = 0; break;
        case 8: scanned_pc = (uintptr_t)rx_memory + main_off + main_bytes - 4; break;
        case 9: state_query_fail = 1; break;
        case 10: thread_list_fail = 1; break;
        case 11: bad_page(1, 7, 7); break; /* RX became writable. */
        case 12: bad_page(2, 7, 7); break; /* RW became executable. */
        case 13: bad_page(1, 1, 7); break;
        case 14: bad_page(2, 1, 7); break;
        case 15: bad_page(1, 5, 3); break;
        case 16: bad_page(2, 3, 5); break;
        case 17: region_query_fail = 1; break;
        case 18: bad_page(1, 5, 7); main_region_gap = 1; break;
        case 19: bad_page(2, 3, 7); main_region_gap = 1; break;
        case 20:
            ios_pool_ledger[0] = (struct ios_pool_alloc){main_off+MB, MB, (void *)image_b, 0};
            ios_pool_ledger_count = 1; break;
        case 21:
            ios_jit_mappings[0].pe_base = (void *)image_b;
            ios_jit_mappings[0].jit_base = (char *)rx_memory + main_off + MB;
            ios_jit_mappings[0].size = MB; ios_jit_mapping_count = 1; break;
        case 22:
            ios_pool_freelist[0] = (struct ios_pool_free){main_off+MB, MB, 90, 0, 0};
            ios_pool_free_count = 1; break;
        case 23:
            ios_tail_carves[ios_tail_carve_n++] = (struct ios_tail_carve){.off=main_off+MB, .size=MB, .peb=(void *)image_b}; break;
        case 24: ios_pool_free_count = IOS_POOL_FREE_MAX; break;
        case 25: ios_pool_ledger_count = IOS_POOL_LEDGER_MAX; break;
        case 26: ios_jit_hole_off_eff = main_off+MB; ios_jit_hole_end_eff = main_off+2*MB; break;
        case 27: ios_jit_hole2_off = main_off+MB; ios_jit_hole2_end = main_off+2*MB; break;
        case 28: want = 65*MB; break;
        case 29: want = 1; break;
        case 30: want = 0; break;
        case 31: setenv("MADEIRA_POOL_RECYCLE_IMAGES", "0", 1); break;
        case 32: setenv("MADEIRA_POOL_RECYCLE_IMAGES", "true", 1); break;
        }
        main_snapshot();
        if (ios_pool_recycle_code_range(want)) { fprintf(stderr, "unexpected transfer in guard case %u\n", test); exit(1); }
        main_unchanged(); unsetenv("MADEIRA_POOL_RECYCLE_IMAGES");
    }
    /* Neither an ordinary 32MiB FREE nor missing retirement proof can bridge
     * the absent certified middle carve, even after a long age. */
    main_setup(1); ios_tail_carves[1].retired = 0; ios_tail_carves[4].freed_at = 1;
    main_snapshot(); CHECK(!ios_pool_recycle_code_range(client_bytes)); main_unchanged();
    main_setup(1); ios_tail_carves[0] = ios_tail_carves[4]; ios_tail_carve_n = 1;
    main_snapshot(); CHECK(!ios_pool_recycle_code_range(32*MB)); main_unchanged();
    main_setup(1);
    for (unsigned i = 0; i < 3; ++i) ios_tail_carves[i].freed_at = fake_now - 3;
    CHECK(ios_pool_recycle_code_range(client_bytes));
    puts("PASS: MAIN proof/grace/thread/W^X/full-span/overlap/metadata/opt-out guards refuse atomically; exact three-second grace succeeds");
}

static void check_renewed_identity(void)
{
    main_setup(0); owner = code_owner;
    size_t ask = 16*MB; void *rx = NULL;
    CHECK(allocate_code(&ask, &rx) == STATUS_SUCCESS && ask == 16*MB);
    struct ios_tail_carve *c = &ios_tail_carves[find_carve((uintptr_t)rx-(uintptr_t)rx_memory)];
    CHECK(!c->free && !c->retired && c->peb == (void *)code_owner);
    CHECK(c->allocation_lease == 61 && !c->retired_lease);
    void *released = NULL; size_t size = 0;
    CHECK(release_code(rx, MEM_RELEASE, &released, &size) == STATUS_SUCCESS);
    CHECK(c->free && !c->retired && !c->retired_lease);
    /* The previous owner's delayed reclaim cannot certify the new lease. */
    ios_jit_reclaim_process((void *)old_owner);
    CHECK(c->free && !c->retired && c->allocation_lease == 61 && !c->retired_lease);
    main_snapshot(); CHECK(!ios_pool_recycle_code_range(client_bytes)); main_unchanged();
    puts("PASS: production code reuse refreshes allocation identity and clears retirement proof; late old-owner reclaim cannot restore it");
}

/* Both candidates occupy real shared aliases. Keep the head/tail collision
 * boundary exhausted so these checks exercise production reuse, never fresh
 * space. The order varies independently of the candidates' addresses. */
static void code_pair(int retired_first, size_t retired_bytes, size_t ordinary_bytes)
{
    main_setup(0); owner = code_owner;
    struct ios_tail_carve retired = ios_tail_carves[0];
    retired.size = retired_bytes;
    struct ios_tail_carve ordinary = {.off=192*MB, .size=ordinary_bytes, .free=1,
                                     .freed_at=90, .allocation_lease=24};
    ios_tail_carve_n = 2;
    ios_tail_carves[!retired_first] = retired;
    ios_tail_carves[retired_first] = ordinary;
    memset((char *)rw_memory + ordinary.off, 0x6b, ordinary.size);
}

static void code_choice(size_t expected_off, size_t expected_size)
{
    unsigned selected = find_carve(expected_off), other = !selected;
    struct ios_tail_carve untouched = ios_tail_carves[other];
    unsigned char first = *((unsigned char *)rx_memory + untouched.off);
    unsigned char last = *((unsigned char *)rx_memory + untouched.off + untouched.size - 1);
    size_t head = jit_pool_offset, tail = ios_jit_tail_reserved, low = ios_jit_low_reserved;
    size_t ask = 16*MB; void *rx = NULL;
    CHECK(allocate_code(&ask, &rx) == STATUS_SUCCESS && ask == expected_size);
    CHECK((uintptr_t)rx == (uintptr_t)rx_memory + expected_off);
    CHECK(*(const uint32_t *)rx == 0xd503201f);
    struct ios_tail_carve *got = &ios_tail_carves[selected];
    CHECK(!got->free && !got->retired && got->peb == (void *)code_owner);
    CHECK(got->allocation_lease == 61 && !got->retired_lease);
    CHECK(ios_tail_carve_n == 2 && !memcmp(&ios_tail_carves[other], &untouched, sizeof untouched));
    CHECK(*((unsigned char *)rx_memory + untouched.off) == first);
    CHECK(*((unsigned char *)rx_memory + untouched.off + untouched.size - 1) == last);
    CHECK(jit_pool_offset == head && ios_jit_tail_reserved == tail && ios_jit_low_reserved == low);
}

static void check_code_placement(void)
{
    for (int retired_first = 0; retired_first < 2; ++retired_first)
    {
        code_pair(retired_first, 16*MB, 32*MB);
        code_choice(main_off, 16*MB); /* Best-fit precedes retirement preference. */
        code_pair(retired_first, 32*MB, 16*MB);
        code_choice(192*MB, 16*MB);
        code_pair(retired_first, 16*MB, 16*MB);
        code_choice(192*MB, 16*MB); /* Preserve the certified image capacity. */

        /* A retired carve without a matching receipt retains the legacy
         * first-entry tie; its ordinary code-reuse eligibility is unchanged. */
        for (unsigned invalid = 0; invalid < 3; ++invalid)
        {
            code_pair(retired_first, 16*MB, 16*MB);
            struct ios_tail_carve *retired = &ios_tail_carves[!retired_first];
            if (!invalid) retired->allocation_lease = 0;
            else retired->retired_lease = invalid == 1 ? 0 : 42;
            code_choice(ios_tail_carves[0].off, 16*MB);
        }
        for (int both_retired = 0; both_retired < 2; ++both_retired)
        {
            code_pair(retired_first, 16*MB, 16*MB);
            if (both_retired)
            {
                ios_tail_carves[retired_first].retired = 1;
                ios_tail_carves[retired_first].allocation_lease = 41;
                ios_tail_carves[retired_first].retired_lease = 41;
            }
            else ios_tail_carves[!retired_first].retired = 0;
            code_choice(ios_tail_carves[0].off, 16*MB);
        }

        /* Classify the existing backed pages as synthetic C. Equal C/C and
         * C/MAIN candidates preserve their original table-order behavior. */
        for (int both_low = 0; both_low < 2; ++both_low)
        {
            code_pair(retired_first, 16*MB, 16*MB);
            ios_jit_low_rx_global = (uintptr_t)rx_memory + main_off;
            ios_jit_low_rw_global = (uintptr_t)rw_memory + main_off;
            ios_jit_low_size_global = (both_low ? 96 : 16)*MB;
            ios_jit_low_reserved = ios_jit_low_size_global;
            code_choice(ios_tail_carves[0].off, 16*MB);
        }
    }
    puts("PASS: production code allocation keeps size best-fit first, uses ordinary MAIN releases on qualified ties in both orders, and retains uncertified/same-class/C tie behavior without touching the other carve");

    code_pair(1, 16*MB, 16*MB);
    ios_tail_carves[1].free = 0;
    code_choice(main_off, 16*MB); /* A live ordinary carve is never a candidate. */
    code_pair(1, 16*MB, 16*MB);
    ios_tail_carves[0].freed_at = fake_now - 2;
    code_choice(192*MB, 16*MB); /* Retirement grace still excludes the first. */
    code_pair(1, 16*MB, 16*MB);
    ios_tail_carves[1].free = 0;
    scanned_pc = (uintptr_t)rx_memory + main_off;
    size_t ask = 16*MB; void *rx = NULL;
    CHECK(allocate_code(&ask, &rx) == STATUS_NO_MEMORY && !rx);
    CHECK(ios_tail_carves[0].free && ios_tail_carves[0].retired);
    CHECK(ios_tail_carves[0].freed_at == fake_now && !ios_tail_carves[1].free);
    CHECK(jit_pool_offset == 128*MB && ios_jit_tail_reserved == 128*MB);
    CHECK(*(unsigned char *)((char *)rx_memory + main_off) == 0xa5);
    puts("PASS: placement preference retains live-carve exclusion, retirement grace and strict thread-scan refusal");
}

struct main_request { unsigned role; uintptr_t peb; int status; size_t size, off; void *rx; };
static void *main_compete(void *opaque)
{
    struct main_request *r = opaque;
    owner = r->peb; schedule_role = r->role;
    if (r->role < 3) r->status = allocate_image(r->size, &r->off);
    else if (r->role == 3) r->status = allocate_code(&r->size, &r->rx);
    else { ios_jit_reclaim_process((void *)old_owner); r->status = 0; }
    CHECK(!carve_lock_depth && !pool_lock_depth);
    return NULL;
}

static void check_main_concurrency(void)
{
    for (unsigned trial = 0; trial < 24; ++trial)
    {
        main_setup(0);
        struct main_request r[4] = {
            {.role=1,.peb=image_a,.size=client_bytes,.off=(size_t)-1},
            {.role=2,.peb=image_b,.size=client_bytes,.off=(size_t)-1},
            {.role=3,.peb=code_owner,.size=16*MB}, {.role=4,.peb=old_owner}
        };
        pthread_t threads[4];
        start_schedule(); main_waiters = 0;
        CHECK(!pthread_create(&threads[0], NULL, main_compete, &r[0])); wait_schedule(&tiny_has_pool);
        CHECK(ios_tail_carve_n == 4 && !ios_pool_free_count && !ios_pool_ledger_count);
        for (unsigned i = 1; i < 4; ++i) CHECK(!pthread_create(&threads[i], NULL, main_compete, &r[i]));
        pthread_mutex_lock(&schedule_lock);
        while ((main_waiters & 28u) != 28u) pthread_cond_wait(&schedule_cond, &schedule_lock);
        pthread_mutex_unlock(&schedule_lock); finish_schedule();
        for (unsigned i = 0; i < 4; ++i) CHECK(!pthread_join(threads[i], NULL));
        schedule_mode = 0;
        unsigned images = !r[0].status + !r[1].status, code = r[2].status == STATUS_SUCCESS;
        CHECK(images + code == 1); /* A 16MiB generation also leaves too little for either image. */
        size_t claimed = 0, free_bytes = 0;
        for (unsigned i = 0; i < 2; ++i)
            if (!r[i].status)
            {
                CHECK(r[i].off == main_off && ios_pool_ledger_holds(r[i].off, client_bytes, (void *)r[i].peb));
                claimed += client_bytes;
            }
            else CHECK(r[i].status == -1 && r[i].off == (size_t)-1);
        if (code)
        {
            size_t off = (uintptr_t)r[2].rx - (uintptr_t)rx_memory;
            CHECK(off >= main_off && off + r[2].size <= main_off + main_bytes);
            CHECK(*(const uint32_t *)r[2].rx == 0xd503201f);
            struct ios_tail_carve *c = &ios_tail_carves[find_carve(off)];
            CHECK(!c->free && c->peb == (void *)code_owner && c->allocation_lease == 61 && !c->retired_lease);
            claimed += r[2].size;
        }
        else CHECK(r[2].status == STATUS_NO_MEMORY && !r[2].rx);
        for (int i = 0; i < ios_pool_free_count; ++i)
        {
            const struct ios_pool_free *f = &ios_pool_freelist[i];
            CHECK(f->off >= main_off && f->off + f->size <= main_off + main_bytes);
            free_bytes += f->size;
            for (int j = 0; j < ios_pool_ledger_count; ++j)
                CHECK(f->off + f->size <= ios_pool_ledger[j].off || f->off >= ios_pool_ledger[j].off + ios_pool_ledger[j].size);
            for (unsigned j = 0; j < ios_tail_carve_n; ++j)
                CHECK(f->off + f->size <= ios_tail_carves[j].off || f->off >= ios_tail_carves[j].off + ios_tail_carves[j].size);
        }
        CHECK(claimed + free_bytes == main_bytes && ios_pool_ledger_count == (int)images);
        CHECK(ios_tail_carve_n == 1 + code && ios_tail_carves[find_carve(224*MB)].peb == (void *)steam_owner);
        CHECK(jit_pool_offset == 128*MB && ios_jit_tail_reserved == 128*MB);
    }
    puts("PASS: 24 actual image/image/code-generation/old-owner-reclaim races hand the 48MiB extent to exactly one owner, account for its remainder, and preserve foreign code");
}

static void *main_map(FILE *backing, int protection)
{
    size_t reservation = mapped_size + 0x4000;
    void *raw = mmap(NULL, reservation, PROT_NONE, MAP_SHARED, fileno(backing), 0);
    CHECK(raw != MAP_FAILED);
    uintptr_t aligned = ((uintptr_t)raw + 0x3fff) & ~(uintptr_t)0x3fff;
    size_t prefix = aligned - (uintptr_t)raw, suffix = reservation - prefix - mapped_size;
    if (prefix) CHECK(!munmap(raw, prefix));
    if (suffix) CHECK(!munmap((void *)(aligned + mapped_size), suffix));
    void *result = mmap((void *)aligned, mapped_size, protection, MAP_SHARED | MAP_FIXED, fileno(backing), 0);
    CHECK(result == (void *)aligned); return result;
}

int main(void)
{
    unsetenv("MADEIRA_POOL_RECYCLE_IMAGES"); unsetenv("MADEIRA_POOL_LOW_IMAGES");
    unsetenv("MADEIRA_POOL_CODE_EXIT_RECLAIM"); unsetenv("MADEIRA_POOL_QUARANTINE");
    mapped_size = 256*MB;
    FILE *backing = tmpfile(); CHECK(backing && !ftruncate(fileno(backing), (off_t)(mapped_size+0x4000)));
    rw_memory = main_map(backing, PROT_READ | PROT_WRITE);
    rx_memory = main_map(backing, PROT_READ | PROT_EXEC);
    CHECK(rw_memory != rx_memory);
    check_main_transfer(); check_main_guards(); check_renewed_identity(); check_code_placement(); check_main_concurrency();
    CHECK(!munmap(rx_memory, mapped_size) && !munmap(rw_memory, mapped_size) && !fclose(backing));
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-pool-retired-main-') as directory:
    unit, binary = Path(directory) / 'main.c', Path(directory) / 'main'
    unit.write_text(fixture)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                    '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-pthread',
                    str(unit), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        result.check_returncode()
