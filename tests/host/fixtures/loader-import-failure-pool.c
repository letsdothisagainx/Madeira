/* Host boundaries for production image retention and process reclamation.
 * The test injects the unmodified functions from virtual_ios.c below. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define IOS_JIT_MAX_CODE_RANGES 96
/* PRODUCTION_MAPPING_STRUCT */

static unsigned char pool[0x30000], first_pe[0x10000], retry_pe[0x10000], sibling_pe[0x10000];
static void *ios_jit_rx_base_global = pool;
static struct ios_jit_mapping ios_jit_mappings[4];
static int ios_jit_mapping_count;
static pthread_mutex_t ios_pool_lock = PTHREAD_MUTEX_INITIALIZER;
struct ios_pool_alloc { size_t off, size; void *peb; uint64_t tag; };
static struct ios_pool_alloc ios_pool_ledger[4];
static int ios_pool_ledger_count;
struct ios_pool_free { size_t off, size; time_t freed_at; int advised; uint64_t tag; };
static struct ios_pool_free ios_pool_freelist[4];
static int ios_pool_free_count;
#define IOS_POOL_FREE_MAX 4
#define IOS_POOL_REUSE_GRACE_SEC 3
typedef int (*ios_pool_clean_fn)(size_t, size_t);
typedef int (*ios_pool_region_fn)(uint64_t *, uint64_t *, unsigned int *);
static struct { uintptr_t user_va, user_va_end, jit_rw_alias, jit_rx_alias; } ios_jit_anon_aliases[2];
static int ios_jit_anon_alias_count;
static void *ios_jit_alias_pushback_peb;
static void (*ios_jit_alias_pushback_cb)(unsigned long long, unsigned long long, unsigned long long);
static void *arm64ec_view;
static size_t ios_pool_big_size, ios_pool_big_off, jit_pool_offset;
static int ios_pool_big_taken;
static time_t ios_pool_big_freed_at;
static time_t now = 100;
static time_t fixture_time(time_t *out) { if (out) *out = now; return now; }
#define time fixture_time

/* Only Mach protection inspection, bitmap storage and external lifecycle
 * callbacks are fixtures. Pool ownership and reclamation execute production. */
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef unsigned mach_msg_type_number_t;
typedef unsigned mach_port_t;
typedef void *vm_region_info_t;
typedef struct { unsigned user_tag, share_mode; } vm_region_extended_info_data_t;
typedef struct { unsigned max_protection; } vm_region_basic_info_data_64_t;
#define VM_REGION_EXTENDED_INFO_COUNT 2
#define VM_REGION_BASIC_INFO_COUNT_64 1
#define VM_REGION_BASIC_INFO_64 1
#define VM_REGION_EXTENDED_INFO 2
#define MACH_PORT_NULL 0
#define KERN_SUCCESS 0
#define VM_PROT_EXECUTE 4
static int mach_task_self(void) { return 0; }
static int mach_vm_region(int task, mach_vm_address_t *base, mach_vm_size_t *size,
                          int flavor, vm_region_info_t info, mach_msg_type_number_t *count, mach_port_t *object)
{
    (void)task; (void)base; (void)size; (void)flavor; (void)info; (void)count; (void)object;
    return 1; /* Diagnostic inspection may fail; it must not alter ownership. */
}
static size_t poisoned_off = (size_t)-1;
static int ios_pool_range_execable(size_t off, size_t size, unsigned int *cur, unsigned int *max)
{
    (void)size;
    unsigned value = off == poisoned_off ? 3 : 5;
    if (cur) *cur = value;
    if (max) *max = value;
    return off != poisoned_off;
}
static int ios_pool_range_clean(size_t off, size_t size)
{
    return ios_pool_range_execable(off, size, NULL, NULL);
}
static int ios_pool_mach_region(uint64_t *base, uint64_t *size, unsigned int *max)
{
    (void)base; (void)size; (void)max; abort();
}
static int ios_pool_execable_runs(uint64_t base, size_t off, size_t size, ios_pool_region_fn region,
                                  size_t *offsets, size_t *sizes, int max)
{
    (void)base; (void)off; (void)size; (void)region; (void)offsets; (void)sizes; (void)max;
    abort(); /* Tagged non-executable images must keep their whole layout. */
}
static void *owner, *sibling_owner;
static unsigned callback_drops, aliases_retired, bitmaps_cleared, carves_retired, owners_noted;
static void ios_sc_grants_owner_died(void *peb) { assert(peb == owner); }
static void ios_alias_cb_drop(void *peb) { assert(peb == owner); callback_drops++; }
static void ios_mono_alias_retire(uint64_t alias)
{
    assert(alias == (uintptr_t)first_pe && ios_jit_anon_aliases[0].user_va_end == 0);
    aliases_retired++;
}
static void clear_arm64ec_range(const void *base, size_t size)
{
    assert(base == pool + 0x4000 && size == 0xc000); bitmaps_cleared++;
}
static void ios_tail_carves_owner_died(void *peb)
{
    assert(peb == owner && ios_pool_ledger_count == 1 && !ios_jit_mappings[0].pe_base);
    carves_retired++;
}
static void ios_exe_win_note_dead_peb(void *peb)
{
    assert(peb == owner && carves_retired == 1 && callback_drops == 1); owners_noted++;
}
static void callback(unsigned long long pe, unsigned long long jit, unsigned long long size)
{
    (void)pe; (void)jit; (void)size; abort();
}

/* PRODUCTION_FUNCTIONS */

int main(int argc, char **argv)
{
    assert(argc == 2);
    int poisoned = atoi(argv[1]);
    static unsigned owner_token, sibling_token;
    owner = &owner_token; sibling_owner = &sibling_token;
    unsetenv("MADEIRA_IMAGE_RELOAD");
    memset(pool, 0x5a, sizeof(pool));
    ios_jit_mapping_count = ios_pool_ledger_count = ios_jit_anon_alias_count = 2;
    ios_jit_mappings[0] = (struct ios_jit_mapping){ .generation = 7, .pe_base = first_pe,
        .jit_base = pool + 0x5000, .size = 0x8000, .map_peb = owner };
    ios_jit_mappings[1] = (struct ios_jit_mapping){ .generation = 8, .pe_base = sibling_pe,
        .jit_base = pool + 0x15000, .size = 0x8000, .map_peb = sibling_owner };
    ios_pool_ledger[0] = (struct ios_pool_alloc){ 0x4000, 0xc000, owner, UINT64_C(0x123456) };
    ios_pool_ledger[1] = (struct ios_pool_alloc){ 0x14000, 0xc000, sibling_owner, UINT64_C(0xabcdef) };
    ios_jit_anon_aliases[0] = (__typeof__(ios_jit_anon_aliases[0])){
        (uintptr_t)first_pe, (uintptr_t)first_pe + 0x8000, 0, (uintptr_t)pool + 0x5000 };
    ios_jit_anon_aliases[1] = (__typeof__(ios_jit_anon_aliases[0])){
        (uintptr_t)sibling_pe, (uintptr_t)sibling_pe + 0x8000, 0, (uintptr_t)pool + 0x15000 };
    ios_jit_alias_pushback_peb = owner; ios_jit_alias_pushback_cb = callback;
    arm64ec_view = &owner_token;
    if (poisoned) poisoned_off = 0x4000;

    /* Failed imports do not delete the retained first view. A different
     * retry's real unmap hook must not turn that live copy into a reload. */
    assert(ios_jit_reload_choice(&ios_jit_mappings[0], 1, 1) == 0);
    assert(ios_pool_ledger_holds(0x5000, 0xb000, owner));
    assert(!ios_pool_ledger_holds(0x5000, 0xb000, sibling_owner));
    assert(!ios_pool_ledger_holds(0x5000, 0xc000, owner));
    ios_jit_note_image_unmapped(retry_pe, 0x8000);
    assert(!ios_jit_mappings[0].unmapped && ios_jit_mappings[0].generation == 7);
    assert(ios_pool_free_count == 0 && ios_pool_ledger_count == 2);
    assert((uintptr_t)retry_pe < (uintptr_t)first_pe ||
           (uintptr_t)retry_pe - (uintptr_t)first_pe >= ios_jit_mappings[0].size);
    assert((uintptr_t)retry_pe >= (uintptr_t)first_pe ||
           (uintptr_t)first_pe - (uintptr_t)retry_pe >= 0x8000);

    /* Only actual process-owner reclamation removes the retained range. */
    ios_jit_reclaim_process(owner);
    assert(ios_pool_ledger_count == 1 && ios_pool_ledger[0].peb == sibling_owner);
    assert(!ios_jit_mappings[0].generation && !ios_jit_mappings[0].size && !ios_jit_mappings[0].pe_base);
    assert(ios_jit_mappings[1].generation == 8 && ios_jit_mappings[1].pe_base == sibling_pe);
    assert(!ios_jit_anon_aliases[0].user_va && ios_jit_anon_aliases[1].user_va == (uintptr_t)sibling_pe);
    assert(!ios_jit_alias_pushback_cb && !ios_jit_alias_pushback_peb);
    assert(aliases_retired == 1 && bitmaps_cleared == 1 && owners_noted == 1);
    assert(ios_pool_free_count == 1 && ios_pool_freelist[0].off == 0x4000 &&
           ios_pool_freelist[0].size == 0xc000 && ios_pool_freelist[0].freed_at == now);
    assert(ios_pool_freelist[0].tag == (poisoned ? UINT64_C(0x123456) : 0));
    assert(!ios_pool_freelist[0].advised);
    assert(ios_pool_best_fit(ios_pool_freelist, ios_pool_free_count, 0xc000, now, (size_t)-1, 0) == -1);
    assert(ios_pool_best_fit(ios_pool_freelist, ios_pool_free_count, 0xc000,
                             now + IOS_POOL_REUSE_GRACE_SEC, (size_t)-1, 0) == 0);
    assert(!ios_pool_ledger_holds(0x5000, 0x8000, owner));
    for (size_t i = 0; i < sizeof(pool); i++) assert(pool[i] == 0x5a);
    puts("PASS production pool retention/reclaim: live copy retained; distinct retry leaves it live; owner cleanup tombstones only its mapping and alias, preserves bytes/grace/layout tag and live sibling");
    return 0;
}
