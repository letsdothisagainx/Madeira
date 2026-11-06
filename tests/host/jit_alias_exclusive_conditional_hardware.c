/* Real execution of captured DXMT peak and report-counter CAS families. Reuse only the proven
 * Mach transport/file-alias fixture; its old benchmark entry is unexecuted. */
#define main unexecuted_atomic_fixture_entry
#include "native-atomic-alias-performance.c"
#undef main

enum { CONDITIONAL_ROUNDS = 400, CONDITIONAL_THREADS = 5 };
static unsigned force_conflict, conflict_request, conflict_done;
static unsigned concurrent_ready, concurrent_start;
static unsigned round_arrivals, round_generation;
static uint64_t *conditional_counter;
struct snapshot { uint64_t x8, x9, x10, x11, x12, x15, nzcv; };
#define TOTAL(name) __atomic_load_n(&(name), __ATOMIC_RELAXED)
typedef void (*maximum_fn)(void *, uint64_t, struct snapshot *);
static maximum_fn maximum;
struct compare_snapshot { uint64_t expected, desired, load_address, loaded_or_address, status, base, nzcv, called; };
typedef void (*compare_fn)(void *, uint64_t, struct compare_snapshot *);
static compare_fn compare;

static void enable_mach_recovery(void)
{
    mach_port_t self = mach_thread_self();
    assert(thread_set_exception_ports(self, EXC_MASK_BAD_ACCESS, exception_port,
             EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64) == KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(), self) == KERN_SUCCESS);
}

/* The faulting CPU has already executed LDXR and is suspended. The separate
 * writer changes the backing before the production CAS, without changing the
 * suspended register snapshot or manufacturing an exclusive status result. */
static void conditional_before_cas(void)
{
    if (!__atomic_exchange_n(&force_conflict, 0, __ATOMIC_ACQ_REL)) return;
    __atomic_store_n(&conflict_request, 1, __ATOMIC_RELEASE);
    uint64_t limit = clock_ns(CLOCK_MONOTONIC) + 2000000000;
    while (!__atomic_load_n(&conflict_done, __ATOMIC_ACQUIRE)) {
        assert(clock_ns(CLOCK_MONOTONIC) < limit);
        sched_yield();
    }
}

static void *independent_conflict_writer(void *unused)
{
    (void)unused;
    while (!__atomic_load_n(&conflict_request, __ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(conditional_counter, 30, __ATOMIC_SEQ_CST);
    __atomic_store_n(&conflict_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void publish_fixture(void)
{
    /* Five ABI setup/initial maximum-test instructions, then the exact 18
     * words from shipped d3d11.dll RVAs 102dc8..102e0c. Only its continuation
     * is a register/flags snapshot followed by RET, rather than constructor
     * instructions unrelated to the recovered atomic operation. */
    static const uint32_t words[] = {
        0xaa0003e8, 0xaa0103e9, 0xf940510c, 0xeb0c013f, 0x54000269,
        0x9102810a, 0xc85f7d4b, 0xeb0c017f, 0x54000141, 0x9102810c,
        0xc80f7d89, 0x3500014f, 0x5280002c, 0x3700014c, 0xeb0b013f,
        0xaa0b03ec, 0x54fffec8, 0x14000006, 0x2a1f03ec, 0xd5033f5f,
        0x17fffff9, 0x2a1f03ec, 0x17fffff7,
        0xa9002448, 0xa9012c4a, 0xa9023c4c, 0xd53b4203, 0xf9001843, 0xd65f03c0
    };
    assert(active.page == 0x4000 && alias_distance == 1152u * 1024 * 1024);
    memcpy(active.rw + 0x100, words, sizeof(words));
    /* Exact ff3a8..ff3c0 strong-CAS core and ff56c cleanup preserve the
     * original 0x1b8 forward B.NE and -0x1a0 cleanup branch. ABI setup saves
     * callee-saved X25. The original three-instruction success call is a
     * fixture-only marker, and continuation records state before restoring
     * X25/LR. No original atomic, retry, comparison or CLREX word changes. */
    uint32_t compare_words[120];
    for (unsigned i = 0; i < 120; ++i) compare_words[i] = 0xd4200000u;
    static const uint32_t compare_prefix[] = {
        0xa9bf7bf9, 0xaa0003f9, 0xaa0103e9, 0xf9408f28, 0xaa1f03e3,
        0x9104632a, 0xc85f7d4b, 0xeb08017f, 0x54000dc1, 0x9104632b,
        0xc80c7d69, 0x35ffff6c,
        0xd2800023, 0xd503201f, 0xd503201f,
        0xa9002448, 0xa9012c4a, 0xa902644c, 0xd53b4204, 0xa9030c44,
        0xa8c17bf9, 0xd65f03c0
    };
    memcpy(compare_words, compare_prefix, sizeof(compare_prefix));
    compare_words[118] = 0xd5033f5f; compare_words[119] = 0x17ffff98;
    memcpy(active.rw + 0x400, compare_words, sizeof(compare_words));
    __builtin___clear_cache((char *)active.rx + 0x100, (char *)active.rx + 0x600);
    ios_jit_rx_base_global = active.rx; ios_jit_rw_base_global = active.rw;
    ios_jit_pool_size_global = active.size;
    ios_jit_mappings[0] = (struct ios_jit_mapping){
        .generation = ios_jit_new_generation(), .pe_base = active.rx,
        .jit_base = active.rx, .size = active.page, .text_offset = 0x100,
        .text_size = 0x500, .owner_peb = &active };
    ios_jit_mappings[1] = (struct ios_jit_mapping){
        .generation = ios_jit_new_generation(), .pe_base = active.rx + active.page,
        .jit_base = active.rx + active.page, .size = active.page, .owner_peb = &active };
    __atomic_store_n(&ios_jit_mapping_count, 2, __ATOMIC_RELEASE);
    conditional_counter = (uint64_t *)(active.rw + active.page + 0x200);
    maximum = (maximum_fn)(active.rx + 0x100);
    compare = (compare_fn)(active.rx + 0x400);
}

static void apply_maximum(uint64_t desired, struct snapshot *out)
{
    void *base = active.rx + active.page + 0x200 - 0xa0;
    maximum(base, desired, out);
    assert(out->x8 == (uintptr_t)base && out->x9 == desired);
}

/* A fast direct writer must not finish every maximum before the RX workers
 * start. Every round contains four genuine native contenders and a lower
 * direct RW value; the highest native value necessarily attempts recovery. */
static void round_barrier(void)
{
    unsigned generation = __atomic_load_n(&round_generation, __ATOMIC_ACQUIRE);
    if (__atomic_fetch_add(&round_arrivals, 1, __ATOMIC_ACQ_REL) == CONDITIONAL_THREADS - 1) {
        __atomic_store_n(&round_arrivals, 0, __ATOMIC_RELAXED);
        __atomic_add_fetch(&round_generation, 1, __ATOMIC_RELEASE);
    } else {
        while (__atomic_load_n(&round_generation, __ATOMIC_ACQUIRE) == generation) sched_yield();
    }
}

static void *concurrent_maximum(void *argument)
{
    unsigned index = (unsigned)(uintptr_t)argument;
    if (index < CONDITIONAL_THREADS - 1) enable_mach_recovery();
    __atomic_add_fetch(&concurrent_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&concurrent_start, __ATOMIC_ACQUIRE)) sched_yield();
    for (unsigned iteration = 0; iteration < CONDITIONAL_ROUNDS; ++iteration) {
        round_barrier();
        uint64_t desired = iteration * CONDITIONAL_THREADS +
            (index == CONDITIONAL_THREADS - 1 ? 1 : index + 2);
        if (index == CONDITIONAL_THREADS - 1) {
            uint64_t observed = __atomic_load_n(conditional_counter, __ATOMIC_RELAXED);
            while (observed < desired && !__atomic_compare_exchange_n(conditional_counter,
                     &observed, desired, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {}
        } else {
            struct snapshot out;
            apply_maximum(desired, &out);
        }
        round_barrier();
    }
    return NULL;
}

static void apply_compare(uint64_t desired, struct compare_snapshot *out)
{
    void *base = active.rx + active.page + 0x200 - 0x118;
    compare(base, desired, out);
    assert(out->base == (uintptr_t)base && out->desired == desired);
}

static void *concurrent_compare(void *argument)
{
    unsigned index = (unsigned)(uintptr_t)argument;
    if (index < CONDITIONAL_THREADS - 1) enable_mach_recovery();
    __atomic_add_fetch(&concurrent_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&concurrent_start, __ATOMIC_ACQUIRE)) sched_yield();
    for (unsigned iteration = 0; iteration < CONDITIONAL_ROUNDS; ++iteration) {
        round_barrier();
        if (index == CONDITIONAL_THREADS - 1) {
            /* A real independent RW CAS participates in coherence/monitor
             * invalidation but never performs the native workers' increment.
             * Thus at least one captured STXR must succeed in every round. */
            uint64_t observed = __atomic_load_n(conditional_counter, __ATOMIC_RELAXED);
            for (;;) {
                uint64_t unchanged = observed;
                if (__atomic_compare_exchange_n(conditional_counter, &observed, unchanged,
                                                  0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) break;
            }
        } else {
            struct compare_snapshot out;
            apply_compare(iteration + 1, &out);
            assert(out.status <= 1 && out.called <= 1);
        }
        round_barrier();
    }
    return NULL;
}

static void run_strong_compare(void)
{
    unsigned char code_before[120 * 4];
    memcpy(code_before, active.rx + 0x400, sizeof(code_before));
    struct compare_snapshot out;
    uintptr_t target = (uintptr_t)active.rx + active.page + 0x200;
    uint64_t faults = TOTAL(fault_count), successes = TOTAL(conditional_successes), conflicts = TOTAL(conditional_conflicts);
    __atomic_store_n(conditional_counter, 10, __ATOMIC_SEQ_CST);
    apply_compare(20, &out);
    assert(TOTAL(fault_count) == faults + 1 && TOTAL(conditional_successes) == successes + 1);
    assert(*conditional_counter == 20 && out.expected == 10 && out.load_address == target &&
           out.loaded_or_address == target && out.status == 0 && out.called == 1 && out.nzcv == 0x60000000u);

    __atomic_store_n(conditional_counter, 10, __ATOMIC_SEQ_CST);
    __atomic_store_n(&conflict_request, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&conflict_done, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&force_conflict, 1, __ATOMIC_RELEASE);
    pthread_t writer;
    assert(!pthread_create(&writer, NULL, independent_conflict_writer, NULL));
    apply_compare(20, &out);
    assert(!pthread_join(writer, NULL));
    assert(TOTAL(fault_count) == faults + 2 && TOTAL(conditional_conflicts) == conflicts + 1);
    assert(*conditional_counter == 30 && out.expected == 10 && out.load_address == target &&
           out.loaded_or_address == 30 && out.status == 1 && !out.called && out.nzcv == 0x20000000u);
    /* compare_exchange_strong permits descending and zero desired values.
     * This is intentionally not another high-water/max-only special case. */
    apply_compare(5, &out);
    assert(*conditional_counter == 5 && out.expected == 30 && !out.status && out.called == 1);
    apply_compare(0, &out);
    assert(!*conditional_counter && out.expected == 5 && !out.status && out.called == 1);

    __atomic_store_n(&concurrent_ready, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&concurrent_start, 0, __ATOMIC_RELAXED);
    uint64_t success_before = TOTAL(conditional_successes), faults_before = TOTAL(fault_count);
    uint64_t wall_start = clock_ns(CLOCK_MONOTONIC), cpu_start = server_cpu_ns();
    pthread_t workers[CONDITIONAL_THREADS];
    for (unsigned index = 0; index < CONDITIONAL_THREADS; ++index)
        assert(!pthread_create(&workers[index], NULL, concurrent_compare, (void *)(uintptr_t)index));
    while (__atomic_load_n(&concurrent_ready, __ATOMIC_ACQUIRE) != CONDITIONAL_THREADS) sched_yield();
    __atomic_store_n(&concurrent_start, 1, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < CONDITIONAL_THREADS; ++index) assert(!pthread_join(workers[index], NULL));
    assert(*conditional_counter == CONDITIONAL_ROUNDS && !TOTAL(phase_failures));
    assert(TOTAL(fault_count) - faults_before >= CONDITIONAL_ROUNDS);
    assert(TOTAL(conditional_successes) - success_before >= CONDITIONAL_ROUNDS);
    assert(!memcmp(code_before, active.rx + 0x400, sizeof(code_before)));
    for (unsigned byte = 0; byte < 8; ++byte) {
        assert(active.rx[active.page + 0x200 - 8 + byte] == 0xa5);
        assert(active.rx[active.page + 0x200 + 8 + byte] == 0xa5);
    }
    check_protection(active.rx, PROT_READ | PROT_EXEC, PROT_WRITE);
    check_protection(active.rw, PROT_READ | PROT_WRITE, PROT_EXEC);
    printf("[strong-compare-exclusive-hardware] opcode=c80c7d69 workers=%u operations=%u "
           "mach-faults=%" PRIu64 " successes=%" PRIu64 " conflicts=%" PRIu64
           " wall-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64 " alias-delta=%#" PRIxPTR
           " result=correct native-retry-clrex=verified retained-expected=preserved "
           "descending-zero-desired=verified registers=preserved flags=preserved rx=nonwritable\n",
           CONDITIONAL_THREADS, CONDITIONAL_ROUNDS * CONDITIONAL_THREADS, TOTAL(fault_count) - faults,
           TOTAL(conditional_successes) - successes, TOTAL(conditional_conflicts) - conflicts,
           clock_ns(CLOCK_MONOTONIC) - wall_start, server_cpu_ns() - cpu_start, alias_distance);
}

int main(void)
{
    (void)quiet_dprintf; /* This helper intentionally emits no per-fault logs. */
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), exception_port, exception_port,
                                 MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    pthread_t server;
    assert(!pthread_create(&server, NULL, exception_server, NULL));
    while (!__atomic_load_n(&server_thread_port, __ATOMIC_ACQUIRE)) sched_yield();
    active = map_image(); publish_fixture(); enable_mach_recovery();
    unsigned char original_code[0x200]; memcpy(original_code, active.rx, sizeof(original_code));
    struct snapshot out;
    __atomic_store_n(conditional_counter, 10, __ATOMIC_SEQ_CST);
    apply_maximum(5, &out);
    assert(!TOTAL(fault_count) && *conditional_counter == 10 && out.x12 == 10);
    apply_maximum(20, &out);
    uintptr_t target = (uintptr_t)active.rx + active.page + 0x200;
    assert(TOTAL(fault_count) == 1 && TOTAL(conditional_successes) == 1 && !TOTAL(conditional_conflicts));
    assert(*conditional_counter == 20 && out.x10 == target && out.x11 == 10 &&
           out.x12 == 1 && out.x15 == 0 && out.nzcv == 0x60000000u);

    __atomic_store_n(conditional_counter, 10, __ATOMIC_SEQ_CST);
    __atomic_store_n(&force_conflict, 1, __ATOMIC_RELEASE);
    pthread_t writer;
    assert(!pthread_create(&writer, NULL, independent_conflict_writer, NULL));
    apply_maximum(20, &out);
    assert(!pthread_join(writer, NULL));
    assert(TOTAL(fault_count) == 2 && TOTAL(conditional_successes) == 1 && TOTAL(conditional_conflicts) == 1);
    assert(*conditional_counter == 30 && out.x10 == target && out.x11 == 30 &&
           out.x12 == 30 && out.x15 == 1 && out.nzcv == 0x80000000u);

    __atomic_store_n(conditional_counter, 0, __ATOMIC_SEQ_CST);
    uint64_t success_before = TOTAL(conditional_successes), faults_before = TOTAL(fault_count);
    uint64_t wall_start = clock_ns(CLOCK_MONOTONIC), cpu_start = server_cpu_ns();
    pthread_t workers[CONDITIONAL_THREADS];
    for (unsigned index = 0; index < CONDITIONAL_THREADS; ++index)
        assert(!pthread_create(&workers[index], NULL, concurrent_maximum, (void *)(uintptr_t)index));
    while (__atomic_load_n(&concurrent_ready, __ATOMIC_ACQUIRE) != CONDITIONAL_THREADS) sched_yield();
    __atomic_store_n(&concurrent_start, 1, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < CONDITIONAL_THREADS; ++index) assert(!pthread_join(workers[index], NULL));
    uint64_t wall = clock_ns(CLOCK_MONOTONIC) - wall_start, handler_cpu = server_cpu_ns() - cpu_start;
    assert(*conditional_counter == CONDITIONAL_ROUNDS * CONDITIONAL_THREADS && !TOTAL(phase_failures));
    assert(TOTAL(fault_count) - faults_before >= CONDITIONAL_ROUNDS);
    assert(TOTAL(conditional_successes) - success_before >= CONDITIONAL_ROUNDS);
    assert(!memcmp(original_code, active.rx, sizeof(original_code)));
    for (unsigned byte = 0; byte < 8; ++byte) {
        assert(active.rx[active.page + 0x200 - 8 + byte] == 0xa5);
        assert(active.rx[active.page + 0x200 + 8 + byte] == 0xa5);
    }
    check_protection(active.rx, PROT_READ | PROT_EXEC, PROT_WRITE);
    check_protection(active.rw, PROT_READ | PROT_WRITE, PROT_EXEC);
    printf("[conditional-exclusive-hardware] opcode=c80f7d89 workers=%u operations=%u "
           "mach-faults=%" PRIu64 " successes=%" PRIu64 " conflicts=%" PRIu64
           " wall-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64 " alias-delta=%#" PRIxPTR
           " result=correct native-retry=verified registers=preserved flags=preserved rx=nonwritable\n",
           CONDITIONAL_THREADS, CONDITIONAL_ROUNDS * CONDITIONAL_THREADS, TOTAL(fault_count),
           TOTAL(conditional_successes), TOTAL(conditional_conflicts), wall, handler_cpu, alias_distance);

    run_strong_compare();

    mach_msg_header_t stop = {0};
    stop.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0); stop.msgh_size = sizeof(stop);
    stop.msgh_remote_port = exception_port; stop.msgh_id = 1;
    assert(mach_msg(&stop, MACH_SEND_MSG, sizeof(stop), 0, MACH_PORT_NULL,
                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
    assert(!pthread_join(server, NULL));
    assert(mach_port_deallocate(mach_task_self(), server_thread_port) == KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(), exception_port) == KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(), exception_port, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    assert(!munmap(active.reserved, active.reservation));
    puts("PASS actual Apple ARM64 conditional-exclusive recovery: both captured CAS families, genuine conflicts, original retry/CLREX and concurrent RW contender");
    return 0;
}
