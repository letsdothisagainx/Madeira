/* Real execution of the captured DXMT peak-counter CAS. Reuse only the proven
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
    __builtin___clear_cache((char *)active.rx + 0x100, (char *)active.rx + 0x100 + sizeof(words));
    ios_jit_rx_base_global = active.rx; ios_jit_rw_base_global = active.rw;
    ios_jit_pool_size_global = active.size;
    ios_jit_mappings[0] = (struct ios_jit_mapping){
        .generation = ios_jit_new_generation(), .pe_base = active.rx,
        .jit_base = active.rx, .size = active.page, .text_offset = 0x100,
        .text_size = sizeof(words), .owner_peb = &active };
    ios_jit_mappings[1] = (struct ios_jit_mapping){
        .generation = ios_jit_new_generation(), .pe_base = active.rx + active.page,
        .jit_base = active.rx + active.page, .size = active.page, .owner_peb = &active };
    __atomic_store_n(&ios_jit_mapping_count, 2, __ATOMIC_RELEASE);
    conditional_counter = (uint64_t *)(active.rw + active.page + 0x200);
    maximum = (maximum_fn)(active.rx + 0x100);
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
    puts("PASS actual Apple ARM64 conditional-exclusive recovery: success, real conflict, native retry, concurrent RW contender");
    return 0;
}
