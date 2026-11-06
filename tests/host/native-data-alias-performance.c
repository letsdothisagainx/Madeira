/* The captured RPM recursive guard is ordinary/private native code. The
 * fixture adapts TEB identity reads to X0 and relocates ADRPs, never the real
 * loads/stores/exclusives/releases/branches. Both phases use identical code
 * except ADRP changes chosen by the production generic data planner. */
#define _DARWIN_C_SOURCE
#include <stddef.h>
#include <stdint.h>
#include "jit_store_census.h"
static uintptr_t ios_write_alias(uintptr_t address);
static int ios_alias_write_is_trapped(uintptr_t address);
static void rpm_record_fault(uint32_t insn);
#define MADEIRA_PERF_RECORD_FAULT(insn) rpm_record_fault(insn)
#define main madeira_atomic_fixture_unexecuted_entry
#include "native-atomic-alias-performance.c"
#undef main
#include "native_data_alias.h"
#include "captured-rpm-functions.h"

enum { RPM_ROUNDS = 400, RPM_LOCK = 0x1000, RPM_UNLOCK = 0x1100,
       RPM_ENABLED = 0xa80, RPM_DEPTH = 0xa90, RPM_OWNER = 0xac0, RPM_PAYLOAD = 0xb00 };
static uint64_t rpm_families[MADEIRA_STORE_FAMILIES];
static unsigned rpm_ready, rpm_start;

static uintptr_t ios_write_alias(uintptr_t address)
{
    if (!inside(address, 1, (uintptr_t)active.rx + active.page, active.page)) return 0;
    return (uintptr_t)active.rw + (address - (uintptr_t)active.rx);
}
static int ios_alias_write_is_trapped(uintptr_t address)
{
    return !ios_write_alias(address);
}
static void rpm_record_fault(uint32_t insn)
{
    __atomic_fetch_add(&rpm_families[madeira_jit_store_family(insn)], 1, __ATOMIC_RELAXED);
}

static unsigned lower_function(uint32_t *code, size_t count, uintptr_t rx, int optimized)
{
    unsigned changed = 0;
    for (size_t index = 0; index < count; ++index) {
        if ((code[index] & 0x9f000000u) != 0x90000000u) continue;
        unsigned reg = code[index] & 31;
        code[index] = adrp(reg, rx + index * 4, (uintptr_t)active.rx + active.page);
    }
    if (optimized) {
        for (size_t index = 0; index < count; ++index) {
            struct madeira_native_data_alias_plan plan;
            if (!madeira_native_data_alias_plan(code, count, rx, (intptr_t)alias_distance,
                                                index, permitted_data, &active, &plan)) continue;
            assert(plan.producer_index == index && code[index] == plan.original);
            code[index] = plan.replacement;
            ++changed;
        }
    }
    __builtin___clear_cache((char *)code, (char *)(code + count));
    __builtin___clear_cache((char *)rx, (char *)(rx + count * 4));
    return changed;
}

static void rpm_emit(int optimized)
{
    assert(active.page >= RPM_UNLOCK + sizeof(captured_rpm_unlock));
    uint32_t *lock = (void *)(active.rw + RPM_LOCK), *unlock = (void *)(active.rw + RPM_UNLOCK);
    memcpy(lock, captured_rpm_lock, sizeof(captured_rpm_lock));
    memcpy(unlock, captured_rpm_unlock, sizeof(captured_rpm_unlock));
    assert(lock[4] == 0xf9401a49u && unlock[7] == 0xf9401a4au);
    lock[4] = 0xaa0003e9u;   /* MOV X9,X0: fixture thread identity, original LDR X9,[X18,#0x30] */
    unlock[7] = 0xaa0003eau; /* MOV X10,X0: same identity, original LDR X10,[X18,#0x30] */
    unsigned lock_changes = lower_function(lock, sizeof(captured_rpm_lock) / 4,
                                           (uintptr_t)active.rx + RPM_LOCK, optimized);
    unsigned unlock_changes = lower_function(unlock, sizeof(captured_rpm_unlock) / 4,
                                             (uintptr_t)active.rx + RPM_UNLOCK, optimized);
    assert(!optimized || (lock_changes == 3 && unlock_changes == 2));
    memset(active.rw + active.page + RPM_ENABLED, 0, 1);
    memset(active.rw + active.page + RPM_DEPTH, 0, 4);
    memset(active.rw + active.page + RPM_OWNER, 0, 8);
    memset(active.rw + active.page + RPM_PAYLOAD, 0, 8);
}

static void native_guard_lock(uintptr_t self)
{
    unsigned char *data = active.rw + active.page;
    uint64_t *owner = (void *)(data + RPM_OWNER);
    uint32_t *depth = (void *)(data + RPM_DEPTH);
    __atomic_store_n(data + RPM_ENABLED, 1, __ATOMIC_RELAXED);
    if (__atomic_load_n(owner, __ATOMIC_ACQUIRE) == self) { ++*depth; return; }
    for (;;) {
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(owner, &expected, self, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) break;
        __asm__ volatile("yield");
    }
    *depth = 1;
}
static void native_guard_unlock(uintptr_t self)
{
    unsigned char *data = active.rw + active.page;
    uint64_t *owner = (void *)(data + RPM_OWNER);
    uint32_t *depth = (void *)(data + RPM_DEPTH);
    assert(__atomic_load_n(owner, __ATOMIC_ACQUIRE) == self && *depth);
    if (!--*depth) __atomic_store_n(owner, 0, __ATOMIC_RELEASE);
}

struct rpm_worker { unsigned index; int direct; };
static void *rpm_run_worker(void *argument)
{
    const struct rpm_worker *worker = argument;
    uintptr_t self = worker->index * 2 + 3;
    mach_port_t thread = mach_thread_self();
    assert(thread_set_exception_ports(thread, EXC_MASK_BAD_ACCESS, exception_port,
               EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64) == KERN_SUCCESS);
    mach_port_deallocate(mach_task_self(), thread);
    void (*lock)(uintptr_t) = (void *)(active.rx + RPM_LOCK);
    void (*unlock)(uintptr_t) = (void *)(active.rx + RPM_UNLOCK);
    unsigned char *data = active.rw + active.page;
    uint64_t *owner = (void *)(data + RPM_OWNER), *payload = (void *)(data + RPM_PAYLOAD);
    uint32_t *depth = (void *)(data + RPM_DEPTH);
    __atomic_add_fetch(&rpm_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&rpm_start, __ATOMIC_ACQUIRE)) __asm__ volatile("yield");
    uint64_t start = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    for (unsigned i = 0; i < RPM_ROUNDS; ++i) {
        if (worker->direct) native_guard_lock(self); else lock(self);
        assert(__atomic_load_n(owner, __ATOMIC_RELAXED) == self && *depth == 1);
        if (!(i % 4)) {
            if (worker->direct) native_guard_lock(self); else lock(self);
            assert(__atomic_load_n(owner, __ATOMIC_RELAXED) == self && *depth == 2);
            if (worker->direct) native_guard_unlock(self); else unlock(self);
            assert(__atomic_load_n(owner, __ATOMIC_RELAXED) == self && *depth == 1);
        }
        uint64_t before = *payload;
        __asm__ volatile("yield");
        *payload = before + 1;
        if (worker->direct) native_guard_unlock(self); else unlock(self);
    }
    __atomic_add_fetch(&worker_cpu_ns, clock_ns(CLOCK_THREAD_CPUTIME_ID) - start, __ATOMIC_RELAXED);
    return NULL;
}

static void rpm_phase(int optimized)
{
    active = map_image(); rpm_emit(optimized);
    unsigned char instructions_before[512];
    memcpy(instructions_before, active.rx + RPM_LOCK, sizeof(instructions_before));
    memset(rpm_families, 0, sizeof(rpm_families)); worker_cpu_ns = 0; rpm_ready = rpm_start = 0;
    uint64_t faults_before = fault_count, server_before = server_cpu_ns(), wall_before = clock_ns(CLOCK_MONOTONIC);
    pthread_t threads[WORKERS + 1]; struct rpm_worker workers[WORKERS + 1];
    for (unsigned i = 0; i <= WORKERS; ++i) {
        workers[i] = (struct rpm_worker){i, i == WORKERS};
        assert(!pthread_create(&threads[i], NULL, rpm_run_worker, &workers[i]));
    }
    while (__atomic_load_n(&rpm_ready, __ATOMIC_ACQUIRE) != WORKERS + 1) sched_yield();
    __atomic_store_n(&rpm_start, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i <= WORKERS; ++i) assert(!pthread_join(threads[i], NULL));
    uint64_t wall = clock_ns(CLOCK_MONOTONIC) - wall_before, handler_cpu = server_cpu_ns() - server_before;
    uint64_t faults = fault_count - faults_before;
    assert(!phase_failures && !memcmp(instructions_before, active.rx + RPM_LOCK, sizeof(instructions_before)));
    unsigned char *data = active.rw + active.page;
    assert(*(uint64_t *)(data + RPM_PAYLOAD) == (WORKERS + 1) * RPM_ROUNDS);
    assert(!*(uint64_t *)(data + RPM_OWNER) && !*(uint32_t *)(data + RPM_DEPTH) && data[RPM_ENABLED] == 1);
    for (size_t i = 0; i < active.page; ++i) {
        if (i == RPM_ENABLED || (i >= RPM_DEPTH && i < RPM_DEPTH + 4) ||
            (i >= RPM_OWNER && i < RPM_OWNER + 8) || (i >= RPM_PAYLOAD && i < RPM_PAYLOAD + 8)) continue;
        assert(data[i] == 0xa5);
    }
    if (optimized) assert(!faults);
    else {
        assert(rpm_families[MADEIRA_STORE_GPR] == WORKERS * (RPM_ROUNDS + RPM_ROUNDS / 4) * 3);
        assert(rpm_families[MADEIRA_STORE_EXCLUSIVE] >= WORKERS * RPM_ROUNDS);
        assert(rpm_families[MADEIRA_STORE_RELEASE] == WORKERS * RPM_ROUNDS);
        assert(!rpm_families[MADEIRA_STORE_OTHER]);
    }
    check_protection(active.rx, PROT_READ | PROT_EXEC, PROT_WRITE);
    check_protection(active.rw, PROT_READ | PROT_WRITE, PROT_EXEC);
    printf("[native-data-throughput] pattern=captured-rpm-recursive-guard mode=%s workers=%u "
           "critical-sections=%u recursive-entries=%u mach-store-faults=%" PRIu64
           " gpr=%" PRIu64 " exclusive=%" PRIu64 " release=%" PRIu64
           " wall-ns=%" PRIu64 " worker-cpu-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64
           " alias-delta=%#" PRIxPTR " host-page=%zu mutual-exclusion=correct recursion=correct RX=executable-nonwritable\n",
           optimized ? "production-plan" : "production-emulation", WORKERS + 1,
           (WORKERS + 1) * RPM_ROUNDS, (WORKERS + 1) * RPM_ROUNDS / 4, faults,
           rpm_families[MADEIRA_STORE_GPR], rpm_families[MADEIRA_STORE_EXCLUSIVE], rpm_families[MADEIRA_STORE_RELEASE],
           wall, worker_cpu_ns, handler_cpu, alias_distance, active.page);
    assert(!munmap(active.reserved, active.reservation)); memset(&active, 0, sizeof(active));
}

int main(void)
{
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    pthread_t server; assert(!pthread_create(&server, NULL, exception_server, NULL));
    while (!__atomic_load_n(&server_thread_port, __ATOMIC_ACQUIRE)) sched_yield();
    rpm_phase(0); rpm_phase(1);
    mach_msg_header_t stop = {0};
    stop.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0); stop.msgh_size = sizeof(stop);
    stop.msgh_remote_port = exception_port; stop.msgh_id = 1;
    assert(mach_msg(&stop, MACH_SEND_MSG, sizeof(stop), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
    assert(!pthread_join(server, NULL)); mach_port_deallocate(mach_task_self(), server_thread_port);
    assert(mach_port_deallocate(mach_task_self(), exception_port) == KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(), exception_port, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    puts("PASS captured RPM guard hardware: actual GPR/postindex/exclusive/release decoders, recursion, ownership, zero-fault lowered code");
    return 0;
}
