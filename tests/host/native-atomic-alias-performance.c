/* Real Apple ARM64/Mach execution of the production fresh-copy atomic plan.
 * No signal/exception is bypassed: baseline faults complete through extracted
 * production emulation; an unexpected address or opcode fails the test.
 */
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mach/arm/thread_status.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/ndr.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "native_atomic_alias.h"

enum { WORKERS = 4, ROUNDS = 2000, CASES = 3 };
static const uintptr_t alias_distance = 0x48000000;
struct image { unsigned char *reserved, *rx, *rw; size_t page, size, reservation; };
static struct image active;
static mach_port_t exception_port, server_thread_port;
static uint64_t fault_count, phase_failures;
static unsigned char seen[(WORKERS + 1) * ROUNDS];
static uint64_t worker_cpu_ns;
#ifndef MADEIRA_PERF_RECORD_FAULT
#define MADEIRA_PERF_RECORD_FAULT(insn) ((void)(insn))
#endif

static uint64_t clock_ns(clockid_t clock)
{
    struct timespec ts;
    assert(!clock_gettime(clock, &ts));
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static uint64_t server_cpu_ns(void)
{
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    assert(thread_info(server_thread_port, THREAD_BASIC_INFO, (thread_info_t)&info, &count) == KERN_SUCCESS);
    return ((uint64_t)info.user_time.seconds + info.system_time.seconds) * 1000000000 +
           ((uint64_t)info.user_time.microseconds + info.system_time.microseconds) * 1000;
}

static int inside(uintptr_t p, size_t size, uintptr_t start, size_t span)
{
    return p >= start && p - start <= span && size <= span - (p - start);
}

static int ios_fault_read_insn(uint64_t pc, uint32_t *out)
{
#ifdef MADEIRA_PERF_CODE_READ
    return MADEIRA_PERF_CODE_READ(pc, out);
#else
    if ((pc & 3) || !inside(pc, 4, (uintptr_t)active.rx, active.page)) return 0;
    memcpy(out, (void *)(uintptr_t)pc, 4);
    return 1;
#endif
}

static int quiet_dprintf(int fd, const char *fmt, ...)
{
    (void)fd; (void)fmt;
    return 0;
}
/* These fixture-owned PE/data aliases contain no private CodeBuffer guards.
 * Keep this native-registry boundary explicit before the production helpers;
 * guarded-pool behavior is exercised by the dedicated code-guard tests. */
int ios_jit_code_guard_contains(uintptr_t address, size_t length)
{
    (void)address; (void)length;
    return 0;
}
#define dprintf quiet_dprintf
#include "production-atomic-emulation.h"
#undef dprintf

#pragma pack(push, 4)
struct exception_request {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread, task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
};
struct exception_reply { mach_msg_header_t head; NDR_record_t ndr; kern_return_t result; };
#pragma pack(pop)

static void *exception_server(void *unused)
{
    (void)unused;
    __atomic_store_n(&server_thread_port, mach_thread_self(), __ATOMIC_RELEASE);
    for (;;) {
        union { struct exception_request req; unsigned char buffer[1024]; } message;
        assert(mach_msg(&message.req.head, MACH_RCV_MSG, 0, sizeof(message), exception_port,
                        MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
        struct exception_request *req = &message.req;
        if (req->head.msgh_id == 1) return NULL;
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        assert(req->exception == EXC_BAD_ACCESS && req->code_count == 2);
        assert(thread_get_state(req->thread.name, ARM_THREAD_STATE64,
                                (thread_state_t)&state, &count) == KERN_SUCCESS);
        uintptr_t pc = arm_thread_state64_get_pc(state), fault = (uintptr_t)req->code[1];
        uint32_t insn = 0;
        int valid = ios_fault_read_insn(pc, &insn) &&
#ifdef MADEIRA_PERF_TARGET_VALID
                    MADEIRA_PERF_TARGET_VALID(fault);
#else
                    inside(fault, 8, (uintptr_t)active.rx + active.page, active.page) && !(fault & 7);
#endif
        uintptr_t alias = (uintptr_t)active.rw + (fault - (uintptr_t)active.rx);
        int handled = valid && baseline_emulate(insn, pc, fault, alias, &state);
        if (!handled) {
            fprintf(stderr, "unexpected atomic exception pc=%#" PRIxPTR " insn=%08x fault=%#" PRIxPTR "\n", pc, insn, fault);
            __atomic_add_fetch(&phase_failures, 1, __ATOMIC_RELAXED);
            abort();
        }
        __darwin_arm_thread_state64_set_pc_fptr(state, (void *)(pc + 4));
        assert(thread_set_state(req->thread.name, ARM_THREAD_STATE64,
                                (thread_state_t)&state, ARM_THREAD_STATE64_COUNT) == KERN_SUCCESS);
        __atomic_add_fetch(&fault_count, 1, __ATOMIC_RELAXED);
        MADEIRA_PERF_RECORD_FAULT(insn);
        struct exception_reply reply = {0};
        reply.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->head.msgh_bits), 0);
        reply.head.msgh_size = sizeof(reply);
        reply.head.msgh_remote_port = req->head.msgh_remote_port;
        reply.head.msgh_id = req->head.msgh_id + 100;
        reply.ndr = NDR_record; reply.result = KERN_SUCCESS;
        assert(mach_msg(&reply.head, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL,
                        MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
        assert(mach_port_deallocate(mach_task_self(), req->thread.name) == KERN_SUCCESS);
        assert(mach_port_deallocate(mach_task_self(), req->task.name) == KERN_SUCCESS);
    }
}

static struct image map_image(void)
{
    struct image result = {0};
    result.page = (size_t)getpagesize(); result.size = result.page * 2;
    result.reservation = alias_distance + result.size;
    result.reserved = mmap(NULL, result.reservation, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(result.reserved != MAP_FAILED);
    char path[] = "/tmp/madeira-atomic-alias-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0 && !unlink(path) && !ftruncate(fd, (off_t)result.size));
    result.rx = mmap(result.reserved, result.size, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 0);
    result.rw = mmap(result.reserved + alias_distance, result.size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, 0);
    assert(result.rx == result.reserved && result.rw == result.reserved + alias_distance);
    assert(!close(fd));
    memset(result.rw, 0xa5, result.size);
    return result;
}

static void check_protection(const void *pointer, int required, int forbidden)
{
    mach_vm_address_t address = (uintptr_t)pointer;
    mach_vm_size_t length = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    assert(mach_vm_region(mach_task_self(), &address, &length, VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info, &count, &object) == KERN_SUCCESS);
    assert((info.protection & required) == required && !(info.protection & forbidden));
    if (object) mach_port_deallocate(mach_task_self(), object);
}

static uint32_t adrp(unsigned reg, uintptr_t pc, uintptr_t target)
{
    int64_t delta = ((int64_t)(target & ~(uintptr_t)4095) - (int64_t)(pc & ~(uintptr_t)4095)) / 4096;
    assert(delta >= -(1 << 20) && delta < (1 << 20));
    uint32_t immediate = (uint32_t)delta & 0x1fffff;
    return 0x90000000u | (immediate & 3) << 29 | (immediate >> 2) << 5 | reg;
}

/* Caller supplies true fresh-image bounds, not guessed guest permissions. */
static int permitted_data(void *context, uintptr_t rx, uintptr_t rw, size_t bytes)
{
    const struct image *image = context;
    return inside(rx, bytes, (uintptr_t)image->rx + image->page, image->page) &&
           rw == (uintptr_t)image->rw + (rx - (uintptr_t)image->rx) && !(rx & (bytes - 1));
}

static void emit_case(unsigned which, int optimized)
{
    uint32_t *code = (uint32_t *)(active.rw + which * 256);
    uintptr_t rx = (uintptr_t)active.rx + which * 256;
    uintptr_t target = (uintptr_t)active.rx + active.page + 0x100 + which * 16;
    unsigned producer, count;
    if (which == 0) {
        uint32_t words[] = {0xd280002a, 0, 0, 0xf82a0129, 0xaa0903e0, 0xd65f03c0};
        count = sizeof(words) / sizeof(words[0]); producer = 1;
        memcpy(code, words, sizeof(words));
        code[1] = adrp(9, rx + 4, target);
        code[2] = 0x91000000u | (target & 4095) << 10 | 9 << 5 | 9;
    } else if (which == 1) {
        uint32_t words[] = {0xd2800021, 0, 0, 0xf8210108, 0xaa0803e0, 0xd65f03c0};
        count = sizeof(words) / sizeof(words[0]); producer = 1;
        memcpy(code, words, sizeof(words));
        code[1] = adrp(8, rx + 4, target);
        code[2] = 0x91000000u | (target & 4095) << 10 | 8 << 5 | 8;
    } else {
        /* Exact captured LDXR/ADD-immediate/STXR/CBNZ; X10 dies at MOV. */
        uint32_t words[] = {0, 0, 0xc85f7d49, 0x91000529, 0xc80b7d49, 0x35ffffab,
                            0xaa1f03ea, 0xd1000520, 0xd65f03c0};
        count = sizeof(words) / sizeof(words[0]); producer = 0;
        memcpy(code, words, sizeof(words));
        code[0] = adrp(10, rx, target);
        code[1] = 0x91000000u | (target & 4095) << 10 | 10 << 5 | 10;
    }
    memset(active.rw + active.page + 0x100 + which * 16, 0, 8);
    if (optimized) {
        uint32_t original[32];
        assert(count <= sizeof(original) / sizeof(original[0]));
        memcpy(original, code, count * sizeof(code[0]));
        struct madeira_native_atomic_alias_plan plan;
        assert(madeira_native_atomic_alias_plan(code, count, rx, (intptr_t)alias_distance,
                                                producer, permitted_data, &active, &plan));
        assert(plan.producer_index == producer && plan.original == code[producer]);
        assert(plan.target_rx == target && plan.target_rw == target + alias_distance);
        code[producer] = plan.replacement;
        for (unsigned i = 0; i < count; ++i)
            assert(code[i] == (i == producer ? plan.replacement : original[i]));
    }
    __builtin___clear_cache((char *)code, (char *)(code + count));
    __builtin___clear_cache((char *)rx, (char *)(rx + count * 4));
}

struct worker { unsigned which, direct; };
static void record_value(uint64_t value)
{
    assert(value < sizeof(seen));
    assert(!__atomic_exchange_n(&seen[value], 1, __ATOMIC_RELAXED));
}

static void *run_worker(void *argument)
{
    const struct worker *worker = argument;
    mach_port_t self = mach_thread_self();
    assert(thread_set_exception_ports(self, EXC_MASK_BAD_ACCESS, exception_port,
               EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64) == KERN_SUCCESS);
    mach_port_deallocate(mach_task_self(), self);
    uint64_t (*operation)(void) = (void *)(active.rx + worker->which * 256);
    uint64_t *counter = (void *)(active.rw + active.page + 0x100 + worker->which * 16);
    uint64_t start = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    for (unsigned iteration = 0; iteration < ROUNDS; ++iteration)
        record_value(worker->direct ? __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED) : operation());
    __atomic_add_fetch(&worker_cpu_ns, clock_ns(CLOCK_THREAD_CPUTIME_ID) - start, __ATOMIC_RELAXED);
    return NULL;
}

static void run_phase(unsigned which, int optimized)
{
    active = map_image();
    emit_case(which, optimized);
    unsigned char instructions_before[256];
    memcpy(instructions_before, active.rx + which * 256, sizeof(instructions_before));
    memset(seen, 0, sizeof(seen)); worker_cpu_ns = 0;
    uint64_t faults_before = __atomic_load_n(&fault_count, __ATOMIC_RELAXED);
    uint64_t server_before = server_cpu_ns(), wall_before = clock_ns(CLOCK_MONOTONIC);
    pthread_t threads[WORKERS + 1]; struct worker workers[WORKERS + 1];
    for (unsigned index = 0; index <= WORKERS; ++index) {
        workers[index] = (struct worker){which, index == WORKERS};
        assert(!pthread_create(&threads[index], NULL, run_worker, &workers[index]));
    }
    for (unsigned index = 0; index <= WORKERS; ++index) assert(!pthread_join(threads[index], NULL));
    uint64_t wall = clock_ns(CLOCK_MONOTONIC) - wall_before;
    uint64_t server_cpu = server_cpu_ns() - server_before;
    uint64_t faults = __atomic_load_n(&fault_count, __ATOMIC_RELAXED) - faults_before;
    assert(!phase_failures);
    assert(!memcmp(instructions_before, active.rx + which * 256, sizeof(instructions_before)));
    assert(*(uint64_t *)(active.rw + active.page + 0x100 + which * 16) == sizeof(seen));
    for (size_t i = 0; i < sizeof(seen); ++i) assert(seen[i]);
    for (unsigned i = 0; i < 8; ++i) {
        assert(active.rx[active.page + 0x100 + which * 16 - 8 + i] == 0xa5);
        assert(active.rx[active.page + 0x100 + which * 16 + 8 + i] == 0xa5);
    }
    if (optimized) assert(!faults);
    else if (which < 2) assert(faults == WORKERS * ROUNDS);
    else assert(faults >= WORKERS * ROUNDS); /* genuine failed exclusive attempts retry */
    check_protection(active.rx, PROT_READ | PROT_EXEC, PROT_WRITE);
    check_protection(active.rw, PROT_READ | PROT_WRITE, PROT_EXEC);
    printf("[native-atomic-throughput] case=%u mode=%s workers=%u operations=%zu "
           "mach-store-faults=%" PRIu64 " wall-ns=%" PRIu64 " worker-cpu-ns=%" PRIu64
           " handler-cpu-ns=%" PRIu64 " alias-delta=%#" PRIxPTR " counter=correct unique-old-values=correct\n",
           which, optimized ? "production-plan" : "production-emulation", WORKERS + 1,
           sizeof(seen), faults, wall, worker_cpu_ns, server_cpu, alias_distance);
    assert(!munmap(active.reserved, active.reservation)); memset(&active, 0, sizeof(active));
}

int main(void)
{
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    pthread_t server;
    assert(!pthread_create(&server, NULL, exception_server, NULL));
    /* Publish the port with a join-free initial handshake, before measuring. */
    while (!__atomic_load_n(&server_thread_port, __ATOMIC_ACQUIRE)) sched_yield();
    for (unsigned which = 0; which < CASES; ++which) {
        run_phase(which, 0);
        run_phase(which, 1);
    }
    mach_msg_header_t stop = {0};
    stop.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    stop.msgh_size = sizeof(stop); stop.msgh_remote_port = exception_port; stop.msgh_id = 1;
    assert(mach_msg(&stop, MACH_SEND_MSG, sizeof(stop), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS);
    assert(!pthread_join(server, NULL));
    mach_port_deallocate(mach_task_self(), server_thread_port);
    assert(mach_port_deallocate(mach_task_self(), exception_port) == KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(), exception_port, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    puts("PASS native atomic alias hardware throughput: real Mach baseline, zero-fault production plan, no lost updates");
    return 0;
}
