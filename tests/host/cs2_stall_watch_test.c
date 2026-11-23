/* All native adapters below return successful, normal snapshots. No executable
 * memory, deliberate faults, protection changes or guest code are exercised. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cs2_stall_watch.h"
typedef unsigned mach_port_t;
typedef unsigned mach_msg_type_number_t;
typedef void *thread_info_t;
typedef void *thread_state_t;
typedef struct { int seconds, microseconds; } fixture_time;
typedef struct { fixture_time user_time, system_time; int run_state, suspend_count; } thread_basic_info_data_t;
typedef struct { uint64_t __x[29], __fp, __lr, __sp, __pc; } arm_thread_state64_t;
#define KERN_SUCCESS 0
#define THREAD_BASIC_INFO 1
#define THREAD_BASIC_INFO_COUNT 1
#define ARM_THREAD_STATE64 2
#define ARM_THREAD_STATE64_COUNT 1
#define arm_thread_state64_get_pc(s) ((s).__pc)
#define arm_thread_state64_get_lr(s) ((s).__lr)
#define arm_thread_state64_get_sp(s) ((s).__sp)
static uint64_t clock_us = 1000000;
static unsigned held, suspended, resumed, captures;
static char output[4096];
static int ios_stuck_clock_us(uint64_t *now) { *now = clock_us; return 1; }
static int thread_info(mach_port_t port, unsigned flavor, thread_info_t out, unsigned *count)
{
    assert(port == 17 && flavor == THREAD_BASIC_INFO && *count == THREAD_BASIC_INFO_COUNT && !held);
    *(thread_basic_info_data_t *)out = (thread_basic_info_data_t){{0,10000}, {0,20000}, 3, 0};
    return KERN_SUCCESS;
}
static int thread_suspend(mach_port_t port) { assert(port == 17 && !held); held++; suspended++; return 0; }
static int thread_resume(mach_port_t port) { assert(port == 17 && held == 1); held--; resumed++; return 0; }
static int thread_get_state(mach_port_t port, unsigned flavor, thread_state_t out, unsigned *count)
{
    arm_thread_state64_t *s = out;
    assert(port == 17 && held && flavor == ARM_THREAD_STATE64 && *count == ARM_THREAD_STATE64_COUNT);
    memset(s, 0, sizeof(*s));
    s->__pc = 0x123400; s->__sp = 0x200000; s->__lr = 0x123500;
    s->__x[8] = 0x7a5aeb3fe1;
    captures++;
    return 0;
}
static void ios_ts_sym(uint64_t pc, char *out, size_t size)
{ assert(!held && pc == 0x123400); snprintf(out, size, "fixture-native"); }
int ios_jit_pool_image_pc(uintptr_t pc, uintptr_t *out)
{ assert(!held && pc == 0x123400); *out = 0; return 0; }
static int ios_ts_read(uint64_t address, void *out, size_t size)
{
    uint32_t insn = 0x3d800500; /* STR Q0,[X8,#16] from the observed copy loop */
    assert(!held && address == 0x123400 && size == 4);
    memcpy(out, &insn, size); return 1;
}
static unsigned long long ios_thread_process_try_observation_lease(void *owner, unsigned pid)
{ assert(!held && owner == (void *)0x100000 && pid == 0x374); return 99; }
static void wine_log_write(const char *format, ...) __attribute__((format(printf,1,2)));
static void wine_log_write(const char *format, ...)
{
    va_list ap;
    assert(!held);
    va_start(ap, format); vsnprintf(output, sizeof(output), format, ap); va_end(ap);
}
#include "actual_store_decode.h"
#include "run_evidence.h"
uint64_t ios_evidence_now(void) { return 123000; }
void ios_evidence_emit(struct ios_evidence_record *r) { assert(!held); (void)r; }
void ios_evidence_access(struct ios_evidence_record *r) { assert(!held); (void)r; }
#include "cs2_stall_watch_native.h"

int main(void)
{
    FILE *rows = fopen(getenv("MADEIRA_TEST_ROWS"), "w");
    unsigned slot = 99;
    struct ios_cs2_stall_rate rate = {0};
    struct ios_cs2_stall_watch *watch;
    assert(rows);
    ios_cs2_stall_register_main(0x100000, 0x374, 99, 0x378, 0x70aef10000, 71);
    ios_cs2_stall_register_main(0x100000, 0x374, 99, 0x999, 0x7000000000, 72);
    watch = ios_cs2_stall_for_native(71, 1, &slot);
    assert(watch && slot == 0 && watch->main.tid == 0x378);
    assert(!ios_cs2_stall_for_native(72, 0, &slot));
    ios_cs2_stall_register_worker(0x100000, 0x374, 99, 0x378, 0x70aef10000, 71);
    ios_cs2_stall_register_worker(0x100000, 0x374, 99, 0x38c, 0x70aefc0000, 73);
    ios_cs2_stall_register_worker(0x100000, 0x374, 99, 0x394, 0x70aeee0000, 74);
    ios_cs2_stall_register_worker(0x100000, 0x374, 99, 0x395, 0x7000000000, 75);
    assert(ios_cs2_stall_for_native(73, 0, &slot) == watch && slot == 1);
    assert(ios_cs2_stall_for_native(74, 0, &slot) == watch && slot == 2);
    assert(!ios_cs2_stall_for_native(73, 1, &slot));
    assert(!ios_cs2_stall_for_native(75, 0, &slot));
    assert(!ios_cs2_stall_find(0x100000, 0x374, 100));
    for (unsigned i = 0; i < IOS_CS2_STALL_SAMPLES; ++i)
    {
        assert(ios_cs2_stall_due(&rate, (uint64_t)i * 1000000));
        assert(!ios_cs2_stall_due(&rate, (uint64_t)i * 1000000 + 999999));
    }
    assert(ios_cs2_stall_due(&rate, UINT64_C(5000000000)));
    /* Waiting main thread is observed, not filtered as an idle thread. */
    ios_cs2_stall_main_sample(17, 71);
    assert(captures == 1 && suspended == 1 && resumed == 1 && !held);
    assert(strstr(output, "run-state=3") && strstr(output, "suspend-count-before=0"));
    assert(strstr(output, "ea=0x7a5aeb3ff1") && strstr(output, "bytes=16"));
    fprintf(rows, "%s\n", output);
    ios_cs2_stall_main_sample(17, 71);
    assert(captures == 1); /* one second rate, not one per task enumeration */
    clock_us += 1000000;
    ios_cs2_stall_main_sample(17, 71);
    assert(captures == 2 && suspended == resumed && strstr(output, "interval-us=1000000"));
    assert(strstr(output, "user-us=0 kernel-us=0"));
    /* Observation never completes or changes the store. It records a normal
     * completion reported by the existing production recovery owner. */
    ios_cs2_stall_recovery_phases_note(73, &(struct ios_store_recovery_phases){.worker_id=123, .held_qos=33, .write_us={17,19}});
    ios_cs2_stall_recovery_note(73, 1, 11, 0, 0, 0, 0, 0x123400, 0x7a5aeb3ff1, 0x3d800500, 16, 1);
    ios_cs2_stall_recovery_note(73, 0, 100000, 100, 1000, 1, 1, 0, 0, 0, 0, 0);
    assert(strstr(output, "tid=038c") && strstr(output, "completed=1") && strstr(output, "last-held-us=11"));
    assert(strstr(output, "recovery-worker=123") && strstr(output, "write0-us=17") && strstr(output, "write1-us=19"));
    fprintf(rows, "%s\n", output);
    assert(!fclose(rows));
    assert(captures == 2 && suspended == resumed);
    puts("scope identity, worker bounds, rate cap, idle-main coverage, balanced normal capture, and recovery observation: PASS");
    return 0;
}
