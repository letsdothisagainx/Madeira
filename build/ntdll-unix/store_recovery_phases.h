/* Fixed-size wall-time attribution for the production recovery scope.
 * No allocation, logging, guest access, timer or cancellation mechanism. */
#ifndef MADEIRA_STORE_RECOVERY_PHASES_H
#define MADEIRA_STORE_RECOVERY_PHASES_H
#include <stdint.h>
#include <time.h>

struct ios_store_recovery_phases
{
    uint64_t advisory_capture_us, prepare_read_us, suspend_us, capture_us, read_us;
    uint64_t validation_us, write_us[2], note_us, publication_us, resume_us;
    uint64_t worker_id;
    unsigned base_qos, held_qos, qos_changed;
    int relative_priority, qos_query_result, qos_set_result, qos_held_query_result, qos_restore_result;
    int capture_result, resume_result;
};

static inline uint64_t ios_store_phase_clock(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000L || (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec / 1000) / 1000000) return 0;
    return (uint64_t)now.tv_sec * 1000000 + (uint64_t)now.tv_nsec / 1000;
}

static inline uint64_t ios_store_phase_elapsed(uint64_t start)
{
    uint64_t now = ios_store_phase_clock();
    return start && now >= start ? now - start : 0;
}
#endif
