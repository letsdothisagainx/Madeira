/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_CS2_STALL_WATCH_NATIVE_H
#define MADEIRA_CS2_STALL_WATCH_NATIVE_H
/* One exact main-thread snapshot/second, <= 20 minutes per accepted process.
 * Reuse xprobe's existing task_threads right and enumeration. All lookups,
 * instruction/mapping reads, symbolization and logging happen with the target
 * RUNNING again. The only held operations are Mach get_state and the balanced
 * resume; their elapsed duration is reported, never assumed negligible. */
static void ios_cs2_stall_main_sample(mach_port_t port, uint64_t native_id)
{
    static struct {
        struct ios_cs2_stall_rate rate;
        uint64_t sampled_us, user_us, system_us;
    } previous[IOS_CS2_STALL_PROCESSES];
    struct ios_cs2_stall_watch *watch;
    thread_basic_info_data_t bi;
    arm_thread_state64_t st = {0};
    mach_msg_type_number_t bic = THREAD_BASIC_INFO_COUNT, sc = ARM_THREAD_STATE64_COUNT;
    uint64_t now, held_start = 0, held_end = 0, cpu_user, cpu_system, du = 0, ds = 0, elapsed = 0;
    uint64_t pc = 0, lr = 0, ea = 0;
    uintptr_t pe = 0;
    uint32_t insn = 0;
    unsigned slot, process, length = 0;
    int got = 0, suspend_result = -1, resume_result = -1, decoded = 0;
    char symbol[120] = "unavailable";
    extern int ios_jit_pool_image_pc(uintptr_t, uintptr_t *);
    watch = ios_cs2_stall_for_native(native_id, 1, &slot);
    if (!watch || !ios_stuck_clock_us(&now)) return;
    process = slot / 3;
    if (!ios_cs2_stall_due(&previous[process].rate, now) ||
        ios_thread_process_try_observation_lease((void *)(uintptr_t)watch->owner, watch->pid) != watch->lease ||
        thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&bi, &bic) != KERN_SUCCESS ||
        bi.user_time.seconds < 0 || bi.system_time.seconds < 0) return;
    cpu_user = (uint64_t)bi.user_time.seconds * 1000000 + bi.user_time.microseconds;
    cpu_system = (uint64_t)bi.system_time.seconds * 1000000 + bi.system_time.microseconds;
    if (previous[process].sampled_us && now >= previous[process].sampled_us &&
        cpu_user >= previous[process].user_us && cpu_system >= previous[process].system_us)
    {
        elapsed = now - previous[process].sampled_us;
        du = cpu_user - previous[process].user_us;
        ds = cpu_system - previous[process].system_us;
    }
    previous[process].sampled_us = now;
    previous[process].user_us = cpu_user;
    previous[process].system_us = cpu_system;
    ios_stuck_clock_us(&held_start);
    suspend_result = thread_suspend(port);
    if (suspend_result == KERN_SUCCESS)
    {
        got = thread_get_state(port, ARM_THREAD_STATE64, (thread_state_t)&st, &sc) == KERN_SUCCESS;
        resume_result = thread_resume(port);
    }
    ios_stuck_clock_us(&held_end);
    if (got)
    {
        pc = arm_thread_state64_get_pc(st); lr = arm_thread_state64_get_lr(st);
        ios_ts_sym(pc, symbol, sizeof(symbol));
        ios_jit_pool_image_pc(pc, &pe);
        decoded = ios_ts_read(pc, &insn, sizeof(insn)) && ios_ldst_ea(insn, &st, &ea, &length);
    }
    wine_log_write("[cs2-main-progress-v1] pid=%04x tid=%04x native=%llu owner=%#llx lease=%llu sample=%u/%u interval-us=%llu user-us=%llu kernel-us=%llu run-state=%d suspend-count-before=%d host-pc=%#llx host-lr=%#llx host-sp=%#llx syscall-x16=%llu symbol=%s image-pc=%#llx captured=%d suspend-result=%d resume-result=%d held-us=%llu code-read=after-resume insn=%08x decoded-access=%d ea=%#llx bytes=%u",
        watch->pid, watch->main.tid, (unsigned long long)native_id, (unsigned long long)watch->owner,
        (unsigned long long)watch->lease, previous[process].rate.samples, IOS_CS2_STALL_SAMPLES,
        (unsigned long long)elapsed, (unsigned long long)du, (unsigned long long)ds,
        bi.run_state, bi.suspend_count, (unsigned long long)pc, (unsigned long long)lr,
        (unsigned long long)(got ? arm_thread_state64_get_sp(st) : 0),
        (unsigned long long)(got ? st.__x[16] : 0), symbol, (unsigned long long)pe,
        got, suspend_result, resume_result,
        (unsigned long long)(held_end >= held_start ? held_end - held_start : 0),
        insn, decoded, (unsigned long long)ea, length);
}

/* Last fixed-size phase capture for the existing three watched timelines.
 * Published by the recovery worker after its matching resume; no new sampler,
 * suspension, allocation or unbounded event stream. Wall time includes scheduling. */
#include "store_recovery_phases.h"
static struct ios_store_recovery_phases ios_cs2_recovery_phase[IOS_CS2_STALL_PROCESSES * 3];
static void ios_cs2_stall_recovery_phases_note(uint64_t native_id,
                                              const struct ios_store_recovery_phases *phase)
{
    unsigned slot;
    if (ios_cs2_stall_for_native(native_id, 0, &slot)) ios_cs2_recovery_phase[slot] = *phase;
}

/* Reuse the recovery owner's existing captures. No extra thread suspension or
 * task scan, and the 400-line historical completion cap cannot hide these
 * three scoped timelines. Counters are cumulative; a last-PC record explicitly
 * carries its age. A gate record is not evidence that a store was attempted. */
static void ios_cs2_stall_recovery_note(uint64_t native_id, int inspected,
    uint64_t elapsed, uint64_t user, uint64_t system, int run_state, int eligible,
    uint64_t pc, uint64_t ea, uint32_t insn, unsigned bytes, int result)
{
    static struct {
        struct ios_cs2_stall_rate rate;
        uint64_t captures, completed, unhandled, refused, partial, publication_failed;
        uint64_t pc, ea, captured_us, held_us;
        uint32_t insn;
        unsigned bytes;
        int result;
    } state[IOS_CS2_STALL_PROCESSES * 3];
    struct ios_cs2_stall_watch *watch;
    const struct ios_cs2_stall_target *target;
    const struct ios_store_recovery_phases *phase;
    uint64_t now;
    unsigned slot;
    watch = ios_cs2_stall_for_native(native_id, 0, &slot);
    if (!watch || !ios_stuck_clock_us(&now)) return;
    if (inspected)
    {
        state[slot].captures++;
        if (result == 1) state[slot].completed++;
        if (result == 0) state[slot].unhandled++;
        if (result == -1) state[slot].refused++;
        if (result <= -3) state[slot].partial++;
        if (result == -2) state[slot].publication_failed++;
        state[slot].pc = pc; state[slot].ea = ea;
        state[slot].held_us = elapsed;
        state[slot].insn = insn; state[slot].bytes = bytes;
        state[slot].captured_us = now; state[slot].result = result;
        return;
    }
    if (!ios_cs2_stall_due(&state[slot].rate, now) ||
        ios_thread_process_try_observation_lease((void *)(uintptr_t)watch->owner, watch->pid) != watch->lease) return;
    phase = &ios_cs2_recovery_phase[slot];
    target = slot % 3 ? &watch->worker[slot % 3 - 1] : &watch->main;
    wine_log_write("[cs2-store-progress-v1] pid=%04x tid=%04x native=%llu slot=%u sample=%u/%u interval-us=%llu user-us=%llu kernel-us=%llu run-state=%d eligible=%d captures=%llu completed=%llu unhandled=%llu refused=%llu partial=%llu publication-failed=%llu last-pc=%#llx last-ea=%#llx last-insn=%08x last-bytes=%u last-result=%d last-held-us=%llu last-age-us=%llu phase-advisory-us=%llu phase-prepare-read-us=%llu phase-suspend-us=%llu phase-capture-us=%llu phase-held-read-us=%llu phase-validation-us=%llu phase-write0-us=%llu phase-write1-us=%llu phase-note-us=%llu phase-publication-us=%llu phase-resume-us=%llu recovery-worker=%llu base-qos=%u held-qos=%u qos-changed=%u qos-query=%d qos-set=%d qos-held-query=%d qos-restore=%d capture-result=%d resume-result=%d result-2=observed-not-attempted captures-source=existing-recovery no-new-suspension=1 phases=wall-us emit=after-resume",
        watch->pid, target->tid, (unsigned long long)native_id, slot % 3,
        state[slot].rate.samples, IOS_CS2_STALL_SAMPLES,
        (unsigned long long)elapsed, (unsigned long long)user, (unsigned long long)system,
        run_state, eligible, (unsigned long long)state[slot].captures,
        (unsigned long long)state[slot].completed, (unsigned long long)state[slot].unhandled,
        (unsigned long long)state[slot].refused, (unsigned long long)state[slot].partial,
        (unsigned long long)state[slot].publication_failed, (unsigned long long)state[slot].pc,
        (unsigned long long)state[slot].ea, state[slot].insn, state[slot].bytes, state[slot].result,
        (unsigned long long)state[slot].held_us,
        (unsigned long long)(state[slot].captured_us && now >= state[slot].captured_us ? now - state[slot].captured_us : 0),
        (unsigned long long)phase->advisory_capture_us, (unsigned long long)phase->prepare_read_us,
        (unsigned long long)phase->suspend_us, (unsigned long long)phase->capture_us,
        (unsigned long long)phase->read_us, (unsigned long long)phase->validation_us,
        (unsigned long long)phase->write_us[0], (unsigned long long)phase->write_us[1],
        (unsigned long long)phase->note_us, (unsigned long long)phase->publication_us,
        (unsigned long long)phase->resume_us, (unsigned long long)phase->worker_id,
        phase->base_qos, phase->held_qos, phase->qos_changed,
        phase->qos_query_result, phase->qos_set_result, phase->qos_held_query_result,
        phase->qos_restore_result, phase->capture_result, phase->resume_result);
}
#endif
