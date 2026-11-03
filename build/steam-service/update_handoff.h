/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 125hz
 * Madeira Converter Exception: see LICENSE-EXCEPTION.md */
#ifndef MADEIRA_STEAM_UPDATE_HANDOFF_H
#define MADEIRA_STEAM_UPDATE_HANDOFF_H
#include <stdint.h>

/* The native observer supplies facts from held process handles, SCM's PID,
 * canonical image paths and process creation times. A PID alone is no proof
 * of ownership, particularly after the original service has exited. */
struct steam_update_witness {
    uint32_t parent_pid, child_parent_pid;
    uint64_t attempt_started, parent_created, child_created;
    unsigned parent_handle_valid, parent_path_matches;
    unsigned child_handle_valid, child_path_matches, parent_exited;
    uint32_t parent_exit_code;
};
static inline int steam_update_child_matches(const struct steam_update_witness *w)
{
    return w->parent_handle_valid && w->parent_path_matches &&
           w->child_handle_valid && w->child_path_matches && w->parent_pid &&
           w->child_parent_pid == w->parent_pid && w->parent_created &&
           w->attempt_started && w->child_created >= w->parent_created &&
           w->child_created >= w->attempt_started;
}
static inline int steam_update_witness_matches(const struct steam_update_witness *w)
{
    return steam_update_child_matches(w) && w->parent_exited && !w->parent_exit_code;
}
struct steam_update_ops {
    uint32_t (*start_attempt)(void);
    int (*capture_verified_updater)(void);
    uint32_t (*wait_updater)(void);
};
static inline uint32_t service_start_with_update_handoff(const struct steam_update_ops *ops)
{
    uint32_t error = ops->start_attempt();
    if (error != 1053 || !ops->capture_verified_updater()) return error;
    if ((error = ops->wait_updater())) return error;
    /* One genuine SCM retry. Its callback must confirm SERVICE_RUNNING. */
    return ops->start_attempt();
}
#endif
