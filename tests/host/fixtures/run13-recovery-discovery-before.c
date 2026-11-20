/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Exact discovery bodies at f0fb85f7c28b7a298d15b462ecc492c406c4b464.
 * Read-only comparison input for normal-success scheduling replay. */
static void ios_stuck_store_check( void )
{
    mach_port_t self_port = pthread_mach_thread_np( pthread_self() );
    thread_act_array_t tl;
    mach_msg_type_number_t tc;
    struct timespec ts;
    uint64_t now, now_us;
    unsigned k;

    if (clock_gettime( CLOCK_MONOTONIC, &ts ))
    {
        ios_stuck_history_reset( &ios_stuck );
        ios_stuck_hot_reset();
        return;
    }
    now_us = (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
    now = now_us / 1000;
    if (task_threads( mach_task_self(), &tl, &tc ) != KERN_SUCCESS)
    {
        ios_stuck_history_reset( &ios_stuck );
        return;
    }
    if (!ios_stuck_history_begin( &ios_stuck, tc )) goto release_threads;
    for (k = 0; k < tc; k++)
    {
        thread_basic_info_data_t bi;
        thread_identifier_info_data_t idi;
        mach_msg_type_number_t bic = THREAD_BASIC_INFO_COUNT, idc = THREAD_IDENTIFIER_INFO_COUNT;
        uint64_t dt, sys, dsys, user, duser;
        struct ios_stuck_entry *entry;
        int user_valid;

        if (tl[k] == self_port) continue;
        if (thread_info( tl[k], THREAD_BASIC_INFO, (thread_info_t)&bi, &bic ) != KERN_SUCCESS) continue;
        if (thread_info( tl[k], THREAD_IDENTIFIER_INFO, (thread_info_t)&idi, &idc ) != KERN_SUCCESS) continue;
        if (bi.system_time.seconds < 0 || bi.system_time.microseconds < 0 ||
            bi.user_time.seconds < 0 || bi.user_time.microseconds < 0) continue;
        sys = (uint64_t)bi.system_time.seconds * 1000000 + bi.system_time.microseconds;
        user = (uint64_t)bi.user_time.seconds * 1000000 + bi.user_time.microseconds;
        entry = ios_stuck_history_observe( &ios_stuck, idi.thread_id, now, sys, &dt, &dsys );
        if (!entry) continue;
        user_valid = user >= entry->user_us;
        duser = user_valid ? user - entry->user_us : 0;
        entry->user_us = user;
        if (ios_stuck_hot_contains( idi.thread_id ))
        {
            /* The same owner handles these through the retained native port.
             * Full-history observations must not duplicate a hot comparison. */
            entry->pc = entry->ea = entry->hits = 0;
            continue;
        }
        ios_cs2_stall_recovery_note(idi.thread_id, 0, dt * 1000, duser, dsys, bi.run_state,
            bi.run_state == TH_STATE_RUNNING && dt && user_valid && ios_stuck_kernel_bound(duser, dsys),
            0, 0, 0, 0, 0);
        if (bi.run_state != TH_STATE_RUNNING || !dt || !user_valid || !ios_stuck_kernel_bound( duser, dsys ))
        {
            entry->pc = entry->ea = entry->hits = 0;
            continue;
        }
        if (ios_stuck_store_inspect( tl[k], idi.thread_id, entry, dt, dsys / 1000 ) > 0)
            ios_stuck_hot_enroll( tl[k], entry );
    }
    ios_stuck_history_end( &ios_stuck );
release_threads:
    for (k = 0; k < tc; k++) mach_port_deallocate( mach_task_self(), tl[k] );
    vm_deallocate( mach_task_self(), (vm_address_t)tl, tc * sizeof(*tl) );
}

static void ios_stuck_store_recovery_tick( uint64_t now_us )
{
    uint64_t now = now_us / 1000;
    ios_stuck_store_hot_check( now_us );
    if (now >= ios_stuck_discovery_due)
    {
        ios_stuck_store_check();
        ios_stuck_discovery_due = now + 100;
    }
}
