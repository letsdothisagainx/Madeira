static int ios_stuck_store_inspect( mach_port_t thread, uint64_t native_id,
                                   struct ios_stuck_entry *entry, uint64_t dt, uint64_t dsys )
{
    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    arm_thread_state64_t st;
    arm_neon_state64_t neon;
    mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT, nc = ARM_NEON_STATE64_COUNT;
    uint64_t pc, bb = 0, ea = 0, held_start = 0, held_end = 0;
    uint32_t insn = 0;
    unsigned len = 0;
    int got, have_neon = 0, cross;

    ios_stuck_clock_us(&held_start);
    if (thread_suspend( thread ) != KERN_SUCCESS)
    {
        entry->pc = entry->ea = entry->hits = 0;
        return -1;
    }
    got = thread_get_state( thread, ARM_THREAD_STATE64, (thread_state_t)&st, &cnt ) == KERN_SUCCESS;
    if (!got || !ios_ts_read( st.__x[28], &bb, 8 ) || bb <= 0x10000)
    {
        entry->pc = entry->ea = entry->hits = 0;
        thread_resume( thread );
        return -1;
    }
    pc = arm_thread_state64_get_pc( st );
    cross = ios_ts_read( pc, &insn, 4 ) && ios_ldst_ea( insn, &st, &ea, &len ) &&
            ((ea ^ (ea + len - 1)) & ~(uint64_t)(vm_page_size - 1));
    if (cross && entry->pc == pc && entry->ea == ea)
    {
        unsigned hits = ++entry->hits;
        /* General-register stores never read vector state. Capture it only
         * for an actual repeated SIMD candidate, while still suspended. */
        if (insn & (1u << 26))
            have_neon = thread_get_state( thread, ARM_NEON_STATE64, (thread_state_t)&neon, &nc ) == KERN_SUCCESS;
        int r = ios_store_split_crossing( insn, &st, have_neon ? &neon : NULL,
                                          (uintptr_t)ios_jit_rx_base_global, (uintptr_t)ios_jit_rw_base_global,
                                          ios_jit_pool_size_global );
        if (r > 0)
        {
            __darwin_arm_thread_state64_set_pc_fptr( st, (void *)(uintptr_t)(pc + 4) );
            if (thread_set_state( thread, ARM_THREAD_STATE64, (thread_state_t)&st, ARM_THREAD_STATE64_COUNT ) != KERN_SUCCESS)
                r = -2;   /* bytes written, authoritative PC unchanged */
            else
                ios_stuck_fixed++;
        }
        thread_resume( thread );
        ios_stuck_clock_us(&held_end);
        ios_cs2_stall_recovery_note(native_id, 1, held_end >= held_start ? held_end - held_start : 0,
            0, 0, 0, 0, pc, ea, insn, len, r);
        if (ios_stuck_logs < 400 && (r > 0 || hits <= 3 || hits % 10 == 0))
        {
            ios_stuck_logs++;
            wine_log_write( "[stuck-store] ml1292 tid=%llu hits=%u pc=0x%llx insn=%08x ea=0x%llx len=%u "
                            "sys+%llu ms in %llu ms: %s confirmed-prefix=%u (%llu completed so far)",
                            (unsigned long long)native_id, hits, (unsigned long long)pc, insn,
                            (unsigned long long)ea, len, (unsigned long long)dsys, (unsigned long long)dt,
                            r > 0 ? "completed, pc+4" : r == -2 ? "written, set_state FAILED"
                            : r <= -3 ? "checked write failed; partial store, PC unchanged"
                            : r < 0 ? "not completed (validation or checked write)" : "not a store it decodes",
                            r > 0 || r == -2 ? len : r <= -3 ? (unsigned)(-r - 2) : 0, ios_stuck_fixed );
        }
        if (r > 0) { entry->pc = entry->ea = entry->hits = 0; return 1; }
        return r <= -2 ? -1 : 0;
    }
    thread_resume( thread );
    ios_stuck_clock_us(&held_end);
    ios_cs2_stall_recovery_note(native_id, 1, held_end >= held_start ? held_end - held_start : 0,
        0, 0, 0, 0, pc, ea, insn, len, 2 /* observed; no completion attempted */);
    entry->pc = cross ? pc : 0;
    entry->ea = cross ? ea : 0;
    return 0;
}
