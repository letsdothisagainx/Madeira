#ifndef MADEIRA_SELF_SUSPEND_DISPATCH_H
#define MADEIRA_SELF_SUSPEND_DISPATCH_H

/* Read-only, version-checked observation at an already successful self-suspend.
 * These are the exact Run 11 client/tier0 layouts, not a general SDK layout.
 * A mismatch skips observation only. No guest instruction, register, handle,
 * suspend count, queue or resource is changed. Fixed reads replace a stack scan.
 * See docs/cs2-run11-dispatch-topology-20261120.md for the frame derivation. */
static int ios_dispatch_read( uintptr_t address, size_t offset, void *out, size_t bytes )
{
    if (!address || offset > UINTPTR_MAX - address || bytes > UINTPTR_MAX - address - offset) return 0;
    return ios_self_suspend_read( address + offset, out, bytes );
}

static int ios_dispatch_code( uint64_t raw, uint64_t *base, uint64_t *rva )
{
    extern uint64_t ios_jit_reverse_translate( uint64_t, uint64_t * );
    extern unsigned long long ios_jit_module_base_for_va( unsigned long long, unsigned long long * );
    uint64_t image = 0, pe = ios_jit_reverse_translate( raw, &image );
    if (!pe) { pe = raw; image = ios_jit_module_base_for_va( raw, NULL ); }
    if (!image || pe < image) return 0;
    *base = image; *rva = pe - image;
    return 1;
}

static int ios_dispatch_at( uint64_t raw, uint64_t expected_base, uint64_t expected_rva )
{
    uint64_t base, rva;
    return ios_dispatch_code( raw, &base, &rva ) && base == expected_base && rva == expected_rva;
}

static int ios_dispatch_image( uintptr_t base, uint32_t timestamp, uint32_t image_size )
{
    unsigned char dos[64], pe[84];
    uint16_t mz, machine, magic;
    uint32_t off, signature, stamp, size;
    if (!ios_dispatch_read( base, 0, dos, sizeof(dos) )) return 0;
    memcpy( &mz, dos, 2 ); memcpy( &off, dos + 60, 4 );
    if (mz != 0x5a4d || off < 64 || off > 4096 || !ios_dispatch_read( base, off, pe, sizeof(pe) )) return 0;
    memcpy( &signature, pe, 4 ); memcpy( &machine, pe + 4, 2 );
    memcpy( &stamp, pe + 8, 4 ); memcpy( &magic, pe + 24, 2 ); memcpy( &size, pe + 80, 4 );
    return signature == 0x4550 && machine == 0x8664 && magic == 0x20b &&
           stamp == timestamp && size == image_size;
}

static int ios_dispatch_bytes( uintptr_t base, size_t rva, const unsigned char *expected, size_t count )
{
    unsigned char bytes[32];
    return count <= sizeof(bytes) && ios_dispatch_read( base, rva, bytes, count ) && !memcmp( bytes, expected, count );
}

static void ios_self_suspend_dispatch_observe( const struct ios_self_suspend_snapshot *snapshot,
        uintptr_t stack_limit, uintptr_t stack_base, unsigned pid, unsigned tid )
{
    static const unsigned char capture[] = {0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,
        0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20,0x41,0x56,0x48,0x81,0xec,0xf0,0x04,0x00,0x00};
    static const unsigned char caller[] = {0x89,0x54,0x24,0x10,0x53,0x56,0x57,0x41,0x54,0x41,
        0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xec,0xe0,0x09,0x00,0x00};
    static const unsigned char callback[] = {0x48,0x83,0xc1,0x50,0x8b,0x51,0x60,0xe9,0x74,0x89,0xeb,0xff};
    static const unsigned char gate[] = {0x83,0xb9,0x30,0x01,0x00,0x00,0x00};
    static const unsigned char invoke[] = {0xff,0x50,0x28};
    int saved_errno = errno;
    const char *reason = "stack-bounds";
    uint64_t client = 0, tier0 = 0, kernel = 0, base = 0, rva = 0;
    uint64_t value, inner, outer, submit, job_arg, job, job_vt, job_callback, pool, pool_vt, pool_add;
    uint64_t saved_r14, saved_rdi, check_vt, vector_begin, vector_end;
    uint32_t creator, saved_tid, field_130;
    unsigned char job_fields[0x10], pool_fields[0x2b];
    unsigned complete_inline = 0;
    uintptr_t sp = snapshot->sp;

    if (!snapshot->valid || !stack_limit || stack_base <= stack_limit || sp < stack_limit ||
        sp > stack_base || stack_base - sp < 0x1040 || (sp & 15)) goto skipped;
    reason = "native-frame";
    if (!ios_dispatch_code( snapshot->lr, &kernel, &rva ) || rva != 0x6dee4 ||
        !ios_dispatch_read( sp, 56, &value, 8 ) || !ios_dispatch_at( value, kernel, 0x78f4c ) ||
        !ios_dispatch_read( sp, 232, &value, 8 ) || !ios_dispatch_code( value, &client, &rva ) || rva != 0x457b)
        goto skipped;
    reason = "client-image";
    if (!ios_dispatch_image( client, 0x6aff8722, 0x298e000 ) ||
        !ios_dispatch_bytes( client, 0x4520, capture, sizeof(capture) ) ||
        !ios_dispatch_bytes( client, 0x3140, caller, sizeof(caller) ) ||
        !ios_dispatch_bytes( client, 0x14a7c0, callback, sizeof(callback) )) goto skipped;
    reason = "capture-caller";
    if (!ios_dispatch_read( sp, 0x5e8, &inner, 8 ) || !ios_dispatch_at( inner, client, 0x4331 )) goto skipped;
    reason = "job-object";
    if (!ios_dispatch_read( sp, 0x728, &job_arg, 8 ) || job_arg < 0x50) goto skipped;
    job = job_arg - 0x50;
    if (!ios_dispatch_read( job, 0, &job_vt, 8 ) || !ios_dispatch_at( job_vt, client, 0x1abc488 ) ||
        !ios_dispatch_read( job_vt, 0x28, &job_callback, 8 ) || !ios_dispatch_at( job_callback, client, 0x14a7c0 ) ||
        !ios_dispatch_read( job, 0x10, job_fields, sizeof(job_fields) ) ||
        !ios_dispatch_read( job, 0xb0, &creator, 4 )) goto skipped;
    memcpy( &pool, job_fields + 8, 8 );
    reason = "pool-object";
    if (!ios_dispatch_read( pool, 0, &pool_vt, 8 ) ||
        !ios_dispatch_read( pool_vt, 0x80, &pool_add, 8 ) ||
        !ios_dispatch_code( pool_add, &tier0, &rva ) || rva != 0xa5500 ||
        (!ios_dispatch_at( pool_vt, tier0, 0x316540 ) && !ios_dispatch_at( pool_vt, tier0, 0x316358 ))) goto skipped;
    reason = "pool-image";
    if (!ios_dispatch_image( tier0, 0x6af4a3e4, 0x401000 ) ||
        !ios_dispatch_bytes( tier0, 0xa5525, gate, sizeof(gate) ) ||
        !ios_dispatch_bytes( tier0, 0xa55a7, invoke, sizeof(invoke) )) goto skipped;
    reason = "dispatch-state";
    if (!ios_dispatch_read( pool, 0x130, pool_fields, sizeof(pool_fields) ) ||
        !ios_dispatch_read( sp, 0x1008, &outer, 8 ) ||
        !ios_dispatch_read( sp, 0x1018, &saved_tid, 4 ) ||
        !ios_dispatch_read( sp, 0x1038, &submit, 8 ) ||
        !ios_dispatch_read( sp, 0xfd8, &saved_r14, 8 ) ||
        !ios_dispatch_read( sp, 0xff0, &saved_rdi, 8 ) ||
        !ios_dispatch_read( job, 0, &check_vt, 8 ) || check_vt != job_vt ||
        !ios_dispatch_read( pool, 0, &check_vt, 8 ) || check_vt != pool_vt) goto skipped;

    complete_inline = ios_dispatch_at( outer, tier0, 0xa55aa ) &&
        ios_dispatch_at( submit, client, 0x53dc ) && saved_r14 == pool && saved_rdi == job && saved_tid == creator;
    memcpy( &field_130, pool_fields, 4 );
    memcpy( &vector_begin, pool_fields + 8, 8 ); memcpy( &vector_end, pool_fields + 16, 8 );
    dprintf( 2, "[self-suspend-dispatch-v1] result=captured pid=%04x tid=%04x "
        "dispatch=%s creator-tid=%04x creator-is-current=%u job=%p pool=%p "
        "job-u8-15=%u pool-u32-130=%u pool-u8-159=%u pool-u8-15a=%u "
        "pool-u64-138=%p pool-u64-140=%p state-time=after-suspend "
        "historical-state=unmeasured frames=matched-run11-contract\n",
        pid, tid, complete_inline ? "inline-submit-validated" : "other-path",
        creator, creator == tid, (void *)(uintptr_t)job, (void *)(uintptr_t)pool,
        job_fields[5], field_130, pool_fields[0x29], pool_fields[0x2a],
        (void *)(uintptr_t)vector_begin, (void *)(uintptr_t)vector_end );
    if (ios_dispatch_code( outer, &base, &rva ))
        dprintf( 2, "[self-suspend-dispatch-v1] event=outer-return module-base=%p rva=0x%llx "
                    "classification=client-frame-return\n", (void *)(uintptr_t)base, (unsigned long long)rva );
    goto done;
skipped:
    dprintf( 2, "[self-suspend-dispatch-v1] result=unavailable pid=%04x tid=%04x reason=%s "
                "action=observation-only-skip\n", pid, tid, reason );
done:
    errno = saved_errno;
}
#endif
