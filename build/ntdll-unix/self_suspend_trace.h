#ifndef MADEIRA_SELF_SUSPEND_TRACE_H
#define MADEIRA_SELF_SUSPEND_TRACE_H

/* One-shot observation of the actual self-suspend boundary. No thread is
 * stopped, resumed, queried for context, or redirected by this observer.
 * Identity/counts come from the server operation, not a second handle lookup.
 * All storage and output are bounded, including a never-resumed target. */
#define IOS_SELF_SUSPEND_WATCHES 16
struct ios_self_suspend_snapshot
{
    uint64_t pc, lr, sp, fp;
    unsigned valid;
};
static struct ios_self_suspend_watch
{
    unsigned state, pid, tid;
    uintptr_t teb;
    unsigned caller_reported, resume_reports, final_reported, wait_reported;
    unsigned resumes, last_old, last_new;
} ios_self_suspend_watches[IOS_SELF_SUSPEND_WATCHES];
static unsigned ios_self_suspend_limit_reported, ios_self_suspend_bad_resume_reports, ios_self_suspend_any_watched;

static unsigned ios_self_suspend_take( unsigned *value, unsigned limit )
{
    unsigned old = __atomic_load_n( value, __ATOMIC_RELAXED );
    while (old < limit)
        if (__atomic_compare_exchange_n( value, &old, old + 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
            return old + 1;
    return 0;
}

static uint64_t ios_self_suspend_now(void)
{
    struct timespec ts;
    if (clock_gettime( CLOCK_MONOTONIC, &ts )) return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static int ios_self_suspend_read( uintptr_t address, void *out, size_t bytes )
{
    mach_vm_size_t got = 0;
    return address && mach_vm_read_overwrite( mach_task_self(), address, bytes,
                   (mach_vm_address_t)(uintptr_t)out, &got ) == KERN_SUCCESS && got == bytes;
}

static struct ios_self_suspend_watch *ios_self_suspend_find( unsigned pid, unsigned tid, uintptr_t teb )
{
    unsigned i;
    for (i = 0; i < IOS_SELF_SUSPEND_WATCHES; ++i)
    {
        struct ios_self_suspend_watch *w = &ios_self_suspend_watches[i];
        if (__atomic_load_n( &w->state, __ATOMIC_ACQUIRE ) == 2 && w->pid == pid && w->tid == tid &&
            (!teb || w->teb == teb)) return w;
    }
    return NULL;
}

/* Called in the serialized server after the successful self suspend, before
 * its reply can be delivered or a resume request processed. Atomics only:
 * never allocate/log while a target could have a persistent Mach hold. */
void ios_self_suspend_server_begin( unsigned pid, unsigned tid, uintptr_t teb,
                                    unsigned by_pid, unsigned by_tid )
{
    int saved_errno = errno;
    unsigned i;
    if (ios_self_suspend_find( pid, tid, teb )) goto done;
    for (i = 0; i < IOS_SELF_SUSPEND_WATCHES; ++i)
    {
        struct ios_self_suspend_watch *w = &ios_self_suspend_watches[i];
        unsigned expected = 0;
        if (!__atomic_compare_exchange_n( &w->state, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED ))
            continue;
        w->pid = pid; w->tid = tid; w->teb = teb;
        __atomic_store_n( &w->state, 2, __ATOMIC_RELEASE );
        __atomic_store_n( &ios_self_suspend_any_watched, 1, __ATOMIC_RELEASE );
        goto done;
    }
done:
    (void)by_pid; (void)by_tid;
    errno = saved_errno;
}

/* Called after resume_thread performed its genuine decrement, Mach release,
 * and wake. Includes internal server resumes, not only NtResumeThread calls.
 * The first final decrement is always logged, independently of nested samples. */
void ios_self_suspend_server_resume( unsigned pid, unsigned tid, uintptr_t teb,
                                     unsigned by_pid, unsigned by_tid,
                                     unsigned old_count, unsigned new_count, unsigned held, unsigned process_suspend )
{
    int saved_errno = errno;
    struct ios_self_suspend_watch *w = ios_self_suspend_find( pid, tid, teb );
    unsigned final = 0, report;
    if (!w) goto done;
    ios_self_suspend_take( &w->resumes, UINT32_MAX );
    __atomic_store_n( &w->last_old, old_count, __ATOMIC_RELAXED );
    __atomic_store_n( &w->last_new, new_count, __ATOMIC_RELAXED );
    if (held) goto done; /* No logger/native-heap work inside a physical hold. */
    if (old_count && !new_count) final = ios_self_suspend_take( &w->final_reported, 1 );
    report = ios_self_suspend_take( &w->resume_reports, 8 );
    if (final || report)
        dprintf( 2, "[self-suspend-flow-v1] event=server-resume mono-ns=%llu pid=%04x tid=%04x "
                    "teb=%p by-pid=%04x by-tid=%04x count=%u->%u held=%u process-suspend=%u first-final=%u "
                    "attempt=%u coverage=first8-plus-first-final\n",
                 (unsigned long long)ios_self_suspend_now(), pid, tid, (void *)teb, by_pid, by_tid,
                 old_count, new_count, held, process_suspend, final, __atomic_load_n( &w->resumes, __ATOMIC_RELAXED ) );
done:
    errno = saved_errno;
}

/* This is the active native syscall frame populated by the dispatcher for
 * THIS API entry, not GetThreadContext(self) or a saved CPUArea guest RIP.
 * Snapshot only the control fields; never modify the frame or its restore flags. */
static void ios_self_suspend_capture( struct ios_self_suspend_snapshot *out, const void *frame )
{
    int saved_errno = errno;
    unsigned char bytes[0x110];
    memset( out, 0, sizeof(*out) );
    if (ios_self_suspend_read( (uintptr_t)frame, bytes, sizeof(bytes) ))
    {
        memcpy( &out->fp, bytes + 0xe8, 8 ); memcpy( &out->lr, bytes + 0xf0, 8 );
        memcpy( &out->sp, bytes + 0xf8, 8 ); memcpy( &out->pc, bytes + 0x100, 8 );
        out->valid = 1;
    }
    errno = saved_errno;
}

static void ios_self_suspend_pc( const char *kind, unsigned index, uint64_t raw )
{
    extern uint64_t ios_jit_reverse_translate( uint64_t, uint64_t * );
    extern unsigned long long ios_jit_module_base_for_va( unsigned long long, unsigned long long * );
    uint64_t base = 0, pe = ios_jit_reverse_translate( raw, &base );
    unsigned long long size = 0;
    if (!pe) { pe = raw; base = ios_jit_module_base_for_va( raw, &size ); }
    if (base && pe >= base)
        dprintf( 2, "[self-suspend-flow-v1] event=caller-address kind=%s index=%u raw=%p pe=%p "
                    "module-base=%p rva=0x%llx classification=code-map-candidate\n",
                 kind, index, (void *)(uintptr_t)raw, (void *)(uintptr_t)pe,
                 (void *)(uintptr_t)base, (unsigned long long)(pe - base) );
}

static unsigned ios_self_suspend_client_begin( const struct madeira_suspend_identity_reply *identity,
        uintptr_t handle, unsigned status, unsigned old_count,
        const struct ios_self_suspend_snapshot *snapshot, unsigned receipt_valid )
{
    int saved_errno = errno;
    struct ios_self_suspend_watch *w;
    unsigned i, hits = 0, ticket = 0;
    if (!identity->self) goto done;
    w = ios_self_suspend_find( identity->pid, identity->tid, (uintptr_t)NtCurrentTeb() );
    if (!w)
    {
        if (ios_self_suspend_take( &ios_self_suspend_limit_reported, 1 ))
            dprintf( 2, "[self-suspend-flow-v1] event=capture-limit watches=16 further-targets=unobserved\n" );
        goto done;
    }
    if (!ios_self_suspend_take( &w->caller_reported, 1 )) goto done;
    ticket = (unsigned)(w - ios_self_suspend_watches) + 1;
    dprintf( 2, "[self-suspend-flow-v1] event=client-result mono-ns=%llu watch=%u pid=%04x tid=%04x "
                "teb=%p handle=%p status=%08x old-count=%u identity=%s current-teb=%p current-peb=%p "
                "frame-valid=%u pc=%p lr=%p sp=%p fp=%p frame-source=active-native-syscall-entry coverage=one-shot-max16\n",
             (unsigned long long)ios_self_suspend_now(), ticket, identity->pid, identity->tid,
             (void *)w->teb, (void *)handle, status, old_count, receipt_valid ? "server-atomic" : "legacy-compare",
             NtCurrentTeb(), NtCurrentTeb()->Peb, snapshot->valid,
             (void *)(uintptr_t)snapshot->pc, (void *)(uintptr_t)snapshot->lr,
             (void *)(uintptr_t)snapshot->sp, (void *)(uintptr_t)snapshot->fp );
    if (!snapshot->valid) goto done;
    ios_self_suspend_pc( "syscall-pc", 0, snapshot->pc );
    ios_self_suspend_pc( "syscall-lr", 0, snapshot->lr );
    /* Bounded address candidates, not an asserted unwind. Only values resolved
     * by the PE code map are emitted; no strings or arbitrary stack contents. */
    for (i = 0; i < 64 && hits < 8 && snapshot->sp <= UINTPTR_MAX - i * 8; ++i)
    {
        uint64_t value, base = 0;
        extern uint64_t ios_jit_reverse_translate( uint64_t, uint64_t * );
        extern unsigned long long ios_jit_module_base_for_va( unsigned long long, unsigned long long * );
        if (!ios_self_suspend_read( (uintptr_t)snapshot->sp + i * 8, &value, 8 )) break;
        if (ios_jit_reverse_translate( value, &base ) || ios_jit_module_base_for_va( value, NULL ))
        { ios_self_suspend_pc( "stack-candidate", i * 8, value ); ++hits; }
    }
done:
    errno = saved_errno;
    return ticket;
}

static void ios_self_suspend_client_wait( unsigned ticket, unsigned status )
{
    int saved_errno = errno;
    struct ios_self_suspend_watch *w;
    if (!ticket || ticket > IOS_SELF_SUSPEND_WATCHES) goto done;
    w = &ios_self_suspend_watches[ticket - 1];
    if (ios_self_suspend_take( &w->wait_reported, 1 ))
        dprintf( 2, "[self-suspend-flow-v1] event=wait-return mono-ns=%llu watch=%u pid=%04x tid=%04x "
                    "status=%08x observed-resumes=%u last-count=%u->%u\n",
                 (unsigned long long)ios_self_suspend_now(), ticket, w->pid, w->tid, status,
                 __atomic_load_n( &w->resumes, __ATOMIC_RELAXED ),
                 __atomic_load_n( &w->last_old, __ATOMIC_RELAXED ),
                 __atomic_load_n( &w->last_new, __ATOMIC_RELAXED ) );
done:
    errno = saved_errno;
}

static void ios_self_suspend_client_resume( const struct madeira_suspend_identity_reply *identity,
        uintptr_t handle, unsigned status, unsigned old_count, unsigned receipt_valid )
{
    int saved_errno = errno;
    if (status && __atomic_load_n( &ios_self_suspend_any_watched, __ATOMIC_ACQUIRE ) &&
        ios_self_suspend_take( &ios_self_suspend_bad_resume_reports, 8 ))
        dprintf( 2, "[self-suspend-flow-v1] event=resume-api-failure mono-ns=%llu by-pid=%04x by-tid=%04x "
                    "handle=%p status=%08x identity-valid=%u target-pid=%04x target-tid=%04x old-count=%u "
                    "coverage=first8-failed-api-calls\n",
                 (unsigned long long)ios_self_suspend_now(), (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueProcess,
                 (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueThread, (void *)handle, status,
                 receipt_valid, identity->pid, identity->tid, old_count );
    errno = saved_errno;
}
#endif
