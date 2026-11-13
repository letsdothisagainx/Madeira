/* Actual b832fa4a fast_wait after its owned overlay; captured from pinned Wine.
 * SHA256 of function body: bd16c566136a9184225b2f2915331e389d31fa5c040c96911eee9ff1567229d7
 * Used only as the inactive-fallback regression control. */
static NTSTATUS madeira_fast_wait( HANDLE handle, const LARGE_INTEGER *timeout,
                                   const LARGE_INTEGER **fallback, LARGE_INTEGER *store )
{
    struct madeira_sync_cell *cell;
    unsigned int manual = 0, gen = 0, kind = 0;
    unsigned long long t0, spent = 0, budget_ns, wait_t0 = 0, timeout_ticks = 0;
    int i, st, rounds;

    *fallback = timeout;
    /* Madeira: relative waits include lookup and both spin phases. */
    if (timeout && timeout->QuadPart < 0)
    {
        timeout_ticks = 0ull - (unsigned long long)timeout->QuadPart;
        wait_t0 = madeira_now_ns();
    }
    if (!madeira_fastsync_enabled())
    {
        /* wake path off: the read-only peek is the only thing allowed here */
        if (timeout && !timeout->QuadPart && madeira_fast_cells_enabled() &&
            __atomic_load_n( &madeira_fast_peek, __ATOMIC_RELAXED ) &&
            (cell = madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind )) &&
            madeira_peek_cell( cell, gen ))
            return STATUS_TIMEOUT;
        goto fallback;
    }
    if (!(cell = madeira_fast_lookup( handle, SYNCHRONIZE, &manual, &gen, &kind )))
        goto fallback;

    if (madeira_fast_try( cell, manual, gen, kind )) return STATUS_SUCCESS;

    /* A zero timeout is a state query; only the RESET answer may be given
     * here (an auto-reset token somebody else took first is the server's to
     * report). */
    if (timeout && !timeout->QuadPart)
        return madeira_peek_cell( cell, gen ) ? STATUS_TIMEOUT : STATUS_NOT_IMPLEMENTED;

    for (i = 0; i < MADEIRA_FAST_SPIN; i++)
    {
        __asm__ __volatile__( "isb" ::: "memory" );
        if (madeira_fast_try( cell, manual, gen, kind )) return STATUS_SUCCESS;
    }

    /* the adaptive, time-bounded spin; the clock is read once per block */
    {
        int spin_probe = 0;
        unsigned long long spin_ns = madeira_fast_spin_budget_ns( timeout, &spin_probe );

        if (spin_ns)
        {
            unsigned long long s0 = madeira_now_ns();

            if (timeout_ticks)
            {
                unsigned long long elapsed = (s0 - wait_t0) / 100, left;

                if (elapsed >= timeout_ticks) goto fallback;
                left = timeout_ticks - elapsed;
                if (left <= spin_ns / 100) spin_ns = left * 100;
            }
            for (;;)
            {
                for (i = 0; i < MADEIRA_FAST_SPIN; i++)
                {
                    __asm__ __volatile__( "isb" ::: "memory" );
                    if (madeira_fast_try( cell, manual, gen, kind ))
                    {
                        madeira_fast_spin_credit_add( spin_probe ? MADEIRA_SPIN_CREDIT_REARM
                                                                 : MADEIRA_SPIN_CREDIT_UP );
                        return STATUS_SUCCESS;
                    }
                }
                if (!madeira_cell_alive( cell, gen )) break;   /* recycled: stop */
                if (madeira_now_ns() - s0 >= spin_ns) break;
            }
            madeira_fast_spin_credit_add( -1 );
        }
    }

    /* Keep the existing park cap, within the original relative deadline. */
    budget_ns = madeira_fast_cap_ns;
    t0 = madeira_now_ns();
    if (timeout_ticks)
    {
        unsigned long long elapsed = (t0 - wait_t0) / 100, left;

        if (elapsed >= timeout_ticks) goto fallback;
        left = timeout_ticks - elapsed;
        if (left <= budget_ns / 100) budget_ns = left * 100;
    }

    /* `rounds' bounds the loop independently of the clock, so a clock that
     * stops or jumps cannot turn it into an unbounded spin. */
    for (rounds = 0; rounds < 64; rounds++)
    {
        spent = madeira_now_ns() - t0;
        if (spent >= budget_ns) break;

        __atomic_add_fetch( &cell->waiters, 1, __ATOMIC_SEQ_CST );
        {
            /* one load answers "still mine" and "what state"; on a mismatch
             * leave `waiters' alone (it belongs to the new occupant now) */
            uint64_t sg = __atomic_load_n( &cell->sg, __ATOMIC_SEQ_CST );

            if (MADEIRA_SG_GEN( sg ) != gen) break;
            st = MADEIRA_SG_STATE( sg );
        }
        /* the value is re-tested inside the syscall */
        if (st == MADEIRA_CELL_RESET)
            madeira_fast_park( madeira_cell_futex( cell ), MADEIRA_CELL_RESET, budget_ns - spent );

        /* The park is the one unbounded pause: the event can be destroyed and
         * its cell handed to a new object meanwhile.  Consuming the new
         * occupant's token, or paying back a `waiters' count the allocator has
         * already zeroed, would both be wrong -- hand the wait to the server. */
        if (!madeira_cell_alive( cell, gen )) break;
        __atomic_sub_fetch( &cell->waiters, 1, __ATOMIC_SEQ_CST );

        /* DISABLED or CLAIMED: queue with the server.  A semaphore has no
         * CLAIMED (2 is a count), only the negative state means "server". */
        if (kind == MADEIRA_CELL_KIND_SEM)
        {
            if (st < 0) break;
        }
        else if (st != MADEIRA_CELL_RESET && st != MADEIRA_CELL_SET) break;
        if (madeira_fast_try( cell, manual, gen, kind )) return STATUS_SUCCESS;
    }

fallback:
    if (timeout_ticks)
    {
        unsigned long long elapsed = (madeira_now_ns() - wait_t0) / 100;

        /* A genuinely expired relative wait becomes a server poll, so the
         * server still checks the object and pending system APCs first. */
        store->QuadPart = elapsed >= timeout_ticks ? 0 :
                         (long long)(0ull - (timeout_ticks - elapsed));
        *fallback = store;
    }
    return STATUS_NOT_IMPLEMENTED;
}
