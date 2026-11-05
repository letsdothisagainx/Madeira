#!/usr/bin/env python3
"""Stage the iOS async-APC delivery correction without editing pinned Wine.

The ordinary/finite fastsync backend must retain request completion APCs in
the pre-wait gap. A subsequent same-process server waiter may execute these
non-thread-affine internal callbacks. Madsync has no kernel-APC wake contract,
so its existing conservative issuer policy remains unchanged.
"""
from pathlib import Path
import argparse
import hashlib

SOURCE_SHA256 = '8dc5928b2655b773b0e225769d4448d20d6265c8c256556f7dc7203f377a52eb'

ADOPT = r'''#ifdef WINE_IOS
extern int madsync_enabled(void);
static int ios_apc_requeue_enabled(void);

/* APC_ASYNC_IO runs the native I/O completion callback, not the application's
 * user APC. Existing queue-time handoff already permits a same-process waiter
 * to execute it. Also cover a waiter which arrives AFTER a retained completion:
 * the original issuer need not ever wait on its overlapped request itself.
 * Keep all other APCs and the source's FIFO order unchanged; no references are
 * acquired/dropped by moving this one existing queue entry.
 */
static void ios_adopt_async_apc( struct thread *thread )
{
    struct thread *source;
    struct thread_apc *apc;
    struct list *head;
    static unsigned int traces;

    if (thread->state == TERMINATED || is_thread_suspended( thread ) ||
        thread->process->is_terminating || !list_empty( &thread->system_apc ) ||
        list_empty( &thread->process->asyncs )) return;
    if (madsync_enabled() || !ios_apc_requeue_enabled()) return;

    LIST_FOR_EACH_ENTRY( source, &thread->process->thread_list, struct thread, proc_entry )
    {
        if (source == thread || source->process != thread->process ||
            source->state == TERMINATED || is_thread_suspended( source ) ||
            (source->wait && (source->wait->flags & SELECT_INTERRUPTIBLE))) continue;
        if (!(head = list_head( &source->system_apc ))) continue;
        apc = LIST_ENTRY( head, struct thread_apc, entry );
        if (apc->call.type != APC_ASYNC_IO || !apc->owner) continue;
        list_remove( &apc->entry );
        list_add_tail( &thread->system_apc, &apc->entry );
        if (traces++ < 16)
            fprintf( stderr, "[io-apc-handoff-v1] action=late-waiter owner=%04x waiter=%04x status=%08x\n",
                     source->id, thread->id, apc->call.async_io.status );
        return;
    }
}
#endif

'''

def stage(source: str) -> str:
    assert hashlib.sha256(source.encode()).hexdigest() == SOURCE_SHA256, 'Wine thread source differs from pinned input'
    anchor = '/* check if the thread waiting condition is satisfied */\nstatic int check_wait('
    assert source.count(anchor) == 1
    source = source.replace(anchor, ADOPT + anchor)
    anchor = '''    assert( wait );

    if ((wait->flags & SELECT_INTERRUPTIBLE) && !list_empty( &thread->system_apc ))'''
    replacement = '''    assert( wait );

#ifdef WINE_IOS
    if (wait->flags & SELECT_INTERRUPTIBLE) ios_adopt_async_apc( thread );
#endif
    if ((wait->flags & SELECT_INTERRUPTIBLE) && !list_empty( &thread->system_apc ))'''
    assert source.count(anchor) == 1
    source = source.replace(anchor, replacement)
    anchor = '    if (!target && async_can_defer_to_issuer( apc->owner, thread )) target = thread;'
    replacement = anchor + '''
    /* Without madsync, waits enter the server directly or after fastsync's
     * bounded peek. Preserve an overlapped completion until that kernel wait
     * instead of destroying its APC and replacing real data with 0x101/0.
     * A late sibling waiter may adopt this internal callback above. */
    if (!target && apc->owner && !madsync_enabled() && thread->state != TERMINATED &&
        !is_thread_suspended( thread ) && !thread->process->is_terminating)
    {
        target = thread;
        if (count < 16)
            fprintf( stderr, "[io-apc-handoff-v1] action=retain-completion owner=%04x status=%08x backend=server-wait\\n",
                     thread->id, apc->call.async_io.status );
    }'''
    assert source.count(anchor) == 1
    return source.replace(anchor, replacement)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.source.resolve() != args.output.resolve(), 'Pinned source must not be overwritten'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(stage(args.source.read_text()))
    print('PASS staged iOS async-APC retention/late waiter; pinned Wine source unchanged')
