#!/usr/bin/env python3
"""Add iOS cooperative termination at native wait boundaries, preserving pinned Wine."""
from pathlib import Path
import sys

def stage(source):
    source=source.replace('NTSTATUS WINAPI NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )\n{',
        'static void ios_native_cancel_checkpoint(void);\n\nNTSTATUS WINAPI NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )\n{\n    ios_native_cancel_checkpoint();',1)
    # An ordinary address alert is NOT an alertable user APC. Recompute the
    # delay on every such wake; only real cancellation exits a non-alertable sleep.
    assert 'for (;;) select( 0, NULL, NULL, NULL, NULL );' in source
    source=source.replace('for (;;) select( 0, NULL, NULL, NULL, NULL );',
        'for (;;) { NtWaitForAlertByThreadId(NULL,NULL); ios_native_cancel_checkpoint(); }',1)
    source=source.replace('            struct timeval tv;\n            NtQuerySystemTime( &now );\n            diff = (when - now.QuadPart + 9) / 10;',
        '            LARGE_INTEGER remaining;\n            ios_native_cancel_checkpoint();\n            NtQuerySystemTime( &now );\n            diff = (when - now.QuadPart + 9) / 10;',1)
    old='''            tv.tv_sec  = diff / 1000000;
            tv.tv_usec = diff % 1000000;
            if (select( 0, NULL, NULL, NULL, &tv ) != -1) break;'''
    assert old in source
    source=source.replace(old,'''            remaining.QuadPart = -(when-now.QuadPart);
            NtWaitForAlertByThreadId(NULL,&remaining);
            ios_native_cancel_checkpoint();''',1)
    marker='NTSTATUS WINAPI NtWaitForAlertByThreadId( const void *address, const LARGE_INTEGER *timeout )\n{'
    assert source.count(marker)==1
    helper='''/* A server kill cannot signal these same-task iOS native waits. The
 * kill hook sets a lease-bound native flag before sending an ordinary alert.
 * Remove THIS abandoned PE64 stack entry from the shared futex table before
 * leaving the thread; no other thread's locks or wait nodes are modified. */
static void ios_native_cancel_checkpoint(void)
{
    extern int ios_native_thread_cancelled(void);
    extern unsigned ios_native_thread_exit_status(void);
    unsigned i, tid;
    TEB *teb;
    if (!ios_native_thread_cancelled()) return;
    if (!(teb=NtCurrentTeb())) return;
    tid=(unsigned)(ULONG_PTR)teb->ClientId.UniqueThread;
    for (i=0; i<256; ++i)
    {
        struct ios_shared_futex_queue *q=&ios_shared_futex_queues[i];
        struct ios_retire_entry { struct ios_retire_entry *next,*prev; const void *addr; unsigned tid; };
        struct ios_retire_entry *head=(void*)q, *entry;
        while (InterlockedCompareExchange(&q->lock,-1,0)) YieldProcessor();
        entry=(void*)q->next;
        while (entry && entry!=head)
        {
            struct ios_retire_entry *next=entry->next;
            if (entry->tid==tid)
            {
                entry->prev->next=entry->next; entry->next->prev=entry->prev;
                entry->addr=NULL;
            }
            entry=next;
        }
        InterlockedExchange(&q->lock,0);
    }
    for (i=0; i<IOS_ALERT_WAITER_MAX; ++i)
        if (ios_alert_waiters[i].tid==teb->ClientId.UniqueThread) ios_alert_waiters[i].addr=NULL;
    { static unsigned reports;
      if (__atomic_fetch_add(&reports,1,__ATOMIC_RELAXED)<96)
          dprintf(2,"[native-thread-cancel-v1] tid=%04x exit=%08x shared-wait-nodes=removed\\n",tid,ios_native_thread_exit_status()); }
    abort_thread(ios_native_thread_exit_status());
}

'''
    source=source.replace(marker,helper+marker+'\n    ios_native_cancel_checkpoint();',1)
    source=source.replace('            ios_woke = mach_absolute_time();   /* ml1122 */',
        '            ios_native_cancel_checkpoint();\n            ios_woke = mach_absolute_time();   /* ml1122 */',1)
    # The alert may have been pending before entering the kernel wait.
    marker='''        return STATUS_ALERTED;
    }
#elif defined(HAVE_KQUEUE)'''
    assert source.count(marker)==1
    pos=source.index('NTSTATUS WINAPI NtWaitForAlertByThreadId(')
    source=source[:pos]+source[pos:].replace(marker,'''        ios_native_cancel_checkpoint();
'''+marker,1)
    return source

if __name__=='__main__':
    path=Path(sys.argv[1]);path.write_text(stage(path.read_text()))
