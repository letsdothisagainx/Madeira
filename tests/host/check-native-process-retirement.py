#!/usr/bin/env python3
"""Run the production native process registry lifetime under ASan/UBSan.

This verifies metadata capacity, not reclamation of all native guest mappings.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
thread = (root / 'build/ntdll-unix/thread_ios.c').read_text()
server = (root / 'build/ntdll-unix/server_ios.c').read_text()
start = thread.index('struct ios_thread_group\n{')
end = thread.index('\nstatic inline int get_unix_exit_code(', start)
production = thread[start:end]
finish = server[server.index('static void ios_finish_process_memory('):server.index('\nvoid process_exit_wrapper(')]
assert finish.index('ios_thread_process_quiescent_lease(dead_peb)') < finish.index('ios_fd_cache_release(dead_peb);')
assert finish.index('native_owner = !ios_wow_base_for_peb(dead_peb)') < finish.index('ios_wow_window_release(dead_peb);')
assert finish.index('ios_exe_win_mark_ready(dead_peb);') < finish.index('if (native_owner && lease) ios_thread_process_finalize_native(dead_peb, lease);')
assert 'group->owner == current->Peb && group->lease == lease' in thread
exit_tail = thread[thread.index('static DECLSPEC_NORETURN void exit_thread('):thread.index('\nvoid exit_process(', thread.index('static DECLSPEC_NORETURN void exit_thread('))]
assert exit_tail.index('lease = ios_thread_groups[index].lease;') < exit_tail.index('ios_thread_retire_current()')
assert 'ios_thread_group_locked' not in exit_tail
assert 'ios_thread_process_forget(dead_peb)' in (root / 'build/ntdll-unix/virtual_ios.c').read_text()

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "native_thread_lifetime.h"
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define ERR(...) ((void)0)
typedef void *HANDLE;
typedef uintptr_t ULONG_PTR;
typedef struct {void *Peb;struct {void *UniqueProcess,*UniqueThread;} ClientId;} TEB;
static _Thread_local TEB current;
static TEB *NtCurrentTeb(void) { return &current; }
static int NtAlertThreadByThreadId(HANDLE thread) { (void)thread;return 0; }
static unsigned identity_releases, callbacks_active;
static void *last_identity;
static void ios_proc_ident_release(void *owner) {
    assert(!callbacks_active); identity_releases++; last_identity=owner;
}
static void ios_thread_finish_fex(void) { assert(!callbacks_active); }
''' + production + r'''
static struct ios_thread_group *find(void *owner) {
    for(unsigned i=0;i<ARRAY_SIZE(ios_thread_groups);i++)if(ios_thread_groups[i].owner==owner)return &ios_thread_groups[i];
    return NULL;
}
static unsigned long long retire(void *owner) {
    current.Peb=owner;ios_retired_thread_owner=NULL;
    unsigned long long lease=ios_thread_process_lease(owner,1);
    assert(lease);assert(ios_thread_process_exit_ready(owner));
    assert(ios_thread_process_quiescent_lease(owner)==lease);return lease;
}
int main(int argc,char **argv) {
    (void)argv;
    void *sibling=(void *)(uintptr_t)0x500310000;
    unsigned long long sibling_lease=ios_thread_process_lease(sibling,1);
    assert(sibling_lease);
    /* Negative control reproduces the old native path: exit and reclaim,
     * but never the WoW-only forget path. Sixty-three retired children plus
     * one surviving process fill the entire table. */
    for(unsigned i=0;i<160;i++) {
        void *owner=(void *)(uintptr_t)(0x1000000000ull+i*0x10000ull);
        current.Peb=owner;ios_retired_thread_owner=NULL;
        unsigned long long lease=ios_thread_process_lease(owner,1);
        if(argc>1 && i==63) {
            assert(!lease && identity_releases==0);
            for(unsigned j=0;j<64;j++)assert(ios_thread_groups[j].owner);
            puts("PASS negative control: old native lifetime exhausts all 64 slots despite retired children");return 0;
        }
        assert(lease);assert(ios_thread_process_exit_ready(owner));
        assert(ios_thread_process_quiescent_lease(owner)==lease);
        if(argc==1) {
            assert(ios_thread_process_finalize_native(owner,lease));
            assert(identity_releases==i+1 && last_identity==owner && !find(owner));
        }
        assert(ios_thread_process_lease(sibling,0)==sibling_lease);
    }
    assert(argc==1);
    void *same=(void *)(uintptr_t)0x600310000;
    unsigned long long old=retire(same);
    assert(ios_thread_process_finalize_native(same,old));
    current.Peb=same;ios_retired_thread_owner=NULL;
    unsigned long long newer=ios_thread_process_lease(same,1);
    assert(newer&&newer!=old);
    unsigned before=identity_releases;
    assert(!ios_thread_process_finalize_native(same,old));
    callbacks_active=1;
    assert(!ios_thread_process_finalize_native(same,newer)); /* live successor */
    callbacks_active=0;
    assert(identity_releases==before&&find(same)->lease==newer&&find(same)->count==1);
    assert(ios_thread_process_exit_ready(same));
    struct ios_thread_group *g=find(same);
    unsigned index=g-ios_thread_groups;
    pthread_mutex_lock(&ios_thread_reapers[index]);
    assert(!ios_thread_process_finalize_native(same,newer));
    pthread_mutex_unlock(&ios_thread_reapers[index]);
    assert(find(same)==g&&identity_releases==before);
    g->reclaimed=0;assert(!ios_thread_process_finalize_native(same,newer));g->reclaimed=1;
    g->exiting=0;assert(!ios_thread_process_finalize_native(same,newer));g->exiting=1;
    g->native_threads=(struct madeira_native_thread *)(uintptr_t)1;
    assert(!ios_thread_process_finalize_native(same,newer));g->native_threads=NULL;
    /* Pending TEB/pthread storage remains recorded and is not dereferenced,
     * detached, or silently discarded to gain capacity. */
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    void *protected=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(protected!=MAP_FAILED);
    g->prev_teb=protected;assert(!ios_thread_process_finalize_native(same,newer));
    assert(g->prev_teb==protected);g->prev_teb=NULL;
    g->prev_pthread=pthread_self();assert(!ios_thread_process_finalize_native(same,newer));
    assert(pthread_equal(g->prev_pthread,pthread_self()));g->prev_pthread=0;
    assert(identity_releases==before&&find(same)==g);
    assert(!munmap(protected,page));
    assert(ios_thread_process_finalize_native(same,newer));
    assert(identity_releases==before+1&&!find(same));
    assert(ios_thread_process_lease(sibling,0)==sibling_lease);
    assert(find(sibling)->count==1&&!find(sibling)->exiting);
    assert(!ios_thread_process_finalize_native(NULL,newer));
    assert(!ios_thread_process_finalize_native(sibling,0));
    puts("PASS 160 native lifecycles reuse registry capacity after cleanup; leases, sibling, live callbacks and deferred reapers stay protected");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-native-retire-') as temporary:
    path=Path(temporary);src=path/'retirement.c';exe=path/'retirement';src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-pthread','-I'+str(root/'build/ntdll-unix'),str(src),'-o',str(exe)],check=True)
    for arguments in ([str(exe),'old-native-path'],[str(exe)]):
        result=subprocess.run(arguments,capture_output=True,text=True,timeout=30)
        assert result.returncode==0,result.stdout+result.stderr
        print(result.stdout,end='')
