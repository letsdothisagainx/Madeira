#!/usr/bin/env python3
"""Exercise production self-suspend/count logic with real cooperating pthreads.

The extracted Wine functions are real. Handle tables, RPC serialization,
native context capture and the wait transport are controlled host adapters;
this is not a CS2/iPhone execution or a Mach suspension measurement.
"""
from pathlib import Path
import hashlib
import os
import re
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    begin = source.index(signature)
    brace = source.index('{', begin)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[begin:brace + token.end()] + '\n'
    raise AssertionError(signature)


client = (ROOT / 'build/ntdll-unix/thread_ios.c').read_text()
server = (ROOT / 'wine/server/thread.c').read_text()
server = runpy.run_path(str(ROOT / 'build/wineserver/stage-self-suspend.py'))['stage'](server)
transport = (ROOT / 'build/ntdll-unix/server_ios.c').read_text()
handles = (ROOT / 'wine/server/handle.c').read_text()
mach = (ROOT / 'build/wineserver/mach_ios.c').read_text()
# Verbatim negative control from bf0f0a0a2b682c59658d318e8491dd4d5a27b0c3.
# Wine thread.c: Copyright 1996, 2003 Alexandre Julliard, LGPL-2.1-or-later;
# includes Madeira's existing iOS self-wait extension. Keep exact source bytes.
BASELINE_SUSPEND = r'''NTSTATUS WINAPI NtSuspendThread( HANDLE handle, ULONG *count )
{
    unsigned int ret;

    SERVER_START_REQ( suspend_thread )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            if (count) *count = reply->count;
        }
    }
    SERVER_END_REQ;
#ifdef WINE_IOS
    /* madeira-bcd: a thread that suspends itself must stop until it is resumed.
     * Elsewhere the server's SIGUSR1 makes usr1_handler wait in wait_suspend();
     * on iOS that signal never runs its handler (task #32), so SuspendThread on
     * oneself returned at once. Crysis's intro-video threads suspend themselves
     * once per frame and are resumed by the main thread: here they spun instead,
     * piling the count up to MAXIMUM_SUSPEND_COUNT, and when a video ended the
     * thread's exit (NtTerminateThread's select) waited on that count forever,
     * so the main thread sat out a 30 s join timeout between videos
     * (log 2026-09-30 12:25, build 244). Wait here the way wait_suspend does:
     * a zero-timeout select only returns once the thread is no longer suspended. */
    if (!ret)
    {
        BOOL self = handle == GetCurrentThread();
        if (!self)
        {
            THREAD_BASIC_INFORMATION tbi;
            self = !NtQueryInformationThread( handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL ) &&
                   HandleToULong( tbi.ClientId.UniqueThread ) == GetCurrentThreadId();
        }
        if (self)
        {
            static LONG self_suspends;
            LONG n = InterlockedIncrement( &self_suspends );
            if (n <= 4 || !(n & (n - 1)))
                dprintf( 2, "[self-suspend] madeira-bcd: tid=%04x suspended itself (#%d); waiting for the resume\n",
                         (int)GetCurrentThreadId(), (int)n );
            server_select( NULL, 0, SELECT_INTERRUPTIBLE, 0, NULL, NULL );
        }
    }
#endif
    return ret;
}
'''
assert hashlib.sha256(BASELINE_SUSPEND.encode()).hexdigest() == '5e9e3a54f6033ffba93b31d7898684fca960a474d69669709425a2aab817a039', 'changed negative-control source'
old_suspend = BASELINE_SUSPEND.replace('NtSuspendThread(', 'old_NtSuspendThread(', 1)
candidate = function(client, 'NTSTATUS WINAPI NtSuspendThread(')

PRELUDE = r'''
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define WINE_IOS 1
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>
#include "self_suspend_protocol.h"
typedef void *HANDLE;
typedef unsigned ULONG, NTSTATUS, UINT;
typedef int BOOL, LONG;
typedef uintptr_t ULONG_PTR;
typedef uintptr_t client_ptr_t;
typedef int64_t timeout_t;
#define WINAPI
#define TRUE 1
#define FALSE 0
#define MAXIMUM_SUSPEND_COUNT 127
#define STATUS_SUCCESS 0u
#define STATUS_TIMEOUT 0x102u
#define STATUS_KERNEL_APC 0x100u
#define STATUS_USER_APC 0xc0u
#define STATUS_INVALID_HANDLE 0xc0000008u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_NO_MEMORY 0xc0000017u
#define STATUS_NOT_SAME_OBJECT 0xc00001acu
#define STATUS_SUSPEND_COUNT_EXCEEDED 0xc000004au
#define RUNNING 0
#define TERMINATED 1
#define THREAD_SUSPEND_RESUME 2u
#define THREAD_QUERY_INFORMATION 0x40u
#define ThreadBasicInformation 0
#define SELECT_INTERRUPTIBLE 1
#define SELECT_ALERTABLE 2
#define SELECT_NONE 0
#define SELECT_WAIT_ALL 2
#define STATUS_WAIT_0 0
#define GetCurrentThread() ((HANDLE)(intptr_t)-2)
#define HandleToULong(h) ((unsigned)(uintptr_t)(h))
#define wine_server_obj_handle(h) ((uintptr_t)(h))
#define InterlockedIncrement(p) __atomic_add_fetch((p), 1, __ATOMIC_SEQ_CST)
struct thread;
struct object { int refs, thread_type, signaled; struct thread *thread; };
struct handle_entry { uintptr_t value; unsigned access; struct object *object; };
struct process { int suspend; struct handle_entry handles[8]; unsigned count, id; };
struct context { int ios_dirty; };
typedef struct {uint64_t pc, sp;} CONTEXT;
struct context_data {uint64_t pc, sp; unsigned machine;};
static void contexts_to_server(struct context_data out[2], const CONTEXT *context) {
    memset(out, 0, 2*sizeof(*out)); out[0].pc = context->pc; out[0].sp = context->sp;
}
static void contexts_from_server(CONTEXT *context, const struct context_data in[2]) {
    context->pc = in[0].pc; context->sp = in[0].sp;
}
struct wait_queue_entry { struct object *obj; };
struct thread_wait {
    int flags, select, count; int64_t when;
    struct wait_queue_entry queues[1];
};
struct thread {
    struct object object;
    struct process *process;
    struct context *context;
    struct thread_wait *wait;
    int suspend, bypass_proc_suspend, ios_mach_suspended, state;
    int system_apc, user_apc;
    unsigned id;
    uintptr_t teb;
    pthread_cond_t condition;
    int entered, continued, before_select, published;
    int gate, gate_open, fail_capture, stop_calls, holds, releases, reuse_after_call;
    struct object *replacement;
    NTSTATUS result; ULONG returned_count;
};
typedef struct { struct {HANDLE UniqueThread, UniqueProcess;} ClientId; } THREAD_BASIC_INFORMATION;
static _Thread_local struct thread *current;
static pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t state_condition = PTHREAD_COND_INITIALIZER;
static int real_suspend, debug_level;
static unsigned query_calls, compare_calls, wait_calls;
struct ios_self_suspend_snapshot {uint64_t pc, lr, sp, fp; unsigned valid;};
struct ios_self_suspend_watch {unsigned caller_reported;};
static struct ios_self_suspend_watch fixture_watch;
static struct ios_self_suspend_watch *ios_self_suspend_find(unsigned pid, unsigned tid, uintptr_t teb) {
    (void)pid; (void)tid; (void)teb; return &fixture_watch;
}
typedef struct {struct {HANDLE UniqueThread, UniqueProcess;} ClientId;} FIXTURE_TEB;
static _Thread_local FIXTURE_TEB fixture_teb;
static FIXTURE_TEB *NtCurrentTeb(void) {
    fixture_teb.ClientId.UniqueThread = (HANDLE)(uintptr_t)current->id;
    fixture_teb.ClientId.UniqueProcess = (HANDLE)(uintptr_t)current->process->id;
    return &fixture_teb;
}
static int trace_capture_failure;
static void *get_syscall_frame(void) { return (void *)(uintptr_t)0x1234; }
static void ios_self_suspend_capture(struct ios_self_suspend_snapshot *snapshot, const void *frame) {
    assert(frame == (void *)(uintptr_t)0x1234); snapshot->valid = !trace_capture_failure;
}
static unsigned ios_self_suspend_client_begin(const struct madeira_suspend_identity_reply *identity,
    uintptr_t handle, unsigned status, unsigned old_count, const struct ios_self_suspend_snapshot *snapshot, int known) {
    (void)handle; (void)status; (void)old_count; (void)known; return identity->self && snapshot->valid ? 1 : 0;
}
static void ios_self_suspend_client_wait(unsigned ticket, unsigned status) { (void)ticket; assert(status == STATUS_TIMEOUT); }
static void ios_self_suspend_client_resume(const struct madeira_suspend_identity_reply *identity,
    uintptr_t handle, unsigned status, unsigned old_count, int known) {
    (void)identity; (void)handle; (void)status; (void)old_count; (void)known;
}
static void ios_self_suspend_server_begin(unsigned pid, unsigned tid, uintptr_t teb, unsigned by_pid, unsigned by_tid) {
    assert(pid == by_pid && tid == by_tid && teb == current->teb);
}
static void ios_self_suspend_server_resume(unsigned pid, unsigned tid, uintptr_t teb,
    unsigned by_pid, unsigned by_tid, unsigned old_count, unsigned new_count, unsigned held, unsigned process_suspend) {
    (void)pid; (void)tid; (void)teb; (void)by_pid; (void)by_tid;
    (void)process_suspend;
    assert(new_count == (old_count ? old_count - 1 : 0)); if (!new_count) assert(!held);
}
void ios_suspend_resume_observe(struct thread *, int);
static int64_t current_time = 1, monotonic_time = 1;
struct thread *ios_pending_persistent_hold;
static struct timespec deadline(void) {
    struct timespec value;
    assert(!clock_gettime(CLOCK_REALTIME, &value)); value.tv_sec += 5; return value;
}
static void changed(void) { assert(!pthread_cond_broadcast(&state_condition)); }
static void wait_state(int *field) {
    struct timespec until = deadline();
    while (!*field) assert(!pthread_cond_timedwait(&state_condition, &server_mutex, &until));
}
static int list_empty(const int *list) { return !*list; }
static void set_error(NTSTATUS status);
static int ios_real_suspend_enabled(void) { return real_suspend; }
static void stop_thread(struct thread *thread) { ++thread->stop_calls; }
static int ios_thread_mach_hold(struct thread *thread) {
    if (!thread->ios_mach_suspended) { thread->ios_mach_suspended = 1; ++thread->holds; }
    return 1;
}
static int ios_thread_mach_release(struct thread *thread) {
    if (thread->ios_mach_suspended) { thread->ios_mach_suspended = 0; ++thread->releases; }
    return 1;
}
static void resume_delayed_debug_events(struct thread *thread) { (void)thread; }
static void ios_wow_ctx_apply(struct thread *thread) { thread->context->ios_dirty = 0; }
static int object_sync_signaled(struct object *object, struct wait_queue_entry *entry) {
    (void)entry; return object->signaled;
}
static void object_sync_unclaim(struct object *object) { (void)object; }
static int end_wait(struct thread *thread, int status) {
    assert(thread->wait && !thread->wait->count); thread->wait = NULL; return status;
}
static int send_thread_wakeup(struct thread *thread, uintptr_t cookie, int signaled) {
    (void)cookie; assert(signaled == STATUS_TIMEOUT); assert(!pthread_cond_signal(&thread->condition)); return 0;
}
static int wake_thread(struct thread *thread);
static unsigned GetCurrentThreadId(void) { return current->id; }
enum {OP_suspend_thread, OP_resume_thread, OP_compare_objects};
struct wire_reply { uint32_t header[2]; ULONG count; unsigned char __pad_12[4]; };
_Static_assert(sizeof(struct wire_reply) == 16, "fixed reply size");
_Static_assert(offsetof(struct wire_reply, count) == 8, "fixed count offset");
struct wire_request { int op; uintptr_t handle, first, second; struct wire_reply *reply; };
static _Thread_local NTSTATUS server_error;
static int identity_mode = 1;
static const volatile char ios_suspend_identity_contract[] = "[self-suspend-identity-v1]";
static void set_error(NTSTATUS status) { server_error = status; }
static NTSTATUS get_error(void) { return server_error; }
static unsigned get_thread_id(const struct thread *thread) { return thread->id; }
static unsigned get_process_id(const struct process *process) { return process->id; }
static void release_object(void *pointer) { struct object *object = pointer; assert(object->refs > 1); --object->refs; }
static struct object *get_handle_obj(struct process *process, uintptr_t handle, unsigned access, void *type) {
    struct object *object = NULL; (void)type;
    if (handle == (uintptr_t)GetCurrentThread()) object = &current->object;
    else for (unsigned n = 0; n < process->count; ++n) if (process->handles[n].value == handle) {
        if ((process->handles[n].access & access) != access) { set_error(STATUS_ACCESS_DENIED); return NULL; }
        object = process->handles[n].object; break;
    }
    if (!object) { set_error(STATUS_INVALID_HANDLE); return NULL; }
    ++object->refs; return object;
}
static struct thread *get_thread_from_handle(uintptr_t handle, unsigned access) {
    struct object *object = get_handle_obj(current->process, handle, access, NULL);
    if (!object) return NULL;
    if (!object->thread_type) { release_object(object); set_error(STATUS_INVALID_HANDLE); return NULL; }
    return object->thread;
}
#define DECL_HANDLER(name) static void handler_##name(const struct wire_request *req, struct wire_reply *reply __attribute__((unused)))
#define SERVER_START_REQ(name) do { struct wire_reply response = {0}; struct wire_reply *reply = &response; \
    struct wire_request request = {.op = OP_##name, .reply = reply}; struct wire_request *req = &request;
#define SERVER_END_REQ } while (0)
static unsigned wine_server_call(struct wire_request *req);
static NTSTATUS NtQueryInformationThread(HANDLE handle, int kind, THREAD_BASIC_INFORMATION *out, size_t length, void *unused) {
    (void)kind; (void)length; (void)unused;
    pthread_mutex_lock(&server_mutex); ++query_calls; server_error = 0;
    struct thread *thread = get_thread_from_handle((uintptr_t)handle, THREAD_QUERY_INFORMATION);
    if (thread) { out->ClientId.UniqueThread = (HANDLE)(uintptr_t)thread->id;
        out->ClientId.UniqueProcess = (HANDLE)thread->process; release_object(&thread->object); }
    NTSTATUS result = server_error; pthread_mutex_unlock(&server_mutex); return result;
}
union select_op;
static unsigned server_select(const union select_op *op, unsigned size, UINT flags, timeout_t timeout, void *context, void *apc);
'''

TRANSPORT = r'''
static unsigned wine_server_call(struct wire_request *req) {
    pthread_mutex_lock(&server_mutex); server_error = 0;
    if (req->op == OP_compare_objects) { ++compare_calls; handler_compare_objects(req, req->reply); }
    else if (req->op == OP_suspend_thread) handler_suspend_thread(req, req->reply);
    else handler_resume_thread(req, req->reply);
    uint32_t tag; memcpy(&tag, req->reply->__pad_12, sizeof(tag));
    if (identity_mode == 0) tag = 0;
    if (identity_mode == 2) tag = UINT32_C(0x12345678);
    if (identity_mode == 3) tag = MADEIRA_SUSPEND_IDENTITY_MAGIC | 2;
    if (identity_mode == 4) tag &= UINT32_C(0xffff);
    memcpy(req->reply->__pad_12, &tag, sizeof(tag));
    if (!server_error && req->op == OP_suspend_thread && current->reuse_after_call) {
        for (unsigned n = 0; n < current->process->count; ++n)
            if (current->process->handles[n].value == req->handle)
                current->process->handles[n].object = current->replacement;
    }
    changed();
    NTSTATUS result = server_error; pthread_mutex_unlock(&server_mutex); return result;
}
static unsigned server_select(const union select_op *op, unsigned size, UINT flags, timeout_t timeout, void *context, void *apc) {
    assert(!op && !size && flags == SELECT_INTERRUPTIBLE && !timeout && !apc);
    (void)context; // Conversion adapters above intentionally make no ARM64EC claim.
    pthread_mutex_lock(&server_mutex); ++wait_calls;
    current->before_select = 1; changed();
    struct timespec until = deadline();
    while (current->gate && !current->gate_open)
        assert(!pthread_cond_timedwait(&state_condition, &server_mutex, &until));
    struct thread_wait wait = {.flags = flags, .select = SELECT_NONE, .when = timeout, .cookie = 1};
    assert(!current->wait); current->wait = &wait;
    current->published = 1; changed();
    int status;
    while ((status = check_wait(current)) == -1) {
        assert(!pthread_cond_timedwait(&current->condition, &server_mutex, &until));
        if (!current->wait) break;
    }
    if (current->wait) status = end_wait(current, status);
    else status = STATUS_TIMEOUT;
    assert(!current->suspend); pthread_mutex_unlock(&server_mutex); return status;
}
'''

TESTS = r'''
static void initialize(struct thread *thread, struct process *process, unsigned id) {
    memset(thread, 0, sizeof(*thread)); thread->id = id; thread->process = process;
    thread->teb = (uintptr_t)thread;
    thread->object.refs = 1; thread->object.thread_type = 1; thread->object.thread = thread;
    assert(!pthread_cond_init(&thread->condition, NULL));
}
static void add_handle(struct process *process, uintptr_t value, struct thread *thread, unsigned access) {
    assert(process->count < 8); process->handles[process->count++] = (struct handle_entry){value, access, &thread->object};
}
struct worker_args {struct thread *thread; HANDLE handle; int old;};
static void *worker(void *arg) {
    struct worker_args *args = arg; current = args->thread;
    pthread_mutex_lock(&server_mutex); current->entered = 1; changed(); pthread_mutex_unlock(&server_mutex);
    if (args->old == 2) {
        CONTEXT context = {0x12345678, 0xabcdef00}; errno = 73;
        wait_suspend(&context); assert(errno == 73 && context.pc == 0x12345678 && context.sp == 0xabcdef00);
    } else current->result = args->old ? old_NtSuspendThread(args->handle, &current->returned_count)
                                      : NtSuspendThread(args->handle, &current->returned_count);
    pthread_mutex_lock(&server_mutex); current->continued = 1; changed(); pthread_mutex_unlock(&server_mutex);
    return NULL;
}
static void baseline_query_rights(void) {
    struct process process = {.id = 0x500}; struct thread target, helper; pthread_t native;
    initialize(&target, &process, 0x700); initialize(&helper, &process, 0x704);
    add_handle(&process, 0x100, &target, THREAD_SUSPEND_RESUME);
    struct worker_args args = {&target, (HANDLE)0x100, 1};
    assert(!pthread_create(&native, NULL, worker, &args)); assert(!pthread_join(native, NULL));
    assert(target.continued && target.suspend == 1 && !target.published && !target.result && !target.returned_count);
    current = &helper; ULONG count = 0; assert(!NtResumeThread((HANDLE)0x100, &count) && count == 1);
    assert(!target.suspend && target.object.refs == 1);
    pthread_cond_destroy(&target.condition); pthread_cond_destroy(&helper.condition);
    puts("BEFORE actual NtSuspendThread: restricted self handle returns while logical suspend count remains1");
}
static void one_case(HANDLE handle, int gate, int nested, int physical) {
    struct process process = {.id = 0x600}; struct thread target, helper; pthread_t native;
    unsigned compares_before = compare_calls;
    initialize(&target, &process, 0x710); initialize(&helper, &process, 0x714);
    add_handle(&process, 0x100, &target, THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION);
    add_handle(&process, 0x104, &target, THREAD_SUSPEND_RESUME); // duplicated, restricted self handle
    target.gate = gate; real_suspend = physical;
    struct worker_args args = {&target, handle, 0};
    assert(!pthread_create(&native, NULL, worker, &args)); current = &helper;
    pthread_mutex_lock(&server_mutex); wait_state(gate ? &target.before_select : &target.published);
    assert(!target.continued && target.suspend == 1); pthread_mutex_unlock(&server_mutex);
    ULONG count = 99;
    if (nested) {
        assert(!NtSuspendThread((HANDLE)0x100, &count) && count == 1);
        assert(!NtResumeThread((HANDLE)0x104, &count) && count == 2);
        pthread_mutex_lock(&server_mutex); assert(!target.continued && target.suspend == 1); pthread_mutex_unlock(&server_mutex);
    }
    assert(!NtResumeThread((HANDLE)0x104, &count) && count == 1);
    if (gate) {
        pthread_mutex_lock(&server_mutex); assert(!target.published && !target.suspend);
        target.gate_open = 1; changed(); pthread_mutex_unlock(&server_mutex);
    }
    assert(!pthread_join(native, NULL));
    assert(target.continued && !target.result && !target.returned_count && !target.suspend && !target.wait);
    assert(target.holds == physical && target.releases == physical && !target.ios_mach_suspended);
    assert(target.object.refs == 1 && helper.object.refs == 1);
    if (identity_mode == 1) assert(compare_calls == compares_before);
    pthread_cond_destroy(&target.condition); pthread_cond_destroy(&helper.condition);
}
static void concurrent_processes(void) {
    struct process processes[2] = {{0}}; struct thread targets[2], helpers[2]; pthread_t natives[2];
    struct worker_args args[2]; real_suspend = 0;
    for (unsigned n = 0; n < 2; ++n) {
        processes[n].id = 0x1000 + n;
        initialize(&targets[n], &processes[n], 0x800 + 8*n); initialize(&helpers[n], &processes[n], 0x804 + 8*n);
        add_handle(&processes[n], 0x100, &targets[n], THREAD_SUSPEND_RESUME);
        args[n] = (struct worker_args){&targets[n], (HANDLE)0x100, 0};
        assert(!pthread_create(&natives[n], NULL, worker, &args[n]));
    }
    pthread_mutex_lock(&server_mutex); wait_state(&targets[0].published); wait_state(&targets[1].published);
    pthread_mutex_unlock(&server_mutex);
    current = &helpers[0]; ULONG count; assert(!NtResumeThread((HANDLE)0x100, &count) && count == 1);
    assert(!pthread_join(natives[0], NULL));
    pthread_mutex_lock(&server_mutex); assert(!targets[1].continued && targets[1].suspend == 1); pthread_mutex_unlock(&server_mutex);
    current = &helpers[1]; assert(!NtResumeThread((HANDLE)0x100, &count) && count == 1);
    assert(!pthread_join(natives[1], NULL));
    for (unsigned n = 0; n < 2; ++n) {
        assert(targets[n].continued && !targets[n].suspend && targets[n].object.refs == 1);
        pthread_cond_destroy(&targets[n].condition); pthread_cond_destroy(&helpers[n].condition);
    }
}
static void reused_handle(void) {
    struct process process = {.id = 0x1100}; struct thread target, helper; pthread_t native;
    initialize(&target, &process, 0x880); initialize(&helper, &process, 0x884);
    add_handle(&process, 0x100, &target, THREAD_SUSPEND_RESUME);
    add_handle(&process, 0x104, &target, THREAD_SUSPEND_RESUME);
    target.reuse_after_call = 1; target.replacement = &helper.object;
    struct worker_args args = {&target, (HANDLE)0x104, 0};
    assert(!pthread_create(&native, NULL, worker, &args)); current = &helper;
    pthread_mutex_lock(&server_mutex); wait_state(&target.published);
    assert(!target.continued && target.suspend == 1 && process.handles[1].object == &helper.object);
    pthread_mutex_unlock(&server_mutex);
    ULONG count; assert(!NtResumeThread((HANDLE)0x100, &count) && count == 1);
    assert(!pthread_join(native, NULL)); assert(target.continued && !target.suspend);
    pthread_cond_destroy(&target.condition); pthread_cond_destroy(&helper.condition);
}
static void created_suspended(void) {
    struct process process = {.id = 0x1200}; struct thread target, helper; pthread_t native;
    initialize(&target, &process, 0x890); initialize(&helper, &process, 0x894);
    add_handle(&process, 0x100, &target, THREAD_SUSPEND_RESUME); target.suspend = 1;
    struct worker_args args = {&target, GetCurrentThread(), 2};
    assert(!pthread_create(&native, NULL, worker, &args)); current = &helper;
    pthread_mutex_lock(&server_mutex); wait_state(&target.published);
    assert(!target.continued && target.suspend == 1); pthread_mutex_unlock(&server_mutex);
    ULONG count; assert(!NtResumeThread((HANDLE)0x100, &count) && count == 1);
    assert(!pthread_join(native, NULL)); assert(target.continued && !target.suspend);
    pthread_cond_destroy(&target.condition); pthread_cond_destroy(&helper.condition);
}
static void honest_errors(void) {
    struct process process = {.id = 0x700}; struct thread target, helper;
    initialize(&target, &process, 0x900); initialize(&helper, &process, 0x904); current = &target;
    ULONG count = 17;
    assert(NtSuspendThread((HANDLE)0xbad, &count) == STATUS_INVALID_HANDLE && count == 17 && !target.suspend);
    add_handle(&process, 0x100, &target, THREAD_QUERY_INFORMATION);
    assert(NtSuspendThread((HANDLE)0x100, &count) == STATUS_ACCESS_DENIED && count == 17 && !target.suspend);
    target.state = TERMINATED;
    assert(NtSuspendThread(GetCurrentThread(), &count) == STATUS_ACCESS_DENIED && count == 17 && !target.suspend);
    target.state = RUNNING;
    target.suspend = MAXIMUM_SUSPEND_COUNT;
    assert(NtSuspendThread(GetCurrentThread(), &count) == STATUS_SUSPEND_COUNT_EXCEEDED && count == 17);
    assert(target.suspend == MAXIMUM_SUSPEND_COUNT); target.suspend = 0;
    assert(!NtResumeThread(GetCurrentThread(), &count) && count == 0 && !target.suspend);
    pthread_cond_destroy(&target.condition); pthread_cond_destroy(&helper.condition);
}
int main(void) {
    baseline_query_rights();
    unsigned baseline_queries = query_calls;
    for (unsigned n = 0; n < 32; ++n) {
        one_case(GetCurrentThread(), 0, 0, 0);
        one_case((HANDLE)0x100, 0, 1, 0);
        one_case((HANDLE)0x104, 0, 0, 0);
        one_case((HANDLE)0x104, 1, 0, 0);
        one_case(GetCurrentThread(), 0, 1, 1);
        concurrent_processes();
        created_suspended();
    }
    reused_handle();
    for (identity_mode = 0; identity_mode < 5; ++identity_mode)
        one_case((HANDLE)0x104, 0, 0, 0);
    identity_mode = 1;
    trace_capture_failure = 1; one_case((HANDLE)0x104, 0, 1, 0); trace_capture_failure = 0;
    honest_errors();
    assert(compare_calls && query_calls == baseline_queries && wait_calls);
    puts("PASS actual suspend/resume/count/check_wait: real pthread continuation, early resume, nested counts, pseudo/real/restricted duplicated handles and concurrent process-scoped tables");
    puts("PASS actual created-suspended wait, authoritative self identity after handle reuse, legacy/malformed identity fallback and honest invalid/access/count errors");
    puts("PASS balanced modeled physical holds and object references; no iPhone/Mach/context-conversion execution claim");
}
'''

server_functions = '\n'.join(function(server, signature) for signature in (
    'static inline int is_thread_suspended(', 'static int check_wait(',
    'int wake_thread(', 'int suspend_thread(', 'int resume_thread('))
# The real wake loop stores a cookie on its private wait type.
PRELUDE = PRELUDE.replace('int flags, select, count; int64_t when;',
    'int flags, select, count; int64_t when; uintptr_t cookie;')
producer = function(mach, 'void ios_suspend_thread_reply(')
assert not re.search(r'\b(?:malloc|calloc|realloc|mem_alloc|set_reply_data|set_reply_data_size)\s*\(', producer), \
    'authoritative identity must not allocate while an existing Mach hold may stop an allocator owner'
source = (PRELUDE + server_functions + producer +
          function(mach, 'void ios_suspend_resume_observe(') +
          function(handles, 'DECL_HANDLER(compare_objects)') +
          function(server, 'DECL_HANDLER(suspend_thread)') + function(server, 'DECL_HANDLER(resume_thread)') +
          TRANSPORT + function(transport, 'NTSTATUS WINAPI NtCompareObjects(') +
          function(client, 'NTSTATUS WINAPI NtResumeThread(') + function(client, 'void wait_suspend(') +
          old_suspend + candidate + TESTS)

with tempfile.TemporaryDirectory(prefix='madeira-self-suspend-') as directory:
    directory = Path(directory)
    code, executable = directory / 'actual.c', directory / 'actual'
    code.write_text(source)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
        '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-pthread',
        '-I', str(ROOT / 'build/ntdll-unix'), str(code), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
