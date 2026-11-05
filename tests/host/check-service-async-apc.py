#!/usr/bin/env python3
"""Execute pinned/staged Wine APC queue, wait, dequeue and destruction paths.

The transport/allocator edges are a host fixture. Queue selection, late handoff,
kernel-versus-user wait priority, and lost-completion destruction are the actual
production C functions. This is not a claim of on-device service registration.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('apc_stage', ROOT / 'build/wineserver/stage-async-apc.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
original = (ROOT / 'wine/server/thread.c').read_text()
fixed = stage.stage(original)
async_source = (ROOT / 'wine/server/async.c').read_text()

def function(source, signature):
    start = source.index(signature)
    body = source.index('\n{', start)
    end = source.index('\n}', body) + 2
    return source[start:end]

fixture = r'''
#define WINE_IOS 1
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wine/list.h"
enum apc_type {APC_NONE, APC_USER, APC_ASYNC_IO, APC_OTHER};
enum {RUNNING, TERMINATED};
enum {SELECT_INTERRUPTIBLE=1, SELECT_ALERTABLE=2, SELECT_WAIT_ALL=3};
enum {STATUS_SUCCESS=0, STATUS_KERNEL_APC=0x100, STATUS_ALERTED=0x101,
      STATUS_PENDING=0x103, STATUS_USER_APC=0xc0, STATUS_WAIT_0=0, STATUS_TIMEOUT=0x102};
struct object_ops {int tag;};
static const struct object_ops thread_apc_ops={1}, sync_ops={2}, async_ops={3};
struct object {const struct object_ops *ops; unsigned refs; int signaled;};
struct process {struct list thread_list, asyncs; unsigned suspend, is_terminating;};
struct thread;
struct wait_queue_entry {struct object *obj;};
struct thread_wait {unsigned flags, select; int count; int64_t when; struct wait_queue_entry queues[2];};
struct thread {struct object obj;struct list proc_entry,system_apc,user_apc;struct process *process;
    struct thread_wait *wait;unsigned id,state,suspend,bypass_proc_suspend;struct object *alert_sync;};
union apc_call {unsigned type;struct {unsigned type,status;uint64_t user,sb;unsigned result;} async_io;};
union apc_result {unsigned type;struct {unsigned type,status,total;} async_io;};
struct thread_apc {struct object obj;struct object *sync;struct list entry;struct thread *caller;
    struct object *owner;void *reserve;int executed;union apc_call call;union apc_result result;};
struct async {struct object obj;struct thread *thread;struct list process_entry;int blocking;
    void *wait_handle;unsigned status,total,completions;struct object event;char payload[16],result[16];};
static unsigned heap_objects, callbacks;
static int inproc_mode;
static int64_t current_time, monotonic_time;
static void thread_apc_destroy(struct object *obj);
static void thread_cancel_apc(struct thread *,struct object *,enum apc_type);
static void *grab_object(void *value) {if(value)((struct object *)value)->refs++;return value;}
static void release_object(void *value) {
    if(!value)return;
    struct object *obj=value;assert(obj->refs);
    if(!--obj->refs){assert(obj->ops!=&async_ops);if(obj->ops==&thread_apc_ops)thread_apc_destroy(obj);heap_objects--;free(obj);}
}
static void *alloc_object(const struct object_ops *ops) {
    struct object *o=calloc(1,ops==&thread_apc_ops?sizeof(struct thread_apc):sizeof(struct object));
    assert(o);o->ops=ops;o->refs=1;heap_objects++;return o;
}
static struct object *create_internal_sync(int manual,int set) {(void)manual;struct object *o=alloc_object(&sync_ops);o->signaled=set;return o;}
static void signal_sync(struct object *o) {if(o)o->signaled=1;}
static void signal_inproc_sync(struct object *o) {signal_sync(o);}
static void reset_inproc_sync(struct object *o) {if(o)o->signaled=0;}
static void reserve_obj_unbind(void *o) {assert(!o);}
static int is_thread_suspended(struct thread *t) {return t->suspend||(!t->bypass_proc_suspend&&t->process->suspend);}
int madsync_enabled(void) {return inproc_mode;}
static int send_thread_signal(struct thread *t,int sig) {(void)t;assert(sig==SIGUSR1);return 0;}
static int is_in_apc_wait(struct thread *t) {return t->wait&&(t->wait->flags&SELECT_INTERRUPTIBLE);}
static struct list *get_apc_queue(struct thread *t,unsigned type) {return type==APC_USER?&t->user_apc:type==APC_NONE?NULL:&t->system_apc;}
static int wake_thread(struct thread *t) {(void)t;return 0;}
static struct thread *ios_process_apc_fallback(struct process *p,struct thread_apc *a) {(void)p;(void)a;return NULL;}
static int object_sync_signaled(struct object *o,struct wait_queue_entry *e) {(void)e;return o->signaled;}
static void object_sync_unclaim(struct object *o) {(void)o;}
static void async_set_result(struct object *owner,unsigned status,unsigned total) {
    struct async *a=(struct async *)owner;assert(owner->ops==&async_ops);
    a->status=status;a->total=total;a->completions++;a->event.signaled=1;
}
'''

tail = r'''
static void process_init(struct process *p) {memset(p,0,sizeof(*p));list_init(&p->thread_list);list_init(&p->asyncs);}
static void thread_init(struct thread *t,struct process *p,unsigned id) {
    memset(t,0,sizeof(*t));t->obj.refs=1;t->process=p;t->id=id;
    list_init(&t->system_apc);list_init(&t->user_apc);list_add_tail(&p->thread_list,&t->proc_entry);
}
static void io_init(struct async *a,struct thread *t) {
    memset(a,0,sizeof(*a));a->obj.ops=&async_ops;a->obj.refs=1;a->thread=t;a->status=STATUS_PENDING;
    for(unsigned n=0;n<sizeof(a->payload);n++)a->payload[n]=(char)(n+1);
    list_add_tail(&t->process->asyncs,&a->process_entry);
}
static int issue(struct async *a) {
    union apc_call call={.async_io={.type=APC_ASYNC_IO,.status=STATUS_ALERTED}};
    return thread_queue_apc(a->thread->process,a->thread,&a->obj,&call);
}
static int execute_one(struct thread *t,struct async *a) {
    struct thread_apc *apc=thread_dequeue_apc(t,1);assert(apc&&apc->owner==&a->obj);
    memcpy(a->result,a->payload,sizeof(a->payload));callbacks++;
    apc->executed=1;apc->result.async_io.type=APC_ASYNC_IO;
    apc->result.async_io.status=STATUS_SUCCESS;apc->result.async_io.total=sizeof(a->payload);
    release_object(apc);return 0;
}
static void wait_init(struct thread *t,struct thread_wait *w,struct object *obj,unsigned flags) {
    memset(w,0,sizeof(*w));w->flags=flags;w->count=1;w->queues[0].obj=obj;w->when=INT64_MAX;t->wait=w;
}
int main(int argc,char **argv) {
    int staged=argc>1&&!strcmp(argv[1],"staged");
    struct process p,q;struct thread issuer,waiter,foreign;struct thread_wait wait;
    struct async a;process_init(&p);process_init(&q);thread_init(&issuer,&p,0x50);thread_init(&waiter,&p,0x54);thread_init(&foreign,&q,0x58);
    io_init(&a,&issuer);
    int queued=issue(&a);
    if(!staged) {
        assert(!queued&&a.status==STATUS_ALERTED&&a.total==0&&a.completions==1&&a.event.signaled);
        assert(!memcmp(a.result,(char[16]){0},16)&&heap_objects==0&&callbacks==0);
        puts(argc>1&&!strcmp(argv[1],"disabled") ?
             "PASS existing requeue-disabled control retains its original policy" :
             "PASS pinned baseline: lost APC completes real I/O as STATUS_ALERTED/zero bytes (RPC header failure)");return 0;
    }
    assert(queued&&a.status==STATUS_PENDING&&!a.event.signaled&&a.completions==0&&a.obj.refs==2);
    // Nonalertable issuer wait drains a kernel APC before consuming the event.
    wait_init(&issuer,&wait,&a.event,SELECT_INTERRUPTIBLE);
    assert(check_wait(&issuer)==STATUS_KERNEL_APC);execute_one(&issuer,&a);
    assert(check_wait(&issuer)==0&&a.status==0&&a.total==16&&!memcmp(a.result,a.payload,16));
    assert(a.obj.refs==1&&heap_objects==0);
    issuer.wait=NULL;
    // A sibling which starts waiting after completion arrival can make progress
    // even when the issuer never waits itself; ownership stays with the request.
    struct async late;io_init(&late,&issuer);assert(issue(&late));
    wait_init(&waiter,&wait,&late.event,SELECT_INTERRUPTIBLE);
    assert(check_wait(&waiter)==STATUS_KERNEL_APC&&list_empty(&issuer.system_apc)&&late.obj.refs==2);
    execute_one(&waiter,&late);assert(check_wait(&waiter)==0&&late.total==16&&late.thread==&issuer);
    assert(late.obj.refs==1&&heap_objects==0);waiter.wait=NULL;
    // User APCs retain thread affinity and cannot be adopted by nonalertable
    // sibling waits. Other kernel APCs ahead of I/O keep their FIFO priority.
    union apc_call user={.type=APC_USER};assert(thread_queue_apc(&p,&issuer,NULL,&user));
    struct object unsignaled={.refs=1};wait_init(&waiter,&wait,&unsignaled,SELECT_INTERRUPTIBLE);
    assert(check_wait(&waiter)==-1&&!list_empty(&issuer.user_apc)&&list_empty(&waiter.user_apc));
    struct thread_apc *ua=thread_dequeue_apc(&issuer,0);assert(ua&&ua->call.type==APC_USER);release_object(ua);waiter.wait=NULL;
    struct thread_apc *other=create_apc(NULL,&(union apc_call){.type=APC_OTHER});
    list_add_tail(&issuer.system_apc,&other->entry);
    struct async ordered;io_init(&ordered,&issuer);assert(issue(&ordered));
    wait_init(&waiter,&wait,&ordered.event,SELECT_INTERRUPTIBLE);
    assert(check_wait(&waiter)==-1&&list_head(&issuer.system_apc)==&other->entry);
    list_remove(&other->entry);release_object(other);
    assert(check_wait(&waiter)==STATUS_KERNEL_APC);execute_one(&waiter,&ordered);waiter.wait=NULL;
    // A foreign process, dead/suspended source, terminating process or
    // noninterruptible waiter must not steal the completion.
    struct async held;io_init(&held,&issuer);assert(issue(&held));
    wait_init(&foreign,&wait,&held.event,SELECT_INTERRUPTIBLE);assert(check_wait(&foreign)==-1);foreign.wait=NULL;
    wait_init(&waiter,&wait,&held.event,0);assert(check_wait(&waiter)==-1);
    wait.flags=SELECT_INTERRUPTIBLE;issuer.suspend=1;assert(check_wait(&waiter)==-1);issuer.suspend=0;
    issuer.state=TERMINATED;assert(check_wait(&waiter)==-1);issuer.state=RUNNING;
    p.is_terminating=1;assert(check_wait(&waiter)==-1);p.is_terminating=0;
    assert(check_wait(&waiter)==STATUS_KERNEL_APC);execute_one(&waiter,&held);waiter.wait=NULL;
    // Cancellation still owns exactly one queue reference after late adoption.
    struct async cancelled;io_init(&cancelled,&issuer);assert(issue(&cancelled));
    wait_init(&waiter,&wait,&cancelled.event,SELECT_INTERRUPTIBLE);
    assert(check_wait(&waiter)==STATUS_KERNEL_APC);unsigned before=callbacks;
    thread_cancel_apc(&waiter,&cancelled.obj,APC_ASYNC_IO);
    assert(callbacks==before&&cancelled.obj.refs==1&&list_empty(&waiter.system_apc)&&heap_objects==0);waiter.wait=NULL;
    // Madsync cannot yet guarantee kernel APC wakeup: do not introduce an
    // uninterruptible overlapped wait there. Existing synchronous guarantee
    // stays supported regardless of backend.
    inproc_mode=1;struct async unsafe;io_init(&unsafe,&issuer);assert(!issue(&unsafe));
    assert(unsafe.status==STATUS_ALERTED&&unsafe.total==0);
    struct async sync;io_init(&sync,&issuer);sync.blocking=1;sync.wait_handle=&sync;
    assert(issue(&sync));wait_init(&issuer,&wait,&sync.event,SELECT_INTERRUPTIBLE);
    assert(check_wait(&issuer)==STATUS_KERNEL_APC);execute_one(&issuer,&sync);issuer.wait=NULL;
    assert(sync.total==16&&heap_objects==0);
    puts("PASS staged actual Wine queue/wait/dequeue/destruction: nonalertable 16-byte completion, late sibling, FIFO/user affinity, ownership/death/cancellation and conservative madsync policy");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-service-apc-') as directory:
    directory = Path(directory)
    for name, source in [('baseline', original), ('staged', fixed)]:
        adopt = stage.ADOPT if name == 'staged' else ''
        functions = [function(async_source, 'int async_can_defer_to_issuer('),
                     function(source, 'static int ios_apc_requeue_enabled( void )'),
                     function(source, 'static void thread_apc_destroy('),
                     function(source, 'static struct thread_apc *create_apc('),
                     function(source, 'static struct thread_apc *thread_dequeue_apc('),
                     function(source, 'void thread_cancel_apc('),
                     function(source, 'static struct thread *ios_apc_requeue_target('),
                     function(source, 'static int queue_apc('),
                     function(source, 'int thread_queue_apc(')]
        # This function's forward declaration does not have a body at its first
        # occurrence; locate the actual definition for exact destructor code.
        functions[2] = function(source[source.index('static void thread_apc_destroy( struct object *obj )\n{'):],
                                'static void thread_apc_destroy(')
        text = fixture + '\n'.join(functions) + '\n' + adopt + function(source, 'static int check_wait(') + tail
        path, binary = directory / (name + '.c'), directory / name
        path.write_text(text)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-Wno-unused-variable', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', *(['-fno-pie','-no-pie'] if sys.platform.startswith('linux') else []), '-I'+str(ROOT/'wine/include'),
                        str(path), '-o', str(binary)], check=True)
        subprocess.run([str(binary), name], check=True, timeout=30)
    disabled = dict(os.environ, MADEIRA_APC_REQUEUE='0')
    subprocess.run([str(directory / 'staged'), 'disabled'], env=disabled, check=True, timeout=30)
print('PASS exact pinned Wine input unchanged and staged correction is iOS-only; no service status or protocol success fabricated')
