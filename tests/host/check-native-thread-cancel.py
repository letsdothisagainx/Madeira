#!/usr/bin/env python3
"""Execute native kill/lease metadata, abandoned-wait cleanup and cancellable Sleep."""
from pathlib import Path
import os,re,runpy,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
thread=(root/'build/ntdll-unix/thread_ios.c').read_text()
sync=runpy.run_path(str(root/'tools/build/stage-native-thread-exit.py'))['stage']((root/'wine/dlls/ntdll/unix/sync.c').read_text())
def body(s,mark):
 a=s.index(mark);b=s.index('{',a);n=0
 for t in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]',s[b:],re.S):
  if t[0]=='{':n+=1
  elif t[0]=='}':
   n-=1
   if not n:return s[a:b+t.end()]
 raise AssertionError(mark)
# Declaration precedes definition; select the actual helper's signature+body.
checkpoint=body(sync,'static void ios_native_cancel_checkpoint(void)\n{')
code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "native_thread_lifetime.h"
typedef uintptr_t ULONG_PTR;typedef void* HANDLE;typedef int BOOL;typedef int BOOLEAN;typedef unsigned NTSTATUS;typedef int32_t LONG;typedef int64_t LONGLONG;typedef int64_t timeout_t;
typedef struct {LONGLONG QuadPart;} LARGE_INTEGER;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define STATUS_THREAD_IS_TERMINATING 0xc000004bu
#define STATUS_SUCCESS 0
#define STATUS_TIMEOUT 0x102
#define STATUS_ALERTED 0x101
#define TIMEOUT_INFINITE INT64_MAX
#define SELECT_INTERRUPTIBLE 1
#define SELECT_ALERTABLE 2
#define IOS_ECO_POLL() ((void)0)
struct fake_teb{void* Peb;struct{void *UniqueProcess,*UniqueThread;} ClientId;};typedef struct fake_teb TEB;
static _Thread_local TEB self;
static TEB* NtCurrentTeb(void){return &self;}
''' +body(thread,'struct ios_thread_group\n{')+r''';
static struct ios_thread_group ios_thread_groups[64];
static pthread_mutex_t ios_thread_group_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local struct madeira_native_thread ios_native_current;
static _Thread_local int ios_native_finishing;
static _Thread_local void* ios_retired_thread_owner;
static unsigned long long ios_thread_next_lease;
static atomic_uint exited,ready;
static pthread_mutex_t wake_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake_cond=PTHREAD_COND_INITIALIZER;
static int notified[128];static unsigned alerts;
static unsigned NtAlertThreadByThreadId(HANDLE tid){
 unsigned t=(unsigned)(uintptr_t)tid;assert(t<128);
 pthread_mutex_lock(&wake_lock);notified[t]=1;alerts++;pthread_cond_broadcast(&wake_cond);pthread_mutex_unlock(&wake_lock);return 0;
}
''' +body(thread,'static void ios_native_link_current_locked(')+'\n'+body(thread,'int ios_native_thread_cancelled(')+'\n'+body(thread,'unsigned ios_native_thread_exit_status(')+'\n'+body(thread,'void ios_native_thread_terminated(')+'\n'+body(thread,'void ios_native_process_terminated(')+r'''
struct ios_shared_futex_queue{void* next,*prev;LONG lock;};
static struct ios_shared_futex_queue ios_shared_futex_queues[256];
#define IOS_ALERT_WAITER_MAX 128
static struct{void* tid;const void* addr;} ios_alert_waiters[IOS_ALERT_WAITER_MAX];
static LONG InterlockedCompareExchange(LONG* p,LONG v,LONG expected){__atomic_compare_exchange_n(p,&expected,v,0,__ATOMIC_ACQ_REL,__ATOMIC_RELAXED);return expected;}
static LONG InterlockedExchange(LONG* p,LONG v){return __atomic_exchange_n(p,v,__ATOMIC_RELEASE);}
static void YieldProcessor(void){sched_yield();}
static void abort_thread(int status){
 assert((unsigned)status==0xc0000005u);ios_native_finishing=1;
 pthread_mutex_lock(&ios_thread_group_mutex);
 struct ios_thread_group *g=&ios_thread_groups[0];
 madeira_native_thread_unlink(&g->native_threads,&ios_native_current);assert(g->count);g->count--;
 pthread_mutex_unlock(&ios_thread_group_mutex);
 atomic_fetch_add(&exited,1);pthread_exit(NULL);
}
''' +checkpoint+r'''
static unsigned NtWaitForAlertByThreadId(const void* address,const LARGE_INTEGER* timeout){
 (void)address;ios_native_cancel_checkpoint();
 unsigned t=(unsigned)(uintptr_t)self.ClientId.UniqueThread;
 pthread_mutex_lock(&wake_lock);
 while(!notified[t]){
  if(timeout){struct timespec until;clock_gettime(CLOCK_REALTIME,&until);long long ns=-timeout->QuadPart*100;
   until.tv_sec+=ns/1000000000;until.tv_nsec+=ns%1000000000;if(until.tv_nsec>=1000000000){until.tv_nsec-=1000000000;until.tv_sec++;}
   int e=pthread_cond_timedwait(&wake_cond,&wake_lock,&until);if(e){pthread_mutex_unlock(&wake_lock);ios_native_cancel_checkpoint();return STATUS_TIMEOUT;}}
  else pthread_cond_wait(&wake_cond,&wake_lock);
 }
 notified[t]=0;pthread_mutex_unlock(&wake_lock);ios_native_cancel_checkpoint();return 0x101;
}
static long long ios_xp_delay,ios_xp_delay_hist[6];
static unsigned server_wait(void* p,int n,int f,const LARGE_INTEGER* t){(void)p;(void)n;(void)f;(void)t;return STATUS_TIMEOUT;}
static unsigned NtYieldExecution(void){return 0;}
static void NtQuerySystemTime(LARGE_INTEGER* t){struct timespec now;clock_gettime(CLOCK_REALTIME,&now);t->QuadPart=(int64_t)now.tv_sec*10000000+now.tv_nsec/100;}
''' +body(sync,'NTSTATUS WINAPI NtDelayExecution(').replace('WINAPI ','')+r'''
struct entry{struct entry* next,*prev;const void* addr;unsigned tid;};
static void* worker(void* input){
 unsigned t=(unsigned)(uintptr_t)input;self.Peb=(void*)0x500310000ull;self.ClientId.UniqueProcess=(void*)0x64;self.ClientId.UniqueThread=(void*)(uintptr_t)t;
 pthread_mutex_lock(&ios_thread_group_mutex);ios_native_link_current_locked(&ios_thread_groups[0]);pthread_mutex_unlock(&ios_thread_group_mutex);
 struct entry e={0,0,(void*)0x1234,t};struct ios_shared_futex_queue *q=&ios_shared_futex_queues[t];struct entry *head=(void*)q;
 while(InterlockedCompareExchange(&q->lock,-1,0))YieldProcessor();
 e.next=e.prev=head;q->next=q->prev=&e;InterlockedExchange(&q->lock,0);
 ios_alert_waiters[t].tid=self.ClientId.UniqueThread;ios_alert_waiters[t].addr=e.addr;
 atomic_fetch_add(&ready,1);
 if(t%2)NtDelayExecution(0,NULL);else NtWaitForAlertByThreadId((void*)0x1234,NULL);
 assert(0);return NULL;
}
static void* ordinary_alert(void* unused){(void)unused;struct timespec delay={0,5000000};nanosleep(&delay,NULL);NtAlertThreadByThreadId((HANDLE)100);return NULL;}
int main(void){
 struct ios_thread_group *g=&ios_thread_groups[0];g->owner=(void*)0x500310000ull;g->lease=5;g->count=64;g->pid=0x64;
 pthread_t threads[64];for(unsigned i=1;i<=64;i++)assert(!pthread_create(&threads[i-1],NULL,worker,(void*)(uintptr_t)i));
 while(atomic_load(&ready)!=64)sched_yield();
 struct entry sibling={0,0,(void*)0xbeef,999};struct ios_shared_futex_queue* sq=&ios_shared_futex_queues[1];
 while(InterlockedCompareExchange(&sq->lock,-1,0))YieldProcessor();
 sibling.next=sq->next;sibling.prev=(void*)sq;((struct entry*)sq->next)->prev=&sibling;sq->next=&sibling;InterlockedExchange(&sq->lock,0);
 ios_native_process_terminated(0x64,0xc0000005u);assert(g->exiting);
 // Wrong generation/TID/TEB cannot cancel an unrelated live thread.
 pthread_mutex_lock(&ios_thread_group_mutex);
 struct madeira_native_thread saved=*g->native_threads;
 assert(!madeira_native_thread_cancel(g->native_threads,g->owner,4,saved.teb,saved.pid,saved.tid,0));
 pthread_mutex_unlock(&ios_thread_group_mutex);
 for(unsigned i=1;i<=64;i++){
  pthread_mutex_lock(&ios_thread_group_mutex);struct madeira_native_thread *n=g->native_threads;
  while(n&&n->tid!=i)n=n->next;assert(n);void *teb=n->teb;pthread_mutex_unlock(&ios_thread_group_mutex);
  ios_native_thread_terminated((uint64_t)(uintptr_t)teb,0x64,i,0xc0000005u);
 }
 for(unsigned i=0;i<64;i++)pthread_join(threads[i],NULL);
 assert(atomic_load(&exited)==64&&!g->count&&!g->native_threads&&alerts==64);
 for(unsigned i=1;i<=64;i++){if(i!=1)assert(ios_shared_futex_queues[i].next==&ios_shared_futex_queues[i]);assert(!ios_alert_waiters[i].addr);}
 assert(sq->next==&sibling&&sq->prev==&sibling&&sibling.addr==(void*)0xbeef);
 // Missing/reused identities do not wake; PID ambiguity never authorizes reclaim.
 ios_native_thread_terminated((uint64_t)(uintptr_t)saved.teb,0x64,saved.tid,0xc0000005u);assert(alerts==64);
 g->count=1;g->exiting=0;ios_thread_groups[1]=*g;ios_thread_groups[1].owner=(void*)0x600310000;
 ios_native_process_terminated(0x64,0xc0000005u);assert(!g->exiting&&!ios_thread_groups[1].exiting);
 self.ClientId.UniqueThread=(void*)100;
 LARGE_INTEGER before,after,delay={-400000};NtQuerySystemTime(&before);
 pthread_t timer;assert(!pthread_create(&timer,NULL,ordinary_alert,NULL));
 assert(!NtDelayExecution(0,&delay));pthread_join(timer,NULL);NtQuerySystemTime(&after);
 assert(after.QuadPart-before.QuadPart>=350000); // ordinary alert must NOT shorten non-alertable Sleep
 assert(notified[100]); // Sleep must preserve the ordinary alert for a subsequent address wait
 assert(NtWaitForAlertByThreadId(NULL,NULL)==STATUS_ALERTED&&!notified[100]);
 puts("PASS actual native kill/lease policy and wait cleanup:64 killed native waiters/infinite sleeps wake without polling,abandoned shared queue nodes removed,all retire;stale identities/lease and ambiguous PID rejected");
}
'''
with tempfile.TemporaryDirectory() as t:
 p=Path(t)/'check.c';p.write_text(code);exe=Path(t)/'check'
 subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-pthread','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Werror=implicit-function-declaration','-I'+str(root/'build/ntdll-unix'),str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True,timeout=30)
