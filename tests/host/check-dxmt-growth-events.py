#!/usr/bin/env python3
"""Verify native-only event registration and real Foundation weak/loan ownership.

The Darwin object supplies a CPU-controlled signaledValue getter; it is NOT a
GPU event or a game test. Actual production registry methods run unchanged.
"""
import importlib.util
import argparse
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-darwin',action='store_true')
args=parser.parse_args()
spec=importlib.util.spec_from_file_location('pressure_event_stage',ROOT/'tools/build/stage-dxmt-memory-pressure.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
original=(ROOT/'dxmt/src/winemetal/unix/winemetal_unix.c').read_text()
staged=stage.stage_pressure_only(original)
header=ROOT/'build/dxmt-ios/resource_growth_event_native.h'
assert staged.count('#include "resource_growth_event_native.h"')==1
start=staged.index('static NTSTATUS\n_MTLDevice_newSharedEvent(void *obj) {')
factory=staged[start:staged.index('\n}',start)+2]
registration='  madeira_growth_event_register_created((id<MTLSharedEvent>)(uintptr_t)params->ret);'
assert factory.count(registration)==1
assert factory.index('return STATUS_SUCCESS;')<factory.index('newSharedEvent];')<factory.index(registration)
assert 'md_resource_growth_handoff(a);' in staged and 'a->op == 43' in staged
for signature in ('_NSObject_retain(NSObject **obj) {','_NSObject_release(NSObject **obj) {'):
    def function(text):
        begin=text.index(signature);return text[begin:text.index('\n}',begin)+2]
    assert function(staged)==function(original), 'generic public reference behavior changed'
assert 'retainCount' not in header.read_text() and 'objc_' not in header.read_text()
assert 'NSPointerFunctionsWeakMemory' in header.read_text()
assert 'params->handle signaledValue' not in header.read_text()
print('PASS genuine native factory registration only; remote/public retain/release behavior unchanged; pointer-free op43 and weak-registry header wired')
if platform.system()!='Darwin':
    if args.require_darwin:
        raise SystemExit('Darwin Foundation/Metal execution was required')
    print('SKIP Foundation ownership execution requires Darwin; no GPU or iPhone result claimed')
    raise SystemExit(0)
code=r'''
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include "resource_growth_event_native.h"
static _Thread_local void* test_owner=(void*)0x1000;
static _Atomic unsigned long long test_lease=1;
static _Atomic int test_live=1;
static _Atomic unsigned destroyed,value_reads,entered,unblock;
static _Atomic int block_read;
void *ios_jit_current_peb(void){errno=40;return test_owner;}
unsigned long long ios_thread_process_snapshot(void*owner,unsigned*threads,int*exiting,int*reclaimed){
 errno=41;
 if(owner!=(void*)0x1000){*threads=0;*exiting=1;*reclaimed=1;return 0;}
 *threads=atomic_load(&test_live)?1:0;*exiting=!atomic_load(&test_live);*reclaimed=*exiting;
 return atomic_load(&test_lease);
}
@interface MDFixtureEvent:NSObject {@public _Atomic uint64_t observed;}
-(uint64_t)signaledValue;
@end
@implementation MDFixtureEvent
-(uint64_t)signaledValue {
 atomic_fetch_add(&value_reads,1);
 if(atomic_load(&block_read)){atomic_store(&entered,1);while(!atomic_load(&unblock))sched_yield();}
 return atomic_load(&observed);
}
-(void)dealloc {atomic_fetch_add(&destroyed,1);[super dealloc];}
@end
static void register_event(MDFixtureEvent*event){errno=72;madeira_growth_event_register_created((id<MTLSharedEvent>)event);assert(errno==72);}
static uint64_t loan(MDFixtureEvent*event,unsigned long long lease){errno=72;uint64_t cookie=madeira_growth_event_retain((uint64_t)(uintptr_t)event,(void*)0x1000,lease);assert(errno==72);return cookie;}
static uint64_t read_event(uint64_t cookie,int expected){uint64_t value=UINT64_MAX;errno=72;assert(madeira_growth_event_value(cookie,&value)==expected);assert(errno==72);return value;}
static void release_event(uint64_t cookie){errno=72;madeira_growth_event_release(cookie);assert(errno==72);}
static void *read_pending(void*payload){uint64_t cookie=*(uint64_t*)payload;assert(read_event(cookie,1)==77);return NULL;}
int main(void){@autoreleasepool {
 unsigned before=atomic_load(&destroyed);
 MDFixtureEvent*event=[[MDFixtureEvent alloc]init];uintptr_t old_handle=(uintptr_t)event;
 register_event(event);[event release];
 assert(atomic_load(&destroyed)==before+1);
 assert(!madeira_growth_event_retain(old_handle,(void*)0x1000,1));
 assert(!madeira_growth_event_retain(UINT64_C(0xdeadbeefdeadbeef),(void*)0x1000,1));
 assert(read_event(UINT64_C(0xfedcba9876543210),0)==0);release_event(UINT64_MAX);
 assert(!atomic_load(&value_reads));
 puts("PASS zeroing-weak registration does not keep the event alive; dead/random handles and opaque cookies are never messaged");

 event=[[MDFixtureEvent alloc]init];atomic_store(&event->observed,7);register_event(event);
 test_owner=(void*)0x2000;assert(!loan(event,1));test_owner=(void*)0x1000;assert(!loan(event,2));
 uint64_t cookie=loan(event,1);assert(cookie);[event release];
 assert(atomic_load(&destroyed)==before+1);assert(read_event(cookie,1)==7);
 atomic_store(&event->observed,19);assert(read_event(cookie,1)==19);
 atomic_store(&test_live,0);assert(!loan(event,1));assert(read_event(cookie,1)==19);
 atomic_store(&test_lease,3);atomic_store(&test_live,1);assert(!loan(event,3));assert(!loan(event,1));
 release_event(cookie);assert(atomic_load(&destroyed)==before+2);assert(read_event(cookie,0)==0);release_event(cookie);
 puts("PASS actual retained loans survive original reference release and CPU quiescence; changing process generation cannot borrow an old event");

 event=[[MDFixtureEvent alloc]init];atomic_store(&event->observed,77);register_event(event);cookie=loan(event,3);assert(cookie);[event release];
 atomic_store(&block_read,1);pthread_t reader;assert(!pthread_create(&reader,NULL,read_pending,&cookie));
 while(!atomic_load(&entered))sched_yield();release_event(cookie);
 assert(atomic_load(&destroyed)==before+2);atomic_store(&unblock,1);pthread_join(reader,NULL);atomic_store(&block_read,0);
 assert(atomic_load(&destroyed)==before+3);assert(read_event(cookie,0)==0);
 puts("PASS concurrent loan close cannot destroy an event while its genuine signaledValue getter is running");

 event=[[MDFixtureEvent alloc]init];register_event(event);uint64_t cookies[MD_GROWTH_EVENT_LOANS];
 for(unsigned i=0;i<MD_GROWTH_EVENT_LOANS;++i){cookies[i]=loan(event,3);assert(cookies[i]);}
 assert(!loan(event,3));for(unsigned i=0;i<MD_GROWTH_EVENT_LOANS;++i)release_event(cookies[i]);
 [event release];assert(atomic_load(&destroyed)==before+4);
 puts("PASS finite strong-loan capacity fails conservatively; duplicate release cannot consume another reference");

 MDFixtureEvent*events[MD_GROWTH_EVENT_SLOTS+1];
 for(unsigned i=0;i<=MD_GROWTH_EVENT_SLOTS;++i){events[i]=[[MDFixtureEvent alloc]init];register_event(events[i]);}
 assert(!loan(events[MD_GROWTH_EVENT_SLOTS],3));
 [events[0]release];register_event(events[MD_GROWTH_EVENT_SLOTS]);cookie=loan(events[MD_GROWTH_EVENT_SLOTS],3);assert(cookie);release_event(cookie);
 for(unsigned i=1;i<=MD_GROWTH_EVENT_SLOTS;++i)[events[i]release];
 assert(atomic_load(&destroyed)==before+4+MD_GROWTH_EVENT_SLOTS+1);
 puts("PASS bounded weak registry safely reuses a genuinely deallocated slot without retaining obsolete device events");
 assert(md_growth_event_next_cookie>1);

 /* This separate optional check uses a real Metal event, not the controlled
  * ownership fixture above. It proves only this Mac's event handoff; it is
  * not a CS2 upload-budget or iPhone performance result. */
 id<MTLDevice>device=MTLCreateSystemDefaultDevice();
 if(device){
   id<MTLSharedEvent>gpu=[device newSharedEvent];assert(gpu);
   errno=72;madeira_growth_event_register_created(gpu);assert(errno==72);
   uint64_t gpu_cookie=madeira_growth_event_retain((uint64_t)(uintptr_t)gpu,(void*)0x1000,3);
   assert(gpu_cookie);assert(read_event(gpu_cookie,1)==0);
   id<MTLCommandQueue>queue=[device newCommandQueue];assert(queue);
   id<MTLCommandBuffer>commands=[queue commandBuffer];assert(commands);
   [commands encodeSignalEvent:gpu value:11];[gpu release];
   [commands commit];[commands waitUntilCompleted];
   assert([commands status]==MTLCommandBufferStatusCompleted);
   assert(read_event(gpu_cookie,1)==11);release_event(gpu_cookie);
   assert(read_event(gpu_cookie,0)==0);[queue release];[device release];
   puts("PASS real Metal command-buffer signal is read through the actual retained native-event registry");
 }else puts("SKIP real Metal event completion: this Mac has no Metal device");
}}
'''
with tempfile.TemporaryDirectory(prefix='madeira-growth-event-') as directory:
    p=Path(directory);source=p/'events.m';binary=p/'events';source.write_text(code)
    compiler=shlex.split(os.environ.get('CC','clang'))
    subprocess.run([*compiler,'-std=gnu11','-O1','-g','-fno-objc-arc','-fobjc-weak','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread','-I',str(header.parent),str(source),
        '-framework','Foundation','-framework','Metal','-o',str(binary)],check=True)
    assert b'[texture-gpu-events-v1]' in binary.read_bytes()
    subprocess.run([str(binary)],check=True,timeout=40,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1'))
print('PASS actual native Foundation weak/retained-event registry; optional Mac GPU completion is separately reported; iPhone allocation results remain unverified')
