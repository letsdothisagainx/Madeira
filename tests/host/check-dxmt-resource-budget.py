#!/usr/bin/env python3
"""Run actual shared-native growth receipts and C++ lifetime guards.

Native footprint values are controlled host inputs, not an iPhone measurement.
Real pthreads and Wine's actual generation/quiescence predicates exercise
parallel admission, foreign release and interrupted-creator retirement.
"""
from pathlib import Path
import os
import argparse
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--run14-normal-only', action='store_true',
                    help='Replay recorded Run14/Run25 pressure inputs and ordinary admission/release only')
args=parser.parse_args()

def function(source, signature):
    begin=source.index(signature)
    return source[begin:source.index('\n}',begin)+2]+'\n'

thread=(ROOT/'build/ntdll-unix/thread_ios.c').read_text()
registry=function(thread,'unsigned long long ios_thread_process_quiescent_lease(')+function(thread,'unsigned long long ios_thread_process_snapshot(')
server=(ROOT/'build/ntdll-unix/server_ios.c').read_text()
retire=function(server,'static void ios_finish_process_memory(')
assert retire.index('madeira_resource_growth_retire(dead_peb, lease)') < retire.index('ios_wow_window_release(dead_peb)') < retire.index('ios_thread_process_finalize_native(dead_peb, lease)')
assert 'if (lease && madeira_resource_growth_retire) madeira_resource_growth_retire(caller_peb, lease);' in server
code=r'''
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <map>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>
#include "winemetal.h"
#include "memory_pressure.hpp"
#include <pthread.h>
// Darwin's relative_np wait deliberately is not a cancellation point. The
// second Linux execution models that native contract, rather than letting
// Linux's cancelable POSIX wait hide a missing explicit boundary check.
#if defined(MODEL_DARWIN_NONCANCEL_WAIT) && !defined(__APPLE__)
static int fixture_noncancel_wait(pthread_cond_t *condition,pthread_mutex_t *mutex,const struct timespec *deadline){
 int previous;assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous));
 const int status=pthread_cond_timedwait(condition,mutex,deadline);
 assert(!pthread_setcancelstate(previous,nullptr));return status;
}
#define pthread_cond_timedwait fixture_noncancel_wait
#endif
#include "memory_pressure_native.h"
#if defined(MODEL_DARWIN_NONCANCEL_WAIT) && !defined(__APPLE__)
#undef pthread_cond_timedwait
#endif
static constexpr uint64_t MiB=uint64_t{1}<<20;
static std::atomic<uint64_t> footprint{4096*MiB}, available{2048*MiB};
static std::atomic<bool> fail_query{false};
static std::atomic<unsigned> queries{0}, acquire_calls{0}, release_calls{0};
// The public allocator-relief worker is exercised in its own actual-header
// fixture. This receipt fixture never claims native free pages were reclaimed.
extern "C" void madeira_native_memory_relief_request(uint64_t, uint64_t) {}
static thread_local void* caller=(void*)0x10000;
static pthread_mutex_t ios_thread_group_mutex=PTHREAD_MUTEX_INITIALIZER;
struct Owner {void* owner;unsigned count;int exiting,reclaimed;unsigned long long lease;};
static Owner ios_thread_groups[4]={{(void*)0x10000,1,0,0,1},{(void*)0x20000,1,0,0,2}};
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))
extern "C" void *ios_jit_current_peb(void) {return caller;}
'''+registry+r'''
extern "C" int mach_task_self(void){return 1;}
extern "C" int task_info(int task,int flavor,task_info_t out,mach_msg_type_number_t*count){
 assert(task==1&&flavor==TASK_VM_INFO); ++queries; errno=41;
 ((task_vm_info_data_t*)out)->phys_footprint=footprint.load();*count=TASK_VM_INFO_COUNT;
 return fail_query?1:0;
}
extern "C" size_t os_proc_available_memory(void){errno=42;return available.load();}
extern "C" int sysctlbyname(const char*key,void*out,size_t*size,void*in,size_t n){
 assert(!strcmp(key,"hw.memsize")&&!in&&!n);*(uint64_t*)out=7672*MiB;*size=sizeof(uint64_t);errno=43;return 0;
}

struct FakeEvent {
 uint64_t handle;void* owner;uint64_t lease;std::atomic<uint64_t> value{0};
 FakeEvent(uint64_t h,void*o,uint64_t l):handle(h),owner(o),lease(l){}
};
static FakeEvent events[]={{0x51,(void*)0x10000,1},{0x52,(void*)0x20000,2},{0x61,(void*)0x10000,3}};
static std::mutex event_mutex;
static std::map<uint64_t,FakeEvent*> event_loans;
static uint64_t next_event_cookie=1;
static std::atomic<unsigned> event_reads{0},event_releases{0};
static std::atomic<bool> check_release_unlocked{false};
static std::atomic<bool> pause_event_close{false},event_close_entered{false},allow_event_close{false};
extern "C" uint64_t madeira_growth_event_retain(uint64_t handle,void*owner,unsigned long long lease){
 std::lock_guard<std::mutex> lock(event_mutex);
 if(event_loans.size()>=MD_RESOURCE_GROWTH_RECEIPTS)return 0;
 for(auto&e:events)if(e.handle==handle&&e.owner==owner&&e.lease==lease){
  uint64_t cookie=next_event_cookie++;event_loans.emplace(cookie,&e);return cookie;
 }
 return 0;
}
extern "C" int madeira_growth_event_value(uint64_t cookie,uint64_t*out){
 std::lock_guard<std::mutex> lock(event_mutex);++event_reads;
 auto i=event_loans.find(cookie);if(i==event_loans.end())return 0;
 *out=i->second->value.load();return 1;
}
extern "C" void madeira_growth_event_release(uint64_t cookie){
 if(pause_event_close){event_close_entered=true;while(!allow_event_close.load())std::this_thread::yield();}
 if(check_release_unlocked){assert(!pthread_mutex_trylock(&md_resource_growth_mutex));pthread_mutex_unlock(&md_resource_growth_mutex);}
 std::lock_guard<std::mutex> lock(event_mutex);assert(event_loans.erase(cookie)==1);++event_releases;
}

void MadeiraCtl(madeira_ctl_args*args){
 assert(args->ret==0);
 if(args->op==40) md_memory_pressure_query(args);
 else if(args->op==41){++acquire_calls;md_resource_growth_acquire(args);}
 else if(args->op==42){++release_calls;md_resource_growth_release(args);}
 else if(args->op==43)md_resource_growth_handoff(args);
 else if(args->op==46)md_resource_growth_snapshot(args);
 else std::abort();
}
static void sample(uint64_t remaining){available=remaining;footprint=6144*MiB-remaining;}
static madeira_ctl_args acquire(uint64_t n,uint64_t retry=0){
 madeira_ctl_args a={41,0,n,retry,{0}};errno=72;MadeiraCtl(&a);assert(errno==72);return a;
}
static bool release(uint64_t token){
 madeira_ctl_args a={42,0,token,0,{0}};errno=72;MadeiraCtl(&a);assert(errno==72);return a.ret==1;
}
static void owner_state(unsigned row,unsigned threads,int exiting,int reclaimed,uint64_t lease){
 assert(!pthread_mutex_lock(&ios_thread_group_mutex));
 auto& o=ios_thread_groups[row];o.count=threads;o.exiting=exiting;o.reclaimed=reclaimed;o.lease=lease;
 assert(!pthread_mutex_unlock(&ios_thread_group_mutex));
}
static std::vector<int> cleanup;
void ios_startup_process_quiesced(void*){cleanup.push_back(1);}
void ios_fd_cache_release(void*){assert(md_resource_growth_held==32*MiB);cleanup.push_back(2);}
void ios_subfloor_release_owner(void*){cleanup.push_back(3);}
void ios_jit_reclaim_process(void*){cleanup.push_back(4);}
void ios_fex_reclaim_process_views(void*){cleanup.push_back(5);}
void ios_cef_reclaim_process_images(void*){cleanup.push_back(6);}
void ios_wow_window_release(void*){cleanup.push_back(7);}
void ios_exe_win_mark_ready(void*){cleanup.push_back(8);}
int ios_wow_base_for_peb(void*){return 0;}
int ios_thread_process_finalize_native(void*,unsigned long long lease){assert(lease==1);cleanup.push_back(9);return 1;}
void wine_log_write(const char*,...){ }
extern "C" void fixture_finish_process_memory(void*);
'''+r'''
static uint64_t detail(const madeira_ctl_args&a,unsigned i){uint64_t v;assert(i<4);memcpy(&v,a.name+8*i,8);return v;}
static madeira_ctl_args handoff(uint64_t token,uint64_t event,uint64_t target){
 madeira_ctl_args a={43,0,token,event,{0}};memcpy(a.name,&target,8);errno=72;MadeiraCtl(&a);assert(errno==72);return a;
}
static void await_waiter(){
 auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
 for(;;){
  assert(!pthread_mutex_lock(&md_resource_growth_mutex));auto n=md_resource_growth_waiters;
  assert(!pthread_mutex_unlock(&md_resource_growth_mutex));if(n)return;
  assert(std::chrono::steady_clock::now()<end);std::this_thread::sleep_for(std::chrono::milliseconds(1));
 }
}
struct WaitResult {madeira_ctl_args result{};};
static void*wait_entry(void*pointer){caller=(void*)0x10000;((WaitResult*)pointer)->result=acquire(16*MiB,1);return pointer;}
int main(){
 caller=(void*)0x10000;
 assert(md_resource_growth_floor(768*MiB)==192*MiB);
 assert(md_resource_growth_floor(128*MiB)==128*MiB);
 assert(md_resource_growth_floor(1024*MiB)==256*MiB);
 sample(1244*MiB);
 std::atomic<unsigned> ready{0},granted{0};std::atomic<bool>go{false},done{false};
 std::vector<std::thread>workers;
 for(unsigned i=0;i<12;i++)workers.emplace_back([&]{
  caller=(void*)0x10000;ready++;while(!go.load())std::this_thread::yield();
  auto a=acquire(128*MiB);if(a.ptr)++granted;else assert(a.ret==3);
  ready++;while(!done.load())std::this_thread::yield();if(a.ptr)assert(release(a.ptr));
 });
 while(ready<12){std::this_thread::yield();}go=true;
 while(ready<24){std::this_thread::yield();}
 assert(granted==8&&md_resource_growth_held==1024*MiB);
 done=true;for(auto&t:workers)t.join();assert(!md_resource_growth_held);
 std::puts("PASS real prospective-credit accounting:8/12 concurrent128MiB creators fit1244MiB headroom while preserving192MiB floor");
 // Exact new device failures: neither a tiny texture nor an ordinary1024BC
 // texture is rejected by a lifetime-spend counter or a1MiB size category.
 for(const auto&observed:std::vector<std::pair<uint64_t,uint64_t>>{{260605704,8},{313657240,1398096},{384108536,1398096},{399918904,87376}}){
  sample(observed.first);auto a=acquire(observed.second);assert(a.ptr&&a.ret==2&&a.len==observed.first);
  assert(detail(a,0)==6144*MiB-observed.first&&detail(a,1)==0&&detail(a,2)==192*MiB&&!detail(a,3));
  assert(md_resource_growth_held==observed.second&&release(a.ptr));
 }
 // The cold path needs actual new upload backing as well as destination
 // bytes. Replay the exact denied headroom with a genuine32MiB fresh block;
 // a warm reused block is covered by the destination-only cases above.
 for(const auto&observed:std::vector<std::pair<uint64_t,uint64_t>>{{260605704,8},{313657240,1398096}}){
  const uint64_t cold_cost=observed.second+32*MiB;
  sample(observed.first);auto a=acquire(cold_cost);assert(a.ptr&&a.ret==2&&a.len==observed.first);
  assert(detail(a,1)==0&&detail(a,2)==192*MiB&&!detail(a,3));
  assert(md_resource_growth_held==cold_cost&&a.len-md_resource_growth_held>=192*MiB);
  assert(release(a.ptr)&&!md_resource_growth_held);
 }
 sample(300*MiB);unsigned resident=0;const uint64_t tex=1398096;
 while(available.load()>=192*MiB+tex){
  auto a=acquire(tex);assert(a.ptr);sample(available.load()-tex);assert(release(a.ptr));++resident;
 }
 assert(resident>64);auto no_room=acquire(tex,1);assert(no_room.ret==3&&detail(no_room,3)==1);
 sample(available.load()+tex);auto real_free=acquire(tex);assert(real_free.ptr);assert(release(real_free.ptr));
 assert(available<400*MiB); // Recovery is real freed capacity, not a960MiB watermark.
 sample(192*MiB);auto at_floor=acquire(8,1);assert(at_floor.ret==3&&detail(at_floor,3)==1);
 sample(192*MiB+8);auto exact=acquire(8);assert(exact.ptr);assert(release(exact.ptr));
 assert(acquire(1,2).ret==4);
 std::puts("PASS actual8/1398096-byte failures now use measured capacity; live resident bytes still constrain growth, and real frees recover below the old960MiB reset watermark");
 // A normal caller must return to PE to flush any unsubmitted initializer
 // work. Only its explicit retry can wait for another creator's credit.
 sample(300*MiB);auto pending=acquire(100*MiB);assert(pending.ptr);
 auto started=std::chrono::steady_clock::now();auto first=acquire(16*MiB);
 assert(first.ret==3&&detail(first,3)==2&&std::chrono::steady_clock::now()-started<std::chrono::seconds(1));
 std::thread cpu_release([&]{caller=(void*)0x10000;await_waiter();assert(release(pending.ptr));});
 const unsigned before_query=queries.load();auto next=acquire(16*MiB,1);cpu_release.join();
 assert(next.ptr&&queries>before_query&&release(next.ptr));assert(!md_resource_growth_waiters);
 pending=acquire(100*MiB);assert(pending.ptr);started=std::chrono::steady_clock::now();
 auto busy=acquire(16*MiB,1);auto elapsed=std::chrono::steady_clock::now()-started;
 assert(busy.ret==3&&detail(busy,3)==2&&elapsed>=std::chrono::milliseconds(180)&&elapsed<std::chrono::seconds(2));
 assert(release(pending.ptr));
 std::puts("PASS first admission never blocks PE submission; explicit concurrency retry releases mutex, wakes on real CPU release and times out within its bounded deadline");
 // Timed retry always revalidates physical memory and owner identity.
 caller=(void*)0x20000;pending=acquire(100*MiB);assert(pending.ptr);caller=(void*)0x10000;
 WaitResult changed;std::thread changed_wait([&]{wait_entry(&changed);});await_waiter();sample(198*MiB);changed_wait.join();
 assert(changed.result.ret==3&&detail(changed.result,3)==1);
 caller=(void*)0x20000;assert(release(pending.ptr));caller=(void*)0x10000;sample(300*MiB);
 caller=(void*)0x20000;pending=acquire(100*MiB);assert(pending.ptr);caller=(void*)0x10000;
 WaitResult owner_exit;std::thread owner_wait([&]{wait_entry(&owner_exit);});await_waiter();owner_state(0,1,1,0,1);owner_wait.join();
 assert(owner_exit.result.ret==4);owner_state(0,1,0,0,1);
 caller=(void*)0x20000;assert(release(pending.ptr));caller=(void*)0x10000;
 // pthread cancellation must not strand the global budget mutex/waiter count.
 caller=(void*)0x20000;pending=acquire(100*MiB);assert(pending.ptr);caller=(void*)0x10000;
 pthread_t canceled;WaitResult canceled_result;assert(!pthread_create(&canceled,nullptr,wait_entry,&canceled_result));
 await_waiter();assert(!pthread_cancel(canceled));void*cancel_result=nullptr;assert(!pthread_join(canceled,&cancel_result));
 assert(cancel_result==PTHREAD_CANCELED&&!md_resource_growth_waiters);
 caller=(void*)0x20000;assert(release(pending.ptr));caller=(void*)0x10000;
 assert(!pthread_mutex_trylock(&md_resource_growth_mutex));pthread_mutex_unlock(&md_resource_growth_mutex);
 std::puts("PASS retry refreshes real physical pressure and owner state; canceled waiter releases native mutex and preserves all other creators' credits");
 // Exact receipt capacity is prospective too, not a permanent texture limit.
 sample(2048*MiB);std::vector<uint64_t>tokens;
 for(unsigned i=0;i<MD_RESOURCE_GROWTH_RECEIPTS;i++){auto a=acquire(1);assert(a.ptr);tokens.push_back(a.ptr);}
 assert(acquire(1).ret==3);
 std::thread slot_release([&]{caller=(void*)0x10000;await_waiter();assert(release(tokens.front()));});
 auto new_slot=acquire(1,1);slot_release.join();assert(new_slot.ptr);
 for(unsigned i=1;i<tokens.size();i++) { assert(release(tokens[i])); }
 assert(release(new_slot.ptr));
 const auto saved_next=md_resource_growth_next;md_resource_growth_next=0;assert(acquire(1).ret==4);md_resource_growth_next=saved_next;
 assert(acquire(UINT64_MAX).ret==3);assert(!md_resource_growth_held);
 fail_query=true;{dxmt::ResourceGrowthPermit p(16*MiB);assert(!p.known()&&!p.denied());}fail_query=false;
 {dxmt::ResourceGrowthPermit p(32*MiB);assert(p.known()&&!p.denied());dxmt::ResourceGrowthPermit q(static_cast<dxmt::ResourceGrowthPermit&&>(p));
  q=dxmt::ResourceGrowthPermit(64*MiB);assert(md_resource_growth_held==64*MiB);}
 assert(!md_resource_growth_held);
 auto own=acquire(64*MiB);caller=(void*)0x20000;assert(!release(own.ptr));caller=(void*)0x10000;assert(release(own.ptr)&&!release(own.ptr));
 std::puts("PASS finite receipt slots recover after actual creator release; overflow, unavailable measurements, C++ RAII/moves and foreign/duplicate releases preserve honest allocation behavior");
 // Preserve the actual server CPU-quiescence proof and generation reuse test.
 auto a=acquire(64*MiB);caller=(void*)0x20000;auto b=acquire(32*MiB);assert(b.ptr);caller=(void*)0x10000;
 madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==96*MiB);
 owner_state(0,1,1,0,1);madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==96*MiB);
 assert(acquire(1).ret==4);owner_state(0,0,1,0,1);madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==96*MiB);
 owner_state(0,0,1,1,1);fixture_finish_process_memory(caller);
 assert((cleanup==std::vector<int>{1,2,3,4,5,6,7,8,9}));assert(md_resource_growth_held==32*MiB);
 owner_state(0,1,0,0,1);assert(!release(a.ptr));caller=(void*)0x20000;assert(release(b.ptr));caller=(void*)0x10000;
 std::puts("PASS actual server cleanup returns only proven quiescent CPU credits before guest-window recycling");
 // Metadata pressure is a submit advisory while physical capacity remains
 // healthy. The128th tiny pending creation requests a genuine private flush;
 // only its eventual event completion makes those receipts reusable.
 sample(2048*MiB);events[0].value=0;
 for(unsigned i=1;i<=MD_RESOURCE_GROWTH_RECEIPTS/2;++i){
  auto p=acquire(1);assert(p.ptr&&p.ret==(i<MD_RESOURCE_GROWTH_RECEIPTS/2 ? 1u:2u));
  assert(handoff(p.ptr,0x51,UINT64_MAX).ret==1&&handoff(p.ptr,0x51,1).ret==1);
 }
 assert(md_resource_growth_held==MD_RESOURCE_GROWTH_RECEIPTS/2&&!md_resource_growth_pressure);
 events[0].value=1;auto after_submit=acquire(1);
 assert(after_submit.ptr&&after_submit.ret==1&&md_resource_growth_held==1&&release(after_submit.ptr));
 assert(event_loans.empty());
 std::puts("PASS healthy half-cap metadata advisory submits pending initialization; actual event completion restores receipt capacity without a byte-history quota");
 // Completed credits and their bounded registry loans retire atomically with
 // respect to slot reuse, despite actual event destruction occurring unlocked.
 // Pause a full256-entry close batch and race another owner/queue against it.
 sample(2048*MiB);events[0].value=0;
 for(unsigned i=0;i<MD_RESOURCE_GROWTH_RECEIPTS;++i){
  auto p=acquire(1);assert(p.ptr&&handoff(p.ptr,0x51,UINT64_MAX).ret==1&&handoff(p.ptr,0x51,1).ret==1);
 }
 assert(event_loans.size()==MD_RESOURCE_GROWTH_RECEIPTS&&md_resource_growth_held==MD_RESOURCE_GROWTH_RECEIPTS);
 pause_event_close=true;events[0].value=1;
 std::thread closing([&]{caller=(void*)0x10000;auto p=acquire(1);assert(p.ptr&&release(p.ptr));});
 auto close_deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
 while(!event_close_entered.load()){assert(std::chrono::steady_clock::now()<close_deadline);std::this_thread::yield();}
 caller=(void*)0x20000;auto during_close=acquire(1);
 assert(during_close.ret==3&&detail(during_close,3)==2&&md_resource_growth_held==MD_RESOURCE_GROWTH_RECEIPTS);
 std::thread second_queue([&]{
  caller=(void*)0x20000;auto p=acquire(1,1);assert(p.ptr);
  assert(handoff(p.ptr,0x52,UINT64_MAX).ret==1&&handoff(p.ptr,0x52,0).ret==1);
 });
 await_waiter();allow_event_close=true;closing.join();second_queue.join();pause_event_close=false;
 assert(!md_resource_growth_held&&event_loans.empty()&&!md_resource_growth_waiters);caller=(void*)0x10000;
 std::puts("PASS256-slot GPU-close race: another queue waits while loans close unlocked, then obtains a genuine event loan without transient false OOM");
 // Validated GPU intent precedes initialization. CPU release cannot undo it;
 // publication is single-shot and a forged event/owner cannot rewrite it.
 sample(600*MiB);a=acquire(64*MiB);assert(a.ptr);
 assert(handoff(a.ptr,0xdead,UINT64_MAX).ret==4&&md_resource_growth_held==64*MiB);
 assert(handoff(a.ptr,0x51,7).ret==4);assert(handoff(a.ptr,0x51,UINT64_MAX).ret==1);
 assert(!release(a.ptr)&&handoff(a.ptr,0x51,UINT64_MAX).ret==4);
 caller=(void*)0x20000;assert(handoff(a.ptr,0x51,7).ret==4);caller=(void*)0x10000;
 assert(handoff(a.ptr,0x52,7).ret==4);assert(handoff(a.ptr,0x51,7).ret==1);
 assert(handoff(a.ptr,0x51,6).ret==4&&!release(a.ptr));
 check_release_unlocked=true;events[0].value=7;
 auto after_gpu=acquire(1);assert(after_gpu.ptr&&md_resource_growth_held==1&&release(after_gpu.ptr));
 assert(event_loans.empty());
 // The C++ permit also keeps intent through destructor/exception paths and
 // transfers final GPU ownership only after a valid actual fence.
 events[0].value=0;
 {dxmt::ResourceGrowthPermit p(32*MiB);assert(p.beginGpuInitialization(0x51));assert(p.finishGpuInitialization(9));}
 assert(md_resource_growth_held==32*MiB);events[0].value=9;
 auto flush=acquire(1);assert(flush.ptr&&md_resource_growth_held==1&&release(flush.ptr));
 {dxmt::ResourceGrowthPermit p(32*MiB);assert(p.beginGpuInitialization(0x51));assert(p.finishGpuInitialization(0));}
 assert(!md_resource_growth_held&&event_loans.empty());
 std::puts("PASS native/actual C++ GPU intent protocol: forged/foreign events, duplicate publication and fence downgrade decline; only real completion or proven no-work ends credit");
 // A132MiB reservation includes100MiB destination plus32MiB NEW scratch.
 // CPU return is not completion. On GPU completion the actual100MiB resident
 // backing stays charged in the fresh OS reading; only prospective132MiB ends.
 sample(340*MiB);events[0].value=0;a=acquire(132*MiB);assert(a.ptr);
 assert(handoff(a.ptr,0x51,UINT64_MAX).ret==1&&handoff(a.ptr,0x51,11).ret==1);
 auto blocked=acquire(32*MiB);assert(blocked.ret==3&&detail(blocked,3)==2);
 std::thread gpu_signal([&]{await_waiter();sample(240*MiB);events[0].value=11;});
 auto ready_gpu=acquire(32*MiB,1);gpu_signal.join();
 assert(ready_gpu.ptr&&detail(ready_gpu,0)==5904*MiB&&detail(ready_gpu,1)==0);
 assert(md_resource_growth_held==32*MiB&&release(ready_gpu.ptr)&&event_loans.empty());
 // Completion never means the resident bytes themselves became free.
 sample(300*MiB);events[0].value=0;a=acquire(100*MiB);assert(a.ptr);
 assert(handoff(a.ptr,0x51,UINT64_MAX).ret==1&&handoff(a.ptr,0x51,12).ret==1);
 std::thread still_resident([&]{await_waiter();sample(200*MiB);events[0].value=12;});
 auto still_no_room=acquire(16*MiB,1);still_resident.join();assert(still_no_room.ret==3&&detail(still_no_room,3)==1);
 assert(!md_resource_growth_held&&event_loans.empty());
 sample(220*MiB);auto actually_freed=acquire(16*MiB);assert(actually_freed.ptr&&release(actually_freed.ptr));
 std::puts("PASS real GPU-event progress wakes bounded retry without CPU release; fresh resident footprint remains charged and only actual physical recovery permits new backing");
 // A canceled process can leave real GPU work. Native quiescence is not a GPU
 // fence, and a new generation must not clear its predecessor's GPU receipts.
 sample(600*MiB);events[0].value=0;a=acquire(64*MiB);assert(a.ptr);
 assert(handoff(a.ptr,0x51,UINT64_MAX).ret==1&&handoff(a.ptr,0x51,15).ret==1);
 owner_state(0,0,1,1,1);madeira_resource_growth_retire((void*)0x10000,1);assert(md_resource_growth_held==64*MiB);
 owner_state(0,1,0,0,3);assert(!release(a.ptr));madeira_resource_growth_retire((void*)0x10000,1);assert(md_resource_growth_held==64*MiB);
 caller=(void*)0x20000;auto other=acquire(1);assert(other.ptr&&md_resource_growth_held==64*MiB+1&&release(other.ptr));
 events[0].value=15;other=acquire(1);assert(other.ptr&&md_resource_growth_held==1&&release(other.ptr)&&event_loans.empty());
 caller=(void*)0x10000;
 // An unknown forced termination MID-initialization has no trustworthy final
 // fence. Retain that intent even if the event advances or the CPU owner dies.
 events[2].value=UINT64_MAX;a=acquire(64*MiB);assert(a.ptr&&handoff(a.ptr,0x61,UINT64_MAX).ret==1);
 owner_state(0,0,1,1,3);madeira_resource_growth_retire((void*)0x10000,3);
 caller=(void*)0x20000;other=acquire(1);assert(other.ptr&&md_resource_growth_held==64*MiB+1&&release(other.ptr));
 assert(md_resource_growth_held==64*MiB&&event_loans.size()==1);
 std::puts("PASS GPU debt survives CPU death/generation reuse until actual completion; interrupted intent without a fence remains conservatively owned");
 assert(queries>8&&acquire_calls>8&&release_calls>8&&event_reads>0&&event_releases>0);
 std::puts("PASS production fresh-live budget and native ownership/wait paths; controlled host measurements/events are not iPhone memory or rendering results");
}
'''
if args.run14_normal_only:
 code=code[:code.index('int main()')]+r'''
static unsigned pressure_observations;
extern "C" void fixture_pressure_observed(void *owner,unsigned long long lease,uint64_t f,uint64_t a,uint64_t n,uint64_t floor) {
 assert(owner==caller && lease==1 && f==footprint && a==available && n>0 && floor>0);
 assert(!pthread_mutex_trylock(&md_resource_growth_mutex));
 pthread_mutex_unlock(&md_resource_growth_mutex);
 ++pressure_observations;
}
int main() {
 struct Case {uint64_t footprint,available,charged,floor;};
 const Case cases[] = {
  {6238714392ull,203736552,2798672,201326592},
  {6238616088ull,203834856,2798672,201326592},
  {6229129752ull,213321192,16777472,201326592},
  {6232586776ull,209864168,33554688,201326592},
  {6253017624ull,189433320,2097408,201326592},
  {6262798872ull,179619304,2798672,201325568},
  {6264437272ull,177980904,2097408,201325568},
  {6265715224ull,176702952,2097408,201325568},
  // Run25 request 27487: BC6H cube-array destination + bounded upload.
  {6200490664ull,241960280,60879232,201326592},
 };
 for (const auto& c:cases) {
  footprint=c.footprint; available=c.available;
  const auto before=md_resource_growth_next;
  auto a=acquire(c.charged);
  assert(a.ret==3 && !a.ptr && a.len==c.available);
  assert(detail(a,0)==c.footprint && !detail(a,1));
  assert(detail(a,2)==c.floor && detail(a,3)==1);
  assert(!md_resource_growth_held && md_resource_growth_next==before);
 }
 assert(pressure_observations==sizeof(cases)/sizeof(cases[0])); // Observer runs after unlocking the real receipt mutex.
 sample(1024*MiB); auto a=acquire(2798672);
 assert(a.ptr && a.ret==1 && md_resource_growth_held==2798672);
 assert(release(a.ptr) && !md_resource_growth_held);
 // Read-only forecasting may exclude only this owner's CPU creation receipt.
 auto held=acquire(16*MiB);assert(held.ptr);
 auto snapshot=dxmt::resourceGrowthBudgetSnapshot();assert(snapshot.valid && snapshot.pending==16*MiB);
 auto own=dxmt::resourceGrowthBudgetSnapshot(held.ptr);assert(own.valid && own.pending==0 && own.floor==192*MiB);
 caller=(void*)0x20000;auto foreign=dxmt::resourceGrowthBudgetSnapshot(held.ptr);assert(foreign.valid && foreign.pending==16*MiB);
 caller=(void*)0x10000;assert(md_resource_growth_held==16*MiB && release(held.ptr));
 // Ordinary parallel creators, no injected native errors or inaccessible pages.
 std::vector<std::thread> workers;
 for(unsigned i=0;i<4;++i) workers.emplace_back([]{
  for(unsigned n=0;n<100;++n) {auto a=acquire(65536); assert(a.ptr); assert(release(a.ptr));}
 });
 for(auto& t:workers)t.join();
 assert(!md_resource_growth_held && !md_resource_growth_waiters);
 std::puts("PASS Run14/Run25 normal-only: actual native predicate reproduces all nine budget refusals; healthy admission/release and 400 parallel receipts remain balanced. Controlled measurements, no physical-memory savings asserted.");
}
'''

abi=(ROOT/'dxmt/src/winemetal/winemetal.h').read_text()
abi=abi[abi.index('struct madeira_ctl_args {'):abi.index('WINEMETAL_API void MadeiraCtl')]
with tempfile.TemporaryDirectory(prefix='madeira-growth-budget-') as directory:
 p=Path(directory)
 (p/'winemetal.h').write_text('#pragma once\n#include <stdint.h>\n'+abi+'\nvoid MadeiraCtl(struct madeira_ctl_args*);\n')
 (p/'mach').mkdir();(p/'mach/mach.h').write_text('''#pragma once
#include <stdint.h>
extern "C" {
typedef struct {uint64_t phys_footprint;} task_vm_info_data_t;
typedef unsigned mach_msg_type_number_t;
typedef int* task_info_t;
#define TASK_VM_INFO_COUNT 42
#define TASK_VM_INFO_REV1_COUNT 12
#define TASK_VM_INFO 22
#define KERN_SUCCESS 0
int mach_task_self(void);int task_info(int,int,task_info_t,mach_msg_type_number_t*);
}
''')
 (p/'os').mkdir();(p/'os/proc.h').write_text('#pragma once\n#include <stddef.h>\nextern "C" size_t os_proc_available_memory(void);\n')
 (p/'sys').mkdir();(p/'sys/sysctl.h').write_text('#pragma once\n#include <stddef.h>\nextern "C" int sysctlbyname(const char*,void*,size_t*,void*,size_t);\n')
 # The native producer and ntdll server are separate production translation
 # units. Preserve that boundary: server's optional weak callback cannot be
 # redeclared after its definition in one synthetic TU (strict Clang rejects
 # that and correctly knows the just-defined function is always non-null).
 server_code='''
extern "C" unsigned long long ios_thread_process_quiescent_lease(void*);
extern "C" void madeira_resource_growth_retire(void*,unsigned long long) __attribute__((weak));
void ios_startup_process_quiesced(void*);
void ios_fd_cache_release(void*);
void ios_subfloor_release_owner(void*);
void ios_jit_reclaim_process(void*);
void ios_fex_reclaim_process_views(void*);
void ios_cef_reclaim_process_images(void*);
void ios_wow_window_release(void*);
void ios_exe_win_mark_ready(void*);
int ios_wow_base_for_peb(void*);
int ios_thread_process_finalize_native(void*,unsigned long long);
void wine_log_write(const char*,...);
'''+retire+'\nextern "C" void fixture_finish_process_memory(void* owner) { ios_finish_process_memory(owner); }\n'
 src=p/'test.cpp';server_src=p/'server.cpp';binary=p/'test';src.write_text(code);server_src.write_text(server_code)
 extra_sources=[]
 if args.run14_normal_only:
  observer=p/'observer.cpp'
  observer.write_text('''#include <stdint.h>
extern "C" void fixture_pressure_observed(void*,unsigned long long,uint64_t,uint64_t,uint64_t,uint64_t);
extern "C" void madeira_pressure_boundary_request(void* o,unsigned long long l,uint64_t f,uint64_t a,uint64_t n,uint64_t s) {
 fixture_pressure_observed(o,l,f,a,n,s);
}
''')
  extra_sources=[str(observer)]
 for model in ([False] if args.run14_normal_only or sys.platform == 'darwin' else [False, True]):
  flags = ['-DMODEL_DARWIN_NONCANCEL_WAIT'] if model else []
  if args.run14_normal_only: flags += ['-Wno-unused-function', '-Wno-unused-variable']
  subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-O1','-Wall','-Wextra','-Werror','-pthread',
   '-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-sanitize-recover=all',*flags,
   '-I',str(p),'-I',str(ROOT/'build/dxmt-ios'),str(src),str(server_src),*extra_sources,'-o',str(binary)],check=True)
  subprocess.run([str(binary)],check=True,timeout=40)
  if model: print('PASS Darwin NOCANCEL relative-wait model: deferred cancellation executes real native cleanup with no stranded waiter or mutex')
