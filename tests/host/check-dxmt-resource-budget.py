#!/usr/bin/env python3
"""Run actual shared-native growth receipts and C++ lifetime guards.

Native footprint values are controlled host inputs, not an iPhone measurement.
Real pthreads and Wine's actual generation/quiescence predicates exercise
parallel admission, foreign release and interrupted-creator retirement.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]

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
#include <thread>
#include <vector>
#include "winemetal.h"
#include "memory_pressure.hpp"
#include "memory_pressure_native.h"
static constexpr uint64_t MiB=uint64_t{1}<<20;
static std::atomic<uint64_t> footprint{4096*MiB}, available{2048*MiB};
static std::atomic<bool> fail_query{false};
static std::atomic<unsigned> queries{0}, acquire_calls{0}, release_calls{0};
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
void MadeiraCtl(madeira_ctl_args*args){
 assert(args->ret==0);
 if(args->op==40) md_memory_pressure_query(args);
 else if(args->op==41){++acquire_calls;md_resource_growth_acquire(args);}
 else if(args->op==42){++release_calls;md_resource_growth_release(args);}
 else std::abort();
}
static void sample(uint64_t remaining){available=remaining;footprint=6144*MiB-remaining;}
static madeira_ctl_args acquire(uint64_t n){
 madeira_ctl_args a={41,0,n,0,{0}};errno=72;MadeiraCtl(&a);assert(errno==72);return a;
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
int main(){
 caller=(void*)0x10000;sample(1244*MiB);
 // All eight streamers see the same real measurement but cannot collectively
 // spend the reserve. No metadata-only read is treated as a byte allocation.
 std::atomic<unsigned> ready{0}, granted{0};std::atomic<bool> go{false}, done{false};
 std::vector<std::thread> workers;
 for(unsigned i=0;i<8;i++)workers.emplace_back([&]{
  caller=(void*)0x10000;ready++;while(!go.load())std::this_thread::yield();
  auto a=acquire(128*MiB);if(a.ret==1||a.ret==2)++granted;
  ready++;while(!done.load())std::this_thread::yield();
  if(a.ptr)assert(release(a.ptr));
 });
 while(ready<8) { std::this_thread::yield(); }
 go=true;
 while(ready<16) { std::this_thread::yield(); }
 assert(granted==6);assert(md_resource_growth_held==768*MiB);
 done=true;for(auto&t:workers)t.join();assert(!md_resource_growth_held);
 std::puts("PASS 8 concurrent creators:6x128MiB admitted within1244MiB headroom/384MiB floor;2 honest denials;all receipts released");
 for(uint64_t mb:{5760,5875,6046,6135,6144}){
  sample((6144-mb)*MiB);auto a=acquire(4*MiB);assert(a.ret==3&&!a.ptr);
 }
 sample((6144-5376)*MiB);auto early=acquire(4*MiB);assert(early.ret==2);assert(release(early.ptr));
 sample((6144-5755)*MiB);early=acquire(4*MiB);assert(early.ret==2);assert(release(early.ptr));
 assert(!md_resource_growth_held);
 std::puts("PASS observed near-limit footprint replay: fresh measured pressure denies growth rather than consuming the physical reserve");
 sample(800*MiB);md_resource_growth_pressure=0;
 auto a=acquire(16*MiB);assert(a.ret==1);auto b=acquire(512*MiB);assert(b.ret==3);assert(release(a.ptr));
 a=acquire(4*MiB);assert(a.ret==2);assert(release(a.ptr));sample(1000*MiB);
 a=acquire(4*MiB);assert(a.ret==1);assert(release(a.ptr));
 a=acquire(500*MiB);assert(a.ret==2);assert(release(a.ptr));
 sample(2048*MiB);fail_query=true;{dxmt::ResourceGrowthPermit p(16*MiB);assert(!p.known()&&!p.denied());}
 fail_query=false;
 std::puts("PASS separated pressure/recovery watermarks and explicit unavailable measurement without invented credit");
 {
  dxmt::ResourceGrowthPermit p(32*MiB);assert(p.known()&&!p.denied());
  assert(md_resource_growth_held==32*MiB);dxmt::ResourceGrowthPermit q(static_cast<dxmt::ResourceGrowthPermit&&>(p));
  assert(md_resource_growth_held==32*MiB);
  q=dxmt::ResourceGrowthPermit(64*MiB);assert(md_resource_growth_held==64*MiB);
 }
 assert(!md_resource_growth_held);
 std::puts("PASS actual C++ permit scope/move/assignment release; constructor failure paths do not retain credit");
 a=acquire(64*MiB);caller=(void*)0x20000;assert(!release(a.ptr));assert(md_resource_growth_held==64*MiB);
 caller=(void*)0x10000;assert(release(a.ptr));assert(!release(a.ptr));
 std::vector<uint64_t> tokens;
 for(unsigned i=0;i<MD_RESOURCE_GROWTH_RECEIPTS;i++){auto r=acquire(1);assert(r.ret==1||r.ret==2);tokens.push_back(r.ptr);}
 assert(acquire(1).ret==4);for(auto token:tokens)assert(release(token));
 assert(!md_resource_growth_held);assert(acquire(UINT64_MAX).ret==3);
 std::puts("PASS finite receipt table, overflow and duplicate/foreign-token refusal without underflow");
 // An interrupted creator cannot unwind its C++ object. The actual native
 // reaper must retain its credit until Wine's existing complete CPU proof.
 a=acquire(64*MiB);caller=(void*)0x20000;b=acquire(32*MiB);assert(b.ptr);caller=(void*)0x10000;
 madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==96*MiB);
 owner_state(0,1,1,0,1);madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==96*MiB);
 assert(acquire(1).ret==4);owner_state(0,0,1,0,1);
 madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==96*MiB);
 owner_state(0,0,1,1,1);fixture_finish_process_memory(caller);
 assert((cleanup==std::vector<int>{1,2,3,4,5,6,7,8,9}));assert(md_resource_growth_held==32*MiB);
 owner_state(0,1,0,0,3);auto c=acquire(16*MiB);assert(c.ptr);assert(!release(a.ptr));
 madeira_resource_growth_retire(caller,1);assert(md_resource_growth_held==48*MiB);
 assert(release(c.ptr));caller=(void*)0x20000;assert(release(b.ptr));assert(!md_resource_growth_held);
 std::puts("PASS canceled creator credit reaped only by actual Wine quiescent generation; live/foreign/reused-owner credit preserved; no GPU/VM resource freed");
 assert(queries>8&&acquire_calls>8&&release_calls>8);
 std::puts("PASS production physical growth admission/RAII/native retirement; host policy tests, not iPhone physical-memory or gameplay results");
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
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-O1','-Wall','-Wextra','-Werror','-pthread',
  '-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-sanitize-recover=all',
  '-I',str(p),'-I',str(ROOT/'build/dxmt-ios'),str(src),str(server_src),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True,timeout=40)
