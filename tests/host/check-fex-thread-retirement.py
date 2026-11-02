#!/usr/bin/env python3
"""Execute staged own-thread FEX destruction under a bounded eight-GiB VA model."""
from pathlib import Path
import os,re,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
def body(s,mark):
 a=s.index(mark);b=s.index('{',a);n=0
 for t in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]',s[b:],re.S):
  if t[0]=='{':n+=1
  elif t[0]=='}':
   n-=1
   if not n:return s[a:b+t.end()]
 raise AssertionError(mark)
with tempfile.TemporaryDirectory() as folder:
 d=Path(folder);stage=d/'stage'
 subprocess.run(['python3',str(root/'tools/build/stage-fex-compat.py'),'stage',str(stage)],check=True)
 module=(stage/'Source/Windows/WOW64/Module.cpp').read_text()
 retire=body(module,'static bool MadeiraRetireThread(')
 callback=body(module,'extern "C" __declspec(dllexport) uint32_t MadeiraBTCpuIosRetireThread(')
 callret=body((root/'FEX/Source/Windows/Common/CallRetStack.h').read_text(),'void DestroyThread(')
 crt=body((root/'FEX/Source/Windows/Common/CRT/CRT_iOS.cpp').read_text(),'void DeinitCRTThread()')
 code=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <atomic>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <thread>
#include "fex_hold_release_abi.h"
#define FEX_IOS_HOST 1
#define __declspec(x)
using DWORD=uint32_t;
struct Allocation{uint64_t at,size,owner,lease;unsigned category;};
static std::vector<Allocation> views;static std::mutex vm;
static constexpr uint64_t capacity=8ull<<30;
static uint64_t reserve(uint64_t size,uint64_t owner,uint64_t lease,unsigned category,uint64_t alignment=0x10000){
 std::lock_guard guard(vm);std::sort(views.begin(),views.end(),[](auto a,auto b){return a.at<b.at;});
 uint64_t at=alignment;for(auto v:views){at=(at+alignment-1)&~(alignment-1);if(at+size<=v.at)break;at=v.at+v.size;}at=(at+alignment-1)&~(alignment-1);
 assert(at+size<=capacity);views.push_back({at,size,owner,lease,category});return at;
}
static void release(uint64_t at){std::lock_guard guard(vm);auto i=std::find_if(views.begin(),views.end(),[&](auto v){return v.at==at;});assert(i!=views.end());views.erase(i);}
static unsigned count(uint64_t owner,unsigned category){std::lock_guard guard(vm);return std::count_if(views.begin(),views.end(),[&](auto v){return v.owner==owner&&v.category==category;});}
static void reap(uint64_t owner,uint64_t lease,bool quiet){assert(quiet);std::lock_guard guard(vm);std::erase_if(views,[&](auto v){return v.owner==owner&&v.lease==lease;});}
static unsigned frontends,gdts,unregistered,finalized;
struct Frontend{bool IosSweepRegistered=true,InLockedRWXRead=false;Frontend(){frontends++;}~Frontend(){frontends--;}};
struct Gdt{Gdt(){gdts++;}~Gdt(){gdts--;}};
namespace FEXCore::Core {struct CPUState{static constexpr unsigned SEGMENT_ARRAY_INDEX_GDT=0;Gdt* segment_arrays[1];};}
struct Frame{FEXCore::Core::CPUState State;};
struct Context;
struct Thread{
 Context* CTX;Frame frame;Frame* CurrentFrame=&frame;void* FrontendPtr;void* ThreadStats=nullptr;
 uint64_t callret,lookup,dispatcher;std::shared_ptr<unsigned> shared;
 ~Thread(){release(lookup);} // context compiler pools can remain reusable
};
namespace FEXCore::Core {using InternalThreadState=::Thread;}
struct TEB{void* Peb;Thread* state;char bytes[0x2000-16];};using __TEB=TEB;
static thread_local TEB* current;
static thread_local DWORD tid;
static TEB* CurrentTEB(){return current;}
static DWORD GetCurrentThreadId(){return tid;}
struct TLS{TEB* teb;Thread*& ThreadState()const{return teb->state;}Thread* ThreadStateIfInitialised()const{return teb->state;}};
static std::mutex ThreadCreationMutex;
static std::unordered_map<DWORD,Thread*> Threads;
struct Stats{void DeallocateSlot(void*){}};static Stats* StatAllocHandler=nullptr;
static Frontend* GetFrontendThreadData(Thread* t){return (Frontend*)t->FrontendPtr;}
static void IosSweepUnregisterThread(Thread*){unregistered++;}
struct Context{void DestroyThread(Thread* t){assert(!current->state);delete t;}};
static std::unique_ptr<Context> CTX=std::make_unique<Context>();
static void* MadeiraContextOwnerPEB=(void*)0x500310000ull;
static uint32_t MadeiraBTCpuIosReleaseThreadHolds(void*,uint64_t*,uint32_t*,uint32_t*){return 0;}
template<class... T>static void IosRawReport(const char*,T...){}
static void rpmalloc_thread_finalize(){finalized++;} // queues heap; does NOT unmap its spans
namespace FEX::Windows {
''' +crt+r'''
namespace CallRetStack {
struct Info{uint64_t AllocationBase;};
static Info GetInfoThread(Thread* t){return {t->callret};}
static constexpr unsigned MEM_RELEASE=0x8000;
}
}
static int VirtualFree(void* p,unsigned,unsigned){release((uintptr_t)p);return 1;}
namespace FEX::Windows::CallRetStack {
''' +callret+r'''
}
''' +retire+'\n'+callback+r'''
static void create(TEB& teb,unsigned id,uint64_t owner,uint64_t lease,std::shared_ptr<unsigned> shared){
 current=&teb;tid=id;teb.Peb=(void*)owner;
 auto* t=new Thread;t->CTX=CTX.get();t->FrontendPtr=new Frontend;t->frame.State.segment_arrays[0]=new Gdt[32];t->shared=shared;
 t->callret=reserve(0x802000,owner,lease,1);t->lookup=reserve(0x200000,owner,lease,2);t->dispatcher=reserve(0x1000000,owner,lease,3);
 // Deliberately retained rpmalloc span; may contain shared allocations.
 reserve(0x1000000,owner,lease,4,0x1000000);
 teb.state=t;Threads.emplace(id,t);
}
static void terminate(TEB& t,unsigned id){current=&t;tid=id;uint64_t state;uint32_t depth,flags;
 assert(MadeiraBTCpuIosRetireThread(&t,&state,&depth,&flags)==MADEIRA_FEX_THREAD_RETIRED&&state&&!t.state);
 assert(!MadeiraBTCpuIosRetireThread(&t,&state,&depth,&flags));
}
int main(){
 constexpr uint64_t owner=0x500310000,lease=5,parent=0x47ffd0000;
 reserve(2ull<<30,parent,1,4,0x1000000);
 auto shared=std::make_shared<unsigned>(0xc001cafe);
 std::vector<TEB> workers(64);
 for(unsigned i=0;i<64;i++)create(workers[i],i+1,owner,lease,shared);
 assert(count(owner,1)==64&&count(owner,2)==64);
 // Cross-thread/foreign notifications must leave a still-running victim intact.
 current=&workers[0];tid=1;assert(MadeiraBTCpuIosRetireThread(&workers[1],nullptr,nullptr,nullptr)==32);
 assert(count(owner,1)==64);
 // The native terminal callback, NOT the peer termination request, destroys53.
 for(unsigned i=0;i<53;i++)terminate(workers[i],i+1);
 assert(count(owner,1)==11&&count(owner,2)==11&&Threads.size()==11);
 assert(count(owner,3)==64&&count(owner,4)==64&&*shared==0xc001cafe&&shared.use_count()==12);
 // An abandoned/private mutex is explicitly refused, never blindly unlocked.
 current=&workers[53];tid=54;ThreadCreationMutex.lock();
 assert(MadeiraBTCpuIosRetireThread(current,nullptr,nullptr,nullptr)==MADEIRA_FEX_THREAD_RETIRE_BUSY&&current->state);
 ThreadCreationMutex.unlock();
 *(uint64_t*)((char*)current+0x16e8)=0x1234;
 assert(MadeiraBTCpuIosRetireThread(current,nullptr,nullptr,nullptr)==MADEIRA_FEX_THREAD_RETIRE_REFUSED&&current->state);
 *(uint64_t*)((char*)current+0x16e8)=0;
 for(unsigned i=53;i<64;i++)terminate(workers[i],i+1);
 assert(Threads.empty()&&!count(owner,1)&&!count(owner,2)&&!frontends&&!gdts&&unregistered==64);
 assert(*shared==0xc001cafe&&shared.use_count()==1); // queued heaps/shared payload never prematurely freed
 // Wrong lease cannot reclaim old or newer process allocations at a reused PEB.
 reserve(0x1000000,owner,6,4);reap(owner,lease,true);assert(count(owner,4)==1);
 reap(owner,6,true);assert(views.size()==1&&views[0].owner==parent);
 // Chromium-like failed browser/successor cycles in the same8GiB bound.
 for(unsigned cycle=0;cycle<25;cycle++){
  uint64_t generation=10+cycle;std::vector<TEB> next(64);
  for(unsigned i=0;i<64;i++)create(next[i],i+1,owner,generation,shared);
  for(unsigned i=0;i<64;i++)terminate(next[i],i+1);
  reap(owner,generation,true);
  std::vector<uint64_t> successor;
  for(unsigned i=0;i<128;i++)successor.push_back(reserve(0x1000000,0x700310000,100+cycle,3,0x1000000));
  for(auto p:successor)release(p);
  assert(views.size()==1&&views[0].owner==parent&&Threads.empty()&&!frontends&&!gdts&&*shared==0xc001cafe);
 }
 puts("PASS actual staged retirement/CallRet destructor/CRT:64->11->0 private stacks/caches,foreign/busy/held refusals,shared payload alive,lease-safe process reap,25 successors repeatedly allocate128x16MiB within8GiB");
}
'''
 p=d/'check.cpp';p.write_text(code);exe=d/'check'
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-pthread','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(root/'build/ntdll-unix'),str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
