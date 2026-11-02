#!/usr/bin/env python3
"""Exercise staged pool/object failure contracts and first-use retirement."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
def fn(s,marker):
 a=s.index(marker);b=s.index('{',a);depth=1;i=b+1
 while depth:
  depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[a:i]
def run(code,d,name,includes=()):
 src=d/(name+'.cpp');src.write_text(code);exe=d/name
 compiler=os.environ.get('CXX','c++');version=subprocess.check_output([compiler,'--version'],text=True)
 flags=[] if 'clang' in version.lower() else ['-Wno-changes-meaning']
 subprocess.run([compiler,'-std=c++20','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-misleading-indentation',*flags,'-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',*['-I'+str(x) for x in includes],str(src),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
with tempfile.TemporaryDirectory() as t:
 d=Path(t);stage=d/'staged'
 subprocess.run(['python3',str(root/'tools/build/stage-fex-compat.py'),'stage',str(stage)],check=True)
 # Compile FEX's actual full pool/retirement implementation against a fake OS
 # allocator. Allocation ownership, iterators and reuse use production code.
 stub=d/'include';utils=stub/'FEXCore/Utils';utils.mkdir(parents=True)
 (stub/'FEXCore/fextl').mkdir(parents=True)
 (stub/'FEXCore/fextl/list.h').write_text(r'''
#include <list>
#include <memory>
inline bool fail_nodes;inline unsigned node_allocations;
template<class T>struct NodeAllocator{
 using value_type=T;NodeAllocator()=default;template<class U>NodeAllocator(const NodeAllocator<U>&){}
 T* allocate(size_t n){node_allocations++;if(fail_nodes)throw Fatal{};return std::allocator<T>{}.allocate(n);}
 void deallocate(T* p,size_t n){std::allocator<T>{}.deallocate(p,n);}
 template<class U>bool operator==(const NodeAllocator<U>&)const{return true;}
};
namespace fextl{template<class T>using list=std::list<T,NodeAllocator<T>>;}
''')
 (utils/'TypeDefines.h').write_text('#define FEX_DEFAULT_VISIBILITY\n')
 (utils/'MathUtils.h').write_text('#include <cstdint>\nnamespace FEXCore::Utils{constexpr size_t FEX_PAGE_SIZE=4096;template<class T> T AlignDown(T x,size_t a){return x&~(a-1);}}\n')
 (utils/'LogManager.h').write_text('#define LOGMAN_THROW_A_FMT(x,...) do{if(!(x))throw Fatal{};}while(0)\nnamespace LogMan::Msg {template<class...T>void EFmt(T...){}}\n')
 (utils/'Allocator.h').write_text(r'''
#pragma once
#include <cstdlib>
#include <cstdint>
#include <unordered_map>
#include <new>
struct Fatal{};
static int fail_map,fail_meta;static unsigned maps,frees,names,guards;static std::unordered_map<void*,size_t> backing;
namespace fextl{[[noreturn]]inline void ReportAllocationFailure(size_t,size_t){throw Fatal{};}}
namespace FEXCore::Allocator{
inline void* malloc(size_t n){return fail_meta?nullptr:std::malloc(n);}inline void free(void* p){std::free(p);}
inline void* aligned_alloc(size_t a,size_t n){return fail_meta?nullptr:std::aligned_alloc(a<sizeof(void*)?sizeof(void*):a,((n+sizeof(void*)-1)/sizeof(void*))*sizeof(void*));}
inline void aligned_free(void* p){std::free(p);}
inline void* VirtualAlloc(size_t n){maps++;if(fail_map==1)return nullptr;if(fail_map==2)return (void*)~uintptr_t{};void* p=std::calloc(1,n);backing[p]=n;return p;}
inline void VirtualFree(void* p,size_t n){assert(backing.at(p)==n);backing.erase(p);frees++;std::free(p);}
enum class ProtectOptions{None};inline bool VirtualProtect(void* p,size_t,ProtectOptions){assert(p);guards++;return true;}
inline void VirtualName(const char*,void* p,size_t){assert(p&&p!=(void*)~uintptr_t{});names++;}
struct FEXAllocOperators{static void operator delete(void* p){free(p);}};
}
''')
 pool_header=stage/'FEXCore/include/FEXCore/Utils/ThreadPoolAllocator.h'
 memory=(stage/'FEXCore/include/FEXCore/fextl/memory.h').read_text().replace('#include <FEXCore/fextl/allocator.h>','').replace('#pragma once','')
 code=r'''
#include <cassert>
#include <cstring>
#include <atomic>
#include <cstdio>
#include <vector>
#include <optional>
#include <thread>
#include <FEXCore/Utils/Allocator.h>
'''+'#include "'+str(pool_header)+'"\nnamespace fextl {template<class T>using FEXAlloc=std::allocator<T>;}\n'+memory+r'''
using namespace FEXCore::Utils;
struct Object{static inline unsigned created,destroyed;Object(){created++;}~Object(){destroyed++;}};
int main(){
 for(int failure=1;failure<=2;failure++){
  PooledAllocatorVirtual p("FEXMem_OpDispatcher");IntrusivePooledAllocator::BufferOwnedFlag flag{IntrusivePooledAllocator::ClientFlags::FLAG_FREE};
  fail_map=failure;unsigned before=names;
  assert(!p.TryClaimBuffer(16<<20,&flag));assert(flag==IntrusivePooledAllocator::ClientFlags::FLAG_FREE&&names==before&&backing.empty());
  bool fatal=false;try{p.ClaimBuffer(16<<20,&flag);}catch(const Fatal&){fatal=true;}assert(fatal);
 }
 fail_map=0;
 {PooledAllocatorVirtual p("FEXMem_Frontend");IntrusivePooledAllocator::BufferOwnedFlag flag{IntrusivePooledAllocator::ClientFlags::FLAG_FREE};
  fail_meta=1;unsigned before=frees;assert(!p.TryClaimBuffer(8<<20,&flag));assert(frees==before+1&&backing.empty());fail_meta=0;}
 {PooledAllocatorVirtualWithGuard p("FEXMem_CPUBackend");IntrusivePooledAllocator::BufferOwnedFlag flag{IntrusivePooledAllocator::ClientFlags::FLAG_FREE};
  fail_map=1;unsigned before=guards;assert(!p.TryClaimBuffer(0x4000,&flag));assert(guards==before&&backing.empty());fail_map=0;}
 {PooledAllocatorVirtual p("reuse"), frontend("frontend-reuse");unsigned before=maps;
  // Hundreds of inactive clients claim no VA; active clients relinquish the
  // same real allocation on termination, including repeated helper churn.
  std::vector<std::unique_ptr<PoolBufferWithTimedRetirement<uintptr_t,5000,500>>> inactive;
  for(unsigned i=0;i<400;i++){inactive.emplace_back(new PoolBufferWithTimedRetirement<uintptr_t,5000,500>(p,16<<20));inactive.emplace_back(new PoolBufferWithTimedRetirement<uintptr_t,5000,500>(frontend,8<<20));}assert(maps==before);
  uintptr_t first=0,first_front=0;
  for(unsigned i=0;i<160;i++){
   PoolBufferWithTimedRetirement<uintptr_t,5000,500> active(p,16<<20);auto a=active.TryReownOrClaimBufferWithSize();assert(a&&a->Ptr);
   if(!first)first=a->Ptr;assert(first==a->Ptr);active.UnclaimBuffer();
   PoolBufferWithTimedRetirement<uintptr_t,5000,500> front(frontend,8<<20);auto f=front.TryReownOrClaimBufferWithSize();assert(f&&f->Ptr);if(!first_front)first_front=f->Ptr;assert(first_front==f->Ptr);front.UnclaimBuffer();
  }
  assert(maps==before+2);inactive.clear();
 }
 {PooledAllocatorVirtual p("pressure");using Flag=IntrusivePooledAllocator::BufferOwnedFlag;using State=IntrusivePooledAllocator::ClientFlags;
  Flag old{State::FLAG_FREE},next{State::FLAG_FREE},third{State::FLAG_FREE};auto first=p.TryClaimBuffer(0x10000,&old);assert(first);
  uintptr_t address=(uintptr_t)(**first)->Ptr;unsigned before=maps;fail_map=1;
  // An OWNED buffer cannot be stolen, nor can a too-small disowned buffer.
  assert(!p.TryClaimBuffer(0x10000,&next)&&old==State::FLAG_OWNED);
  p.DisownBuffer(*first);assert(!p.TryClaimBuffer(0x20000,&next)&&old==State::FLAG_DISOWNED);
  // Recent disowned storage can be transferred after OS allocation fails,
  // without waiting five seconds or allocating a metadata/list node.
  fail_meta=1;auto stolen=p.TryClaimBuffer(0x10000,&next);assert(stolen&&*stolen==*first&&old==State::FLAG_FREE&&next==State::FLAG_OWNED);
  assert((uintptr_t)(**stolen)->Ptr==address&&!p.TryToReownBuffer(*first,0x10000,&old));
  assert(!p.TryClaimBuffer(0x10000,&third)); // new owner is protected
  p.UnclaimBuffer(*stolen,&next);fail_map=0;fail_meta=0;assert(maps==before+4);
 }
 {PooledAllocatorVirtual p("cas-race");using Flag=IntrusivePooledAllocator::BufferOwnedFlag;using State=IntrusivePooledAllocator::ClientFlags;
  for(unsigned i=0;i<100;i++){
   fail_map=0;Flag old{State::FLAG_FREE},next{State::FLAG_FREE};auto first=p.TryClaimBuffer(0x10000,&old);assert(first);p.DisownBuffer(*first);fail_map=1;
   std::atomic<bool> go{false};bool old_won=false;
   std::thread reclaim([&]{while(!go.load())std::this_thread::yield();old_won=bool(p.TryToReownBuffer(*first,0x10000,&old));});
   go=true;auto transferred=p.TryClaimBuffer(0x10000,&next);reclaim.join();assert(old_won!=bool(transferred));
   if(old_won){assert(old==State::FLAG_OWNED&&next==State::FLAG_FREE);p.UnclaimBuffer(*first,&old);}
   else {assert(old==State::FLAG_FREE&&next==State::FLAG_OWNED);p.UnclaimBuffer(*transferred,&next);}
  }fail_map=0;
 }
 {PooledAllocatorVirtual p("resize");PoolBufferWithTimedRetirement<uintptr_t,5000,500> a(p,0x10000);
  auto old=a.TryReownOrClaimBufferWithSize();assert(old);std::strcpy((char*)old->Ptr,"retained");
  fail_map=1;assert(!a.TryReownOrClaimBufferWithSize(0x20000));
  auto retained=a.TryReownOrClaimBufferWithSize();assert(retained&&retained->Ptr==old->Ptr&&retained->Size==old->Size&&!std::strcmp((char*)old->Ptr,"retained"));
  PoolBufferWithTimedRetirement<uintptr_t,5000,500> other(p,0x10000);assert(!other.TryReownOrClaimBufferWithSize()); // old remains owned
  fail_map=0;auto grown=a.TryReownOrClaimBufferWithSize(0x20000);assert(grown&&grown->Ptr!=old->Ptr&&grown->Size==0x20000);
  auto reused=other.TryReownOrClaimBufferWithSize();assert(reused&&reused->Ptr==old->Ptr);
 }
 {PooledAllocatorVirtual p("node-pressure");PoolBufferWithTimedRetirement<uintptr_t,5000,500> a(p,0x10000),b(p,0x20000);
  auto small=a.TryReownOrClaimBufferWithSize(),big=b.TryReownOrClaimBufferWithSize();assert(small&&big);
  unsigned nodes=node_allocations;fail_nodes=true;b.UnclaimBuffer(); // cleanup must allocate no node
  auto grown=a.TryReownOrClaimBufferWithSize(0x20000);assert(grown&&grown->Ptr==big->Ptr);
  auto small_reused=b.TryReownOrClaimBufferWithSize(0x10000);assert(small_reused&&small_reused->Ptr==small->Ptr);
  a.UnclaimBuffer();b.UnclaimBuffer();assert(node_allocations==nodes);fail_nodes=false;
 }
 assert(backing.empty());
 // A recoverable object allocator never constructs through NULL; the legacy
 // no-exceptions API keeps its explicit fatal contract.
 fail_meta=1;auto absent=fextl::try_make_unique<Object>();assert(!absent&&!Object::created);
 bool fatal=false;try{auto old=fextl::make_unique<Object>();}catch(const Fatal&){fatal=true;}assert(fatal&&!Object::created);
 fail_meta=0;{auto present=fextl::try_make_unique<Object>();assert(present&&Object::created==1);}assert(Object::destroyed==1);
 puts("PASS staged pool/object allocator: NULL/MAP_FAILED rejected before ownership, metadata rollback, no guard/null arithmetic, genuine legacy fatal retained, 400 inactive clients reserve nothing and 160 active lifetimes reuse one 16MB/8MB pair");
}
'''
 run(code,d,'pool',(stub,))
 # Execute the actual first-use preparer and actual self cleanup with two
 # different failed required pools. The OS termination stub verifies all locks
 # and resources have been released before it can retire the native thread.
 module=(stage/'Source/Windows/WOW64/Module.cpp').read_text()
 prep=fn(module,'static void MadeiraPrepareFirstDispatch()')
 cleanup=fn(module,'static void MadeiraRetireThread(')
 core=(stage/'FEXCore/Source/Interface/Core/Core.cpp').read_text()
 prepare=fn(core,'extern "C" const char* MadeiraFEXPrepareThread(')
 code=r'''
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <memory>
#define FEX_IOS_HOST 1
using DWORD=uint32_t;using NTSTATUS=int32_t;
static unsigned failure,entered,created,destroyed,callrets,frontends,gdts,unregistered,crt,raw_logs;
static std::mutex ThreadCreationMutex,jit;
struct FrontendThreadData{bool MadeiraPrepared{},IosSweepRegistered{true};FrontendThreadData(){frontends++;}~FrontendThreadData(){frontends--;}};
struct Segment{Segment(){gdts++;}~Segment(){gdts--;}};
namespace FEXCore::Core{
struct CPUState{static constexpr int SEGMENT_ARRAY_INDEX_GDT=0;Segment* segment_arrays[1]{};};
struct Frame{CPUState State;};
struct Required{bool TryReownOrClaimBuffer(){return failure!=1;}bool TryPrepareBuffer(){return failure!=2;}};
struct InternalThreadState{Frame* CurrentFrame;Required* CPUBackend,*LookupCache,*FrontendDecoder,*PassManager,*OpDispatcher;void* FrontendPtr;void* ThreadStats;};
}
using Thread=FEXCore::Core::InternalThreadState;
static Thread* current;
static std::unordered_map<DWORD,Thread*> Threads;
struct TLS{Thread*& ThreadState()const{return current;}Thread* ThreadStateIfInitialised()const{return current;}};
static TLS GetTLS(){return {};}
static DWORD GetCurrentThreadId(){return 0x388;}
static FrontendThreadData* GetFrontendThreadData(Thread* t){return static_cast<FrontendThreadData*>(t->FrontendPtr);}
static void IosSweepUnregisterThread(Thread*){unregistered++;}
struct Stats{void DeallocateSlot(void*){}};static Stats* StatAllocHandler=nullptr;
struct Context{void DestroyThread(Thread* t){assert(!current);delete t->CurrentFrame;delete t;destroyed++;}} context;
static Context* CTX=&context;
namespace FEX::Windows{
void DeinitCRTThread(){crt--;}
namespace CallRetStack{void DestroyThread(Thread*){callrets--;}}
}
static void IosRawReport(const char*,unsigned,const char* stage){assert(stage);raw_logs++;}
static void* GetCurrentThread(){return (void*)-2;}
struct Retired{NTSTATUS status;};
static NTSTATUS NtTerminateThread(void*,NTSTATUS status){
 assert(!current&&Threads.empty()&&!frontends&&!gdts&&!callrets&&!crt);
 assert(ThreadCreationMutex.try_lock());ThreadCreationMutex.unlock();assert(jit.try_lock());jit.unlock();throw Retired{status};
}
''' + prepare + '\n' + cleanup + '\n' + prep + r'''
static void init(){
 static FEXCore::Core::Required req;
 current=new Thread{new FEXCore::Core::Frame,&req,&req,&req,&req,&req,new FrontendThreadData,nullptr};
 current->CurrentFrame->State.segment_arrays[0]=new Segment[1];Threads[GetCurrentThreadId()]=current;
 callrets++;crt++;created++;
}
int main(){
 for(failure=1;failure<=2;failure++){
  init();bool retired=false;try{MadeiraPrepareFirstDispatch();entered++;}catch(const Retired& e){retired=true;assert(uint32_t(e.status)==0xc0000017u);}assert(retired&&!entered);
 }
 assert(created==destroyed&&unregistered==2&&raw_logs==2);
 for(unsigned i=0;i<40;i++){
  failure=1+i%2;init();bool retired=false;try{MadeiraPrepareFirstDispatch();entered++;}catch(const Retired& e){retired=true;assert(uint32_t(e.status)==0xc0000017u);}assert(retired&&!entered);
 }
 assert(created==destroyed&&unregistered==42&&raw_logs==32);
 failure=0;init();MadeiraPrepareFirstDispatch();assert(current&&GetFrontendThreadData(current)->MadeiraPrepared);entered++;
 failure=1;MadeiraPrepareFirstDispatch();assert(current&&entered==1); // subsequent simulation is unchanged, no repeated preclaim
 MadeiraRetireThread(GetTLS(),GetCurrentThreadId(),true);assert(created==destroyed&&!frontends&&!gdts&&!callrets&&!crt);
 assert(ThreadCreationMutex.try_lock());ThreadCreationMutex.unlock();
 puts("PASS actual first-dispatch failure: both required buffers checked before execution, published thread/TEB pointer cleared, registry/GDT/frontend/callret/sweep/CRT cleaned, no JIT/create lock held at Native retirement, success and re-entry preserved");
}
'''
 run(code,d,'first-use')
 # Production CreateThread + InitializeCompiler + CPU factory, with allocator
 # fault injection at every top-level startup object. Component methods are
 # stubs; the allocation/rollback/control flow being tested is production code.
 corefn=fn(core,'static bool MadeiraCompilerInitFailed(')+'\n'+fn(core,'bool ContextImpl::InitializeCompiler(')
 create=fn(core,'ContextImpl::CreateThread(')
 create='FEXCore::Core::InternalThreadState*\n'+create
 destroy=fn(core,'void ContextImpl::DestroyThread(')
 factory=fn((stage/'FEXCore/Source/Interface/Core/JIT/JIT.cpp').read_text(),'fextl::unique_ptr<CPUBackend> CreateArm64JITCore(')
 code=r'''
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <new>
static unsigned fail_at,allocations,alive,state_destroyed;static bool fail_l1;
static std::unordered_map<void*,size_t> objects;
namespace FEXCore::Allocator {
inline void* aligned_alloc(size_t a,size_t n){if(++allocations==fail_at)return nullptr;void* p=nullptr;assert(!posix_memalign(&p,a<sizeof(void*)?sizeof(void*):a,n));objects[p]=n;return p;}
inline void aligned_free(void* p){if(p){assert(objects.erase(p)==1);std::free(p);}}
inline void VirtualName(const char*,const void*,size_t){}
enum class ProtectOptions{Read=1,Write=2};inline ProtectOptions operator|(ProtectOptions a,ProtectOptions b){return ProtectOptions(int(a)|int(b));}
inline bool VirtualProtect(void*,size_t,ProtectOptions){return true;}
struct FEXAllocOperators{static void operator delete(void* p){aligned_free(p);}};
}
namespace fextl {template<class T>using FEXAlloc=std::allocator<T>;[[noreturn]]void ReportAllocationFailure(size_t,size_t){assert(false);std::abort();}}
namespace LogMan::Msg{template<class...T>void EFmt(T...){}}
''' + memory + r'''
namespace FEXCore {namespace Core{struct InternalThreadState;}namespace Context{struct ContextImpl;}}
struct Tracked{Tracked(){alive++;}virtual ~Tracked(){alive--;}};
namespace FEXCore::IR{
struct OpDispatchBuilder:Tracked {OpDispatchBuilder(FEXCore::Context::ContextImpl*,FEXCore::Core::InternalThreadState*){}void SetMultiblock(bool){}};
struct PassManager:Tracked {void AddDefaultPasses(void*){}void AddDefaultValidationPasses(){}void RegisterSyscallHandler(void*){}void InsertRegisterAllocationPass(void*){}void Finalize(){}};
}
namespace FEXCore{
struct LookupCache:Tracked{LookupCache(Context::ContextImpl*){}uintptr_t GetL1Pointer(){return fail_l1?0:0x1234;}uintptr_t GetScaledL1PointerMask(){return 0xffff;}uintptr_t GetPagePointer(){return 0;}};
namespace Frontend{struct Decoder:Tracked{Decoder(Core::InternalThreadState*){}};}
namespace CPU{struct CPUBackend:Tracked{};struct Arm64JITCore:CPUBackend{Arm64JITCore(Context::ContextImpl*,Core::InternalThreadState*){}};}
namespace Core {
struct Counter{void Store(unsigned){}};
struct CPUState{uint64_t rip{},gregs[16]{},L1Pointer{},L1Mask{};Counter DeferredSignalRefCount;};
struct Frame{CPUState State;struct{uint64_t L2Pointer{};}Pointers;InternalThreadState* Thread{};};
struct JITSymbolBuffer{};
struct InternalThreadState:Allocator::FEXAllocOperators{
 Frame* const CurrentFrame=&BaseFrame;Context::ContextImpl* const CTX;
 fextl::unique_ptr<IR::OpDispatchBuilder> OpDispatcher {};
 fextl::unique_ptr<LookupCache> LookupCache {};
 fextl::unique_ptr<Frontend::Decoder> FrontendDecoder {};
 fextl::unique_ptr<IR::PassManager> PassManager {};
 fextl::unique_ptr<CPU::CPUBackend> CPUBackend {};
 fextl::unique_ptr<JITSymbolBuffer> SymbolBuffer {};
 uint8_t InterruptFaultPage{};Frame BaseFrame{};
 ~InternalThreadState(){state_destroyed++;}
};}
namespace X86State{constexpr unsigned REG_RSP=4;}
namespace JITSymbols{inline fextl::unique_ptr<Core::JITSymbolBuffer> AllocateBuffer(){return {};}}
namespace CPU{
''' + factory + r'''
}
namespace Context {
struct ContextImpl{
 struct {bool Multiblock{};bool BlockJITNaming(){return false;}bool GlobalJITNaming(){return false;}bool LibraryJITNaming(){return false;}}Config;
 struct Dispatch{void InitThreadPointers(Core::InternalThreadState*){}} dispatcher;Dispatch* Dispatcher=&dispatcher;void* SyscallHandler{};
 bool InitializeCompiler(Core::InternalThreadState*);
 Core::InternalThreadState* CreateThread(uint64_t,uint64_t,const Core::CPUState*);
 void DestroyThread(Core::InternalThreadState*);
};
''' + corefn + '\n' + create + '\n' + destroy + r'''
}}
int main(){FEXCore::Context::ContextImpl c;
 for(fail_at=1;fail_at<=6;fail_at++){
  allocations=0;auto* t=c.CreateThread(0x400000,0x123450,nullptr);assert(!t&&!alive&&objects.empty());
 }
 fail_at=0;allocations=0;fail_l1=true;assert(!c.CreateThread(0x400000,0x123450,nullptr)&&!alive&&objects.empty());fail_l1=false;
 allocations=0;auto* t=c.CreateThread(0x400000,0x123450,nullptr);assert(t&&alive==5&&allocations==6);
 assert(t->CurrentFrame->State.rip==0x400000&&t->CurrentFrame->State.gregs[4]==0x123450);c.DestroyThread(t);assert(!alive&&objects.empty());
 puts("PASS actual staged CreateThread: ThreadState/OpDispatcher/LookupCache/Decoder/PassManager/CPUBackend and invalid L1 reject with complete partial cleanup; successful complete state preserved");}
'''
 run(code,d,'core-init')
 lookup_source=(stage/'FEXCore/Source/Interface/Core/LookupCache.cpp').read_text()
 a=lookup_source.index('LookupCache::LookupCache(');ctor=lookup_source[a:lookup_source.index('LookupCache::~LookupCache()',a)];dtor=fn(lookup_source,'LookupCache::~LookupCache()')
 code=r'''
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <atomic>
#define FEX_IOS_HOST 1
static bool disable_l2=true;static int map_result;static unsigned names,scrubs,marked,unmarked,freed;
static std::atomic<uint64_t> LookupCacheLive{},LookupCacheCumulative{},LookupCacheBytesLive{};
namespace LogMan::Msg{template<class...T>void EFmt(T...){}}
namespace FEXCore{
namespace Utils{constexpr size_t FEX_PAGE_SIZE=4096;}
namespace Allocator{
void* VirtualAlloc(size_t n,bool,bool){if(map_result==1)return nullptr;if(map_result==2)return (void*)~uintptr_t{};return std::calloc(1,n);}
void VirtualFree(void* p,size_t){assert(p&&p!=(void*)~uintptr_t{});freed++;std::free(p);}
enum class THPControl{Disable};void VirtualTHPControl(const void* p,size_t,THPControl){assert(p&&p!=(void*)~uintptr_t{});}
void VirtualName(const char*,void* p,size_t){assert(p);names++;}
size_t ZeroScrub(void* p,size_t){assert(p);scrubs++;return 0;}
}
namespace Context{struct ContextImpl{struct{uint64_t VirtualMemSize=0x1000000;}Config;
 struct Sys{void MarkOvercommitRange(uint64_t p,size_t){assert(p);marked++;}void UnmarkOvercommitRange(uint64_t p,size_t){assert(p);unmarked++;}} sys;Sys* SyscallHandler=&sys;};}
struct LookupCache{
 Context::ContextImpl* ctx;bool L2Enabled;uintptr_t AllocationBase{},L1Pointer{},PagePointer{},PageMemory{},L1PointerMask{},VirtualMemSize{};
 size_t TotalCacheSize{},AllocationSize{};
 static constexpr size_t MAX_L1_SIZE=0x10000,CODE_SIZE=0x4000,MIN_L1_ENTRIES=1024,MAX_L1_ENTRIES=4096;
 bool DisableL2Cache(){return disable_l2;}bool DynamicL1Cache(){return false;}
 LookupCache(Context::ContextImpl*);~LookupCache();
};
''' + ctor + '\n' + dtor + r'''
}
int main(){FEXCore::Context::ContextImpl c;
 for(int mode=0;mode<2;mode++){disable_l2=mode;
  for(map_result=1;map_result<=2;map_result++){
   unsigned n=names,s=scrubs,m=marked,u=unmarked,f=freed;
   {FEXCore::LookupCache cache(&c);assert(!cache.L1Pointer);}
   assert(names==n&&scrubs==s&&marked==m&&unmarked==u&&freed==f&&!LookupCacheLive&&!LookupCacheBytesLive);
  }
  map_result=0;{FEXCore::LookupCache cache(&c);assert(cache.L1Pointer&&LookupCacheLive==1&&LookupCacheBytesLive==cache.AllocationSize);}
  assert(!LookupCacheLive&&!LookupCacheBytesLive&&marked==unmarked);
 }
 puts("PASS actual LookupCache constructor/destructor: NULL/MAP_FAILED both L1-only/full layouts avoid naming, overcommit, scrubbing, invalid frees and census underflow; successful ownership balanced");
}
'''
 run(code,d,'lookup-null')
