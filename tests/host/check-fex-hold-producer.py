#!/usr/bin/env python3
"""Run staged WoW own-thread retirement against the actual mutex implementation."""
from pathlib import Path
import os, re, subprocess, tempfile

root=Path(__file__).resolve().parents[2]
def body(source,signature):
    a=source.index(signature); b=source.index('{',a); depth=0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',source[b:],re.S):
        if token.group()=='{':depth+=1
        elif token.group()=='}':
            depth-=1
            if not depth:return source[a:b+token.end()]
    raise AssertionError(signature)

with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);stage=d/'staged'
    subprocess.run(['python3',str(root/'tools/build/stage-fex-compat.py'),'stage',str(stage)],check=True)
    module=(stage/'Source/Windows/WOW64/Module.cpp').read_text()
    allocator=(stage/'FEXCore/Source/Utils/Allocator.cpp').read_text()
    wpm=(stage/'FEXCore/include/FEXCore/Utils/WritePriorityMutex.h').read_text()
    old=(root/'FEX/FEXCore/include/FEXCore/Utils/WritePriorityMutex.h').read_text()
    callback=body(module,'extern "C" __declspec(dllexport) uint32_t MadeiraBTCpuIosReleaseThreadHolds(').replace('__declspec(dllexport)','')
    own=body(module,'static void MadeiraReleaseOwnThreadHolds(')
    fatal=body(module,'extern "C" void MadeiraFEXReleaseCurrentThreadHoldsForFatalAllocation(')
    registration=body(module,'static void MadeiraRegisterOwnHoldRelease(')
    report=body(allocator,'[[noreturn]] void ReportAllocationFailure(')
    term=body(module,'void BTCpuThreadTerm(')
    assert term.index('MadeiraReleaseOwnThreadHolds("thread-term")')<term.index('MadeiraRetireThread(')
    assert report.index('MadeiraFEXReleaseCurrentThreadHoldsForFatalAllocation()')<report.index('FEX_TRAP_EXECUTION')
    process=body(module,'void BTCpuProcessInit()')
    assert process.index('CTX = FEXCore::Context::Context::CreateNewContext')<process.index('MadeiraRegisterOwnHoldRelease()')<process.index('CTX->InitCore()')
    cmake=(stage/'Source/Windows/WOW64/CMakeLists.txt').read_text()
    assert 'target_include_directories(wow64fex PRIVATE "${CMAKE_SOURCE_DIR}/../build/ntdll-unix")' in cmake
    # Replace only the architecture-specific register read on this x86 host.
    # Actual lock/unlock, stamp/depth updates, atomics and wake operations run.
    def portable(header,namespace):
        header=header.replace('#pragma once','').replace('#include <FEXCore/Utils/LogManager.h>','').replace('#include <FEXCore/Utils/SpinWaitLock.h>','')
        actual=body(header,'  static uint64_t IosSelfTeb()')
        header=header.replace(actual,'  static uint64_t IosSelfTeb() { return TestCurrentTEB(); }')
        return header.replace('namespace FEXCore::Utils::WritePriorityMutex {','namespace FEXCore::Utils::'+namespace+' {')
    code=r'''
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <memory>
#include <shared_mutex>
#include "fex_hold_release_abi.h"
struct Terminal{};static unsigned traps,raw_reports;
#define LOGMAN_THROW_A_FMT(x,...) do{assert(x);}while(0)
#define FEX_TRAP_EXECUTION do{traps++;throw Terminal{};}while(0)
namespace LogMan::Msg {template<class... T>void EFmt(T...){}}
static thread_local uint64_t test_teb;
static uint64_t TestCurrentTEB(){return test_teb;}
#define FEX_IOS_HOST 1
#define _WIN32 1
''' + portable(old,'OriginalMutex')+portable(wpm,'WritePriorityMutex')+r'''
static_assert(sizeof(FEXCore::Utils::OriginalMutex::Mutex)==sizeof(FEXCore::Utils::WritePriorityMutex::Mutex));
struct FakeContext {FEXCore::Utils::WritePriorityMutex::Mutex mutex;auto& GetCodeInvalidationMutex(){return mutex;}};
struct Frontend {bool InLockedRWXRead;};
struct Thread {FakeContext* CTX;void* FrontendPtr;};
struct _TEB {void* Peb;Thread* thread;char storage[0x2000-16];};using __TEB=_TEB;
static _TEB* CurrentTEB(){return reinterpret_cast<_TEB*>(test_teb);}
struct TLS {_TEB* TEB;Thread* ThreadStateIfInitialised(){return TEB->thread;}};
static Frontend* GetFrontendThreadData(Thread* t){return static_cast<Frontend*>(t->FrontendPtr);}
static std::unique_ptr<FakeContext> CTX;
static void* MadeiraContextOwnerPEB=(void*)0x500310000ull;
template<class... T>static void IosRawReport(const char*,T...){raw_reports++;}
''' + callback+'\n'+own+'\n'+fatal+r'''
using NTSTATUS=uint32_t;using MEMORY_INFORMATION_CLASS=int;using PROCESSINFOCLASS=int;
#define STATUS_INVALID_PARAMETER 0xc000000du
static uint32_t query_status,set_status;static unsigned set_calls;static void* query_alias;
static madeira_fex_hold_registration received;
static void* GetCurrentProcess(){return (void*)(intptr_t)-1;}
static uint32_t NtQueryVirtualMemory(void* process,void* address,int kind,void* out,size_t n,void*){
 assert(process==GetCurrentProcess()&&address==reinterpret_cast<void*>(&MadeiraBTCpuIosReleaseThreadHolds)&&kind==1005&&n==8);
 *static_cast<void**>(out)=query_alias;return query_status;
}
static uint32_t NtSetInformationProcess(void* process,int kind,void* input,size_t n){
 assert(process==GetCurrentProcess()&&kind==1011&&n==24);set_calls++;memcpy(&received,input,24);return set_status;
}
''' + registration+r'''
static uintptr_t ios_fex_band_base=0xb40000000ull,ios_fex_band_end=0xd3fffffffull;
namespace fextl {
''' + report+r'''
}
static uint32_t wrong_callback(void*,uint64_t*,uint32_t*,uint32_t*){return 0;}
static uint32_t& depth(_TEB& t){return *reinterpret_cast<uint32_t*>((char*)&t+0x16f0);}
static uint64_t& stamp(_TEB& t){return *reinterpret_cast<uint64_t*>((char*)&t+0x16f8);}
static uint32_t& tid(_TEB& t){return *reinterpret_cast<uint32_t*>((char*)&t+0x48);}
int main(){
 CTX=std::make_unique<FakeContext>();Frontend frontend{};Thread state{CTX.get(),&frontend};
 _TEB a{},foreign{};a.Peb=MadeiraContextOwnerPEB;a.thread=&state;foreign.Peb=(void*)0x600310000ull;test_teb=(uintptr_t)&a;
 tid(a)=0x1e8;
 auto& mutex=CTX->mutex;uint64_t out_stamp=99;uint32_t out_depth=99,out_flags=99;
 assert(MadeiraBTCpuIosReleaseThreadHolds(nullptr,&out_stamp,&out_depth,&out_flags)==16&&!out_stamp&&!out_depth&&!out_flags);
 for(unsigned count: {1u,3u}){
  for(unsigned i=0;i<count;i++)mutex.lock_shared();assert(depth(a)==count&&stamp(a)==mutex.IosStampAddress());
  assert(MadeiraBTCpuIosReleaseThreadHolds(&a,&out_stamp,&out_depth,&out_flags)==1);
  assert(out_depth==count&&out_stamp==mutex.IosStampAddress()&&!out_flags&&!depth(a)&&!stamp(a));
  assert(mutex.try_lock());mutex.unlock();assert(!MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr));
 }
 mutex.lock_shared();assert(MadeiraBTCpuIosReleaseThreadHolds(&foreign,nullptr,nullptr,nullptr)==32&&depth(a)==1);
 auto saved_peb=a.Peb;a.Peb=foreign.Peb;assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==64&&depth(a)==1);a.Peb=saved_peb;
 auto saved_thread=a.thread;a.thread=nullptr;assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==8);a.thread=saved_thread;
 FakeContext different;state.CTX=&different;assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==8);state.CTX=CTX.get();
 auto saved_ctx=std::move(CTX);assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==8);CTX=std::move(saved_ctx);
 auto correct_stamp=stamp(a);stamp(a)=different.mutex.IosStampAddress();assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==4);stamp(a)=correct_stamp;
 frontend.InLockedRWXRead=true;assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==128&&depth(a)==1);frontend.InLockedRWXRead=false;
 mutex.unlock_shared();
 // Aggregate TEB depth from another mutex must not cause a double unlock.
 mutex.lock_shared();different.mutex.lock_shared();assert(depth(a)==2);
 assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==128&&!mutex.try_lock());
 different.mutex.unlock_shared();mutex.unlock_shared();
 // Releasing the stamped mutex while another WPM hold survives leaves a
 // stale aggregate stamp at depth ONE. It does not prove CodeMutex ownership.
 mutex.lock_shared();different.mutex.lock_shared();mutex.unlock_shared();
 assert(depth(a)==1&&stamp(a)==mutex.IosStampAddress()&&mutex.MadeiraSharedHoldsForTEB((uintptr_t)&a)==0);
 unsigned char code_before[sizeof(mutex)],foreign_before[sizeof(different.mutex)];
 memcpy(code_before,&mutex,sizeof(mutex));memcpy(foreign_before,&different.mutex,sizeof(different.mutex));
 assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==128);
 assert(!memcmp(code_before,&mutex,sizeof(mutex))&&!memcmp(foreign_before,&different.mutex,sizeof(different.mutex)));
 assert(depth(a)==1&&stamp(a)==mutex.IosStampAddress()&&mutex.try_lock());mutex.unlock();
 assert(!different.mutex.try_lock());different.mutex.unlock_shared();
 assert(!depth(a)&&!stamp(a)&&different.mutex.try_lock());different.mutex.unlock();
 // A missing ring slot is ambiguous even at depth one; never guess that a
 // matching aggregate stamp permits unlocking an unrecorded reader.
 _TEB crowded[16]{};
 unsigned next_tid=0x200;for(auto& t:crowded){tid(t)=next_tid++;test_teb=(uintptr_t)&t;mutex.lock_shared();}
 test_teb=(uintptr_t)&a;mutex.lock_shared();
 assert(depth(a)==1&&stamp(a)==mutex.IosStampAddress()&&!mutex.MadeiraSharedHoldsForTEB((uintptr_t)&a));
 memcpy(code_before,&mutex,sizeof(mutex));
 assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==128&&depth(a)==1);
 assert(!memcmp(code_before,&mutex,sizeof(mutex)));mutex.unlock_shared();
 for(auto& t:crowded){test_teb=(uintptr_t)&t;mutex.unlock_shared();assert(!depth(t)&&!stamp(t));}
 test_teb=(uintptr_t)&a;assert(mutex.try_lock());mutex.unlock();
 // A refused dead thread's ring row must not become a new thread's proof
 // when the same TEB address is reused. Release must pair both TEB AND TID.
 mutex.lock_shared();assert(mutex.MadeiraSharedHoldsForTEB((uintptr_t)&a)==1);
 const auto old_tid=tid(a);tid(a)=0x404;depth(a)=0;stamp(a)=0;
 assert(!mutex.MadeiraSharedHoldsForTEB((uintptr_t)&a));
 mutex.lock_shared();different.mutex.lock_shared();mutex.unlock_shared();
 assert(depth(a)==1&&stamp(a)==mutex.IosStampAddress()&&!mutex.MadeiraSharedHoldsForTEB((uintptr_t)&a));
 memcpy(code_before,&mutex,sizeof(mutex));memcpy(foreign_before,&different.mutex,sizeof(different.mutex));
 assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==128);
 assert(!memcmp(code_before,&mutex,sizeof(mutex))&&!memcmp(foreign_before,&different.mutex,sizeof(different.mutex)));
 different.mutex.unlock_shared();assert(!depth(a)&&!stamp(a));
 // Retire the fixture's retained OLD incarnation without borrowing its hold.
 tid(a)=old_tid;depth(a)=1;stamp(a)=mutex.IosStampAddress();mutex.unlock_shared();
 assert(mutex.try_lock());mutex.unlock();
 for(unsigned i=0;i<17;i++)mutex.lock_shared();assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==128&&depth(a)==17);
 for(unsigned i=0;i<17;i++)mutex.unlock_shared();assert(mutex.try_lock());mutex.unlock();
 // Fatal allocation still traps; only same-thread holds are retired first.
 raw_reports=0;
 for(unsigned i=0;i<42;i++){
  mutex.lock_shared();bool trapped=false;try{fextl::ReportAllocationFailure(8,0x2800000);}catch(Terminal&){trapped=true;}
  assert(trapped&&!depth(a)&&!stamp(a)&&mutex.try_lock());mutex.unlock();
 }
 assert(traps==42&&raw_reports==32);
 query_alias=reinterpret_cast<void*>(&MadeiraBTCpuIosReleaseThreadHolds);MadeiraRegisterOwnHoldRelease();
 assert(set_calls==1&&received.size==24&&received.version==1&&received.peb==MadeiraContextOwnerPEB&&received.callback==query_alias);
 query_status=0xc0000001;MadeiraRegisterOwnHoldRelease();assert(set_calls==1);query_status=0;
 query_alias=nullptr;MadeiraRegisterOwnHoldRelease();assert(set_calls==1);
 query_alias=reinterpret_cast<void*>(&wrong_callback);MadeiraRegisterOwnHoldRelease();assert(set_calls==1);
 CTX.reset();assert(MadeiraBTCpuIosReleaseThreadHolds(&a,nullptr,nullptr,nullptr)==8);
 puts("PASS actual staged WoW producer and mutex: same ABI/layout, self/PEB/TLS/CTX/stamp proof, exact single/nested holds, mixed/foreign/exclusive/oversized refusal, writer reentry after own cleanup, 42 unchanged fatal traps with 32 bounded reports, and typed alias/selftest registration");
}
'''
    p=d/'producer.cpp';p.write_text(code);exe=d/'producer'
    compiler=os.environ.get('CXX','c++')
    subprocess.run([compiler,'-std=c++20','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-misleading-indentation',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
                    '-I'+str(root/'build/ntdll-unix'),str(p),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
    # Compile the actual stable TSD getter for ARM64 without needing a Windows
    # SDK. The native test below substitutes only MRS/MOV register sources.
    getter=body(wpm,'  static uint64_t IosSelfTeb()')
    platform='typedef unsigned long long uint64_t;typedef unsigned long long uintptr_t;typedef unsigned int uint32_t;\nextern "C" uint32_t IosTebTsdOffset;\n'
    p=d/'teb-arm64.cpp';p.write_text(platform+'#define FEX_IOS_HOST 1\n#define ARCHITECTURE_arm64 1\n'+getter)
    clang=__import__('shutil').which('clang++')
    if clang:subprocess.run([clang,'--target=aarch64-unknown-linux-gnu','-std=c++20','-fsyntax-only','-Wall','-Wextra','-Wno-unused-function','-Werror',str(p)],check=True)
    adapted=getter.replace('__asm volatile("mrs %0, TPIDRRO_EL0" : "=r"(Tsd));','Tsd = FakeTsd;').replace('__asm volatile("mov %0, x18" : "=r"(Teb));','Teb = FakeX18;')
    p=d/'teb-host.cpp';p.write_text('#include <cassert>\n#include <cstdint>\nstatic uintptr_t FakeTsd,FakeX18;uint32_t IosTebTsdOffset;\n#define FEX_IOS_HOST 1\n#define ARCHITECTURE_arm64 1\n'+adapted+r'''
int main(){alignas(8)uint64_t slots[8]={};FakeTsd=(uintptr_t)slots|3;IosTebTsdOffset=16;slots[2]=0x500240000ull;
 FakeX18=0;assert(IosSelfTeb()==slots[2]);FakeX18=0x600240000ull;assert(IosSelfTeb()==slots[2]);
 slots[2]=0;assert(IosSelfTeb()==FakeX18);IosTebTsdOffset=0;assert(IosSelfTeb()==FakeX18);}
''')
    exe=d/'teb-host';subprocess.run([compiler,'-std=c++20','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
    print('PASS actual WoW mutex TSD getter compiles for ARM64 and selects authoritative slot when x18 is zero or foreign; fallback unchanged')
