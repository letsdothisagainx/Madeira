#!/usr/bin/env python3
"""Execute the staged FEX producer against real permanent native guard pages.

The OS allocation boundary is a fixture. Guard arming, bitmap queries and the
owned-allocation confirmation are compiled from production. Actual producer
methods retain their shared references; no sweep or game progress is invented.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def producer_parts(staged):
    """Reusable literal producer fragments for the C allocator companion test."""
    source = (staged / 'FEXCore/Source/Interface/Core/CPUBackend.cpp').read_text()
    header = (staged / 'FEXCore/Source/Interface/Core/CPUBackend.h').read_text()
    hooks = (staged / 'FEXCore/include/FEXCore/Utils/AllocatorHooks.h').read_text()
    return {
        'code_buffer': function(header, '  struct CodeBuffer {') + ';',
        'manager': function(header, '  class CodeBufferManager {') + ';',
        'ctor': function(source, '  CodeBuffer::CodeBuffer(size_t Size)'),
        'dtor': function(source, '  CodeBuffer::~CodeBuffer()'),
        'allocate': function(source, '  auto CodeBufferManager::AllocateNew('),
        'getlatest': function(source, '  fextl::shared_ptr<CodeBuffer> CodeBufferManager::GetLatest()'),
        'grow': function(source, '  fextl::shared_ptr<CodeBuffer> CodeBufferManager::StartLargerCodeBuffer()'),
        'isaddress': function(source, '  bool CPUBackend::IsAddressInCodeBuffer('),
        'virtual_alloc': function(hooks, 'inline void* VirtualAllocCodeBuffer('),
        'virtual_protect': function(hooks, 'inline bool VirtualProtect('),
        'constants': '\n'.join(dict.fromkeys(re.findall(
            r'  static constexpr size_t (?:INITIAL_CODE_SIZE|MAX_CODE_SIZE) = [^;]+;', source))),
    }


def run():
    native = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
    record = function(native, 'struct ios_tail_carve\n') + ';'
    confirm = function(native, 'static int ios_fex_code_guard_confirm(')
    warm_start = native.index('            size_t head, tail;', native.index('static void *ios_pool_warmer_thread('))
    warm_end = native.index('            /* madeira-bcd pool-low:', warm_start)
    warm = native[warm_start:warm_end].replace('ios_jit_code_guard_contains(', 'warm_query(')
    assert 'pthread_mutex_lock( &ios_pool_lock )' in warm
    assert 'pthread_mutex_unlock( &ios_pool_lock )' in warm
    assert warm.count('sink +=') == 4
    abi = ROOT / 'build/ntdll-unix/fex_code_buffer_abi.h'
    guards = ROOT / 'build/ntdll-unix/fex_code_guards.h'
    with tempfile.TemporaryDirectory(prefix='madeira-guarded-producer-') as temporary:
        directory = Path(temporary)
        staged = directory / 'staged'
        subprocess.run(['python3', str(ROOT / 'tools/build/stage-fex-compat.py'),
                        'stage', str(staged), '--backend', 'both'], check=True)
        p = producer_parts(staged)
        code = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
// Emulate the native Windows compilation branch after host headers are read.
#define FEX_IOS_HOST 1
#define _WIN32 1
#undef __linux__
#define MB ((size_t)1<<20)
''' + '#include "' + str(abi) + '"\n' + r'''
using mach_vm_address_t=uintptr_t;using mach_vm_size_t=size_t;
using kern_return_t=int;
#define KERN_SUCCESS 0
#define VM_PROT_NONE 0
static void* ios_jit_rx_base_global;
static void* ios_jit_rw_base_global;
static size_t ios_jit_pool_size_global=1152*MB;
static unsigned protection_calls,fail_protection_call;
static unsigned allocations,frees,lookups,warnings,legacy_allocations;
static bool bad_confirmation;
static uintptr_t mach_task_self(){return 1;}
static int mach_vm_protect(uintptr_t,uintptr_t address,size_t size,int maximum,int prot) {
  assert(!maximum&&prot==VM_PROT_NONE&&size==MADEIRA_FEX_CODE_GUARD_BYTES);
  ++protection_calls;
  if(protection_calls==fail_protection_call)return 5;
  return mprotect((void*)address,size,PROT_NONE)?5:KERN_SUCCESS;
}
''' + '#include "' + str(guards) + '"\n' + record + r'''
static ios_tail_carve ios_tail_carves[256];
static unsigned ios_tail_carve_n;
static pthread_mutex_t ios_tail_carve_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ios_pool_lock=PTHREAD_MUTEX_INITIALIZER;
static thread_local void* current_owner=(void*)0x12340000;
static thread_local unsigned long long current_lease=9;
static void* ios_jit_current_peb(){return current_owner;}
static unsigned long long ios_thread_process_lease(void*,int){return current_lease;}
''' + confirm + r'''
static unsigned char *rx,*rw;
static void* reservations[2];
static size_t next_offset=768*MB,per_request_limit=128*MB;
static std::vector<size_t> requests;
static std::mutex vm_mutex;
static constexpr unsigned MemExtendedParameterAttributeFlags=5;
static constexpr unsigned MEM_EXTENDED_PARAMETER_EC_CODE=0x40;
static constexpr unsigned MEM_COMMIT=0x1000,MEM_RESERVE=0x2000;
static constexpr unsigned PAGE_EXECUTE_READWRITE=0x40,PAGE_NOACCESS=1;
static constexpr unsigned PAGE_READONLY=2,PAGE_READWRITE=4,PAGE_EXECUTE_READ=0x20;
using DWORD=uint32_t;
struct MEM_EXTENDED_PARAMETER {uint64_t Type;union{uint64_t ULong64;uint32_t ULong;};};
static_assert(sizeof(MEM_EXTENDED_PARAMETER)==16);
static void* allocate_native(size_t size,bool guarded) {
  std::lock_guard lock(vm_mutex);requests.push_back(size);
  if(size>per_request_limit)return nullptr;
  for(unsigned i=0;i<ios_tail_carve_n;i++) {
    auto& c=ios_tail_carves[i];
    if(c.free&&c.guarded==(guarded?1u:0u)&&c.size==size) {
      c.free=0;c.peb=current_owner;c.allocation_lease=current_lease;
      // Real exact-class reuse must not restore or write the permanent guard.
      size_t body=size-(guarded?MADEIRA_FEX_CODE_GUARD_BYTES:0);
      std::fill_n((uint32_t*)(rw+c.off),body/4,0xd503201fu);
      ++allocations;return rx+c.off;
    }
  }
  if(size>ios_jit_pool_size_global-next_offset||ios_tail_carve_n==256)return nullptr;
  size_t off=next_offset;next_offset+=size;
  assert(!ios_jit_code_guard_contains((uintptr_t)rx+off,size));
  assert(!mprotect(rx+off,size,PROT_READ|PROT_EXEC));
  assert(!mprotect(rw+off,size,PROT_READ|PROT_WRITE));
  std::fill_n((uint32_t*)(rw+off),size/4,0xd503201fu);
  auto& c=ios_tail_carves[ios_tail_carve_n++];c={};
  c.off=off;c.size=size;c.peb=current_owner;c.allocation_lease=current_lease;
  c.guarded=guarded?2:0;
  if(guarded&&!ios_fex_code_guard_arm(off,size)) {
    c.peb=nullptr;c.allocation_lease=0;return nullptr;
  }
  c.guarded=guarded?1:0;++allocations;return rx+off;
}
static void* VirtualAlloc2(void* process,void* base,size_t size,unsigned flags,unsigned prot,
                            MEM_EXTENDED_PARAMETER* parameters,unsigned count) {
  assert(!process&&!base&&flags==(MEM_COMMIT|MEM_RESERVE)&&prot==PAGE_EXECUTE_READWRITE);
  assert(count==2&&parameters[0].Type==MemExtendedParameterAttributeFlags&&
         parameters[0].ULong64==MEM_EXTENDED_PARAMETER_EC_CODE&&
         parameters[1].Type==MADEIRA_FEX_CODE_PARAMETER_TYPE&&
         parameters[1].ULong64==MADEIRA_FEX_CODE_GUARD_ABI_V1);
  return allocate_native(size,true);
}
static int VirtualProtect(void* pointer,size_t size,unsigned prot,DWORD* previous) {
  assert(previous&&prot==PAGE_NOACCESS);*previous=PAGE_EXECUTE_READWRITE;
  return !bad_confirmation&&ios_fex_code_guard_confirm((uintptr_t)pointer,size);
}
struct Fatal{};
namespace LogMan::Msg {
template<class...T>void EFmt(const char* message,T...){
  if(!std::strcmp(message,"Failed to mprotect last page of code buffer."))++warnings;
}
}
#define LOGMAN_THROW_A_FMT(value,...) assert(value)
#define LOGMAN_MSG_A_FMT(...) do{}while(0)
namespace fextl {
template<class T>using unique_ptr=std::unique_ptr<T>;
template<class T>using shared_ptr=std::shared_ptr<T>;
using std::make_unique;using std::make_shared;
[[noreturn]]static void ReportAllocationFailure(size_t,size_t){throw Fatal{};}
}
template<class T>static T AlignDown(T value,size_t alignment){return value&~(T)(alignment-1);}
namespace FEXCore {
using ForkableUniqueMutex=std::mutex;
namespace Utils {constexpr size_t FEX_PAGE_SIZE=4096;}
namespace Config {static bool Get_ENABLECODECACHINGWIP(){return false;}}
struct GuestToHostMap {GuestToHostMap(){++lookups;}};
namespace Allocator {
enum class ProtectOptions:unsigned{None=0,Read=1,Write=2,Exec=4};
constexpr ProtectOptions operator|(ProtectOptions a,ProtectOptions b){return(ProtectOptions)((unsigned)a|(unsigned)b);}
enum class THPControl{Enable};
static void* VirtualAlloc(size_t size,bool execute){assert(execute);++legacy_allocations;return allocate_native(size,false);}
static void VirtualFree(void* pointer,size_t size){
  std::lock_guard lock(vm_mutex);
  for(unsigned i=0;i<ios_tail_carve_n;i++){
    auto& c=ios_tail_carves[i];if(rx+c.off==pointer){assert(!c.free&&c.size==size);c.free=1;++frees;return;}
  }
  assert(false);
}
static void VirtualName(const char*,void*,size_t){}
static void VirtualTHPControl(void*,size_t,THPControl){}
''' + p['virtual_alloc'] + '\n' + p['virtual_protect'] + r'''
}
namespace CPU {
''' + p['code_buffer'] + '\n' + p['manager'] + '\n' + p['constants'] + r'''
static std::atomic<uint64_t> IosCodeBufferGenCounter{0};
__attribute__((no_sanitize("alignment")))
''' + p['ctor'] + '\n' + p['dtor'] + '\n' + p['allocate'] + '\n' + p['getlatest'] + '\n' + p['grow'] + r'''
struct IosMigrateLockGuard{explicit IosMigrateLockGuard(std::atomic<uint64_t>&){}};
class CPUBackend{
public:mutable std::atomic<uint64_t> IosMigrateLock{};
  std::shared_ptr<CodeBuffer> CurrentCodeBuffer;
  std::vector<std::shared_ptr<CodeBuffer>> SignalHandlerCodeBuffers;
  bool IsAddressInCodeBuffer(uintptr_t Address)const;
};
''' + p['isaddress'] + r'''
}
}
static unsigned char* alias(int fd,unsigned which) {
  size_t n=ios_jit_pool_size_global+0x4000;
  void* p=mmap(nullptr,n,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);assert(p!=MAP_FAILED);
  reservations[which]=p;uintptr_t aligned=((uintptr_t)p+0x3fff)&~(uintptr_t)0x3fff;
  assert(mmap((void*)aligned,ios_jit_pool_size_global,PROT_NONE,MAP_SHARED|MAP_FIXED,fd,0)==(void*)aligned);
  return(unsigned char*)aligned;
}
static void initialize() {
  rlimit core={0,0};assert(!setrlimit(RLIMIT_CORE,&core));
  assert(0x4000%(size_t)sysconf(_SC_PAGESIZE)==0);
  FILE* f=tmpfile();assert(f&&!ftruncate(fileno(f),ios_jit_pool_size_global));
  rx=alias(fileno(f),0);rw=alias(fileno(f),1);fclose(f);
  ios_jit_rx_base_global=rx;ios_jit_rw_base_global=rw;
}
static void finish(){for(auto p:reservations)assert(!munmap(p,ios_jit_pool_size_global+0x4000));}
static void payload(unsigned char* pointer) {
  size_t off=pointer-rx;
#if defined(__aarch64__) || defined(__arm64__)
  const uint32_t words[]={0x52800540u,0xd65f03c0u};
#else
  const unsigned char words[]={0xb8,42,0,0,0,0xc3};
#endif
  std::memcpy(rw+off,words,sizeof(words));
  __builtin___clear_cache((char*)pointer,(char*)pointer+sizeof(words));
}
static int execute(unsigned char* pointer){using Fn=int(*)();return((Fn)pointer)();}
static uintptr_t fault_lo,fault_hi;
static void fault_handler(int signo,siginfo_t* info,void*){
  uintptr_t a=(uintptr_t)info->si_addr;
  _Exit((signo==SIGSEGV||signo==SIGBUS)&&a>=fault_lo&&a<fault_hi?85:87);
}
static void expect_fault(unsigned char* pointer,unsigned operation){
  pid_t pid=fork();assert(pid>=0);if(!pid){
    fault_lo=(uintptr_t)pointer;fault_hi=fault_lo+0x4000;
    struct sigaction a{};a.sa_sigaction=fault_handler;a.sa_flags=SA_SIGINFO;sigemptyset(&a.sa_mask);
    assert(!sigaction(SIGSEGV,&a,nullptr)&&!sigaction(SIGBUS,&a,nullptr));
    if(operation==0){volatile auto v=*(volatile unsigned char*)pointer;(void)v;}
    else if(operation==1)*(volatile unsigned char*)pointer=1;
    else (void)execute(pointer);
    _Exit(88);
  }int status;assert(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==85);
}
static void check_buffer(const std::shared_ptr<FEXCore::CPU::CodeBuffer>& b){
  assert(b->GuardSize==0x4000&&b->UsableSize()==b->AllocatedSize-0x4000);
  size_t off=b->Ptr-rx,guard=off+b->UsableSize();
  assert(ios_fex_code_guard_confirm((uintptr_t)rx+guard,0x4000));
  assert(ios_fex_code_guard_confirm((uintptr_t)rw+guard,0x4000));
  assert(!ios_fex_code_guard_confirm((uintptr_t)rx+guard,0x1000));
  assert(!ios_jit_code_guard_contains((uintptr_t)b->Ptr,b->UsableSize()));
  assert(ios_jit_code_guard_contains((uintptr_t)rx+guard-1,2));
  assert(ios_jit_code_guard_contains((uintptr_t)rw+guard,1));
  payload(b->Ptr);payload(b->Ptr+b->UsableSize()-16);
  assert(execute(b->Ptr)==42&&execute(b->Ptr+b->UsableSize()-16)==42);
  for(unsigned op=0;op<3;op++){expect_fault(rx+guard,op);expect_fault(rw+guard,op);}
  FEXCore::CPU::CPUBackend backend;backend.CurrentCodeBuffer=b;
  assert(backend.IsAddressInCodeBuffer((uintptr_t)b->Ptr+b->UsableSize()-1));
  assert(!backend.IsAddressInCodeBuffer((uintptr_t)b->Ptr+b->UsableSize()));
}
static void guarded_growth(){
  initialize();assert(!setenv(MADEIRA_FEX_CODE_GUARD_ENV,"1",1));
  FEXCore::CPU::CodeBufferManager manager;
  auto first=manager.GetLatest();check_buffer(first);assert(first->AllocatedSize==16*MB);
  manager.LatestOffset=first->UsableSize()-32;
  auto second=manager.StartLargerCodeBuffer();assert(second->AllocatedSize==32*MB);check_buffer(second);
  auto third=manager.StartLargerCodeBuffer();assert(third->AllocatedSize==64*MB);check_buffer(third);
  per_request_limit=16*MB;
  size_t before=requests.size();auto fourth=manager.StartLargerCodeBuffer();
  assert((std::vector<size_t>(requests.begin()+before,requests.end())==std::vector<size_t>{128*MB,64*MB,32*MB,16*MB}));
  assert(fourth->AllocatedSize==16*MB&&fourth->GuardSize==0x4000);check_buffer(fourth);
  per_request_limit=128*MB;
  auto fifth=manager.StartLargerCodeBuffer();assert(fifth->AllocatedSize==32*MB);check_buffer(fifth);
  // The fifth request follows actual16, not its previously requested128.
  assert(requests.back()==32*MB&&!frees&&!legacy_allocations&&!warnings);
  std::atomic<bool> stop{false},ready{false};
  auto retained=first;auto* old=first->Ptr;
  std::thread worker([retained,&stop,&ready]{ready=true;while(!stop.load())assert(execute(retained->Ptr)==42);});
  while(!ready.load())std::this_thread::yield();
  first.reset();retained.reset();assert(!frees);
  stop=true;worker.join();assert(frees==1);
  auto reused=std::make_shared<FEXCore::CPU::CodeBuffer>(16*MB);assert(reused->Ptr==old);check_buffer(reused);
  assert(!warnings&&ios_jit_code_guard_contains((uintptr_t)old+16*MB-0x4000,0x4000));
  // All prior pinned generations still execute; their guards remain closed.
  assert(execute(second->Ptr)==42&&execute(third->Ptr)==42&&execute(fourth->Ptr)==42);
  current_lease++;assert(!ios_fex_code_guard_confirm((uintptr_t)old+16*MB-0x4000,0x4000));current_lease--;
  current_owner=(void*)0x56780000;assert(!ios_fex_code_guard_confirm((uintptr_t)old+16*MB-0x4000,0x4000));current_owner=(void*)0x12340000;
  puts("PASS actual staged producer:16→32→64, honest128/64/32 refusal→actual16→32; old references execute until released, exact-class reuse retains permanent RX/RW guards");
  // Destructors run before unmapping fixture backing.
}
static void legacy_mode(){
  initialize();assert(!setenv(MADEIRA_FEX_CODE_GUARD_ENV,"0",1));
  FEXCore::CPU::CodeBufferManager manager;auto first=manager.GetLatest();
  assert(first->GuardSize==4096&&first->UsableSize()==16*MB-4096);
  auto next=manager.StartLargerCodeBuffer();assert(next->AllocatedSize==128*MB&&next->GuardSize==4096);
  assert(legacy_allocations==2&&warnings==2&&!protection_calls);
  puts("PASS legacy session: existing4KB bounds, untagged allocation,128MB growth and honest unsupported-guard warnings remain unchanged");
}
static void partial_failure(){
  initialize();assert(!setenv(MADEIRA_FEX_CODE_GUARD_ENV,"1",1));
  fail_protection_call=2;
  assert(!FEXCore::Allocator::VirtualAllocCodeBuffer(16*MB,0x4000));
  assert(ios_tail_carve_n==1&&ios_tail_carves[0].guarded==2);
  auto& c=ios_tail_carves[0];size_t guard=c.off+c.size-0x4000;
  assert(ios_jit_code_guard_contains((uintptr_t)rx+guard,1));
  assert(!ios_fex_code_guard_is_armed(guard));
  c.peb=current_owner;c.allocation_lease=current_lease;
  assert(!ios_fex_code_guard_confirm((uintptr_t)rx+guard,0x4000));
  c.guarded=1;assert(!ios_fex_code_guard_confirm((uintptr_t)rx+guard,0x4000));c.guarded=2;
  // A denial bit must never manufacture a successful physical certificate.
  assert(!FEXCore::Allocator::VirtualAllocCodeBuffer(3*MB,0x4000));
  assert(!FEXCore::Allocator::VirtualAllocCodeBuffer(16*MB,0x2000));
  fail_protection_call=0;
  auto good=std::make_shared<FEXCore::CPU::CodeBuffer>(16*MB);assert(good->Ptr!=rx+c.off);check_buffer(good);
  size_t old_frees=frees,old_lookups=lookups;bad_confirmation=true;
  try{auto rejected=std::make_shared<FEXCore::CPU::CodeBuffer>(16*MB);(void)rejected;assert(false);}catch(Fatal&){}
  assert(frees==old_frees+1&&lookups==old_lookups);
  puts("PASS failed guard arm quarantines its class without publishing a pointer; partial/foreign/stale/invalid confirmations fail and constructor cannot publish a broken guard contract");
}
static std::atomic<bool> warm_paused{false},warm_continue{false},factory_waiting{false},factory_done{false};
static std::atomic<bool> pause_warm_once{true};
static thread_local bool warmer_thread;
static uintptr_t warm_target;
static size_t jit_pool_offset,ios_jit_tail_reserved;
static int ios_pool_code_guards=1;
static int warm_query(uintptr_t pointer,size_t size){
  int result=ios_jit_code_guard_contains(pointer,size);
  if(warmer_thread&&!result&&pointer==warm_target&&pause_warm_once.exchange(false)){
    warm_paused=true;while(!warm_continue.load())std::this_thread::yield();
  }
  return result;
}
#define IOS_POOL_IN_HOLE(o) 0
// This production C block is compiled as C++ in the producer companion.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-volatile"
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvolatile"
#endif
static size_t actual_warm_batch(){
  volatile const char* rx=(volatile const char*)ios_jit_rx_base_global;
  volatile const char* rw=(volatile const char*)ios_jit_rw_base_global;
  size_t total=ios_jit_pool_size_global;
''' + warm + r'''
  (void)sink;return touched;
}
#if defined(__clang__)
#pragma clang diagnostic pop
#else
#pragma GCC diagnostic pop
#endif
static void warmer_race(){
  initialize();size_t size=16*MB,off=ios_jit_pool_size_global-size;
  assert(!mprotect(rx+off,size,PROT_READ|PROT_EXEC));
  assert(!mprotect(rw+off,size,PROT_READ|PROT_WRITE));
  payload(rx+off);jit_pool_offset=0;ios_jit_tail_reserved=size;
  warm_target=(uintptr_t)rw+ios_jit_pool_size_global-0x4000;
  auto& c=ios_tail_carves[ios_tail_carve_n++];c={};c.off=off;c.size=size;c.guarded=2;
  size_t first_touched=0;
  std::thread warmer([&]{warmer_thread=true;first_touched=actual_warm_batch();});
  while(!warm_paused.load())std::this_thread::yield();
  std::thread factory([&]{
    factory_waiting=true;assert(!pthread_mutex_lock(&ios_pool_lock));
    assert(ios_fex_code_guard_arm(off,size));c.guarded=1;c.peb=current_owner;c.allocation_lease=current_lease;
    factory_done=true;assert(!pthread_mutex_unlock(&ios_pool_lock));
  });
  while(!factory_waiting.load())std::this_thread::yield();
  assert(pthread_mutex_trylock(&ios_pool_lock)==EBUSY);
  assert(!factory_done.load());warm_continue=true;
  warmer.join();factory.join();
  assert(first_touched==2*size/0x4000&&factory_done.load());
  assert(actual_warm_batch()==2*size/0x4000-2);
  assert(execute(rx+off)==42);
  expect_fault(rx+ios_jit_pool_size_global-0x4000,0);
  expect_fault(rw+ios_jit_pool_size_global-0x4000,0);
  puts("PASS actual four-loop warmer: forced query/read interleaving holds the publication lock; factory arms only after the read batch, then both guard pages are skipped");
}
static void case_run(void(*fn)()){
  pid_t p=fork();assert(p>=0);if(!p){fn();finish();fflush(stdout);_Exit(0);}
  int status;assert(waitpid(p,&status,0)==p&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
}
int main(){case_run(guarded_growth);case_run(legacy_mode);case_run(partial_failure);case_run(warmer_race);}
'''
        source = directory / 'producer.cpp'
        source.write_text(code)
        binary = directory / 'producer'
        compiler = shlex.split(os.environ.get('CXX', 'c++'))
        subprocess.run([*compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pthread',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-omit-frame-pointer', str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    run()
