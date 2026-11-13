#!/usr/bin/env python3
"""Execute the real tracker, interval lists, locks and staged heap factory.

Only Windows/Context/allocator boundaries are controlled. The fixture exercises
both frontends. WOW64 retains its original ThreadCreationMutex; callback
publication is controlled at the Windows boundary, without adding production
notification guards.
"""
from pathlib import Path
import importlib.util
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]'
    for token in re.finditer(pattern, source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[start:brace + token.end()]
    raise AssertionError(signature)


PREFIX = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
using DWORD=uint32_t;using ULONG=uint32_t;using LPCVOID=const void*;
using NTSTATUS=uint32_t;
constexpr NTSTATUS STATUS_SUCCESS=0,STATUS_NO_MEMORY=0xc0000017,STATUS_PROCESS_IS_TERMINATING=0xc000010a,STATUS_INVALID_DEVICE_STATE=0xc0000184;
enum {PAGE_NOACCESS=1,PAGE_READONLY=2,PAGE_READWRITE=4,PAGE_WRITECOPY=8,PAGE_EXECUTE=16,
      PAGE_EXECUTE_READ=32,PAGE_EXECUTE_READWRITE=64,PAGE_EXECUTE_WRITECOPY=128,PAGE_GUARD=256,MEM_COMMIT=0x1000};
namespace LogMan::Msg {template<class...T>void EFmt(const char*,T&&...){}template<class...T>void DFmt(const char*,T&&...) {}}
namespace FEXCore::Config {enum {CONFIG_SMC_NONE,CONFIG_SMC_MTRACK};}
#define FEX_CONFIG_OPT(name,key) const auto name=FEXCore::Config::CONFIG_SMC_MTRACK
namespace FEXCore::Utils {constexpr uint64_t FEX_PAGE_SIZE=4096,FEX_PAGE_MASK=~UINT64_C(4095);}
namespace FEXCore::Core {struct InternalThreadState {};}
static thread_local unsigned current_owner;
static thread_local unsigned char teb_token;
static void* NtCurrentTeb(){return &teb_token;}
struct ContextLock {
  std::mutex mutex;std::atomic<uintptr_t> owner{0};
  void lock(){mutex.lock();owner.store((uintptr_t)NtCurrentTeb());}
  void unlock(){owner.store(0);mutex.unlock();}
  bool IosHeldExclusiveByThisThread(){return owner.load()==(uintptr_t)NtCurrentTeb();}
  const uint64_t* IosOwnerReturnAddresses(){return nullptr;}
};
static bool owner_alive[4];
static void assert_no_allocations(unsigned);
namespace FEXCore::Context {
class Context {
public:
  unsigned owner;ContextLock lock;std::mutex events_lock;std::vector<std::pair<uint64_t,uint64_t>> invalidations;
  explicit Context(unsigned id):owner(id){assert(!owner_alive[id]);owner_alive[id]=true;}
  ~Context(){assert_no_allocations(owner);owner_alive[owner]=false;}
  ContextLock& GetCodeInvalidationMutex(){return lock;}
  void InvalidateCodeBuffersCodeRange(uint64_t at,uint64_t bytes){std::lock_guard guard(events_lock);invalidations.emplace_back(at,bytes);}
  void InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState*,uint64_t,uint64_t){}
};
}
struct MEMORY_BASIC_INFORMATION {void* BaseAddress;size_t RegionSize;ULONG State,Protect;};
static std::atomic<unsigned> constructor_queries{0},null_reentry{0},constructor_null_reentry{0},nested_reentry{0},terminating_declines{0};
static std::atomic<unsigned> fail_allocations{0};
static thread_local bool allocation_callback,in_constructor_query;
static void notify_allocator_reentry();
struct Allocation {unsigned owner;size_t bytes;};
static std::mutex allocations_lock;
static std::map<void*,Allocation> allocations;
namespace FEXCore::Allocator {
void* aligned_alloc(size_t alignment,size_t bytes){
  assert(current_owner&&owner_alive[current_owner]);
  if(fail_allocations.exchange(0))return nullptr;
  if(!allocation_callback){allocation_callback=true;notify_allocator_reentry();allocation_callback=false;}
  void* result=nullptr;assert(!posix_memalign(&result,std::max(alignment,sizeof(void*)),bytes));
  std::lock_guard guard(allocations_lock);assert(allocations.emplace(result,Allocation{current_owner,bytes}).second);return result;
}
void aligned_free(void* pointer){
  if(!pointer)return;
  if(!allocation_callback){allocation_callback=true;notify_allocator_reentry();allocation_callback=false;}
  std::lock_guard guard(allocations_lock);auto at=allocations.find(pointer);assert(at!=allocations.end());
  assert(owner_alive[at->second.owner]&&at->second.owner==current_owner);allocations.erase(at);free(pointer);
}
}
static void assert_no_allocations(unsigned owner){std::lock_guard guard(allocations_lock);for(auto entry:allocations)assert(entry.second.owner!=owner);}
static size_t VirtualQuery(LPCVOID address,MEMORY_BASIC_INFORMATION* info,size_t bytes){
  assert(bytes==sizeof(*info));constructor_queries.fetch_add(1);
  in_constructor_query=true;notify_allocator_reentry();in_constructor_query=false;
  uint64_t base=UINT64_C(0x10000000)+current_owner*0x100000;
  if((uintptr_t)address>=base+0x10000)return 0;
  *info={(void*)base,0x10000,MEM_COMMIT,PAGE_EXECUTE_READWRITE};return sizeof(*info);
}
/* Test-only access permits exercising the actual private lock directly. */
#include <FEXCore/Utils/IntervalList.h>
#define private public
#include "InvalidationTracker.h"
#undef private
#include <FEXCore/fextl/memory.h>
namespace fextl {[[noreturn]]void ReportAllocationFailure(size_t,size_t){throw std::bad_alloc();}}
namespace FEX::Windows {
'''

SUFFIX = r'''
}
using Tracker=FEX::Windows::InvalidationTracker;
using ThreadsMap=std::unordered_map<DWORD,FEXCore::Core::InternalThreadState*>;
struct Owner {
  unsigned id;FEXCore::Context::Context context;ThreadsMap threads;
  FEXCore::Context::Context* CTX=nullptr;
  std::atomic<bool> ProcessTerminating{false};unsigned mutations=0;bool ProcessInitStarted=false;
  fextl::unique_ptr<Tracker> InvalidationTracker;
  explicit Owner(unsigned value):id(value),context(value){}
  ~Owner(){ProcessTerminating.store(true,std::memory_order_relaxed);}
};
static Owner* owners[4];
struct CPUArea {void* ThreadState(){return (void*)1;}};
static CPUArea GetCPUArea(){return {};}
static void notify_allocator_reentry(){
  auto* owner=owners[current_owner];if(!owner){null_reentry.fetch_add(1);return;}
  auto& InvalidationTracker=owner->InvalidationTracker;auto& ProcessTerminating=owner->ProcessTerminating;
  if(!InvalidationTracker){null_reentry.fetch_add(1);if(in_constructor_query)constructor_null_reentry.fetch_add(1);}
  if(ProcessTerminating.load())terminating_declines.fetch_add(1);
@NOTIFICATION_GUARD@
  nested_reentry.fetch_add(1);
  owner->InvalidationTracker->HandleMemoryProtectionNotification(UINT64_C(0xf0000000),4096,PAGE_READWRITE);
}
struct FatalRefusal {};
#define IOS_WOW64_REPORT_AND_DIE(...) throw FatalRefusal()
#define ERROR_AND_DIE_FMT(...) throw FatalRefusal()
static NTSTATUS init(Owner& owner){
  auto& InvalidationTracker=owner.InvalidationTracker;
  auto& ProcessTerminating=owner.ProcessTerminating;
  auto& CTX=owner.CTX;auto& Threads=owner.threads;
  struct {uint64_t Base=0;} GuestWindow;
  auto& ProcessInitStarted=owner.ProcessInitStarted;
  (void)ProcessTerminating;(void)GuestWindow;(void)Threads;(void)ProcessInitStarted;
@INIT_GUARD@
  owner.mutations++;
  CTX=&owner.context;
@CONSTRUCT@
@OOM_GUARD@
  return STATUS_SUCCESS;
}
static void expected_query(Tracker& tracker,unsigned owner){
  uint64_t base=UINT64_C(0x10000000)+owner*0x100000;
  auto info=tracker.QueryExecutableRange(base+0x1000);
  assert(info.Base==base&&info.Size==0x10000&&info.Writable);
  auto missing=tracker.QueryExecutableRange(base-1);assert(!missing.Size);
}
static void protected_old_query_fails(Owner& owner){
  size_t bytes=(sizeof(Tracker)+getpagesize()-1)&~size_t(getpagesize()-1);
  void* storage=mmap(nullptr,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(storage!=MAP_FAILED);
#if defined(ARCHITECTURE_arm64ec)
  auto* tracker=::new(storage) Tracker(owner.context,owner.threads);
#else
  auto* tracker=::new(storage) Tracker(owner.context,owner.threads,0);
#endif
  assert(!mprotect(storage,bytes,PROT_READ|PROT_EXEC));
  pid_t child=fork();assert(child>=0);
  if(!child){struct rlimit limit={0,0};assert(!setrlimit(RLIMIT_CORE,&limit));expected_query(*tracker,owner.id);_exit(0);}
  int status;assert(waitpid(child,&status,0)==child);
  assert(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS));
  assert(!mprotect(storage,bytes,PROT_READ|PROT_WRITE));tracker->~Tracker();assert(!munmap(storage,bytes));
}
static void real_lock_contention(Owner& owner){
  auto& lock=owner.InvalidationTracker->IntervalsLock;
  lock.lock_shared();assert(lock.try_lock_shared());lock.unlock_shared();
  std::atomic<bool> writer_tried{false},writer_entered{false};
  std::thread writer([&]{current_owner=owner.id;assert(!lock.try_lock());writer_tried.store(true);lock.lock();writer_entered.store(true);assert(lock.HeldByThisThread());lock.unlock();});
  while(!writer_tried.load())std::this_thread::yield();
  std::this_thread::sleep_for(std::chrono::milliseconds(20));assert(!writer_entered.load());lock.unlock_shared();writer.join();assert(writer_entered.load());
  lock.lock();assert(lock.HeldByThisThread());
  std::thread reader([&]{current_owner=owner.id;assert(!lock.HeldByThisThread());assert(!lock.try_lock_shared());});reader.join();
  lock.unlock();assert(!lock.HeldByThisThread());
}
static void protected_heap_owner_succeeds(Owner& owner){
  const size_t bytes=getpagesize();
  void* page=mmap(nullptr,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(page!=MAP_FAILED);
  auto** slot=::new(page) Tracker*(owner.InvalidationTracker.get());
  assert(!mprotect(page,bytes,PROT_READ|PROT_EXEC));
  for(unsigned i=0;i<100;i++)expected_query(**slot,owner.id);
  assert(*slot==owner.InvalidationTracker.get());
  assert(!munmap(page,bytes));
}
int main(){
#if !defined(ARCHITECTURE_arm64ec)
  {
    current_owner=3;Owner failed(3);owners[3]=&failed;
    fail_allocations=1;
    bool refused=false;try{init(failed);}catch(FatalRefusal&){refused=true;}assert(refused);
    assert(failed.CTX==&failed.context&&!failed.InvalidationTracker);
    assert_no_allocations(3);
    unsigned mutations=failed.mutations,before=constructor_queries.load();
    bool duplicate=false;try{init(failed);}catch(FatalRefusal&){duplicate=true;}assert(duplicate);
    assert(failed.mutations==mutations&&constructor_queries.load()==before);
  }
  owners[3]=nullptr;assert(!owner_alive[3]);
#else
  {
    current_owner=3;Owner failed(3);owners[3]=&failed;
    unsigned before=constructor_queries.load();fail_allocations=1;
    assert(!failed.CTX&&!failed.InvalidationTracker);
    assert(init(failed)==STATUS_NO_MEMORY);
    assert(failed.CTX==&failed.context&&!failed.InvalidationTracker);
    assert(constructor_queries.load()==before&&failed.mutations==1);
    unsigned mutations=failed.mutations;
    assert(init(failed)==STATUS_INVALID_DEVICE_STATE);
    assert(failed.CTX==&failed.context&&!failed.InvalidationTracker);
    assert(failed.mutations==mutations&&constructor_queries.load()==before);
    failed.ProcessTerminating=true;assert(init(failed)==STATUS_PROCESS_IS_TERMINATING);
  }
  owners[3]=nullptr;assert(!owner_alive[3]);
#endif
  {
    current_owner=1;Owner first(1);owners[1]=&first;
    protected_old_query_fails(first);
    unsigned null_before=constructor_null_reentry.load();
    assert(init(first)==STATUS_SUCCESS&&first.InvalidationTracker);assert(constructor_null_reentry.load()>null_before);
    auto* stable=first.InvalidationTracker.get();unsigned mutations=first.mutations,before=constructor_queries.load();
#if defined(ARCHITECTURE_arm64ec)
    assert(init(first)==STATUS_INVALID_DEVICE_STATE);
    first.ProcessTerminating=true;assert(init(first)==STATUS_PROCESS_IS_TERMINATING);first.ProcessTerminating=false;
#else
    bool duplicate=false;try{init(first);}catch(FatalRefusal&){duplicate=true;}assert(duplicate);
#endif
    assert(first.InvalidationTracker.get()==stable&&first.mutations==mutations&&constructor_queries.load()==before);
    assert(&stable->Threads==&first.threads);
    expected_query(*stable,1);real_lock_contention(first);
    protected_heap_owner_succeeds(first);
    {
      current_owner=2;Owner second(2);owners[2]=&second;assert(init(second)==STATUS_SUCCESS);expected_query(*second.InvalidationTracker,2);
      assert(!second.InvalidationTracker->QueryExecutableRange(UINT64_C(0x10100000)).Size);
      current_owner=1;assert(!first.InvalidationTracker->QueryExecutableRange(UINT64_C(0x10200000)).Size);
      unsigned skips=FEX::Windows::NestedNotificationSkips.load();
      first.InvalidationTracker->HandleMemoryProtectionNotification(UINT64_C(0x30100000),4096,PAGE_EXECUTE_READ);
      assert(FEX::Windows::NestedNotificationSkips.load()>skips&&nested_reentry.load()>0);
      auto extra=first.InvalidationTracker->QueryExecutableRange(UINT64_C(0x30100000));assert(extra.Size==4096&&!extra.Writable);
      current_owner=2;assert(!second.InvalidationTracker->QueryExecutableRange(UINT64_C(0x30100000)).Size);
      current_owner=1;std::atomic<unsigned> queries{0};std::vector<std::thread> readers;
      for(unsigned i=0;i<4;i++)readers.emplace_back([&]{current_owner=1;for(unsigned n=0;n<1000;n++){expected_query(*first.InvalidationTracker,1);queries.fetch_add(1);}});
      for(auto& thread:readers){thread.join();}
      assert(queries==4000);
      current_owner=2; // Termination guard blocks destructor-triggered callbacks.
    }
    current_owner=1;owners[2]=nullptr;assert(!owner_alive[2]);expected_query(*first.InvalidationTracker,1);
  }
  owners[1]=nullptr;assert(!owner_alive[1]&&allocations.empty()&&terminating_declines.load()>0);
  puts("PASS actual InvalidationTracker heap storage: protected canonical writes fault; staged factory/OOM rollback/reentry/first-entry guards, real interval queries/shared-exclusive locks, 4000 concurrent queries, borrowed Threads references, two owner heaps and destruction-before-Context preserved");
}
'''


with tempfile.TemporaryDirectory(prefix='madeira-fex-invalidation-storage-') as folder:
    work = Path(folder)
    spec = importlib.util.spec_from_file_location('fex_stage', ROOT / 'tools/build/stage-fex-compat.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    staged = work / 'staged'
    stage.stage(staged, ROOT / 'FEX', 'both')
    source = (staged / 'Source/Windows/Common/InvalidationTracker.cpp').read_text()
    ctor_start = source.index('#if !defined(ARCHITECTURE_arm64ec)\nInvalidationTracker::InvalidationTracker(')
    ctor = source[ctor_start:source.index('\nstatic bool ProtHasExec(', ctor_start)]
    query_start = source.index('#if !defined(ARCHITECTURE_arm64ec)\nFEXCore::HLE::ExecutableRangeInfo InvalidationTracker::QueryExecutableRange(')
    query = source[query_start:source.index('\nvoid InvalidationTracker::DetectMonoBackpatcherBlock(', query_start)]
    actual = '\n'.join(function(source, signature) for signature in (
        'uint64_t InvalidationTracker::OwnedSharedMutex::Self(', 'static bool ProtHasExec(',
        'static bool ProtIsReadable(', 'static bool ProtIsWritable(', 'static bool NestedInvalidationAllowed(',
        'bool InvalidationTracker::LockCodeInvalidationUnlessHeld(',
        'void InvalidationTracker::InvalidateIntervalInternal(', 'void InvalidationTracker::InvalidateIntervalInternalLocked('))
    notify_start = source.index('void InvalidationTracker::HandleMemoryProtectionNotification(')
    notify = source[notify_start:source.index('\nvoid InvalidationTracker::HandleProcessExecuteFlagsChange(', notify_start)]
    actual = 'static std::atomic<uint64_t> NestedNotificationSkips{0};\n' + actual + '\n' + notify + '\n' + ctor + '\n' + query
    shim = work / 'shims/FEXCore'
    (shim / 'Utils').mkdir(parents=True)
    (shim / 'HLE').mkdir(parents=True)
    (shim / 'Utils/AllocatorHooks.h').write_text('#pragma once\n#include <cstddef>\n#define FEX_DEFAULT_VISIBILITY\nnamespace FEXCore::Allocator {void* aligned_alloc(std::size_t,std::size_t);void aligned_free(void*);}\n')
    (shim / 'HLE/SyscallHandler.h').write_text('#pragma once\n#include <cstdint>\nnamespace FEXCore::HLE {struct ExecutableRangeInfo {uint64_t Base,Size;bool Writable;};}\n')
    cxx = os.environ.get('CXX', 'c++')
    for backend in ('arm64ec', 'wow64'):
        module = (staged / ('Source/Windows/ARM64EC/Module.cpp' if backend == 'arm64ec' else 'Source/Windows/WOW64/Module.cpp')).read_text()
        assert 'std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker' not in module
        assert 'fextl::unique_ptr<FEX::Windows::InvalidationTracker> InvalidationTracker;' in module
        assert 'InvalidationTracker.emplace(' not in module and 'InvalidationTracker.reset(' not in module
        assert module.index('fextl::unique_ptr<FEXCore::Context::Context> CTX;') < module.index('fextl::unique_ptr<FEX::Windows::InvalidationTracker> InvalidationTracker;')
        signature = 'NTSTATUS ProcessInit(' if backend == 'arm64ec' else 'void BTCpuProcessInit('
        init = function(module, signature)
        first = init.index('{') + 1
        if backend == 'arm64ec':
            guard_end = init.index('  /* iOS-Madeira: DualMap::WriteOffset')
            guard = init[first:guard_end]
            assert 'if (CTX || InvalidationTracker)' in guard
            assignment_start = init.index('  InvalidationTracker = fextl::try_make_unique<')
            assignment_end = init.index(';', assignment_start) + 1
            construct = init[assignment_start:assignment_end]
            oom = function(init[assignment_end:], '  if (!InvalidationTracker)')
            notification = function(module, 'void NotifyMemoryAlloc(')
            notification_guard = function(notification, '  if (!InvalidationTracker')
            assert 'ProcessTerminating.load' in notification_guard
        else:
            guard_end = init.index('  FEX::Windows::InitCRTProcess();')
            guard = init[first:guard_end]
            assert 'ProcessInitStarted' in guard
            # Each fixture Owner models a separate native image and its initializers.
            guard = re.sub(r'  static bool ProcessInitStarted[^;]*;', '', guard)
            assignment_start = init.index('  InvalidationTracker = fextl::try_make_unique<')
            assignment_end = init.index(';', assignment_start) + 1
            construct = init[assignment_start:assignment_end]
            oom = function(init[assignment_end:], '  if (!InvalidationTracker)')
            assert 'std::mutex ThreadCreationMutex;' in module
            # WOW64 native allocations do not call the guest BTCpu notification
            # hooks. This controlled boundary skips unpublished/retired owners.
            notification_guard = '  if(!InvalidationTracker||ProcessTerminating.load())return;'
        suffix = (SUFFIX.replace('@INIT_GUARD@', guard).replace('@CONSTRUCT@', construct).replace('@OOM_GUARD@', oom)
                  .replace('@NOTIFICATION_GUARD@', notification_guard))
        suffix = suffix.replace('GuestWindow::Base', 'GuestWindow.Base')
        cpp = work / (backend + '.cpp')
        cpp.write_text(PREFIX + actual + suffix)
        binary = work / backend
        flags = ['-DARCHITECTURE_arm64ec'] if backend == 'arm64ec' else []
        # GCC diagnoses IntervalList's existing member/type name collision;
        # Clang, used by production PE builds, accepts that unchanged source.
        version = subprocess.run([cxx, '--version'], capture_output=True, text=True, check=True).stdout
        compiler = ['-fpermissive', '-Wno-changes-meaning'] if 'clang' not in version.lower() else []
        subprocess.run([cxx, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-pthread', *compiler, *flags,
                        '-I', str(work / 'shims'), '-I', str(staged / 'FEXCore/include'), '-I', str(ROOT / 'FEX/FEXCore/include'),
                        '-I', str(ROOT / 'FEX/Source/Windows/Common'), str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=30)
