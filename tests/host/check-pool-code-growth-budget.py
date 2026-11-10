#!/usr/bin/env python3
"""Exercise the production growth bound, cursor CAS and FEX buffer producer.

Native pool helpers and the pinned FEX CodeBuffer constructor/destructor are
compiled verbatim. The producer fixture supplies an owned VM boundary; complete
Wine EC_CODE/image/recycler replay remains check-pool-cs2-budget.py. Its synthetic
thread references test C++ buffer lifetime, not on-device FEX sweep execution.
"""
from pathlib import Path
import argparse
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify-policy-wiring', action='store_true', help='Run only actual-producer selector mutation controls')
args = parser.parse_args()
native = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
allocator = (ROOT / 'app/Madeira/JITAllocator.c').read_text()
backend = (ROOT / 'FEX/FEXCore/Source/Interface/Core/CPUBackend.cpp').read_text()
header = (ROOT / 'FEX/FEXCore/Source/Interface/Core/CPUBackend.h').read_text()


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


helpers = '\n'.join(function(native, name) for name in (
    'static size_t ios_pool_parse_head_reserve(',
    'static size_t ios_pool_parse_code_tail_limit(',
    'static size_t ios_pool_hole_tail_start(',
    'static size_t ios_pool_hole_between(',
    'static size_t ios_pool_code_cap(',
    'static size_t ios_pool_holes_tail_start(',
    'static size_t ios_pool_code_growth_cap(',
    'static int ios_pool_code_growth_fits(',
    'static int ios_pool_partition_allows_code(',
))
reservation = function(native, 'static int ios_pool_reserve_code_tail(')
# Interleave immediately before the actual atomic compare/exchange. The wrapper
# still uses the compiler's real CAS, and the source retry/validation is intact.
reservation = reservation.replace('__sync_bool_compare_and_swap(', 'interleaved_cas(')
fresh = function(native, 'static int ios_pool_fresh_tail_fits(')
carve = native.index('struct ios_tail_carve\n')
carve = native[carve:native.index('\n};', carve) + 3]
ready = function(native, 'static int ios_tail_carve_ready(')
better = function(native, 'static int ios_pool_code_carve_better(')
producer = '__attribute__((no_sanitize("alignment")))\n' + function(backend, '  CodeBuffer::CodeBuffer(size_t Size)')
producer += '\n' + function(backend, '  CodeBuffer::~CodeBuffer()')
structure = header[header.index('  struct CodeBuffer {'):]
structure = structure[:structure.index('\n  };') + 5]
plan_limit = function(allocator, 'uint64_t jit_cs2_code_tail_limit_mb(')
plan_image = function(allocator, 'uint64_t jit_cs2_image_arena_mb(')

code = r'''
#include <algorithm>
#include <atomic>
#include <barrier>
#include <cassert>
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
#include <unistd.h>
#define MB ((size_t)1 << 20)
#define IOS_POOL_LOW_CARVE_MAX (128 * MB)
#define IOS_POOL_REUSE_GRACE_SEC 3
#define FEX_IOS_HOST 1
static size_t ios_pool_code_tail_limit;
static size_t ios_pool_image_limit;
''' + helpers + r'''
static std::barrier<>* cas_barrier;
static thread_local bool interleaved;
static int interleaved_cas(volatile size_t* pointer,size_t expected,size_t desired) {
  if(cas_barrier&&!interleaved) { interleaved=true;cas_barrier->arrive_and_wait(); }
  return __sync_bool_compare_and_swap(pointer,expected,desired);
}
''' + reservation + '\n' + fresh + '\n' + plan_limit + '\n' + plan_image + '\n' + carve + r'''
static int ios_tail_carve_in_low(size_t) {return 0;}
''' + ready + '\n' + better + r'''
static const size_t total=1152*MB;
static volatile size_t tail;
static size_t image_head;
static unsigned char *rx,*rw;
static size_t host_page;
static std::vector<ios_tail_carve> carves;
static std::vector<size_t> attempts;
static unsigned frees;
static std::mutex vm_mutex;
static volatile sig_atomic_t expect_oom,expect_permission;
static uintptr_t expected_fault_lo,expected_fault_hi;
static void select_production_code_limit() {
  ios_pool_code_tail_limit=jit_cs2_code_tail_limit_mb()*MB;
  ios_pool_image_limit=jit_cs2_image_arena_mb()*MB;
}

static void signal_handler(int signal,siginfo_t* info,void*) {
  if(expect_permission&&(signal==SIGSEGV||signal==SIGBUS)&&
     (uintptr_t)info->si_addr>=expected_fault_lo&&(uintptr_t)info->si_addr<expected_fault_hi) _Exit(85);
  if(expect_oom&&(signal==SIGSEGV||signal==SIGBUS)&&info->si_addr==(void*)0xdead&&
     attempts.size()==8&&attempts.back()==MB&&tail==0) _Exit(86);
  _Exit(87);
}
static void initialize_aliases() {
  rlimit core={0,0};assert(!setrlimit(RLIMIT_CORE,&core));
  host_page=(size_t)sysconf(_SC_PAGESIZE);assert(host_page&&!(host_page&(host_page-1)));
  FILE* file=tmpfile();assert(file&&ftruncate(fileno(file),(off_t)total)==0);
  rx=(unsigned char*)mmap(nullptr,total,PROT_NONE,MAP_SHARED,fileno(file),0);
  rw=(unsigned char*)mmap(nullptr,total,PROT_NONE,MAP_SHARED,fileno(file),0);
  assert(rx!=MAP_FAILED&&rw!=MAP_FAILED&&rx!=rw);fclose(file);
  struct sigaction action{};action.sa_sigaction=signal_handler;action.sa_flags=SA_SIGINFO;
  sigemptyset(&action.sa_mask);assert(!sigaction(SIGSEGV,&action,nullptr));assert(!sigaction(SIGBUS,&action,nullptr));
}
static void activate(size_t offset,size_t bytes) {
  assert(!(offset&(host_page-1))&&!(bytes&(host_page-1))&&offset<=total&&bytes<=total-offset);
  assert(!mprotect(rx+offset,bytes,PROT_READ|PROT_EXEC));
  assert(!mprotect(rw+offset,bytes,PROT_READ|PROT_WRITE));
}
static void protect_guard(void* pointer,size_t bytes) {
  uintptr_t start=(uintptr_t)pointer&~(uintptr_t)(host_page-1);
  uintptr_t end=((uintptr_t)pointer+bytes+host_page-1)&~(uintptr_t)(host_page-1);
  size_t offset=start-(uintptr_t)rx;assert(offset<total&&end-start<=total-offset);
  assert(!mprotect(rx+offset,end-start,PROT_NONE));assert(!mprotect(rw+offset,end-start,PROT_NONE));
}
namespace LogMan::Msg {template<class...T>void EFmt(const char*,T...){}}
#define LOGMAN_THROW_A_FMT(value,...) assert(value)
namespace fextl {template<class T>using unique_ptr=std::unique_ptr<T>;using std::make_unique;}
namespace FEXCore {
namespace Utils {constexpr size_t FEX_PAGE_SIZE=4096;}
struct GuestToHostMap {};
namespace Allocator {
enum class ProtectOptions {None};enum class THPControl {Enable};
void* VirtualAlloc(size_t size,bool executable) {
  assert(executable);std::lock_guard lock(vm_mutex);attempts.push_back(size);
  size_t best=SIZE_MAX;
  for(size_t i=0;i<carves.size();i++)
    if(ios_tail_carve_ready(&carves[i],1000)&&carves[i].size>=size&&
       (best==SIZE_MAX||ios_pool_code_carve_better(&carves[i],&carves[best])))best=i;
  if(best!=SIZE_MAX) {
    // The public VM boundary returns a preexisting, genuinely free code carve.
    // The complete production eligibility/scans are tested by the pool replay.
    carves[best].free=0;carves[best].retired=0;carves[best].retired_lease=0;
    activate(carves[best].off,carves[best].size);return rx+carves[best].off;
  }
  size_t cap=std::min(ios_pool_code_cap(total,image_head,tail,0,0,240*MB),
                      ios_pool_code_growth_cap(tail,ios_pool_code_tail_limit));
  if(size>cap||!ios_pool_fresh_tail_fits(total,image_head,tail,size,0,0,0,0))return nullptr;
  size_t previous=SIZE_MAX,offset=SIZE_MAX,added=SIZE_MAX;
  if(!ios_pool_reserve_code_tail(&tail,total,size,ios_pool_code_tail_limit,0,0,0,0,&offset,&added,&previous))return nullptr;
  // This owned VM shim applies the real caller's physical collision contract;
  // the cursor helper alone intentionally does not grant mappings.
  assert(offset<=total&&size<=total-offset&&total-offset-size>=image_head);
  size_t off=total-offset-size;ios_tail_carve record{};
  record.off=off;record.size=size;record.allocation_lease=1;record.peb=(void*)0x324;
  carves.push_back(record);activate(off,size);return rx+off;
}
bool VirtualProtect(void* pointer,size_t bytes,ProtectOptions value) {
  assert(value==ProtectOptions::None);protect_guard(pointer,bytes);return true;
}
void VirtualName(const char*,void* pointer,size_t size) {assert(pointer&&size);}
void VirtualTHPControl(void*,size_t,THPControl) {}
void VirtualFree(void* pointer,size_t size) {
  std::lock_guard lock(vm_mutex);size_t offset=(unsigned char*)pointer-rx;
  auto found=std::find_if(carves.begin(),carves.end(),[&](const auto& c){return c.off==offset;});
  assert(found!=carves.end()&&!found->free&&found->size==size);
  found->free=1;found->retired=0;found->retired_lease=0;found->freed_at=1000;++frees;
  assert(!mprotect(rx+offset,size,PROT_NONE));assert(!mprotect(rw+offset,size,PROT_NONE));
}
}
template<class T>static T AlignDown(T value,size_t alignment){return value&~(alignment-1);}
namespace CPU {
''' + structure + '\n' + producer + r'''
}
}
using FEXCore::CPU::CodeBuffer;
#ifdef __clang__
__attribute__((no_sanitize("undefined")))
#else
__attribute__((no_sanitize_undefined))
#endif
static int execute(const void* pointer) {
  return reinterpret_cast<int(*)()>(const_cast<void*>(pointer))();
}
static void put_code(const CodeBuffer& buffer) {
  size_t off=buffer.Ptr-rx;
#if defined(__aarch64__)||defined(__arm64__)
  const uint32_t instructions[]={0x52800220,0xd65f03c0};
#elif defined(__x86_64__)
  const unsigned char instructions[]={0xb8,17,0,0,0,0xc3};
#else
#error unsupported native executable fixture architecture
#endif
  memcpy(rw+off,instructions,sizeof(instructions));
  __builtin___clear_cache((char*)buffer.Ptr,(char*)buffer.Ptr+sizeof(instructions));
  assert(!memcmp(buffer.Ptr,rw+off,sizeof(instructions))&&execute(buffer.Ptr)==17);
}
static void native_permissions(const CodeBuffer& buffer) {
  size_t offset=buffer.Ptr-rx;
  // The same VM permissions are exercised in forked children; no production
  // handler or exception path is modified or suppressed.
  for(int mode=0;mode<3;mode++) {
    pid_t child=fork();assert(child>=0);
    if(!child) {
      expect_permission=1;
      uintptr_t target=mode==0?(uintptr_t)buffer.Ptr:mode==1?(uintptr_t)(rw+offset):
                         (uintptr_t)(rw+offset+buffer.AllocatedSize-1);
      expected_fault_lo=target&~(uintptr_t)(host_page-1);expected_fault_hi=expected_fault_lo+host_page;
      if(mode==0)*reinterpret_cast<volatile unsigned char*>(buffer.Ptr)=0;
      else if(mode==1)(void)execute(rw+offset);
      else *reinterpret_cast<volatile unsigned char*>(rw+offset+buffer.AllocatedSize-1)=0;
      _Exit(0);
    }
    int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==85);
  }
}
static void policy_tests() {
  assert(jit_cs2_code_tail_limit_mb()==384&&jit_cs2_image_arena_mb()==768);
  assert(ios_pool_parse_code_tail_limit("512",total)==512*MB);
  for(const char* invalid:{"","0","15","1153","-1","512x","99999999999999999999999999"})
    assert(!ios_pool_parse_code_tail_limit(invalid,total));
  assert(!ios_pool_parse_code_tail_limit(nullptr,total));
  assert(ios_pool_parse_code_tail_limit("16",total)==16*MB);
  assert(ios_pool_parse_head_reserve("240")==240*MB);
  constexpr size_t captured_head=0x1825c000,captured_tail=0x1f01c000;
  assert(ios_pool_code_cap(total,captured_head,captured_tail,0,0,208*MB)==32*MB);
  assert(ios_pool_code_cap(total,captured_head,captured_tail,0,0,237*MB)==32*MB);
  assert(ios_pool_code_cap(total,captured_head,captured_tail,0,0,238*MB)==16*MB);
  assert(ios_pool_code_cap(total,captured_head,captured_tail,0,0,240*MB)==16*MB);
  for(size_t early_head:{0x1000000UL,0x8000000UL,captured_head}) {
    // Unlike gap-only headroom, the fresh large growth bound does not depend
    // on when images arrive. Required 16MiB units still get real allocation.
    assert(ios_pool_code_growth_cap(captured_tail,512*MB)==16*MB);
    assert(!ios_pool_code_growth_fits(captured_tail,32*MB,512*MB));
    assert(ios_pool_code_growth_fits(captured_tail,16*MB,512*MB));
    ios_pool_code_tail_limit=512*MB;
    assert(!ios_pool_fresh_tail_fits(total,early_head,captured_tail,32*MB,0,0,0,0));
  }
  // 448MiB would downsize the third observed128MiB working-set generation.
  // 512MiB preserves it while refusing the later extra32MiB reservation.
  assert(ios_pool_code_growth_cap(0x1701c000,448*MB)==64*MB);
  assert(!ios_pool_code_growth_fits(0x1701c000,128*MB,448*MB));
  assert(ios_pool_code_growth_cap(0x1701c000,512*MB)==128*MB);
  assert(ios_pool_code_growth_fits(0x1701c000,128*MB,512*MB));
  assert(ios_pool_code_growth_cap(captured_tail,0)==128*MB);
  assert(ios_pool_code_growth_fits(captured_tail,128*MB,0));
  assert(!ios_pool_code_growth_fits(0,0,512*MB));
  assert(!ios_pool_code_growth_fits(SIZE_MAX,32*MB,512*MB));
  assert(ios_pool_code_growth_fits(SIZE_MAX,16*MB,512*MB));
  assert(!ios_pool_fresh_tail_fits(total,total-1,captured_tail,16*MB,0,0,0,0));
}
static void atomic_reservation_tests() {
  volatile size_t used=448*MB;std::barrier barrier(2);cas_barrier=&barrier;
  size_t offsets[2]={SIZE_MAX,SIZE_MAX},added[2]={SIZE_MAX,SIZE_MAX},previous[2]={SIZE_MAX,SIZE_MAX};
  int result[2]={0,0};std::thread workers[2];
  for(unsigned i=0;i<2;i++)workers[i]=std::thread([&,i]{
    result[i]=ios_pool_reserve_code_tail(&used,total,64*MB,512*MB,0,0,0,0,&offsets[i],&added[i],&previous[i]);
  });
  for(auto& worker:workers)worker.join();cas_barrier=nullptr;
  assert(result[0]+result[1]==1&&used==512*MB);
  for(unsigned i=0;i<2;i++)if(result[i])assert(offsets[i]==448*MB&&added[i]==64*MB&&previous[i]==448*MB);
  else assert(offsets[i]==SIZE_MAX&&added[i]==SIZE_MAX&&previous[i]==SIZE_MAX);
  // A hole skipped by the successful tail geometry consumes retained address
  // capacity, even though the request itself would fit the pre-skip budget.
  used=512*MB;size_t offset=SIZE_MAX,delta=SIZE_MAX,before=SIZE_MAX;
  assert(!ios_pool_reserve_code_tail(&used,total,64*MB,600*MB,500*MB,600*MB,0,0,&offset,&delta,&before));
  assert(used==512*MB&&offset==SIZE_MAX&&delta==SIZE_MAX&&before==SIZE_MAX);
  used=SIZE_MAX-7;
  assert(!ios_pool_reserve_code_tail(&used,total,16,0,0,0,0,0,&offset,&delta,&before));
  assert(used==SIZE_MAX-7&&offset==SIZE_MAX&&delta==SIZE_MAX&&before==SIZE_MAX);
  used=512*MB;
  assert(ios_pool_reserve_code_tail(&used,total,16*MB,512*MB,0,0,0,0,&offset,&delta,&before));
  assert(used==528*MB&&offset==512*MB&&delta==16*MB&&before==512*MB);
  puts("PASS production code-growth helpers: captured208 failure threshold, timing-independent large cap, validated parse, two64MiB contenders publish exactly one reservation, skipped-hole accounting, overflow and unchanged refused outputs");
}
int main(int argc,char** argv) {
  if(argc==3&&!strcmp(argv[1],"selector-probe")) {
    initialize_aliases();select_production_code_limit();
    tail=368*MB;image_head=0x144f0000;attempts.clear();
    auto buffer=std::make_shared<CodeBuffer>(128*MB);
    size_t expected=(size_t)strtoul(argv[2],nullptr,10);
    printf("[producer-selector-probe] selected=%llu image=%llu effective=%zu effective-image=%zu grant=%zu expected=%zu attempts=%zu\n",
           (unsigned long long)jit_cs2_code_tail_limit_mb(),(unsigned long long)jit_cs2_image_arena_mb(),
           ios_pool_code_tail_limit/MB,ios_pool_image_limit/MB,
           buffer->AllocatedSize/MB,expected,attempts.size());fflush(stdout);
    assert(buffer->AllocatedSize==expected*MB);
    assert(ios_pool_code_tail_limit==jit_cs2_code_tail_limit_mb()*MB);
    assert(ios_pool_image_limit==jit_cs2_image_arena_mb()*MB);
    put_code(*buffer);return 0;
  }
  policy_tests();atomic_reservation_tests();initialize_aliases();
  /* Retain the historical unpartitioned512 trace as a named baseline. The
   * production hard384/768 selector is exercised through the real constructor
   * separately below, never substituted by this baseline assignment. */
  ios_pool_code_tail_limit=512*MB;ios_pool_image_limit=0;
  if(argc==2&&!strcmp(argv[1],"oom")) {
    tail=0;image_head=total-MB/2;attempts.clear();expect_oom=1;
    auto impossible=std::make_shared<CodeBuffer>(128*MB);(void)impossible;return 88;
  }
  tail=0x701c000;image_head=0x130f4000;
  std::vector<std::shared_ptr<CodeBuffer>> retained;
  for(unsigned i=0;i<3;i++) {
    if(i)image_head=0x144f0000;
    attempts.clear();auto buffer=std::make_shared<CodeBuffer>(128*MB);
    assert(buffer->AllocatedSize==128*MB&&attempts==std::vector<size_t>{128*MB});
    put_code(*buffer);retained.push_back(std::move(buffer));
  }
  assert(tail==0x1f01c000&&frees==0);
  for(size_t offset:{0x44000000UL,0x46000000UL}) {
    ios_tail_carve free{};free.off=offset;free.size=16*MB;free.free=1;free.freed_at=1000;carves.push_back(free);
  }
  image_head=0x1825c000;size_t fixed_tail=tail;attempts.clear();
  auto active=std::make_shared<CodeBuffer>(128*MB);
  assert(active->AllocatedSize==16*MB&&attempts==std::vector<size_t>({128*MB,64*MB,32*MB,16*MB}));
  assert(tail==fixed_tail);put_code(*active);native_permissions(*active);
  // A real thread executes through a held shared_ptr while its manager-side
  // reference is replaced. The extracted production destructor cannot retire
  // that range until the executing/pending-reference holder releases it.
  std::atomic<bool> started{false},stop{false};auto old=active;unsigned char* old_pc=old->Ptr;
  std::thread executing([held=std::move(old),&started,&stop]()mutable{
    started.store(true,std::memory_order_release);
    while(!stop.load(std::memory_order_acquire))assert(execute(held->Ptr)==17);
    held.reset();
  });
  while(!started.load(std::memory_order_acquire))std::this_thread::yield();
  auto next=std::make_shared<CodeBuffer>(128*MB);assert(next->Ptr!=old_pc&&next->AllocatedSize==16*MB);
  put_code(*next);active.reset();assert(frees==0&&execute(old_pc)==17);
  stop.store(true,std::memory_order_release);executing.join();assert(frees==1);
  active=std::move(next);
  for(unsigned turn=0;turn<32;turn++) {
    auto generation=std::make_shared<CodeBuffer>(128*MB);
    assert(generation->AllocatedSize==16*MB&&generation->Ptr!=active->Ptr&&tail==fixed_tail);
    put_code(*generation);active=std::move(generation);
    for(const auto& buffer:retained)assert(execute(buffer->Ptr)==17);
  }
  active.reset();assert(frees==34);
  for(const auto& c:carves)if(c.free)assert(!c.retired&&!c.retired_lease);
  assert(tail==fixed_tail);for(const auto& buffer:retained)assert(execute(buffer->Ptr)==17);
  retained.clear();assert(frees==37);
  // A large generation may be reused after its genuine last reference dies;
  // the fresh-growth budget must not reject already reserved executable code.
  attempts.clear();auto reused_large=std::make_shared<CodeBuffer>(128*MB);
  assert(reused_large->AllocatedSize==128*MB&&attempts==std::vector<size_t>{128*MB});
  assert(tail==fixed_tail);put_code(*reused_large);reused_large.reset();assert(frees==38);
  puts("PASS actual FEX CodeBuffer constructor/destructor: three128MiB generations retained, 128/64/32 honest refusals reach distinct16MiB reuse, 32 later rotations retain the tail cursor, live execution/reference delays release, RX/RW/guard permissions and executable payloads preserved");
}
'''
# POSIX wait macros are kept out of the embedded producer; this is the host test.
code = code.replace('#include <sys/resource.h>', '#include <sys/resource.h>\n#include <sys/wait.h>')

with tempfile.TemporaryDirectory(prefix='madeira-code-growth-') as directory:
    directory = Path(directory)
    source = directory / 'code-growth.cpp'
    source.write_text(code)
    executable = directory / 'code-growth'
    # The pinned producer deliberately uses an unaligned 0xdead store for its
    # fatal path. Leave that exact instruction to the hardware signal handler;
    # A constructor-only alignment annotation leaves all helper/lifetime
    # arithmetic under UBSan; the production constructor body is unchanged.
    command = shlex.split(os.environ.get('CXX', 'c++')) + [
        '-std=c++20', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-Wno-unused-function', '-Wno-misleading-indentation',
        '-fsanitize=undefined', '-fno-sanitize-recover=all', '-pthread',
        str(source), '-o', str(executable),
    ]
    subprocess.run(command, check=True)
    if not args.verify_policy_wiring:
        subprocess.run([str(executable)], check=True, timeout=90)
        result = subprocess.run([str(executable), 'oom'], timeout=30)
        assert result.returncode == 86, 'The real producer must retain its genuine final allocation-failure trap'
        print('PASS actual FEX producer true exhaustion: all eight128-to1MiB requests fail honestly and the original fatal path remains observable')
    subprocess.run([str(executable), 'selector-probe', '16'], check=True, timeout=30)
    assert plan_limit.count('return 384;') == 1 and plan_image.count('return 768;') == 1, 'Update paired hard-partition controls when production changes'
    mutated = code.replace(plan_limit, plan_limit.replace('return 384;', 'return 448;', 1), 1)
    mutated = mutated.replace(plan_image, plan_image.replace('return 768;', 'return 704;', 1), 1)
    source.write_text(mutated)
    subprocess.run(command, check=True)
    subprocess.run([str(executable), 'selector-probe', '64'], check=True, timeout=30)
    # Reproduce disconnected test wiring with both effective arena inputs at
    # the old512/640 split. The constructor must expose128MiB, not silently
    # pass the paired448/704 selector's expected64MiB assertion.
    wire = 'ios_pool_code_tail_limit=jit_cs2_code_tail_limit_mb()*MB;'
    assert mutated.count(wire) == 1
    image_wire = 'ios_pool_image_limit=jit_cs2_image_arena_mb()*MB;'
    assert mutated.count(image_wire) == 1
    broken_source = mutated.replace(wire, 'ios_pool_code_tail_limit=512*MB; /* negative wiring control */', 1)
    source.write_text(broken_source.replace(image_wire, 'ios_pool_image_limit=640*MB; /* negative partition wiring */', 1))
    subprocess.run(command, check=True)
    broken = subprocess.run([str(executable), 'selector-probe', '64'], capture_output=True, text=True, timeout=30)
    assert broken.returncode != 0 and 'selected=448 image=704 effective=512 effective-image=640 grant=128 expected=64' in broken.stdout, broken.stdout + broken.stderr
    print('PASS actual FEX producer hard-partition selector wiring: production384/768->16MiB, in-memory448/704->64MiB; disconnected512/640 wiring is rejected after actual allocation')
