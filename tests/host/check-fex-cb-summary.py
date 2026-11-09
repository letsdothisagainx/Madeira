#!/usr/bin/env python3
"""Reproduce CompileBlock telemetry races from exact production source.

The deterministic schedules do not race plain volatile accesses: both readers
pass the old predicate before either atomic decrement, and summary stores are
explicitly ordered high-ticket before low-ticket. No FEX checkout is modified.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--before-only', action='store_true', help='run only the literal old production race witnesses')
args = parser.parse_args()
source = (ROOT / 'FEX/FEXCore/Source/Interface/Core/Core.cpp').read_text()
marker = source.index('    static volatile uint64_t g_cb_last_summary_total = 0;')
start = source.rfind('  {', 0, marker)
end_marker = '\n  }\n\n  /* MADEIRA: the HOT RIP probe'
end = source.index(end_marker, marker) + len('\n  }')
block = source[start:end]
assert block.count('__sync_sub_and_fetch(&g_cb_hot_rip_count, 1);') == 1
assert block.count('g_cb_last_summary_total = total;') == 1
# Only scheduling/observation hooks are added; all old decisions, native atomic
# operations, thresholds and complete logging arguments remain production code.
observed = block.replace('    if (GuestRIP == g_cb_hot_rip)', r'''    if (observe) return Snapshot{
      __atomic_load_n(&g_cb_hot_rip, __ATOMIC_RELAXED),
      __atomic_load_n(&g_cb_hot_rip_count, __ATOMIC_RELAXED),
      __atomic_load_n(&g_cb_last_summary_total, __ATOMIC_RELAXED),
      __atomic_load_n(&g_cb_total, __ATOMIC_RELAXED)};
    if (GuestRIP == g_cb_hot_rip)''', 1)
observed = observed.replace('      g_cb_last_summary_total = total;',
                            '      before_summary_store(total);\n      g_cb_last_summary_total = total;\n      after_summary_store(total);', 1)

harness = r'''
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <mutex>
#include <thread>
struct Snapshot { uint64_t rip,count,last,total; };
static volatile uint64_t g_cb_total=0,g_cb_real_compiles=0;
static std::atomic<unsigned> summaries{0};
struct LookupFixture { uint64_t GetL1Pointer() const { return 0x12340000; } };
struct ThreadFixture { LookupFixture *LookupCache; };
struct FrameFixture { struct {uint64_t L1Pointer,L1Mask;}State;ThreadFixture *Thread; };
static LookupFixture lookup;static ThreadFixture thread_fixture{&lookup};
static FrameFixture frame_fixture{{0x12340000,255},&thread_fixture};
static FrameFixture *Frame=&frame_fixture;
namespace LogMan { namespace Msg {
  template<typename... T> void EFmt(const char *format,T&&...){assert(format);summaries.fetch_add(1,std::memory_order_relaxed);}
}}
static std::mutex gate_mutex;
static std::condition_variable gate_cv;
static unsigned sub_arrivals=0,summary_arrivals=0;
static uint64_t highest_ticket=0;
static bool sub_gate=false,summary_gate=false,highest_stored=false;
static uint64_t gated_sub(volatile uint64_t *counter,uint64_t amount){
  if(sub_gate){
    std::unique_lock<std::mutex> lock(gate_mutex);
    ++sub_arrivals;gate_cv.notify_all();
    gate_cv.wait(lock,[]{return sub_arrivals==2;});
  }
  return __atomic_sub_fetch(counter,amount,__ATOMIC_SEQ_CST);
}
static void before_summary_store(uint64_t total){
  if(!summary_gate)return;
  std::unique_lock<std::mutex> lock(gate_mutex);
  ++summary_arrivals;if(total>highest_ticket)highest_ticket=total;
  gate_cv.notify_all();gate_cv.wait(lock,[]{return summary_arrivals==2;});
  if(total!=highest_ticket)gate_cv.wait(lock,[]{return highest_stored;});
}
static void after_summary_store(uint64_t total){
  if(!summary_gate)return;
  std::lock_guard<std::mutex> lock(gate_mutex);
  if(total==highest_ticket){highest_stored=true;gate_cv.notify_all();}
}
#define __sync_sub_and_fetch(counter,amount) gated_sub(counter,amount)
static Snapshot actual_underflow(uint64_t GuestRIP,bool observe=false){
ACTUAL_BLOCK
  return {};
}
static Snapshot actual_summary(uint64_t GuestRIP,bool observe=false){
ACTUAL_BLOCK
  return {};
}
#undef __sync_sub_and_fetch
int main(){
  actual_underflow(0x1111);
  Snapshot initial=actual_underflow(0,true);assert(initial.rip==0x1111&&initial.count==1&&initial.total==1);
  sub_gate=true;
  std::thread a([]{actual_underflow(0x2222);}),b([]{actual_underflow(0x2222);});a.join();b.join();
  sub_gate=false;Snapshot bad=actual_underflow(0,true);
  assert(sub_arrivals==2&&bad.rip==0x1111&&bad.count==std::numeric_limits<uint64_t>::max()&&bad.total==3);
  std::printf("REPRODUCED literal production hot-RIP race: two synchronized mismatches from count=1 produce count=%llu (UINT64_MAX), total=%llu; no concurrent plain candidate/count access\n",
              (unsigned long long)bad.count,(unsigned long long)bad.total);
  __atomic_store_n(&g_cb_total,0,__ATOMIC_RELAXED);summaries.store(0,std::memory_order_relaxed);
  actual_summary(0x3333);
  __atomic_store_n(&g_cb_total,16383,__ATOMIC_RELAXED);summary_gate=true;
  std::thread c([]{actual_summary(0x3333);}),d([]{actual_summary(0x3333);});c.join();d.join();
  summary_gate=false;Snapshot duplicate=actual_summary(0,true);
  assert(summary_arrivals==2&&highest_ticket==16385&&highest_stored&&summaries.load()==2);
  assert(duplicate.last==16384&&duplicate.total==16385);
  std::printf("REPRODUCED literal production summary race: both claim one 16K boundary, summaries=%u, last-summary regresses 16385 -> %llu while total=%llu; summary writes explicitly ordered\n",
              summaries.load(),(unsigned long long)duplicate.last,(unsigned long long)duplicate.total);
  return 0;
}
'''.replace('ACTUAL_BLOCK', observed)
with tempfile.TemporaryDirectory(prefix='madeira-fex-cb-summary-') as directory:
    work = Path(directory)
    cpp, binary = work / 'summary.cpp', work / 'summary'
    cpp.write_text(harness)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread', str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=20)
if args.before_only:
    raise SystemExit(0)

spec = importlib.util.spec_from_file_location('fex_compat_stage', ROOT / 'tools/build/stage-fex-compat.py')
stager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stager)
with tempfile.TemporaryDirectory(prefix='madeira-fex-cb-fixed-') as directory:
    work = Path(directory)
    staged = work / 'staged'
    stager.stage(staged, ROOT / 'FEX', 'both')
    fixed_source = (staged / 'FEXCore/Source/Interface/Core/Core.cpp').read_text()
    # git apply previously returned success while silently skipping every
    # --include path if the destination lived below another Git worktree.
    outer = work / 'outer-repository'
    outer.mkdir()
    subprocess.run(['git', 'init', '-q', str(outer)], check=True)
    nested = outer / 'deep/nested/stage'
    stager.stage(nested, ROOT / 'FEX', 'both')
    nested_core = (nested / 'FEXCore/Source/Interface/Core/Core.cpp').read_text()
    assert nested_core == fixed_source
    assert '#include <Windows/include/wine/debug.h>' in nested_core
    assert 'MadeiraFEXDiagnostics::RecordDispatch(statistics, GuestRIP)' in nested_core
    assert (ROOT / 'FEX/FEXCore/Source/Interface/Core/Core.cpp').read_text() == source
    print('PASS actual production stager applies existing and diagnostic hunks inside a nested foreign Git worktree; pinned vendor source unchanged')
    assert 'MadeiraFEXDiagnostics::RecordDispatch(statistics, GuestRIP)' in fixed_source, 'the actual production overlay must be applied'
    assert 'static volatile uint64_t g_cb_hot_rip_count' not in fixed_source, 'old racy estimator must not survive staging'
    fixed_marker = fixed_source.index('    auto& statistics = MadeiraFEXCompileStats();')
    fixed_start = fixed_source.rfind('  {', 0, fixed_marker)
    fixed_end = fixed_source.index(end_marker, fixed_marker) + len('\n  }')
    fixed_block = fixed_source[fixed_start:fixed_end]
    getter_start = fixed_source.index('static MadeiraFEXDiagnostics::CompileState& MadeiraFEXCompileStats()')
    getter = fixed_source[getter_start:fixed_source.index('\n}', getter_start) + 2]
    compile_line = '  MadeiraFEXDiagnostics::RecordCompile(MadeiraFEXCompileStats());'
    assert fixed_source.count(compile_line) == 1
    fixed_cpp = r'''
#include "native_diagnostics.h"
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <future>
#include <limits>
#include <mutex>
#include <new>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <vector>
using MadeiraFEXDiagnostics::CompileState;
using MadeiraFEXDiagnostics::RecordDispatch;
using MadeiraFEXDiagnostics::RecordCompile;
using MadeiraFEXDiagnostics::SummaryDue;
static CompileState MadeiraFEXCompileStorage;
MadeiraFEXNativeWriteContract MadeiraFEXCompileWriteContract = {
  MadeiraFEXCompileTag,sizeof(MadeiraFEXCompileStorage),alignof(CompileState),&MadeiraFEXCompileStorage,0};
ACTUAL_GETTER
struct LookupFixture { uint64_t GetL1Pointer() const { return 0x12340000; } };
struct ThreadFixture { LookupFixture *LookupCache; };
struct FrameFixture { struct {uint64_t L1Pointer,L1Mask;}State;ThreadFixture *Thread; };
static LookupFixture lookup;static ThreadFixture thread_fixture{&lookup};
static FrameFixture frame_fixture{{0x12340000,255},&thread_fixture};
static FrameFixture *Frame=&frame_fixture;
struct Log {uint64_t total,reals,hits,rate;};
static std::mutex logs_mutex;static std::vector<Log> logs;
namespace LogMan { namespace Msg {
  template<typename A,typename B,typename C,typename D,typename... T>
  void EFmt(const char *format,A total,B real,C hits,D rate,T&&...){
    assert(format);std::lock_guard<std::mutex> lock(logs_mutex);
    logs.push_back({static_cast<uint64_t>(total),static_cast<uint64_t>(real),static_cast<uint64_t>(hits),static_cast<uint64_t>(rate)});
  }
}}
static void actual_fixed(uint64_t GuestRIP){
ACTUAL_FIXED_BLOCK
}
static void actual_compile(){
ACTUAL_COMPILE_LINE
}
static void select_state(CompileState *state){
  __atomic_store_n(&MadeiraFEXCompileWriteContract.writer,reinterpret_cast<uintptr_t>(state),__ATOMIC_RELEASE);
}
static void sequential_and_underflow(){
  CompileState state;select_state(&state);
  actual_fixed(0x1111);actual_fixed(0x1111);actual_fixed(0x2222);
  assert(state.total==3&&state.hot_rip==0x1111&&state.hot_balance==1&&state.sample_skips==0);
  actual_fixed(0x2222);assert(state.hot_balance==0);
  actual_fixed(0x3333);assert(state.hot_balance==1&&state.hot_rip==0x3333);
  for(unsigned i=0;i<10000;i++){
    actual_fixed(i&1?0x3333:0x4444);
    assert(state.hot_balance.load()<=state.total.load()&&state.hot_balance.load()!=UINT64_MAX);
  }
  select_state(nullptr);
  std::puts("PASS actual corrected header/staged block: uncontended Boyer-Moore candidate/balance, no underflow, exact dispatch totals");
}
static void held_sampler_nonblocking(){
  CompileState state;RecordDispatch(state,0x1111);state.sampling.store(1);select_state(&state);
  std::promise<void> done;auto ready=done.get_future();
  std::thread worker([&]{for(unsigned i=0;i<2000;i++)actual_fixed(0x2222);done.set_value();});
  bool progressed=ready.wait_for(std::chrono::seconds(2))==std::future_status::ready;
  state.sampling.store(0);worker.join();
  assert(progressed&&state.total==2001&&state.sample_skips==2000&&state.hot_balance==1&&state.hot_rip==0x1111);
  select_state(nullptr);
  std::puts("PASS corrected estimator never waits for a held sampler:2000 dispatches complete with exact totals/skip accounting and untouched candidate");
}
static void concurrent_staged_reports(){
  CompileState state;select_state(&state);logs.clear();
  constexpr unsigned threads=8,rounds=65536;
  std::vector<std::thread> workers;
  const auto functional_start=std::chrono::steady_clock::now();
  for(unsigned n=0;n<threads;n++)workers.emplace_back([&,n]{
    for(unsigned i=0;i<rounds;i++){
      if(!(i%7))actual_compile();
      actual_fixed(i%5?0x7777:0x10000+n);
    }
  });
  for(auto& worker:workers)worker.join();
  const auto functional_wall=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-functional_start).count();
  assert(state.total==uint64_t(threads)*rounds);
  assert(state.real_compiles==uint64_t(threads)*((rounds+6)/7));
  assert(state.hot_balance.load()<=state.total.load()-state.sample_skips.load());
  assert(state.sampling==0&&logs.size()==threads*rounds/16384);
  std::sort(logs.begin(),logs.end(),[](const Log&a,const Log&b){return a.total<b.total;});
  for(size_t i=0;i<logs.size();i++){
    assert(logs[i].total==(i+1)*16384&&logs[i].reals<=logs[i].total);
    assert(logs[i].hits==logs[i].total-logs[i].reals&&logs[i].rate<=100);
  }
  std::printf("[fex-cb-contention] fixture=asan-ubsan-functional workers=8 dispatches=%llu estimator-samples=%llu sample-skips=%llu wall-ns=%llu includes=thread-startup-and-report-fixture no-phone-performance-extrapolation\n",
              (unsigned long long)state.total.load(),(unsigned long long)(state.total.load()-state.sample_skips.load()),
              (unsigned long long)state.sample_skips.load(),(unsigned long long)functional_wall);
  select_state(nullptr);
  std::puts("PASS actual staged 8-thread telemetry:524288 exact dispatches, exact true compiles,32 unique 16K reports, bounded balance/skips, no duplicate thresholds or report subtraction wrap");
}
static void unique_tickets_and_report_cap(){
  CompileState state;constexpr unsigned threads=8,rounds=8192;
  std::vector<uint64_t> tickets[threads];std::vector<std::thread> workers;
  for(unsigned n=0;n<threads;n++)workers.emplace_back([&,n]{
    for(unsigned i=0;i<rounds;i++)tickets[n].push_back(RecordDispatch(state,0x1111+n));
  });
  for(auto& worker:workers)worker.join();
  std::vector<uint64_t> merged;
  for(auto& values:tickets)merged.insert(merged.end(),values.begin(),values.end());
  std::sort(merged.begin(),merged.end());
  for(size_t i=0;i<merged.size();i++)assert(merged[i]==i+1);
  assert(!SummaryDue(0)&&!SummaryDue(16383)&&SummaryDue(16384)&&!SummaryDue(16385));
  CompileState cap;cap.total=16383;cap.real_compiles=1000000;select_state(&cap);logs.clear();actual_fixed(0xabc);
  assert(logs.size()==1&&logs[0].total==16384&&logs[0].reals==16384&&logs[0].hits==0&&logs[0].rate==0);
  assert(cap.real_compiles==1000000);select_state(nullptr);
  std::puts("PASS corrected unique atomic tickets across65536 concurrent calls; actual staged report caps future real-count snapshot without changing authoritative compile count");
}
static void mapped_writer(){
  const size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));constexpr uintptr_t delta=0x48000000;
  auto *reserved=static_cast<unsigned char*>(mmap(nullptr,delta+page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0));
  assert(reserved!=MAP_FAILED);char path[]="/tmp/madeira-fex-cb-XXXXXX";int fd=mkstemp(path);
  assert(fd>=0&&!unlink(path)&&!ftruncate(fd,static_cast<off_t>(page)));
  void *rx=mmap(reserved,page,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
  void *rw=mmap(reserved+delta,page,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
  assert(rx==reserved&&rw==reserved+delta&&!close(fd));
  auto *state=new(rw) CompileState();
  const auto canonical_before=MadeiraFEXCompileStorage.total.load();
  select_state(nullptr);assert(&MadeiraFEXCompileStats()==&MadeiraFEXCompileStorage);actual_fixed(0x1111);
  assert(MadeiraFEXCompileStorage.total==canonical_before+1);
  select_state(state);assert(&MadeiraFEXCompileStats()==state);
  for(unsigned i=0;i<10000;i++)actual_fixed(i&1?0xabc:0xdef);
  assert(state->total==10000&&MadeiraFEXCompileStorage.total==canonical_before+1);
  uint64_t visible=0;std::memcpy(&visible,static_cast<unsigned char*>(rx)+offsetof(CompileState,total),sizeof(visible));
  assert(visible==10000);select_state(nullptr);state->~CompileState();
  assert(!munmap(reserved,delta+page));
  std::puts("PASS actual getter/staged updates select own retained RW alias; canonical fallback intact;10000 shared RX-visible counter updates with RX never made writable");
}
int main(){
  sequential_and_underflow();held_sampler_nonblocking();concurrent_staged_reports();unique_tickets_and_report_cap();mapped_writer();
}
'''.replace('ACTUAL_GETTER', getter).replace('ACTUAL_FIXED_BLOCK', fixed_block).replace('ACTUAL_COMPILE_LINE', compile_line)
    cpp, binary = work / 'fixed.cpp', work / 'fixed'
    cpp.write_text(fixed_cpp)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                    '-I', str(ROOT / 'build/fex-compat'), str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=40)


# This separate executable deliberately omits sanitizers, logging and the
# staged-block fixture. It measures only the actual owned RecordDispatch
# helper on ordinary native RW storage; it does not measure Mach recovery or
# predict iPhone FPS. Both thread counts perform the same number of dispatches.
performance_cpp = r"""
#include "native_diagnostics.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <thread>
#include <vector>
static void run(unsigned threads){
  constexpr uint64_t events=524288;
  MadeiraFEXDiagnostics::CompileState state;
  std::atomic<unsigned> ready{0};std::atomic<bool> start{false};
  std::vector<std::thread> workers;
  for(unsigned n=0;n<threads;n++)workers.emplace_back([&,n]{
    ready.fetch_add(1,std::memory_order_release);
    while(!start.load(std::memory_order_acquire))std::this_thread::yield();
    for(uint64_t i=0;i<events/threads;i++)
      (void)MadeiraFEXDiagnostics::RecordDispatch(state,(i&31)?UINT64_C(0x12340000):UINT64_C(0x23450000)+n);
  });
  while(ready.load(std::memory_order_acquire)!=threads)std::this_thread::yield();
  const auto wall_start=std::chrono::steady_clock::now();const std::clock_t cpu_start=std::clock();
  start.store(true,std::memory_order_release);
  for(auto& worker:workers)worker.join();
  const std::clock_t cpu_end=std::clock();
  const auto wall=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-wall_start).count();
  const bool cpu_valid=cpu_start!=std::clock_t(-1)&&cpu_end!=std::clock_t(-1)&&cpu_end>=cpu_start;
  const uint64_t cpu=cpu_valid?static_cast<uint64_t>((static_cast<long double>(cpu_end-cpu_start)*1000000000.0L)/CLOCKS_PER_SEC):0;
  const uint64_t total=state.total.load(),skips=state.sample_skips.load();
  assert(total==events&&skips<=total&&state.hot_balance.load()<=total-skips&&state.sampling.load()==0);
  std::printf("[fex-cb-native-cost] fixture=unsanitized-actual-header-native-RW workers=%u dispatches=%llu estimator-samples=%llu sample-skips=%llu wall-ns=%llu process-cpu-ns=%llu cpu-clock-valid=%u no-Mach-no-gameplay-extrapolation\n",
              threads,(unsigned long long)total,(unsigned long long)(total-skips),(unsigned long long)skips,
              (unsigned long long)wall,(unsigned long long)cpu,cpu_valid?1u:0u);
}
int main(){run(1);run(8);}
"""
with tempfile.TemporaryDirectory(prefix='madeira-fex-cb-native-cost-') as directory:
    work=Path(directory)
    cpp,binary=work/'cost.cpp',work/'cost'
    cpp.write_text(performance_cpp)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-O2','-Wall','-Wextra','-Werror','-pthread',
                    '-I',str(ROOT/'build/fex-compat'),str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=40)
