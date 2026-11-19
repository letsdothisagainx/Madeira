#!/usr/bin/env python3
"""Replay the staged sweep/migration with real locks and shared references.

The clock and platform boundary are controlled; migration, registry, lifetime,
retry decisions and both new cached-return branches are literal production code.
This is not an iPhone timing or game-progress benchmark.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    for match in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', source[brace:], re.S):
        if match[0] == '{':
            depth += 1
        elif match[0] == '}':
            depth -= 1
            if not depth:
                return source[start:brace + match.end()]
    raise AssertionError(signature)


def check():
    original = (ROOT / 'FEX/FEXCore/Source/Interface/Core/CPUBackend.cpp').read_text()
    with tempfile.TemporaryDirectory(prefix='madeira-code-sweep-') as temporary:
        directory = Path(temporary)
        stage = directory / 'staged'
        subprocess.run(['python3', str(ROOT / 'tools/build/stage-fex-compat.py'),
                        'stage', str(stage), '--backend', 'both'], check=True)
        current = (stage / 'FEXCore/Source/Interface/Core/CPUBackend.cpp').read_text()
        core = (stage / 'FEXCore/Source/Interface/Core/Core.cpp').read_text()
        compile_block = function(core, 'uintptr_t ContextImpl::CompileBlock(')
        lookup = (ROOT / 'FEX/FEXCore/Source/Interface/Core/LookupCache.h').read_text()
        lookup_find = function(lookup, '  uintptr_t FindBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address)')
        assert lookup_find.index('auto lk = Shared->AcquireReadLock();') < lookup_find.index('    if (HostPtr && DynamicL1Cache())')
        assert 'IosSweepRetryLeft' not in current
        assert 'std::chrono::steady_clock::now()' in function(current, '  static uint64_t IosSweepMonotonicUS()')
        cache_branch = function(compile_block, '    if (auto HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP))')
        race_branch = function(compile_block, 'if (!DebugData)')
        assert 'IosMaybeSweepCodeBuffers(Thread);' in cache_branch
        assert 'if (!IosUnpublished)' in race_branch
        assert compile_block.index('lk = std::shared_lock {CodeInvalidationMutex};') < compile_block.index(cache_branch)
        assert compile_block.index('CompileCode(Thread, GuestRIP, MaxInst)') < compile_block.index(race_branch)
        assert '#if defined(_WIN32)' in cache_branch
        assert '#if defined(FEX_IOS_HOST) && defined(_WIN32)' in race_branch

        common = r'''
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>
#include <cstring>
#include <algorithm>
#include <utility>
#define FEX_IOS_HOST 1
#define _WIN32 1
namespace fextl {template<class T> using shared_ptr=std::shared_ptr<T>;}
namespace LogMan::Msg {template<class... A> void EFmt(const char*,A&&...) {}}
static thread_local bool invalidation_owned,lookup_read_owned;
static std::atomic<unsigned> destroyed{},clock_queries{},write_attempts{},migration_count{},reset_count{};
static std::atomic<uint64_t> fixture_time{100000};
static std::atomic<bool> map_entered{};
static uint64_t IosSweepMonotonicUS(){++clock_queries;return fixture_time.load();}
struct Map {
 std::shared_mutex lock;
 auto AcquireWriteLock(){
   assert(invalidation_owned&&!lookup_read_owned);
   ++write_attempts;map_entered=true;
   return std::unique_lock{lock};
 }
};
struct Buffer {
 std::unique_ptr<Map> map=std::make_unique<Map>();Map* LookupCache=map.get();
 ~Buffer(){++destroyed;}
};
using CodeBuffer=Buffer;
struct Manager {
 std::shared_ptr<Buffer> Latest;
 std::atomic<unsigned> calls{};
 std::shared_ptr<Buffer> GetLatest(){++calls;return Latest;}
};
struct Thread;
namespace FEXCore::Core {
 using InternalThreadState=::Thread;
 void ResetCallRetStack(Thread*,const char*){++reset_count;}
}
struct Frame {unsigned SignalHandlerRefCounter=0;};
struct Lookup {
 Map* Shared;
 uintptr_t FindBlock(Thread*,uint64_t){
   assert(invalidation_owned&&!lookup_read_owned);
   {std::shared_lock guard(Shared->lock);lookup_read_owned=true;lookup_read_owned=false;}
   return 0x12345000;
 }
 template<class Token> void ChangeGuestToHostMapping(Buffer& prev,Map& next,const Token& lk){
   assert(lk.owns_lock()&&Shared==prev.LookupCache&&invalidation_owned);
   Shared=&next;++migration_count;
 }
};
using IosMigrateLockGuard=std::scoped_lock<std::mutex>;
struct Backend {
 std::shared_ptr<Buffer> CurrentCodeBuffer;
 std::vector<std::shared_ptr<Buffer>> SignalHandlerCodeBuffers;
 std::mutex IosMigrateLock;
 Thread* ThreadState;
 Manager* manager;
 Manager& GetCodeBufferManager(){return *manager;}
 int IosRemoteMigrateStale(const std::shared_ptr<Buffer>& LatestBuf);
};
struct Thread {Backend* CPUBackend;Frame* CurrentFrame;Lookup* LookupCache;};
static std::atomic<uint64_t> IosCodeBufferGenCounter{1};
static uint64_t IosCodeBufferSweepGate=0;
'''
        migration = function(current, '  int CPUBackend::IosRemoteMigrateStale(').replace('CPUBackend::', 'Backend::')
        registration = function(current, '  extern "C" void IosSweepRegisterThreadEx(')
        arm_registration = function(current, '  extern "C" void IosSweepRegisterThread(FEXCore::Core::InternalThreadState* Thread, volatile uint8_t* InSimPtr) {\n    std::scoped_lock')
        unregister = function(current, '  extern "C" void IosSweepUnregisterThread(').replace('__asm volatile("yield");', 'std::this_thread::yield();')
        cache_functions = r'''
static std::shared_mutex invalidation_mutex;
static uintptr_t cache_hit(Thread* Thread,uint64_t GuestRIP){
 std::shared_lock invalidation(invalidation_mutex);invalidation_owned=true;
''' + cache_branch + r'''
 return 0;
}
static uintptr_t raced_cache(Thread* Thread,bool IosUnpublished){
 std::shared_lock invalidation(invalidation_mutex);invalidation_owned=true;
 auto* CodePtr=reinterpret_cast<uint8_t*>(0x12345000);bool DebugData=false;
''' + race_branch + r'''
 return 0;
}
'''
        for baseline in (True, False):
            source = original if baseline else current
            registry_start = source.index('  namespace {\n    struct IosSweepSlot')
            registry_end = source.index('  } // namespace', registry_start) + len('  } // namespace')
            registry = source[registry_start:registry_end]
            if baseline:
                policy_start = source.index('  static std::atomic<uint32_t> IosSweepRetryLeft')
            else:
                policy_start = source.index('  static std::atomic<uint32_t> IosSweepThrottle')
            policy_end = source.index('  extern "C" void IosMaybeSweepCodeBuffers(', policy_start)
            policy = source[policy_start:policy_end]
            if not baseline:
                production_clock = function(policy, '  static uint64_t IosSweepMonotonicUS()')
                policy = policy.replace(production_clock, production_clock.replace('IosSweepMonotonicUS', 'ProductionMonotonicUS'))
            sweep = function(source, '  extern "C" void IosMaybeSweepCodeBuffers(')
            code = common + migration + registry + '\n#if !defined(ARCHITECTURE_arm64ec)\n' + registration + '\n#else\n' + arm_registration + '\n#endif\n' + unregister + policy + sweep
            if not baseline:
                code += cache_functions
            code += r'''
struct Pair {
 Manager manager;
 Frame caller_frame,target_frame;
 Lookup caller_lookup,target_lookup;
 Backend caller_backend,target_backend;
 Thread caller{&caller_backend,&caller_frame,&caller_lookup};
 Thread target{&target_backend,&target_frame,&target_lookup};
 volatile uint8_t in_sim=1,migrated=0;
 std::weak_ptr<Buffer> old;
 Pair(bool caller_old=false){
   memset(IosSweepSlots,0,sizeof(IosSweepSlots));IosSweepSlotHighWater=0;
   IosSweepBusy=0;IosSweepLastGen=0;IosSweepLastSkipped=0;IosSweepThrottle=0;
#ifdef BASELINE
   IosSweepRetryLeft=0;
#else
   IosSweepNextRetryUS=0;
#endif
   IosCodeBufferGenCounter=1;fixture_time=100000;write_attempts=0;map_entered=false;clock_queries=0;
   manager.Latest=std::make_shared<Buffer>();
   caller_backend.manager=target_backend.manager=&manager;
   caller_backend.ThreadState=&caller;target_backend.ThreadState=&target;
   target_backend.CurrentCodeBuffer=std::make_shared<Buffer>();old=target_backend.CurrentCodeBuffer;
   caller_backend.CurrentCodeBuffer=caller_old?target_backend.CurrentCodeBuffer:manager.Latest;
   target_lookup.Shared=target_backend.CurrentCodeBuffer->LookupCache;
   caller_lookup.Shared=caller_backend.CurrentCodeBuffer->LookupCache;
#if !defined(ARCHITECTURE_arm64ec)
   IosSweepRegisterThreadEx(&target,&in_sim,&migrated);
#else
   IosSweepRegisterThread(&target,&in_sim);
#endif
 }
 ~Pair(){IosSweepUnregisterThread(&target);assert(!IosSweepBusy&&!IosCodeBufferSweepGate);}
 void trigger(unsigned n=1,uint64_t step=1000){
   invalidation_owned=true;
   for(unsigned i=0;i<n;i++){fixture_time+=step;IosMaybeSweepCodeBuffers(&caller);}
   invalidation_owned=false;
 }
};
int main(){
 {
   Pair p;p.trigger();p.trigger(4096);
#ifdef BASELINE
   assert(IosSweepRetryLeft==0);
#endif
   p.in_sim=0;p.trigger(10000);
#ifdef BASELINE
   assert(!p.old.expired()&&p.target_backend.CurrentCodeBuffer!=p.manager.Latest&&write_attempts==0);
   puts("BASELINE REPRODUCED: actual sweep exhausts256 retries/4096 triggers; eligible target retains old generation after10000 further triggers");
   return 0;
#else
   assert(p.old.expired()&&p.target_backend.CurrentCodeBuffer==p.manager.Latest);
   puts("PASS late migration: actual sweep releases final old-generation reference after more than4096 triggers and later eligibility");
#endif
 }
#ifndef BASELINE
 assert(std::chrono::steady_clock::is_steady);
 auto clock_before=ProductionMonotonicUS();auto clock_after=ProductionMonotonicUS();assert(clock_after>=clock_before);
 {
   Pair p;p.trigger();p.trigger(20000);
   assert(!p.old.expired()&&write_attempts==0);
   assert(p.manager.calls>256&&p.manager.calls<=1+20000000/IosSweepRetryIntervalUS);
   unsigned attempts=p.manager.calls.load();p.trigger(16000,0);assert(p.manager.calls==attempts);
   fixture_time=1;p.trigger(16000,0);assert(p.manager.calls==attempts);
   fixture_time=30000000;p.in_sim=0;p.trigger(16,0);assert(p.old.expired());
   puts("PASS continued simulation, no permanent retry exhaustion, monotonic deadline limits busy callers/stalled or regressing test clocks");
 }
 {
   Pair p;p.in_sim=0;p.target_frame.SignalHandlerRefCounter=1;p.trigger();p.trigger(20000);
   assert(!p.old.expired()&&p.target_backend.CurrentCodeBuffer!=p.manager.Latest&&write_attempts>256);
   p.target_frame.SignalHandlerRefCounter=0;p.trigger(64);assert(p.old.expired());
   puts("PASS signal-pinned generations remain referenced until the actual signal counter clears");
 }
 {
   Pair p;p.trigger();fixture_time+=IosSweepRetryIntervalUS;
   auto before=p.manager.calls.load();std::vector<std::thread> workers;
   for(unsigned i=0;i<32;i++)workers.emplace_back([&]{invalidation_owned=true;for(unsigned j=0;j<128;j++)IosMaybeSweepCodeBuffers(&p.caller);});
   for(auto& t:workers)t.join();
   assert(p.manager.calls==before+1&&!p.old.expired()&&!IosSweepBusy&&!IosCodeBufferSweepGate);
   fixture_time+=IosSweepRetryIntervalUS;p.in_sim=0;p.trigger(16,0);assert(p.old.expired());
   puts("PASS32 concurrent callers perform one same-generation sweep per deadline, with balanced entry/busy gates");
 }
 {
   Pair p;p.trigger();auto before=p.manager.calls.load();
   IosCodeBufferGenCounter++;p.trigger(1,0);assert(p.manager.calls==before+1);
   assert(!p.old.expired());
   puts("PASS new generations are considered immediately without waiting for the previous retry deadline");
 }
 {
   Pair p;p.trigger();p.in_sim=0;fixture_time+=IosSweepRetryIntervalUS;
   auto old=p.target_backend.CurrentCodeBuffer;std::unique_lock map_lock(old->LookupCache->lock);
   std::atomic<bool> removed=false;
   std::thread sweep([&]{p.trigger(16,0);});
   while(!map_entered.load())std::this_thread::yield();
   std::thread unregister([&]{IosSweepUnregisterThread(&p.target);removed=true;});
   for(unsigned i=0;i<1000;i++)std::this_thread::yield();
   assert(!removed&&IosSweepBusy);
   map_lock.unlock();sweep.join();unregister.join();old.reset();
   assert(removed&&p.old.expired());
   puts("PASS actual unregister waits for snapshotted migration and map-lock release before allowing thread destruction");
 }
 {
   Pair p(true);p.trigger();p.in_sim=0;fixture_time+=IosSweepRetryIntervalUS;
   for(unsigned i=0;i<16;i++)assert(cache_hit(&p.caller,0x1000)==0x12345000);
   assert(p.target_backend.CurrentCodeBuffer==p.manager.Latest&&!p.old.expired());
   assert(p.caller_backend.CurrentCodeBuffer!=p.manager.Latest);
   puts("PASS actual cached-return branch releases lookup-read before map-write sweep; returned code remains caller-pinned");
 }
 {
   Pair p;p.trigger();p.in_sim=0;fixture_time+=IosSweepRetryIntervalUS;
   for(unsigned i=0;i<16;i++)assert(raced_cache(&p.caller,true)==0x12345000);
   assert(!p.old.expired());
   for(unsigned i=0;i<16;i++)assert(raced_cache(&p.caller,false)==0x12345000);
   assert(p.old.expired());
   puts("PASS raced-cache return permits ordinary maintenance and excludes unpublished/reentrant delivery compilation");
 }
#endif
}
'''
            file = directory / ('baseline.cpp' if baseline else 'corrected.cpp')
            file.write_text(code)
            for architecture in ('wow64', 'arm64ec'):
                executable = directory / (file.stem + '-' + architecture)
                command = [os.environ.get('CXX', 'c++'), '-std=c++20', '-O1', '-g', '-pthread',
                           '-fsanitize=address,undefined', '-fno-sanitize-recover=all']
                if baseline:
                    command.append('-DBASELINE')
                if architecture == 'arm64ec':
                    command.append('-DARCHITECTURE_arm64ec')
                subprocess.run([*command, str(file), '-o', str(executable)], check=True)
                subprocess.run([str(executable)], check=True, timeout=30)
        print('PASS literal staged sweep/migration/registry and cache-return paths for WOW64 and ARM64EC; pinned FEX unchanged')


if __name__ == '__main__':
    check()
