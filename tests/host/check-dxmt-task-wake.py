#!/usr/bin/env python3
"""Run the production DXMT task scheduler with real native host threads.

Only the platform thread/condition-variable adapters are hosted. The complete
pinned/staged scheduler, ready queues, dependency locks and shutdown body run
unchanged. Host measurements are not CS2 FPS or iPhone scheduling results.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NAME = 'src/dxmt/dxmt_tasks.hpp'
spec = importlib.util.spec_from_file_location('dxmt_task_wake', ROOT / 'tools/build/stage-dxmt-task-wake.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
CXX = shlex.split(os.environ.get('CXX', 'c++'))

PREFIX = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
using namespace std::chrono_literals;
static constexpr int THREAD_PRIORITY_TIME_CRITICAL=15;
static int GetCurrentThread(){return 0;}
static int SetThreadPriority(int,int){return 1;}
static std::atomic<unsigned> one_wakes{0}, all_wakes{0}, waits{0}, completion_queue_locks{0};
// Observational host adapter: task SetIsDone begins completion accounting and
// the unchanged production running.fetch_sub boundary ends it. Only the ready
// queue lock can be acquired inside that interval; task dependency locking and
// ordinary worker polling stay outside it.
static thread_local bool host_in_completion=false;
static void host_completion_end(){host_in_completion=false;}
static std::atomic<bool> pause_wait{false}, claimed_wait{false}, entered_wait{false}, release_wait{false};
namespace dxmt {
class mutex {
  std::mutex native;
public:
  void lock(){if(host_in_completion)completion_queue_locks.fetch_add(1);native.lock();}
  void unlock(){native.unlock();}
  bool try_lock(){if(host_in_completion)completion_queue_locks.fetch_add(1);return native.try_lock();}
};
class condition_variable;
static std::atomic<condition_variable*> paused_condition{nullptr};
class condition_variable {
  std::condition_variable_any cv;
public:
  template<class Lock,class Pred> void wait(Lock&lock,Pred pred){
    while(!pred()){
      if(pause_wait.load() && !claimed_wait.exchange(true)){
        paused_condition.store(this);
        entered_wait.store(true);
        // This is the real checked-predicate -> native-wait boundary, still
        // holding the production scheduler's worker mutex.
        while(!release_wait.load()) std::this_thread::yield();
      }
      waits.fetch_add(1);
      cv.wait(lock);
    }
  }
  void notify_one(){cv.notify_one();one_wakes.fetch_add(1);}
  void notify_all(){cv.notify_all();all_wakes.fetch_add(1);}
  void rescue(){cv.notify_all();}
};
class thread {
  std::thread native;
public:
  template<class Fn> explicit thread(Fn&&fn):native(std::forward<Fn>(fn)){}
  thread(thread&&)=default;
  bool joinable(){return native.joinable();}
  void join(){native.join();}
  static unsigned hardware_concurrency(){return 4;}
};
}
template<class Pred> static void eventually(Pred pred,const char*reason){
 const auto limit=std::chrono::steady_clock::now()+5s;
 while(!pred()){
  if(std::chrono::steady_clock::now()>limit){std::fprintf(stderr,"TIMEOUT %s\n",reason);std::abort();}
  std::this_thread::sleep_for(100us);
 }
}
'''

SUFFIX = r'''
struct Job {
  std::atomic<bool> done{false};
  std::atomic<unsigned> attempts{0}, completed{0};
  Job*dependency=nullptr;
  std::atomic<bool>*gate=nullptr;
};
namespace dxmt {
template<> struct task_trait<Job*> {
 Job*run_task(Job*j){
  j->attempts.fetch_add(1);
  if(j->dependency && !j->dependency->done.load(std::memory_order_acquire))return j->dependency;
  if(j->gate)while(!j->gate->load())std::this_thread::yield();
  j->completed.fetch_add(1);
  return j;
 }
 bool get_done(Job*j){return j->done.load(std::memory_order_acquire);}
 void set_done(Job*j){j->done.store(true,std::memory_order_release);host_in_completion=true;}
};
}

static void independent(bool candidate){
 one_wakes=0;all_wakes=0;waits=0;completion_queue_locks=0;
 constexpr unsigned count=512;
 std::vector<std::unique_ptr<Job>> jobs;
 for(unsigned i=0;i<count;++i)jobs.emplace_back(std::make_unique<Job>());
 unsigned submitted_wakes=0;
 const auto start=std::chrono::steady_clock::now();
 {
  dxmt::task_scheduler<Job*> scheduler;
  for(auto&job:jobs)scheduler.submit(job.get());
  for(auto&job:jobs)eventually([&]{return job->done.load();},"independent job");
  for(auto&job:jobs)assert(job->completed==1);
  // GetIsDone publishes before the completion wake. Quiescence excludes a
  // partially observed final completion from the notification comparison.
  eventually([&]{return scheduler.get_running_threads()==0;},"quiescent independent jobs");
  submitted_wakes=one_wakes.load();
  assert(submitted_wakes==count);
  assert(all_wakes==(candidate?0:count));
  assert(completion_queue_locks==(candidate?0:count));
 }
 const auto us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
 assert(all_wakes==(candidate?1:count+1)); // One genuine shutdown broadcast.
 std::printf("%s independent tasks=%u submit-one=%u completion-all=%u completion-queue-locks=%u elapsed-us=%lld\n",
  candidate?"candidate":"baseline",count,submitted_wakes,unsigned(all_wakes)-1,unsigned(completion_queue_locks),(long long)us);
}

static void fanout(bool candidate){
 one_wakes=0;all_wakes=0;waits=0;completion_queue_locks=0;
 constexpr unsigned dependents=40;
 std::atomic<bool> gate{false};
 Job root;root.gate=&gate;
 std::vector<std::unique_ptr<Job>> jobs;
 for(unsigned i=0;i<dependents;++i){auto j=std::make_unique<Job>();j->dependency=&root;jobs.push_back(std::move(j));}
 unsigned completion_ones=0,completion_alls=0;
 {
  dxmt::task_scheduler<Job*> scheduler;
  scheduler.submit(&root);
  eventually([&]{return root.attempts==1;},"root started");
  for(auto&job:jobs)scheduler.submit(job.get());
  for(auto&job:jobs)eventually([&]{return job->attempts>=1;},"dependent registered or in registration");
  gate=true;
  eventually([&]{return root.done.load();},"root completion");
  for(auto&job:jobs)eventually([&]{return job->done.load();},"dependent completion");
  eventually([&]{return scheduler.get_running_threads()==0;},"quiescent fanout");
  for(auto&job:jobs)assert(job->completed==1 && job->attempts>=2);
  completion_ones=one_wakes.load()-(dependents+1);
  completion_alls=all_wakes.load();
  if(candidate){assert(completion_alls==0);assert(completion_ones>=1 && completion_ones<=8);}
  else assert(completion_alls==dependents+1);
  assert(completion_queue_locks==(candidate?1:dependents+1));
 }
 std::printf("%s fanout=%u completion-one=%u completion-all=%u completion-queue-locks=%u all-jobs-once=1\n",
  candidate?"candidate":"baseline",dependents,completion_ones,completion_alls,unsigned(completion_queue_locks));
}

static void idle_workload(bool candidate){
 one_wakes=0;all_wakes=0;waits=0;completion_queue_locks=0;
 constexpr unsigned workers=8,count=96;
 std::atomic<bool> gate{false};
 std::vector<std::unique_ptr<Job>> warm, jobs;
 for(unsigned i=0;i<workers;++i){auto j=std::make_unique<Job>();j->gate=&gate;warm.push_back(std::move(j));}
 for(unsigned i=0;i<count;++i)jobs.emplace_back(std::make_unique<Job>());
 {
  dxmt::task_scheduler<Job*> scheduler;
  scheduler.submit(warm[0].get());scheduler.submit(warm[1].get());
  eventually([&]{return scheduler.get_running_threads()==2;},"warm initial workers");
  for(unsigned i=2;i<workers;++i){
   scheduler.submit(warm[i].get());
   eventually([&]{return scheduler.get_running_threads()==i+1;},"warm additional worker");
  }
  gate=true;
  for(auto&j:warm)eventually([&]{return j->done.load();},"warm worker done");
  eventually([&]{return scheduler.get_running_threads()==0;},"warm pool idle");
  std::this_thread::sleep_for(2ms);
  one_wakes=0;all_wakes=0;waits=0;completion_queue_locks=0;
  const auto cpu_start=std::clock();
  const auto start=std::chrono::steady_clock::now();
  for(auto&j:jobs){
   scheduler.submit(j.get());
   eventually([&]{return j->done.load() && scheduler.get_running_threads()==0;},"idle workload task");
   // Let genuine native waits park between cache-hit-like independent tasks.
   std::this_thread::sleep_for(250us);
  }
  const auto us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
  const auto cpu_us=(std::clock()-cpu_start)*1000000.0/CLOCKS_PER_SEC;
  assert(one_wakes==count && all_wakes==(candidate?0:count));
  assert(completion_queue_locks==(candidate?0:count));
  // The scheduler's own queued tasks complete exactly once under both paths.
  for(auto&j:jobs)assert(j->completed==1);
  std::printf("%s idle-pool tasks=%u native-wait-entries=%u completion-all=%u process-cpu-us=%.0f wall-us=%lld\n",
   candidate?"candidate":"baseline",count,unsigned(waits),unsigned(all_wakes),cpu_us,(long long)us);
 }
}

static void dependency_races(){
 // Complete roots concurrently with dependency registration and submission.
 // Both sides of the deps_mutex_/GetIsDone handshake must execute each child
 // exactly once, with no fabricated task completion or stranded ready work.
 for(unsigned round=0;round<60;++round){
  std::atomic<bool> gate{false};Job root;root.gate=&gate;
  std::vector<std::unique_ptr<Job>> jobs;
  for(unsigned i=0;i<24;++i){auto j=std::make_unique<Job>();j->dependency=&root;jobs.push_back(std::move(j));}
  dxmt::task_scheduler<Job*> scheduler;
  scheduler.submit(&root);
  std::thread producer([&]{for(auto&j:jobs)scheduler.submit(j.get());});
  if(round%2)std::this_thread::yield();
  gate=true;producer.join();
  for(auto&j:jobs)eventually([&]{return j->done.load();},"racing dependency");
  for(auto&j:jobs)assert(j->completed==1);
 }
 std::puts("candidate dependency publication races=60 all-jobs-once=1");
}

static void shutdown_race(bool candidate){
 one_wakes=0;all_wakes=0;waits=0;
 pause_wait=true;claimed_wait=false;entered_wait=false;release_wait=false;
 auto scheduler=std::make_unique<dxmt::task_scheduler<Job*>>();
 eventually([]{return entered_wait.load();},"worker predicate/wait gate");
 std::atomic<bool> entered_shutdown{false},shutdown_done{false};
 std::thread closer([&]{entered_shutdown=true;scheduler.reset();shutdown_done=true;});
 eventually([&]{return entered_shutdown.load();},"shutdown entered");
 if(!candidate)eventually([]{return all_wakes.load()==1;},"baseline lost shutdown notification");
 else std::this_thread::sleep_for(10ms);
 const bool notified_before_park=all_wakes.load()!=0;
 assert(notified_before_park==!candidate);
 release_wait=true;
 if(!candidate){
  // The old notify occurred while the gated worker still held its mutex,
  // before it could enter native wait. Rescue this negative control only.
  eventually([]{return waits.load()>=1;},"baseline enters wait");
  std::this_thread::sleep_for(10ms);
  assert(!shutdown_done.load());
  dxmt::paused_condition.load()->rescue();
 }
 eventually([&]{return shutdown_done.load();},"scheduler shutdown");
 closer.join();pause_wait=false;
 std::printf("%s shutdown-notification-before-park=%u external-rescue=%u\n",
  candidate?"candidate":"baseline",notified_before_park,!candidate);
}

int main(int argc,char**argv){
 const bool candidate=argc==2 && argv[1][0]=='1';
 independent(candidate);fanout(candidate);idle_workload(candidate);shutdown_race(candidate);
 if(candidate)dependency_races();
}
'''


def hosted(source):
    boundary = '    running.fetch_sub(1, std::memory_order_relaxed);'
    assert source.count(boundary) == 1, 'production completion accounting boundary changed'
    source = source.replace(boundary, '    host_completion_end();\n' + boundary, 1)
    return '\n'.join(line for line in source.splitlines()
                     if not line.startswith('#include "') and line != '#pragma once')


def main():
    path = ROOT / 'dxmt' / NAME
    original = path.read_bytes()
    candidate = stage.stage_file(NAME, original.decode())
    # Worker priorities/limits and task/dependency readiness code are retained.
    for anchor in ('max_threads = dxmt::thread::hardware_concurrency() * 2;',
                   'SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);',
                   'task_trait.set_done(continuation);',
                   'task_continuation_.insert({continuation, task});',
                   'worker_cond_.notify_one();'):
        assert anchor in candidate
    try:
        stage.stage_file(NAME, candidate)
    except ValueError:
        pass
    else:
        raise AssertionError('double staging accepted')
    with tempfile.TemporaryDirectory(prefix='madeira-dxmt-task-wake-') as directory:
        directory = Path(directory)
        for name, source in (('baseline', original.decode()), ('candidate', candidate)):
            cpp = directory / (name + '.cpp')
            executable = directory / name
            cpp.write_text(PREFIX + hosted(source) + SUFFIX)
            subprocess.run([*CXX, '-std=c++20', '-O2', '-pthread', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', str(cpp), '-o', str(executable)], check=True)
            subprocess.run([str(executable), '1' if name == 'candidate' else '0'], check=True, timeout=40)
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(original).digest()
    print('PASS production DXMT scheduler: empty-completion queue lock elision, work-proportional wakes, genuine fanout and completion races, '
          'lost shutdown wake negative control and synchronized correction; host threads, not iPhone FPS')


if __name__ == '__main__':
    main()
