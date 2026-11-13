#!/usr/bin/env python3
"""Execute the source-staged WOW syscall body against protected alias storage."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def body(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]


def main():
    with tempfile.TemporaryDirectory(prefix='madeira-wow-syscall-writer-') as directory:
        work = Path(directory)
        spec = importlib.util.spec_from_file_location('fex_stage', ROOT / 'tools/build/stage-fex-compat.py')
        stager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stager)
        staged = work / 'staged'
        stager.stage(staged, ROOT / 'FEX', 'wow64')
        relative = 'Source/Windows/WOW64/Module.cpp'
        old_source = (ROOT / 'FEX' / relative).read_text()
        new_source = (staged / relative).read_text()
        signature = 'extern "C" IosSyscallResume IosWowSyscallC('
        old = body(old_source, signature)
        new = body(new_source, signature)
        selected = 'MadeiraFEXNativeWriter(MadeiraFEXSyscallWriteContract, MadeiraFEXSyscallDeclined)'
        original_declaration = '  static std::atomic<uint32_t> Redirects {0}, Declined {0};'
        replacement_declaration = '  static std::atomic<uint32_t> Redirects {0};'
        restored = new.replace(selected, 'Declined').replace(replacement_declaration, original_declaration)
        assert restored == old, 'syscall execution, parking, counters, ordering, and logs must remain intact'
        assert 'alignas(8) std::atomic<uint32_t> MadeiraFEXSyscallDeclined {0};' in new_source
        assert 'MadeiraFEXSyscallTag, sizeof(MadeiraFEXSyscallDeclined), alignof(decltype(MadeiraFEXSyscallDeclined))' in new_source
        exports = (staged / 'Source/Windows/WOW64/libwow64fex.def').read_text()
        assert '  MadeiraFEXSyscallWriteContract DATA\n  MadeiraFEXSyscallDeclined DATA\n' in exports
        resume = body(old_source, 'struct IosSyscallResume {') + ';'
        # Both bodies execute their original statements. Only the old function's
        # canonical counter placement is adapted to the shared protected page.
        old = old.replace('IosWowSyscallC(', 'OldIosWowSyscallC(', 1)
        old = old.replace(original_declaration, replacement_declaration + '\n  auto& Declined = *syscall_canonical;')
        source = PRELUDE + resume + '\n' + old + '\n' + new + '\n' + HARNESS
        cpp = work / 'syscall.cpp'
        cpp.write_text(source)
        compiler = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('c++')
        assert compiler, 'a C++ compiler is required'
        executable = work / 'syscall-test'
        subprocess.run([compiler, '-std=c++20', '-O2', '-pthread', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT / 'build/fex-compat'), str(cpp), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
    print('WOW syscall writer: production body, native atomics, protected aliases, parking, and fallback passed')


PRELUDE = r'''
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <new>
#include <thread>
#include <vector>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "native_diagnostics.h"
static_assert(sizeof(std::atomic<uint32_t>) == 4);
static MadeiraFEXNativeWriteContract *syscall_contract;
static std::atomic<uint32_t> *syscall_canonical;
#define MadeiraFEXSyscallWriteContract (*syscall_contract)
#define MadeiraFEXSyscallDeclined (*syscall_canonical)
struct FrontendData {
  uint32_t IosSyscallDepth = 0;
  bool IosSyscallArmed = false, IosSweepRegistered = true;
  uint32_t IosMigrated = 0;
};
static thread_local FrontendData current;
struct FixtureTLS { FrontendData *ThreadState() const { return &current; } };
static FixtureTLS GetTLS() { return {}; }
static FrontendData *GetFrontendThreadData(FrontendData *thread) { return thread; }
static std::atomic<uint32_t> declined_logs {0}, resumed_logs {0};
namespace LogMan::Msg {
template<typename... T> void EFmt(const char *format, T&&...) {
  if (strstr(format, "not parked")) declined_logs.fetch_add(1, std::memory_order_relaxed);
  if (strstr(format, "resumed")) resumed_logs.fetch_add(1, std::memory_order_relaxed);
}
}
namespace FEXCore::Core {
struct CpuStateFrame {
  uint64_t ReturningStackLocation = 0x9000;
  struct { uint64_t DispatcherLoopTopFillSRA = 0x1234000; } Pointers;
  uint64_t InSyscallInfo = 0x55;
  struct { uint64_t rip = 0xabc; } State;
};
}
namespace FEXCore::HLE {
struct SyscallArguments { uint64_t marker = 0x123; };
struct SyscallHandler {
  unsigned calls = 0, expected_depth = 1;
  bool expected_arm = false, migrate = false;
  void HandleSyscall(FEXCore::Core::CpuStateFrame *frame, SyscallArguments *args) {
    assert(args->marker == 0x123 && current.IosSyscallDepth == expected_depth);
    assert(current.IosSyscallArmed == expected_arm);
    ++calls;
    if (migrate) {
      current.IosMigrated = 1;
      frame->ReturningStackLocation = 0xbad0;
      frame->InSyscallInfo = 0xbad;
    }
  }
};
}
'''


HARNESS = r'''
using Frame = FEXCore::Core::CpuStateFrame;
using Handler = FEXCore::HLE::SyscallHandler;
using Arguments = FEXCore::HLE::SyscallArguments;
static void declined_call() {
  current = {};
  Frame frame;
  frame.ReturningStackLocation = 0x8000;
  Handler handler;
  Arguments args;
  const auto result = IosWowSyscallC(&handler, &frame, &args, 0x9000);
  assert(handler.calls == 1 && !result.NewSP && !result.Target);
  assert(current.IosSyscallDepth == 0 && !current.IosSyscallArmed);
}
int main() {
  rlimit no_core {0, 0};
  assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
  char path[] = "/tmp/madeira-wow-counter-XXXXXX";
  const int fd = mkstemp(path);
  assert(fd >= 0 && unlink(path) == 0);
  const size_t size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  assert(ftruncate(fd, size) == 0);
  auto *rw = static_cast<unsigned char*>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  auto *rx = static_cast<unsigned char*>(mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0));
  assert(rw != MAP_FAILED && rx != MAP_FAILED && rw != rx);
  close(fd);
  syscall_contract = new(rw) MadeiraFEXNativeWriteContract {
    MadeiraFEXSyscallTag, 4, 4, rx + 64, reinterpret_cast<uintptr_t>(rw + 64)};
  auto *counter = new(rw + 64) std::atomic<uint32_t> {0};
  syscall_canonical = reinterpret_cast<std::atomic<uint32_t>*>(rx + 64);
  // The original production increment faults against the protected canonical
  // view; the source-staged function increments through its retained RW alias.
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    Frame frame;
    frame.ReturningStackLocation = 0x8000;
    Handler handler;
    Arguments args;
    OldIosWowSyscallC(&handler, &frame, &args, 0x9000);
    _exit(3);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
  assert(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
  assert(counter->load() == 0);
  for (unsigned i = 0; i < 8; ++i) declined_call();
  assert(counter->load() == 8 && syscall_canonical->load() == 8 && declined_logs.load() == 4);
  constexpr unsigned workers = 8, calls = 4000;
  std::vector<std::thread> threads;
  for (unsigned i = 0; i < workers; ++i) threads.emplace_back([] {
    for (unsigned j = 0; j < calls; ++j) declined_call();
  });
  for (auto& thread : threads) thread.join();
  assert(counter->load() == 8 + workers * calls && declined_logs.load() == 4);
  const auto total = counter->load();
  // Exercise the real outer/deep syscall and migration branches. The private
  // writer changes no decision, syscall arguments, depth restoration or resume.
  for (unsigned mode = 0; mode < 5; ++mode) {
    current = {};
    current.IosSyscallArmed = true;
    Frame frame;
    Handler handler;
    Arguments args;
    if (mode == 0) handler.expected_arm = true;
    if (mode == 1) { handler.expected_arm = true; handler.migrate = true; }
    if (mode == 2) { current.IosSyscallDepth = 2; handler.expected_depth = 3; }
    if (mode == 3) current.IosSweepRegistered = false;
    if (mode == 4) frame.Pointers.DispatcherLoopTopFillSRA = 0;
    const auto result = IosWowSyscallC(&handler, &frame, &args, 0x8f00);
    assert(handler.calls == 1 && current.IosSyscallArmed);
    assert(current.IosSyscallDepth == (mode == 2 ? 2u : 0u));
    if (mode == 1) {
      assert(result.NewSP == 0x9000 && result.Target == 0x1234000);
      assert(frame.ReturningStackLocation == 0x9000 && !frame.InSyscallInfo && !current.IosMigrated);
    } else assert(!result.NewSP && !result.Target);
  }
  assert(counter->load() == total && resumed_logs.load() == 1);
  // Missing/unknown ABI keeps canonical-address execution and recovery.
  __atomic_store_n(&syscall_contract->writer, uintptr_t{0}, __ATOMIC_RELEASE);
  const pid_t fallback_child = fork();
  assert(fallback_child >= 0);
  if (!fallback_child) { declined_call(); _exit(3); }
  assert(waitpid(fallback_child, &status, 0) == fallback_child && WIFSIGNALED(status));
  assert(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
  assert(counter->load() == total);
  std::atomic<uint32_t> fallback {0};
  syscall_canonical = &fallback;
  declined_call();
  assert(fallback.load() == 1 && counter->load() == total);
  assert(munmap(rx, size) == 0 && munmap(rw, size) == 0);
}
'''


if __name__ == '__main__':
    main()
