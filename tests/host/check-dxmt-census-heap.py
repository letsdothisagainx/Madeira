#!/usr/bin/env python3
"""Run actual staged census helpers, cross-TU lifetime and repeated unloads.

This exercises native counters and ownership, not Metal execution or frame rate.
"""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'tools/build' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


stage = module('stage-dxmt-census-heap')
dynamic = module('stage-dxmt-dynamic-memory')

ALLOCATOR = r'''
#include "dxmt_mem_census.hpp"
#include <cstdlib>
#include <new>
extern "C" void census_lifecycle(char, void *);
static constinit void *tracked_state = nullptr;
void *operator new(std::size_t bytes) {
  void *p = std::malloc(bytes);
  if (!p) std::abort();
  if (bytes == sizeof(dxmt::MemCensusState)) {
    if (tracked_state) std::abort();
    tracked_state = p;
    census_lifecycle('a', p);
  }
  return p;
}
void operator delete(void *p) noexcept {
  if (p && p == tracked_state) {
    census_lifecycle('f', p);
    tracked_state = nullptr;
  }
  std::free(p);
}
void operator delete(void *p, std::size_t) noexcept { ::operator delete(p); }
extern "C" uint64_t MTLDevice_currentAllocatedSize(obj_handle_t) { return 0; }
'''

USER = r'''
#include "dxmt_mem_census.hpp"
#include <cassert>
extern "C" void census_lifecycle(char, void *);
namespace {
struct StaticUser {
  StaticUser() {
    auto &s = dxmt::memCensusState();
    s.live_buffer.created.fetch_add(1);
    census_lifecycle('c', &s);
  }
  ~StaticUser() {
    auto &s = dxmt::memCensusState();
    assert(s.live_buffer.created.load() == 2);
    s.live_buffer.destroyed.fetch_add(1);
    census_lifecycle('d', &s);
  }
} user;
}
extern "C" void *USER_ADDRESS() { return &dxmt::memCensusState(); }
'''

EXERCISE = r'''
#include "dxmt_mem_census.hpp"
#include <cassert>
#include <thread>
#include <vector>
extern "C" void *address_a();
extern "C" void *address_b();
extern "C" size_t exercise() {
  using namespace dxmt;
  auto &s = memCensusState();
  assert(address_a() == &s && address_b() == &s);
  assert(s.live_buffer.created.load() == 2 && !s.live_buffer.destroyed.load());
  assert(!s.census.live[MEMOWN_BUFFER].load() && !s.dynamic_next_id.load());
  assert(!s.dynamic[DYN_CENSUS_SLOTS - 1].trimmed_bytes.load());
  assert(!s.sites[BSITE_SLOTS - 1].total_bytes.load());
  assert(!s.device_valid && !s.last_report_ns.load() && !s.last_reported_seq.load());
  std::vector<std::thread> workers;
  for (unsigned thread = 0; thread != 4; ++thread) workers.emplace_back([] {
    for (unsigned n = 0; n != 1000; ++n) {
      mem_census_add(MEMOWN_BUFFER, 256);
      mem_census_buffer_detail(256, 0, 2, 1);
      buf_site_add(1234, 256);
      memCensusState().dynamic[3560].eligible_n.fetch_add(1);
      memCensusState().dynamic[3560].eligible_bytes.fetch_add(256);
      mem_census_buffer_detail(256, 0, 2, 0);
      mem_census_sub(MEMOWN_BUFFER, 256);
      buf_site_sub(1234, 256);
    }
  });
  for (auto &worker : workers) worker.join();
  assert(!s.census.live[MEMOWN_BUFFER].load());
  assert(s.census.requested[MEMOWN_BUFFER].load() == 4000 * 256);
  assert(s.census.allocs[MEMOWN_BUFFER].load() == 4000);
  assert(s.census.frees[MEMOWN_BUFFER].load() == 4000);
  assert(s.census.buf_bucket_n[0].load() == 4000 && !s.census.buf_bucket_live[0].load());
  assert(s.census.buf_storage_n[0].load() == 4000 && !s.census.buf_storage_live[0].load());
  assert(s.census.buf_flag_n[1].load() == 4000);
  assert(s.sites[0].total_n.load() == 4000 && !s.sites[0].live_bytes.load());
  assert(s.dynamic[3560].eligible_n.load() == 4000);
  assert(s.dynamic[3560].eligible_bytes.load() == 4000 * 256);
  s.dynamic_next_id.store(3561);
  mem_census_set_device(WMT::Device{});
  assert(s.device_valid);
  dyn_census_report();
  buf_site_report();
  mem_census_report("warn-test");
  return sizeof(s);
}
extern "C" void *image_cell() { return &dxmt::census_detail::state; }
extern "C" void exercise_readonly() {
  using namespace dxmt;
  auto &s = memCensusState();
  const uint64_t n = s.dynamic[3560].eligible_n.load();
  const uint64_t bytes = s.dynamic[3560].eligible_bytes.load();
  for (unsigned i = 0; i != 1000; ++i) {
    s.dynamic[3560].eligible_n.store(n + i + 1, std::memory_order_relaxed);
    s.dynamic[3560].eligible_bytes.store(bytes + (i + 1) * 256, std::memory_order_relaxed);
    s.dynamic[2024].wfa_min.store(i, std::memory_order_relaxed);
    s.last_report_ns.fetch_add(1, std::memory_order_relaxed);
    s.last_reported_seq.fetch_add(1, std::memory_order_relaxed);
    mem_census_add(MEMOWN_BUFFER, 256);
    mem_census_sub(MEMOWN_BUFFER, 256);
  }
  assert(s.dynamic[3560].eligible_n.load() == n + 1000);
  assert(s.dynamic[3560].eligible_bytes.load() == bytes + 256000);
  assert(s.dynamic[2024].wfa_min.load() == 999);
  assert(s.last_report_ns.load() == 1000 && s.last_reported_seq.load() == 1000);
  // These production report paths formerly mutated static ranking scratch.
  dyn_census_report(); buf_site_report(); mem_census_report("warn-readonly");
}
'''

LEGACY = r'''
#include "dxmt_mem_census.hpp"
namespace dxmt { DynStat g_dyn_stats[DYN_CENSUS_SLOTS]{}; }
extern "C" void *legacy_target() { return &dxmt::g_dyn_stats[3560]; }
extern "C" void legacy_store() {
  dxmt::g_dyn_stats[3560].eligible_n.store(1, std::memory_order_relaxed);
  dxmt::g_dyn_stats[3560].eligible_bytes.store(256, std::memory_order_relaxed);
}
'''

DRIVER = r'''
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <dlfcn.h>
#include <csignal>
#include <cstdint>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
static unsigned allocations, frees, constructors, destructors;
static void *state;
extern "C" void census_lifecycle(char event, void *p) {
  if (event == 'a') { assert(!state); state = p; ++allocations; }
  else {
    assert(p == state);
    if (event == 'c') ++constructors;
    else if (event == 'd') ++destructors;
    else if (event == 'f') {
      assert(constructors == 2 && destructors == 2);
      ++frees; state = nullptr;
    } else assert(false);
  }
}
int main(int argc, char **argv) {
  assert(argc == 3);
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto protect = [page_size](void *address, int flags) {
    void *page = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(address) & ~(page_size - 1));
    assert(mprotect(page, page_size, flags) == 0);
  };
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    rlimit no_core{}; setrlimit(RLIMIT_CORE, &no_core);
    void *legacy = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    assert(legacy);
    auto target = reinterpret_cast<void *(*)()>(dlsym(legacy, "legacy_target"));
    auto store = reinterpret_cast<void (*)()>(dlsym(legacy, "legacy_store"));
    assert(target && store);
    protect(target(), PROT_READ);
    store();
    _exit(7);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS));
  size_t bytes = 0;
  for (unsigned cycle = 0; cycle != 24; ++cycle) {
    allocations = frees = constructors = destructors = 0;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) { std::fprintf(stderr, "%s\n", dlerror()); return 1; }
    auto exercise = reinterpret_cast<size_t (*)()>(dlsym(module, "exercise"));
    assert(exercise);
    bytes = exercise();
    assert(allocations == 1 && !frees && constructors == 2 && !destructors);
    auto image_cell = reinterpret_cast<void *(*)()>(dlsym(module, "image_cell"));
    auto exercise_readonly = reinterpret_cast<void (*)()>(dlsym(module, "exercise_readonly"));
    assert(image_cell && exercise_readonly);
    protect(image_cell(), PROT_READ);
    exercise_readonly();
    protect(image_cell(), PROT_READ | PROT_WRITE);
    assert(dlclose(module) == 0);
    if (allocations != 1 || frees != 1 || constructors != 2 || destructors != 2 || state)
      std::fprintf(stderr, "unload: a=%u f=%u c=%u d=%u state=%p\n", allocations, frees, constructors, destructors, state);
    assert(allocations == 1 && frees == 1 && constructors == 2 && destructors == 2 && !state);
  }
  std::printf("PASS staged census: %zu bytes, one cross-TU heap owner, exact concurrent counters, protected old image faults/new native writes pass, static ctor/dtor use, 24 complete unload/reloads\n", bytes);
}
'''

NATIVE_DRIVER = r'''
#include <cassert>
#include <cstdio>
#include <thread>
static unsigned allocations = 0, frees = 0;
extern "C" void census_lifecycle(char event, void *) {
  if (event == 'a') ++allocations;
  else if (event == 'f') ++frees;
  else std::abort();
}
int main() {
  using namespace dxmt;
  assert(allocations == 1 && !frees);
  auto *const state = &memCensusState();
  std::atomic<bool> ready{false}, proceed{false};
  std::thread pending([&] {
    ready.store(true, std::memory_order_release);
    while (!proceed.load(std::memory_order_acquire)) std::this_thread::yield();
    // Actual queue/resource census helpers may still run during app exit.
    assert(&memCensusState() == state);
    mem_census_add(MEMOWN_BUFFER, 256);
    state->dynamic[3560].eligible_n.store(1, std::memory_order_relaxed);
    state->dynamic[3560].eligible_bytes.store(256, std::memory_order_relaxed);
    mem_census_sub(MEMOWN_BUFFER, 256);
  });
  while (!ready.load(std::memory_order_acquire)) std::this_thread::yield();
  // One TU means this is the real final header anchor. Explicitly invoke the
  // same destructor CRT would call, while keeping this process image mapped.
  census_detail::lifetime.~Lifetime();
  assert(census_detail::state == state && allocations == 1 && !frees);
  proceed.store(true, std::memory_order_release);
  pending.join();
  assert(state->census.requested[MEMOWN_BUFFER].load() == 256);
  assert(state->census.allocs[MEMOWN_BUFFER].load() == 1);
  assert(state->census.frees[MEMOWN_BUFFER].load() == 1);
  assert(!state->census.live[MEMOWN_BUFFER].load());
  assert(state->dynamic[3560].eligible_n.load() == 1);
  assert(state->dynamic[3560].eligible_bytes.load() == 256);
  for (unsigned n = 0; n != 128; ++n) {
    census_detail::Lifetime late_anchor;
    assert(&memCensusState() == state && allocations == 1 && !frees);
  }
  assert(allocations == 1 && !frees);
  std::puts("PASS native app-image census: pending worker writes after final anchor, one fixed allocation through 128 late-anchor cycles, process lifetime retention");
  std::fflush(stdout);
  // The test has already invoked the real anchor's destructor once. Avoid a
  // second invocation; the OS now reclaims this process-lifetime native state.
  std::_Exit(0);
}
'''


with tempfile.TemporaryDirectory(prefix='madeira-census-heap-') as directory:
    directory = Path(directory)
    staged_dynamic = directory / 'dynamic'
    dynamic.stage(ROOT / 'dxmt', staged_dynamic)
    output = directory / 'census'
    originals = {name: hashlib.sha256((ROOT / 'dxmt' / name).read_bytes()).hexdigest() for name in stage.FILES}
    stage.stage(ROOT / 'dxmt', output, staged_dynamic)
    for name in stage.FILES:
        assert hashlib.sha256((ROOT / 'dxmt' / name).read_bytes()).hexdigest() == originals[name]
        assert 'g_dyn_stats' not in (output / name).read_text()
        try:
            stage.stage_file(name, (output / name).read_text())
        except ValueError:
            pass
        else:
            raise AssertionError('double census staging accepted')
    assert 'TrimCompletedForQueue' in (output / stage.FILES[2]).read_text()
    # Compile the complete production header and census.cpp. Only logging and
    # switch lookup are replaced; actual Metal wrapper/types remain included.
    include = output / 'src/dxmt'
    (directory / 'log').mkdir()
    (directory / 'log/log.hpp').write_text('#pragma once\n#define ERR(...) ((void)0)\n')
    (directory / 'util_madeira_switch.hpp').write_text('#pragma once\nnamespace dxmt { inline bool madeiraSwitch(const char *) { return false; } }\n')
    (directory / 'allocator.cpp').write_text(ALLOCATOR)
    for name in ('a', 'b'):
        (directory / (name + '.cpp')).write_text(USER.replace('USER_ADDRESS', 'address_' + name))
    (directory / 'exercise.cpp').write_text(EXERCISE)
    original_include = directory / 'original'
    original_include.mkdir()
    shutil.copyfile(ROOT / 'dxmt/src/dxmt/dxmt_mem_census.hpp', original_include / 'dxmt_mem_census.hpp')
    (directory / 'legacy.cpp').write_text(LEGACY)
    (directory / 'driver.cpp').write_text(DRIVER)
    compiler = shutil.which('clang++') or shutil.which('g++')
    common = [compiler, '-std=c++20', '-O1', '-g', '-pthread', '-DDXMT_NATIVE', '-fPIC',
              '-I', str(include), '-I', str(directory), '-I', str(ROOT / 'dxmt/src/winemetal')]
    if 'g++' in Path(compiler).name:
        # GNU-unique template symbols make glibc retain a C++ DSO forever;
        # production Clang PE/Mach-O images do not have that ELF extension.
        common.append('-fno-gnu-unique')
    for name in ('a', 'b', 'allocator', 'exercise'):
        subprocess.run([*common, '-c', str(directory / (name + '.cpp')), '-o', str(directory / (name + '.o'))], check=True)
    # DXMT_NATIVE suppresses platform import decoration in the real headers.
    # Undefine it only after those headers to compile the production PE owner
    # branch, without adding a test-only knob to production sources.
    owner = directory / 'owner-pe.cpp'
    owner.write_text('#include "dxmt_mem_census.hpp"\n#undef DXMT_NATIVE\n#include "' +
                     str(include / 'dxmt_mem_census.cpp') + '"\n')
    subprocess.run([*common, '-c', str(owner), '-o', str(directory / 'owner.o')], check=True)
    driver = directory / 'driver'
    darwin = sys.platform == 'darwin'
    driver_flags = ['-Wl,-export_dynamic'] if darwin else ['-rdynamic', '-ldl']
    subprocess.run([compiler, '-std=c++20', '-O1', '-g', str(directory / 'driver.cpp'), *driver_flags, '-o', str(driver)], check=True)
    exports = directory / 'exports.map'
    exports.write_text('_exercise\n_image_cell\n_exercise_readonly\n' if darwin else
                       '{ global: exercise; image_cell; exercise_readonly; local: *; };\n')
    shared_flags = ['-dynamiclib', '-Wl,-undefined,dynamic_lookup', '-Wl,-exported_symbols_list,' + str(exports)] if darwin else [
        '-shared', '-Wl,-Bsymbolic', '-Wl,--version-script=' + str(exports)]
    legacy = directory / ('legacy.dylib' if darwin else 'legacy.so')
    subprocess.run([compiler, '-std=c++20', '-O1', '-DDXMT_NATIVE', '-fPIC', '-I', str(original_include),
                    '-I', str(ROOT / 'dxmt/src/winemetal'), '-dynamiclib' if darwin else '-shared',
                    str(directory / 'legacy.cpp'), '-o', str(legacy)], check=True)
    for order in (('a', 'owner', 'b'), ('owner', 'b', 'a'), ('b', 'a', 'owner')):
        library = directory / ('census-' + '-'.join(order) + ('.dylib' if darwin else '.so'))
        subprocess.run([compiler, *shared_flags, '-pthread',
                        *(str(directory / (name + '.o')) for name in (*order, 'allocator', 'exercise')),
                        '-o', str(library)], check=True)
        subprocess.run([str(driver), str(library), str(legacy)], check=True, timeout=30)
    # Verify the real header's public inline helpers have no mutable image
    # targets: all former names occur only as accessors into the same owner.
    names = subprocess.check_output(['nm', '-C', str(directory / 'owner.o')], text=True)
    assert 'dxmt::census_detail::state' in names
    assert not any('dxmt::' + name in names for name in stage.NAMES)
    native = directory / 'native.cpp'
    native.write_text(ALLOCATOR + '\n#include "' + str(include / 'dxmt_mem_census.cpp') + '"\n' + NATIVE_DRIVER)
    native_exe = directory / 'native'
    subprocess.run([*common, str(native), '-o', str(native_exe)], check=True)
    subprocess.run([str(native_exe)], check=True, timeout=30)
    print('PASS staged dynamic-memory producers and all existing census fields share the owned state; pinned vendor bytes unchanged')
