#!/usr/bin/env python3
"""Exercise staged production PreDraw counting, BC cadence and heap lifetime."""
import argparse
import ctypes
import importlib.util
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dxmt-root', type=Path, default=ROOT / 'dxmt')
parser.add_argument('--mingw-bin', type=Path,
                    default=Path(os.environ['LLVM_MINGW_BIN']) if os.environ.get('LLVM_MINGW_BIN') else None,
                    help='optional llvm-mingw bin directory for three-ABI DLL link checks')
args = parser.parse_args()
CXX = shlex.split(os.environ.get('CXX', '')) or [shutil.which('clang++') or shutil.which('g++') or 'c++']
COMPILER_VERSION = subprocess.check_output([*CXX, '--version'], text=True).lower()
GNU_COMPILER = 'clang' not in COMPILER_VERSION and ('gcc' in COMPILER_VERSION or 'g++' in COMPILER_VERSION)
DARWIN = sys.platform == 'darwin'
NATIVE_UNIX = DARWIN or sys.platform.startswith('linux')
spec = importlib.util.spec_from_file_location('perf_heap', ROOT / 'tools/build/stage-dxmt-perf-heap.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
original = {name: (args.dxmt_root / name).read_text() for name in stage.FILES}
staged = {name: stage.stage_file(name, text) for name, text in original.items()}


def block(source, marker):
    begin = source.index(marker)
    opening = source.index('{', begin)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[begin:end + 1]
    raise ValueError('unterminated production function: ' + marker)


def header(source):
    start = source.index('struct PerfCounters {')
    worker = source.find('extern std::atomic<uint64_t> ' + stage.WORKER_SINK + ';')
    if worker >= 0:
        start = worker
    return source[start:source.index('\nclass CommandQueue;')]


def bc_report(source):
    return source[source.index('/* ml744: aggregate outcome'):source.index('/* ml1252: 2x2 box filter')]


def predraw(source):
    # Compile the actual admission/counting prefix. Rendering after the census
    # is excluded; assert its complete production suffix is unchanged below.
    body = block(source, '  template <bool IndexedDraw>\n  DrawCallStatus\n  PreDraw()')
    return body[:body.index('    UpdateVertexBuffer();')] + '    return status;\n  }\n'


PRELUDE = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <thread>
#include <vector>
static unsigned bc_reports = 0, gpu_reports = 0;
static uint32_t bc_total = 0;
static std::string gpu_line;
template<class... A> void report(const char *, uint32_t total, A...) { ++bc_reports; bc_total = total; }
static void report(const char *line) { ++gpu_reports; gpu_line = line; }
#define ERR(...) report(__VA_ARGS__)
'''

CONTEXT = r'''
enum class DrawCallStatus { Invalid, Ordinary, Tessellation, Geometry };
class Context {
public:
  struct { struct { bool IndexBuffer = true; } InputAssembler; } state_;
  DrawCallStatus next = DrawCallStatus::Ordinary;
  unsigned finalizations = 0;
  template<bool> DrawCallStatus FinalizeCurrentRenderPipeline() { ++finalizations; return next; }
'''

QUEUE = r'''
using obj_handle_t = void *;
struct madeira_ctl_args { uint32_t op; uint32_t ret; uint64_t ptr; };
static double gpu_start = 0.1, gpu_end = 0.101;
static void MadeiraCtl(madeira_ctl_args *a) {
  struct Timing { uint64_t cb; double start, end; };
  auto *t = reinterpret_cast<Timing *>(uintptr_t(a->ptr));
  t->start = gpu_start; t->end = gpu_end; a->ret = 1;
}
class CommandQueue {
public:
  struct { uint64_t window_frame = ~0ull; double window_start = 0, last_end = 0, busy = 0;
           uint64_t cmdbufs = 0; } perf_;
  void AccountGpuTime(obj_handle_t, uint64_t);
};
'''


def production(texts):
    queue_h, queue_cpp, impl, _ = (texts[name] for name in stage.FILES)
    owner = stage.OWNER if 'perf-heap-v1' in queue_h else ''
    return (PRELUDE + '\nnamespace dxmt {\n' + header(queue_h) + owner
            + bc_report(impl) + CONTEXT + predraw(impl) + '};\n' + QUEUE
            + block(queue_cpp, 'void\nCommandQueue::AccountGpuTime(') + '\n}\n')


FUNCTIONAL = r'''
int main() {
  using namespace dxmt;
  Context c;
  c.state_.InputAssembler.IndexBuffer = false;
  assert(c.PreDraw<true>() == DrawCallStatus::Invalid && c.finalizations == 0);
  c.next = DrawCallStatus::Invalid;
  assert(c.PreDraw<false>() == DrawCallStatus::Invalid);
  assert(COUNTERS.draws == 0);
  c.state_.InputAssembler.IndexBuffer = true;
  for (auto status : {DrawCallStatus::Ordinary, DrawCallStatus::Tessellation, DrawCallStatus::Geometry}) {
    c.next = status;
    assert(c.PreDraw<true>() == status && c.PreDraw<false>() == status);
  }
  assert(COUNTERS.draws == 6 && COUNTERS.draws_tess == 2 && COUNTERS.draws_gs == 2);
  std::vector<std::thread> workers;
  for (unsigned t = 0; t < 8; ++t) workers.emplace_back([] {
    Context c;
    for (unsigned n = 0; n < 2000; ++n) c.PreDraw<false>();
  });
  for (auto &worker : workers) worker.join();
  assert(COUNTERS.draws == 16006 && COUNTERS.draws_tess == 2 && COUNTERS.draws_gs == 2);
  BC_OK[1].fetch_add(7); BC_OK[7].fetch_add(3);
  for (unsigned i = 0; i < 2049; ++i) {
    BCStreamReport();
    assert(bc_reports == 1 + i / 1024 && bc_total == 10);
  }
  { PerfTimer timer{COUNTERS.decode_ns};
    while (std::chrono::steady_clock::now() - timer.t0 < std::chrono::microseconds(10)) {} }
  assert(COUNTERS.decode_ns > 0);
  COUNTERS.map_waits = 5; COUNTERS.map_wait_ns = 3000000; COUNTERS.map_waits_unsubmitted = 2;
  COUNTERS.polls_event = 9; COUNTERS.polls_other = 4; COUNTERS.refill_ns = 1000;
  COUNTERS.refill_worker_ns = 2000; COUNTERS.refill_queued = 3; COUNTERS.refill_applied = 2;
  COUNTERS.refill_stale = 1; COUNTERS.refill_overbudget = 4;
  CommandQueue q;
  for (unsigned frame = 0; frame < 64; ++frame) {
    gpu_start = 0.1 + frame * .002; gpu_end = gpu_start + .001;
    q.AccountGpuTime(nullptr, frame); assert(gpu_reports == 0);
  }
  gpu_start += .002; gpu_end += .002; q.AccountGpuTime(nullptr, 64);
  assert(gpu_reports == 1 && gpu_line.find("64 frames") != std::string::npos);
  assert(gpu_line.find("queued 3 applied 2 stale 1 over-budget 4") != std::string::npos);
  assert(!COUNTERS.draws && !COUNTERS.draws_tess && !COUNTERS.draws_gs && !COUNTERS.decode_ns);
  assert(!COUNTERS.map_waits && !COUNTERS.map_wait_ns && !COUNTERS.map_waits_unsubmitted);
  assert(!COUNTERS.polls_event && !COUNTERS.polls_other && !COUNTERS.refill_ns);
  assert(!COUNTERS.refill_worker_ns && !COUNTERS.refill_queued && !COUNTERS.refill_applied);
  assert(!COUNTERS.refill_stale && !COUNTERS.refill_overbudget);
  assert(BC_OK[1] == 7 && BC_OK[7] == 3); // BC reports do not drain counts.
}
'''

PROTECTED = r'''
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#if defined(__APPLE__)
extern char __start_madeira_perf_image[] __asm("section$start$__DATA$mdperf_image");
extern char __stop_madeira_perf_image[] __asm("section$end$__DATA$mdperf_image");
#else
extern "C" char __start_madeira_perf_image[], __stop_madeira_perf_image[];
#endif
__attribute__((used, section(IMAGE_SECTION), aligned(16384))) static char image_end_padding[16384];
int main(int argc, char **) {
  struct rlimit no_core = {0, 0}; assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
  const uintptr_t page = uintptr_t(sysconf(_SC_PAGESIZE));
  const uintptr_t begin = uintptr_t(__start_madeira_perf_image) & ~(page - 1);
  const uintptr_t end = (uintptr_t(__stop_madeira_perf_image) + page - 1) & ~(page - 1);
  // Read-only image data reproduces the denied native atomic write on both
  // ELF and Apple Silicon without requesting executable data mappings.
  assert(mprotect(reinterpret_cast<void *>(begin), end - begin, PROT_READ) == 0);
  if (argc == 1) {
    dxmt::Context c; c.PreDraw<true>(); c.PreDraw<false>();
    assert(COUNTERS.draws == 2);
  } else {
    for (unsigned n = 0; n < 2049; ++n) dxmt::BCStreamReport();
    assert(bc_reports == 3);
  }
  assert(mprotect(reinterpret_cast<void *>(begin), end - begin, PROT_READ | PROT_WRITE) == 0);
}
'''


def replacements(source, new):
    return source.replace('COUNTERS', 'dxmt::perfCounters()' if new else 'dxmt::g_perf').replace(
        'BC_OK', 'dxmt::perfCounters().bc_stream_ok' if new else 'dxmt::g_bc_stream_ok')


def compile_exe(directory, name, source):
    path = directory / (name + '.cpp')
    path.write_text(source)
    exe = directory / name
    order_flags = ['-fno-toplevel-reorder'] if GNU_COMPILER else []
    subprocess.run([*CXX, '-std=c++20', '-O1', '-g', '-pthread', *order_flags,
                    str(path), '-o', str(exe)], check=True)
    return exe


def check_lifetime(directory):
    # Extract production header/owner; only allocator tracing is test-injected.
    # Separate clients use it in both static constructors and destructors.
    tracked = header(staged[stage.FILES[0]]).replace('struct PerfCounters {', '''struct PerfCounters {
  static void *operator new(size_t n) { auto *p = ::operator new(n); track_event(1); return p; }
  static void operator delete(void *p) { track_event(3); ::operator delete(p); }
  ~PerfCounters() { track_event(2); }''', 1)
    hpp = PRELUDE + '\nextern "C" void track_event(int);\nnamespace dxmt {\n' + tracked + '\n}\n'
    (directory / 'perf.hpp').write_text('#pragma once\n' + hpp)
    exports = r'''
static unsigned allocations = 0;
static void (*observer)(int) = nullptr;
extern "C" void track_event(int n) { if (n == 1) ++allocations; if (observer) observer(n); }
#define API extern "C" __attribute__((visibility("default")))
API void set_observer(void (*callback)(int)) { observer = callback; }
API unsigned allocation_count() { return allocations; }
API uintptr_t state_address() { return uintptr_t(&dxmt::perfCounters()); }
API uint64_t draws() { return dxmt::perfCounters().draws.load(); }
API void add_draws(unsigned n) { dxmt::perfCounters().draws.fetch_add(n); }
'''
    (directory / 'owner.cpp').write_text('#include "perf.hpp"\nnamespace dxmt {\n' + stage.OWNER + '\n}\n' + exports)
    for name in ('first', 'second'):
        (directory / (name + '.cpp')).write_text('''#include "perf.hpp"
namespace {
struct Consumer {
  Consumer() { assert(dxmt::perf_detail::state); dxmt::perfCounters().draws.fetch_add(1); }
  ~Consumer() { assert(dxmt::perf_detail::state); dxmt::perfCounters().draws.fetch_add(1); track_event(4); }
} consumer;
}
''')
    libraries = []
    for index, names in enumerate((('owner', 'first', 'second'), ('second', 'first', 'owner'))):
        lib = directory / ('lifetime' + str(index) + ('.dylib' if DARWIN else '.so'))
        exports = directory / 'lifetime-exports.map'
        api = ('set_observer', 'allocation_count', 'state_address', 'draws', 'add_draws')
        exports.write_text(''.join('_' + symbol + '\n' for symbol in api) if DARWIN else
                           '{ global: ' + '; '.join(api) + '; local: *; };\n')
        shared_flags = ['-dynamiclib', '-Wl,-exported_symbols_list,' + str(exports)] if DARWIN else [
            '-shared', '-Wl,-Bsymbolic', '-Wl,--version-script=' + str(exports)]
        unique_flags = ['-fno-gnu-unique'] if GNU_COMPILER and not DARWIN else []
        subprocess.run([*CXX, '-std=c++20', '-O1', *shared_flags, '-fPIC', '-fvisibility=hidden',
                        *unique_flags, *(str(directory / (name + '.cpp')) for name in names),
                        '-o', str(lib)], check=True)
        libraries.append(lib)
    import _ctypes
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_int)
    for cycle in range(5):
        opened = []
        for path in libraries:
            events = []
            callback = callback_type(events.append)
            lib = ctypes.CDLL(str(path), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            lib.set_observer.argtypes = [callback_type]
            lib.set_observer(callback)
            lib.state_address.restype = ctypes.c_size_t
            lib.draws.restype = ctypes.c_uint64
            assert lib.allocation_count() == 1 and lib.draws() == 2
            opened.append((lib, events, callback))
        first, second = (entry[0] for entry in opened)
        assert first.state_address() != second.state_address()
        first.add_draws(17)
        assert first.draws() == 19 and second.draws() == 2
        for lib, events, callback in opened:
            _ctypes.dlclose(lib._handle)
            assert events == [4, 4, 2, 3], (cycle, events)
    print('PASS multi-TU early/late consumers, two link orders, isolated images and five load/unload cycles')


def check_detached_timer_lifetime(directory):
    # Keep the module image mapped while controlling its final real TU anchor:
    # detached work can overlap CRT teardown before the image is unmapped.
    # The production worker's timer line must not consult the expired owner.
    actual = staged[stage.FILES[2]]
    marker = '        PerfTimer _t{' + stage.WORKER_SINK + '};'
    assert actual.count(marker) == 1
    controlled = header(staged[stage.FILES[0]]).replace(
        '[[maybe_unused]] static const Lifetime lifetime;', '')
    controlled = controlled.replace('struct PerfCounters {', '''struct PerfCounters {
  static void *operator new(size_t n) { ++allocations; return ::operator new(n); }
  static void operator delete(void *p) { ++deallocations; ::operator delete(p); }
  ~PerfCounters() { ++destructions; }''', 1)
    source = (PRELUDE + '\nstatic unsigned allocations = 0, deallocations = 0, destructions = 0;\n'
              + 'namespace dxmt {\n' + controlled + stage.OWNER + '\n}\n' + r'''
int main() {
  using namespace dxmt;
  std::atomic<unsigned> phase{0};
  std::thread pending;
  {
    perf_detail::Lifetime anchor;
    assert(allocations == 1 && !deallocations);
    assert(&perfCounters().refill_worker_ns == &g_perf_refill_worker_ns);
    pending = std::thread([&] {
      {
WORKER_TIMER
        phase.store(1, std::memory_order_release);
        while (phase.load(std::memory_order_acquire) != 2) std::this_thread::yield();
      }
      phase.store(3, std::memory_order_release);
    });
    while (phase.load(std::memory_order_acquire) != 1) std::this_thread::yield();
  } // Actual final anchor destroys/deallocates the heap with a timer pending.
  assert(!perf_detail::state && destructions == 1 && deallocations == 1);
  phase.store(2, std::memory_order_release);
  pending.join();
  assert(phase.load() == 3 && g_perf_refill_worker_ns.load() > 0);
  const uint64_t pending_ns = g_perf_refill_worker_ns.load();
  // The immortal refill worker can also start a queued job after CRT teardown.
  std::thread later([] {
WORKER_TIMER
    while (std::chrono::steady_clock::now() - _t.t0 < std::chrono::microseconds(10)) {}
  });
  later.join();
  assert(g_perf_refill_worker_ns.load() > pending_ns);
  const uint64_t completed_ns = g_perf_refill_worker_ns.load();
  {
    perf_detail::Lifetime next_anchor;
    assert(&perfCounters().refill_worker_ns == &g_perf_refill_worker_ns);
    assert(perfCounters().refill_worker_ns.exchange(0, std::memory_order_relaxed) == completed_ns);
    assert(!g_perf_refill_worker_ns.load());
  }
  assert(allocations == 2 && destructions == 2 && deallocations == 2);
}
'''.replace('WORKER_TIMER', marker))
    exe = compile_exe(directory, 'detached-timer-lifetime', source)
    subprocess.run([str(exe)], check=True, timeout=30)
    print('PASS actual detached worker timer: pending across final-anchor free, later job, shared report sink')


def check_native_owner_lifetime(directory):
    # DXMT_NATIVE is statically linked into the fixed app image. Its queued
    # callbacks can outlive CRT anchors before force-exit; retain one owner to
    # preserve the original BSS lifetime, with no hot-path lease/refcount.
    controlled = production(staged).replace('[[maybe_unused]] static const Lifetime lifetime;', '')
    controlled = controlled.replace('struct PerfCounters {', '''struct PerfCounters {
  static void *operator new(size_t n) { ++allocations; return ::operator new(n); }
  static void operator delete(void *p) { ++deallocations; ::operator delete(p); }
  ~PerfCounters() { ++destructions; }''', 1)
    source = ('#define DXMT_NATIVE 1\n'
              'static unsigned allocations = 0, deallocations = 0, destructions = 0;\n'
              + controlled + r'''
int main() {
  using namespace dxmt;
  std::atomic<unsigned> phase{0};
  std::thread pending;
  PerfCounters *address;
  {
    perf_detail::Lifetime anchor;
    address = &perfCounters();
    Context c; c.PreDraw<false>();
    pending = std::thread([&] {
      phase.store(1, std::memory_order_release);
      while (phase.load(std::memory_order_acquire) != 2) std::this_thread::yield();
      // Actual draw/BC/timer production consumers after the final anchor.
      Context c; c.next = DrawCallStatus::Geometry;
      c.PreDraw<true>(); c.PreDraw<false>();
      BCStreamReport();
      PerfTimer timer{perfCounters().decode_ns};
      while (std::chrono::steady_clock::now() - timer.t0 < std::chrono::microseconds(10)) {}
    });
    while (phase.load(std::memory_order_acquire) != 1) std::this_thread::yield();
  }
  assert(perf_detail::state == address && allocations == 1 && !destructions && !deallocations);
  phase.store(2, std::memory_order_release);
  pending.join();
  assert(perfCounters().draws == 3 && perfCounters().draws_gs == 2 && perfCounters().decode_ns > 0);
  assert(bc_reports == 1 && perfCounters().bc_stream_report_tick == 1);
  {
    perf_detail::Lifetime reacquired;
    assert(&perfCounters() == address && allocations == 1 && perfCounters().draws == 3);
  }
  Context later; later.PreDraw<false>();
  assert(&perfCounters() == address && perfCounters().draws == 4);
  assert(allocations == 1 && !destructions && !deallocations);
}
''')
    exe = compile_exe(directory, 'native-owner-lifetime', source)
    subprocess.run([str(exe)], check=True, timeout=30)
    print('PASS DXMT_NATIVE final-anchor callbacks: retained app owner, exact counts, no duplicate allocation')


def check_windows_links(directory):
    mingw = args.mingw_bin
    if mingw is None:
        compiler = shutil.which('arm64ec-w64-mingw32-clang++')
        mingw = Path(compiler).parent if compiler else None
    if mingw is None:
        print('SKIP three-ABI DLL link check: supply --mingw-bin or LLVM_MINGW_BIN')
        return
    path = directory / 'perf-cross.cpp'
    path.write_text(production(staged) + replacements(FUNCTIONAL, True) + '''
extern "C" __declspec(dllexport) void perf_heap_check() { main(); }
''')
    for arch in ('x86_64', 'aarch64', 'arm64ec'):
        compiler = mingw / (arch + '-w64-mingw32-clang++')
        dll = directory / ('perf-' + arch + '.dll')
        subprocess.run([str(compiler), '-std=c++20', '-O1', '-shared', str(path), '-o', str(dll)], check=True)
        assert dll.is_file() and dll.stat().st_size > 0
        subprocess.run([str(mingw / 'llvm-readobj'), '--file-headers', '--coff-imports', str(dll)],
                       check=True, stdout=subprocess.DEVNULL)
    print('PASS extracted production perf helpers compile/link as x86_64, AArch64 and ARM64EC Windows DLLs')


for name in stage.FILES:
    assert not re.search(r'\bg_perf\b', staged[name])
    try:
        stage.stage_file(name, staged[name])
    except ValueError:
        pass
    else:
        raise AssertionError('restaging must fail closed: ' + name)
old_predraw = block(original[stage.FILES[2]], '  template <bool IndexedDraw>\n  DrawCallStatus\n  PreDraw()')
new_predraw = block(staged[stage.FILES[2]], '  template <bool IndexedDraw>\n  DrawCallStatus\n  PreDraw()')
assert new_predraw.replace('perfCounters()', 'g_perf') == old_predraw
for name in stage.FILES[1:]:
    # Exact token replacement preserves every operation and memory order.
    if name != stage.FILES[2]:
        without_owner = staged[name].replace(stage.OWNER, '')
        assert without_owner.replace('perfCounters()', 'g_perf') == original[name]

with tempfile.TemporaryDirectory(prefix='dxmt-perf-heap-') as temp:
    directory = Path(temp)
    for new, texts in ((False, original), (True, staged)):
        source = production(texts)
        exe = compile_exe(directory, 'functional-' + str(new), source + replacements(FUNCTIONAL, new))
        subprocess.run([str(exe)], check=True, timeout=30)
        if NATIVE_UNIX:
            section = '__DATA,mdperf_image' if DARWIN else 'madeira_perf_image'
            image = '#define IMAGE_SECTION "' + section + '"\n' + source
            # This fixture is one TU. Remove COMDAT linkage so ELF can place
            # all old globals and the local tick in one isolated RX section.
            image = image.replace('inline void BCStreamReport()', 'void BCStreamReport()')
            if new:
                image = image.replace('constinit PerfCounters *state = nullptr;',
                    '__attribute__((section(IMAGE_SECTION), aligned(16384))) constinit PerfCounters *state = nullptr;')
            else:
                image = image.replace('inline PerfCounters g_perf;',
                    '__attribute__((section(IMAGE_SECTION), aligned(16384))) PerfCounters g_perf;')
                image = re.sub(r'inline std::atomic<uint32_t> (g_\w+)',
                    '__attribute__((section(IMAGE_SECTION), aligned(16384))) std::atomic<uint32_t> \\1', image)
                image = image.replace('  static std::atomic<uint32_t> tick{0};',
                    '  static std::atomic<uint32_t> tick __attribute__((section(IMAGE_SECTION), aligned(16384))){0};')
            exe = compile_exe(directory, 'protected-' + str(new), image + replacements(PROTECTED, new))
            for mode in ([], ['bc']):
                result = subprocess.run([str(exe), *mode], capture_output=True, timeout=30)
                expected = (0,) if new else (-signal.SIGSEGV, -signal.SIGBUS)
                assert result.returncode in expected, (new, mode, result.returncode, result.stderr)
    print('PASS production PreDraw admission/counts, concurrent draws, BC 1024-call cadence and GPU 64-frame drain')
    if NATIVE_UNIX:
        print('PASS protected image regression: original PreDraw/BC tick fault; staged heap counters run normally')
        check_lifetime(directory)
    else:
        print('SKIP page-protection/dlopen fixtures on non-POSIX host')
    check_detached_timer_lifetime(directory)
    check_native_owner_lifetime(directory)
    check_windows_links(directory)
    output = directory / 'staged'
    stage.stage(args.dxmt_root, output)
    assert all((args.dxmt_root / name).read_text() == text for name, text in original.items())
    changed = dict(original)
    changed[stage.FILES[2]] = changed[stage.FILES[2]].replace('static std::atomic<uint32_t> tick{0}', 'changed_tick_contract')
    overlay = directory / 'bad-overlay'
    path = overlay / stage.FILES[2]
    path.parent.mkdir(parents=True)
    path.write_text(changed[stage.FILES[2]])
    failed = directory / 'failed-output'
    try:
        stage.stage(args.dxmt_root, failed, overlay)
    except ValueError:
        assert not failed.exists()
    else:
        raise AssertionError('changed production contract must fail before writing output')
print('PASS immutable input, all-or-none contract validation and no duplicate staging')
