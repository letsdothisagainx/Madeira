#!/usr/bin/env python3
"""Replay command-data retirement and owned VM backing with task footprint.

The baseline is the exact tested CommitCurrentChunk retention call. Both cases
execute the staged ring, their actual backing allocator, AllocateCommandData
and full CommitCurrentChunk. Command execution and its completion frontier are
controlled adapters; only consumed/reset command storage is declared complete.
On Darwin malloc/mmap/munmap and task phys_footprint measurements are real.
The middle case applies bounded retention with malloc, preserving evidence that
freeing capacity alone need not return pages from the native allocator.

Every written byte belongs to an identical used command payload. Unused block
tails are never touched to manufacture RSS. Owned capacity, cumulative traffic
and sampled footprint are reported separately; physical improvement is observed,
not asserted. This is not an iPhone or remote-CS2 performance result.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DXMT = ROOT / 'dxmt/src/dxmt'
BASELINE_COMMIT_SHA256 = 'f9427bf713e0220d0e26a7eb76721081071189fd4b4f41b6d1a089dd2fa5b902'


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[start:brace + token.end()]
    raise AssertionError('unterminated function: ' + signature)


PRELUDE = r'''
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <queue>
#include <thread>
#include <utility>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#endif
#define ASYNC_ENCODING 1
#define DXMT_NATIVE 1
#define WARN(...) ((void)0)
static uint64_t physical_footprint() {
#if defined(__APPLE__)
  task_vm_info_data_t info = {};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  assert(task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS);
  assert(count >= TASK_VM_INFO_REV1_COUNT);
  return info.phys_footprint;
#else
  return 0; // Only emitted-source correctness can run here; the Python entry skips.
#endif
}
struct HostStats {
  struct Entry { size_t size; uint64_t last_use = 0; bool vm = false; };
  std::map<uintptr_t, Entry> blocks;
  const std::thread::id producer = std::this_thread::get_id();
  uint64_t completed = 0, allocations = 0, frees = 0, traffic = 0;
  uint64_t owned = 0, owned_peak = 0, footprint_before = 0, footprint_peak = 0;
  uint64_t checksum = 0, payload_bytes = 0, logs = 0, resets = 0, signaled_resets = 0;
  void producerOnly() const { assert(std::this_thread::get_id() == producer); }
  void sample() { footprint_peak = std::max(footprint_peak, physical_footprint()); }
  void begin() { footprint_before = footprint_peak = physical_footprint(); }
  void used(void *pointer, size_t size, uint64_t seq) {
    producerOnly();
    auto it = blocks.upper_bound(reinterpret_cast<uintptr_t>(pointer));
    assert(it != blocks.begin()); --it;
    auto offset = reinterpret_cast<uintptr_t>(pointer) - it->first;
    assert(offset <= it->second.size && size <= it->second.size - offset);
    it->second.last_use = std::max(it->second.last_use, seq);
  }
} stats;
static bool fail_next_vm_allocation = false;
static bool fail_next_vm_release = false;
static void *tracked_malloc(size_t bytes) {
  stats.producerOnly();
  void *result = std::malloc(bytes); assert(result);
  assert(stats.blocks.emplace(reinterpret_cast<uintptr_t>(result), HostStats::Entry{bytes}).second);
  ++stats.allocations; stats.traffic += bytes; stats.owned += bytes;
  stats.owned_peak = std::max(stats.owned_peak, stats.owned);
  stats.sample();
  return result;
}
static void tracked_free(void *pointer) {
  if (!pointer) return;
  stats.producerOnly();
  auto it = stats.blocks.find(reinterpret_cast<uintptr_t>(pointer));
  assert(it != stats.blocks.end() && !it->second.vm && it->second.last_use <= stats.completed);
  stats.owned -= it->second.size; stats.blocks.erase(it); ++stats.frees;
  std::free(pointer); stats.sample();
}
static void *tracked_mmap(void *hint, size_t bytes, int protection, int flags, int fd, off_t offset) {
  stats.producerOnly();
  assert(hint == nullptr && protection == (PROT_READ | PROT_WRITE) && fd == -1 && !offset);
  assert((flags & MAP_PRIVATE) && (flags & MAP_ANON));
  if (fail_next_vm_allocation) {
    fail_next_vm_allocation = false; errno = ENOMEM; return MAP_FAILED;
  }
  void *result = ::mmap(hint, bytes, protection, flags, fd, offset);
  if (result == MAP_FAILED) return result;
  assert(stats.blocks.emplace(reinterpret_cast<uintptr_t>(result), HostStats::Entry{bytes, 0, true}).second);
  ++stats.allocations; stats.traffic += bytes; stats.owned += bytes;
  stats.owned_peak = std::max(stats.owned_peak, stats.owned); stats.sample();
  return result;
}
static int tracked_munmap(void *pointer, size_t bytes) {
  stats.producerOnly();
  auto it = stats.blocks.find(reinterpret_cast<uintptr_t>(pointer));
  assert(it != stats.blocks.end() && it->second.vm && it->second.size == bytes && it->second.last_use <= stats.completed);
  if (fail_next_vm_release) {
    fail_next_vm_release = false; errno = EBUSY; return -1;
  }
  const int result = ::munmap(pointer, bytes);
  assert(result == 0);
  stats.owned -= it->second.size; stats.blocks.erase(it); ++stats.frees; stats.sample();
  return result;
}
static void *ptr_add(void *pointer, size_t offset) { return static_cast<char *>(pointer) + offset; }
namespace dxmt {
using mutex = std::mutex;
using clock = std::chrono::steady_clock;
struct null_mutex {
  void lock() { stats.producerOnly(); }
  void unlock() noexcept { stats.producerOnly(); }
  bool try_lock() { stats.producerOnly(); return true; }
};
template<class T, class U> size_t align(T value, U alignment) {
  return (size_t(value) + size_t(alignment) - 1) & ~(size_t(alignment) - 1);
}
constexpr size_t kStagingBlockSize = 32u << 20;
constexpr size_t kStagingBlockLifetime = 300;
constexpr size_t kCommandChunkCPUHeapSize = 4u << 20;
constexpr uint32_t kCommandChunkCount = 32;
size_t madeiraRingBlockSize(size_t natural) { return natural; }
bool ringOversizeReuseEnabled() { return false; }
template<class T> void atomic_notify_one(std::atomic<T> &value) { value.notify_one(); }
template<class T> void atomic_wait(std::atomic<T> &value, T old, std::memory_order order) {
  value.wait(old, order);
}
struct Logger {
  template<class... T> static void info(T&&...) { ++stats.logs; }
};
/* ACTUAL_PRESSURE_TYPES */
MemoryPressureSnapshot fixture_pressure;
MemoryPressureSnapshot memoryPressureSnapshot(bool = false) {
  auto value = fixture_pressure;
  value.footprint = physical_footprint();
  return value;
}
} // namespace dxmt
'''


QUEUE = r'''
namespace dxmt {
struct GpuResource {
  static inline uint64_t live = 0;
  std::array<unsigned char,64> bytes;
  GpuResource() { bytes.fill(0x73); ++live; }
  ~GpuResource() { assert(bytes.front() == 0x73 && bytes.back() == 0x73); --live; }
};
struct Payload {
  unsigned char *bytes; size_t size; uint8_t value;
  std::shared_ptr<GpuResource> resource = std::make_shared<GpuResource>();
  Payload(unsigned char *p,size_t n,uint8_t v):bytes(p),size(n),value(v) {}
  ~Payload() { assert(bytes[0] == value && bytes[size-1] == value); }
};
struct CommandList {
  std::vector<std::unique_ptr<Payload>> items;
  void reset() { items.clear(); ++stats.resets; }
};
struct Tracker { void clear() {} };
struct Chunk {
  uint64_t chunk_id = 0, chunk_event_id = 0, frame_ = 0, resource_initializer_event_id = 0, signal_frame_latency_fence_ = 0;
  std::unique_ptr<int> visibility_readback;
  std::vector<std::shared_ptr<GpuResource>> completion_targets;
  CommandList list_enc;
  Tracker ref_tracker;
  std::shared_ptr<int> attached_cmdbuf;
  bool encoded = false;
  /* ACTUAL_CHUNK_RESET */
};
struct Fence {
  std::atomic<uint64_t> value{0};
  uint64_t signaledValue() const { return value.load(std::memory_order_acquire); }
  void signal(uint64_t completed) {
    assert(stats.resets > stats.signaled_resets);
    stats.signaled_resets = stats.resets; stats.completed = completed;
    value.store(completed, std::memory_order_release);
  }
};
class CommandQueue {
public:
  std::atomic<uint64_t> ready_for_encode{1}, chunk_ongoing{0};
  std::array<Chunk, kCommandChunkCount> chunks;
  Fence cpu_coherent;
  uint64_t frame_count = 0, next_event = 0, next_complete = 1;
  struct {
    uint64_t command_buffer_count = 0;
    clock::duration commit_interval{};
  } frame_statistics;
  struct { uint64_t flushToWait() { return 0; } } initializer;
  RingBumpState<CPU_BACKING_ALLOCATOR, kCommandChunkCPUHeapSize, null_mutex> cpu_command_allocator{{}};
  MemoryPressureController cpu_command_pressure_controller_;
  std::atomic<bool> cpu_command_release_requested_{false};
  unsigned cpu_command_pressure_reports_ = 0;
  auto &CurrentFrameStatistics() { return frame_statistics; }
  uint64_t memoryDomain() const { return 1; }
  uint64_t GetNextEventSeqId() { return ++next_event; }
  /* ACTUAL_CURRENT_CHUNK */
  /* ACTUAL_ALLOCATE */
  uint64_t maintainCompletedCommandData(uint64_t completed);
  void CommitCurrentChunk();
  void record(size_t bytes, uint8_t value) {
    stats.producerOnly();
    auto *destination = static_cast<unsigned char *>(AllocateCommandData(bytes, 16));
    assert(destination);
    // This exact input range is later consumed byte-for-byte. Unused tails
    // in the real 4 MiB allocations are deliberately never touched.
    memset(destination, value, bytes);
    stats.used(destination, bytes, ready_for_encode.load());
    CurrentChunk()->list_enc.items.emplace_back(std::make_unique<Payload>(destination, bytes, value));
    stats.sample();
  }
  void encodeOne(uint64_t seq) {
    stats.producerOnly();
    assert(seq < ready_for_encode.load());
    auto &chunk = chunks[seq % kCommandChunkCount];
    assert(chunk.chunk_id == seq);
    if (chunk.encoded) return;
    for (const auto &owned : chunk.list_enc.items) {
      const auto &command = *owned;
      uint64_t sum = 0;
      for (size_t i = 0; i < command.size; ++i) {
        const auto byte = command.bytes[i];
        assert(byte == command.value); sum += byte;
      }
      stats.checksum += sum; stats.payload_bytes += command.size;
      chunk.completion_targets.push_back(command.resource);
    }
    chunk.encoded = true;
  }
  bool completeOne(bool gpu_done = true, bool encode_done = true) {
    stats.producerOnly();
    assert(next_complete < ready_for_encode.load() && chunk_ongoing.load() > 0);
    auto &chunk = chunks[next_complete % kCommandChunkCount];
    assert(chunk.chunk_id == next_complete);
    if (!gpu_done || !encode_done || !chunk.encoded) return false;
    // The actual finisher publication block executes only after the controlled
    // GPU-complete edge. Encoding alone never destroys closures or signals it.
    const uint64_t internal_seq = next_complete;
    /* ACTUAL_FINISH_PUBLICATION */
    chunk.encoded = false; ++next_complete;
    return true;
  }
  void completeAll() {
    while (next_complete < ready_for_encode.load()) {
      encodeOne(next_complete); assert(completeOne());
    }
  }
};
/* ACTUAL_MAINTENANCE */
/* ACTUAL_COMMIT */
} // namespace dxmt
'''


MAIN = r'''
static int backendSelfTest() {
  using namespace dxmt;
  const size_t payload = size_t(sysconf(_SC_PAGESIZE)) + 7;
  const auto native_page = size_t(sysconf(_SC_PAGESIZE));
  CpuCommandBlockAllocator allocator;
  {
    auto original = allocator.allocate(payload);
    assert(original.ptr && original.allocation_size == CpuCommandBlockAllocator::rounded_size(payload, native_page));
    assert(stats.owned == original.allocation_size && original.backend == CpuCommandBlockAllocator::Backend::Posix);
    auto *pointer = original.ptr;
    const auto extent = original.allocation_size;
    memset(pointer, 0x59, payload);
    CpuCommandBlockAllocator::Block moved(std::move(original));
    assert(!original.ptr && original.allocation_size == 0 && original.backend == CpuCommandBlockAllocator::Backend::None);
    assert(moved.ptr == pointer && moved.allocation_size == extent && moved.backend == CpuCommandBlockAllocator::Backend::Posix);
    for (size_t i = 0; i < payload; ++i) assert(static_cast<unsigned char *>(moved.ptr)[i] == 0x59);
    const auto frees_before = stats.frees;
    fail_next_vm_release = true;
    assert(!moved.try_release() && !fail_next_vm_release);
    assert(moved.ptr == pointer && moved.allocation_size == extent && stats.owned == extent && stats.frees == frees_before);
    assert(moved.try_release() && !moved.ptr && !moved.allocation_size);
    assert(moved.backend == CpuCommandBlockAllocator::Backend::None);
  }
  assert(!stats.owned && stats.blocks.empty() && stats.allocations == stats.frees);
  fail_next_vm_allocation = true;
  bool failed = false;
  try { auto block = allocator.allocate(payload); failed = !block.ptr; }
  catch (const std::bad_alloc &) { failed = true; }
  assert(failed && !fail_next_vm_allocation && !stats.owned && stats.blocks.empty());
  for (size_t invalid : {size_t{0}, std::numeric_limits<size_t>::max()}) {
    failed = false;
    try { auto block = allocator.allocate(invalid); failed = !block.ptr; }
    catch (const std::bad_alloc &) { failed = true; }
    assert(failed && !stats.owned && stats.blocks.empty());
  }
  puts("PASS actual owned-VM backend: native mmap/munmap, rounded extent, move ownership, failed-release ownership/retry, controlled MAP_FAILED, zero/overflow refusal and balanced exact release");
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--backend-test")) return backendSelfTest();
  assert(argc == 1);
  using namespace dxmt;
  stats.begin();
  const auto started = clock::now();
  uint64_t after_burst = 0, before_pressure = 0, after_pressure = 0, after_zero = 0;
  uint64_t owned_after_pressure = 0, owned_after_zero = 0, submissions = 0;
  uint64_t checksum_expected = 0, bytes_expected = 0;
  {
    CommandQueue queue;
    fixture_pressure = {0, uint64_t{1536} << 20, 0, uint64_t{768} << 20, 1, true};
    for (unsigned i = 0; i < 16; ++i) {
      constexpr size_t bytes = 3u << 20;
      const uint8_t value = uint8_t(17 + i);
      queue.record(bytes, value); checksum_expected += uint64_t(value) * bytes; bytes_expected += bytes;
    }
    assert(stats.owned == 16u * (4u << 20));
    queue.CommitCurrentChunk();
    queue.encodeOne(1);
    assert(GpuResource::live == 16 && !queue.completeOne(false));
    after_burst = physical_footprint();
    const auto frees_while_pending = stats.frees;
    fixture_pressure.available = uint64_t{192} << 20; ++fixture_pressure.sampled_ns;
    queue.CommitCurrentChunk(); // Maintenance cannot free sequence1's CPU data.
    assert(stats.frees == frees_while_pending && stats.owned == 16u * (4u << 20));
    assert(GpuResource::live == 16 && !queue.completeOne(true, false));
    assert(queue.cpu_coherent.signaledValue() == 0 && stats.completed == 0);
    queue.completeAll();
    assert(GpuResource::live == 0);
    before_pressure = physical_footprint();
    queue.CommitCurrentChunk(); // Now the real completed frontier permits trimming.
    after_pressure = physical_footprint(); owned_after_pressure = stats.owned;
    assert(stats.owned == (CANDIDATE ? 4u : 64u) * (1u << 20));
    queue.completeAll();
    const uint64_t allocations_before_steady = stats.allocations;
    for (unsigned i = 0; i < 20; ++i) {
      constexpr size_t bytes = 256u << 10;
      const uint8_t value = uint8_t(91 + i);
      ++fixture_pressure.sampled_ns;
      queue.record(bytes, value); checksum_expected += uint64_t(value) * bytes; bytes_expected += bytes;
      queue.CommitCurrentChunk(); queue.completeAll();
    }
    assert(stats.allocations == allocations_before_steady);
    fixture_pressure.available = 0; ++fixture_pressure.sampled_ns;
    queue.CommitCurrentChunk();
    after_zero = physical_footprint(); owned_after_zero = stats.owned;
    assert(stats.owned == (CANDIDATE ? 0u : 64u) * (1u << 20));
    queue.completeAll();
    // Healthy recovery preserves ordinary backing and byte-correct recording.
    fixture_pressure.available = uint64_t{1536} << 20; ++fixture_pressure.sampled_ns;
    queue.record(4096, 0x73); checksum_expected += uint64_t(0x73) * 4096; bytes_expected += 4096;
    queue.CommitCurrentChunk(); queue.completeAll(); stats.sample();
    assert(stats.checksum == checksum_expected && stats.payload_bytes == bytes_expected && GpuResource::live == 0);
    assert(stats.logs <= 8 && stats.completed + 1 == queue.ready_for_encode.load());
    submissions = queue.frame_statistics.command_buffer_count;
  }
  stats.sample();
  assert(stats.allocations == stats.frees && stats.owned == 0 && stats.blocks.empty());
  const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - started).count();
  printf("CPU_COMMAND_NATIVE_RESULT {\"policy\":\"POLICY_NAME\",\"physical_source\":\"PHYSICAL_SOURCE\",\"completion\":\"controlled-gpu-complete-then-real-reset\",\"submissions\":%llu,\"pressure_cycles\":1,\"payload_bytes\":%llu,\"checksum\":%llu,\"allocations\":%llu,\"frees\":%llu,\"allocation_traffic_bytes\":%llu,\"owned_peak_bytes\":%llu,\"owned_after_pressure_bytes\":%llu,\"owned_after_zero_bytes\":%llu,\"footprint_before_bytes\":%llu,\"sampled_footprint_peak_bytes\":%llu,\"footprint_after_burst_bytes\":%llu,\"footprint_before_pressure_bytes\":%llu,\"footprint_after_pressure_bytes\":%llu,\"footprint_after_zero_bytes\":%llu,\"footprint_after_destruction_bytes\":%llu,\"elapsed_us\":%lld}\n",
    (unsigned long long)submissions, (unsigned long long)stats.payload_bytes, (unsigned long long)stats.checksum,
    (unsigned long long)stats.allocations, (unsigned long long)stats.frees,
    (unsigned long long)stats.traffic, (unsigned long long)stats.owned_peak,
    (unsigned long long)owned_after_pressure, (unsigned long long)owned_after_zero,
    (unsigned long long)stats.footprint_before, (unsigned long long)stats.footprint_peak,
    (unsigned long long)after_burst, (unsigned long long)before_pressure,
    (unsigned long long)after_pressure, (unsigned long long)after_zero,
    (unsigned long long)physical_footprint(), (long long)elapsed);
}
'''


def generated_sources():
    spec = importlib.util.spec_from_file_location('cpu_command_stage', ROOT / 'tools/build/stage-dxmt-upload-memory.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    ring = stage.stage_ring((DXMT / 'dxmt_ring_bump_allocator.hpp').read_text())
    start = ring.index('template <typename Allocator, size_t BlockSize =')
    end = ring.index('\nclass GpuPrivateBufferBlockAllocator', start)
    methods = ring.index('template <typename Allocator, size_t BlockSize, class mutex>\nstd::pair', end)
    allocator = function(ring, 'class HostBufferBlockAllocator {') + ';'
    vm_allocator = function(ring, 'class CpuCommandBlockAllocator {') + ';'
    actual_ring = 'namespace dxmt {\n' + ring[start:end] + '\n#define malloc tracked_malloc\n#define free tracked_free\n'
    actual_ring += allocator + '\n#undef free\n#undef malloc\n#define mmap tracked_mmap\n#define munmap tracked_munmap\n'
    actual_ring += vm_allocator + '\n#undef munmap\n#undef mmap\n' + ring[methods:]
    original = (DXMT / 'dxmt_command_queue.cpp').read_text()
    baseline_commit = function(original, 'void\nCommandQueue::CommitCurrentChunk()')
    assert hashlib.sha256((baseline_commit + '\n').encode()).hexdigest() == BASELINE_COMMIT_SHA256, 'frozen tested baseline CommitCurrentChunk changed'
    staged = stage.stage_queue(original)
    maintenance = function(staged, 'uint64_t\nCommandQueue::maintainCompletedCommandData(')
    candidate_commit = function(staged, 'void\nCommandQueue::CommitCurrentChunk()')
    assert 'cpu_command_allocator.free_blocks(cpu_coherent.signaledValue());' in baseline_commit
    assert 'maintainCompletedCommandData(cpu_coherent.signaledValue());' in candidate_commit
    header = stage.stage_queue_header((DXMT / 'dxmt_command_queue.hpp').read_text())
    assert 'RingBumpState<CpuCommandBlockAllocator, kCommandChunkCPUHeapSize, dxmt::null_mutex> cpu_command_allocator;' in header
    original_header = (DXMT / 'dxmt_command_queue.hpp').read_text()
    reset = function(original_header, '  void\n  reset() noexcept')
    finish = function(original, 'uint32_t\nCommandQueue::WaitForFinishThread()')
    publication_start = finish.index('    chunk.reset();')
    publication_end = finish.index('\n\n    staging_allocator.', publication_start)
    publication = finish[publication_start:publication_end]
    assert publication.index('chunk.reset();') < publication.index('cpu_coherent.signal(internal_seq)')
    assert finish.index('chunk.attached_cmdbuf.waitUntilCompleted();') < finish.index('chunk.reset();')
    pressure = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
    pressure = pressure[pressure.index('struct MemoryPressureSnapshot {'):pressure.index('namespace memory_pressure_detail {')]
    body = QUEUE.replace('/* ACTUAL_CURRENT_CHUNK */', function(header, '  CommandChunk *\n  CurrentChunk()').replace('CommandChunk *', 'Chunk *', 1))
    body = body.replace('/* ACTUAL_CHUNK_RESET */', reset).replace('/* ACTUAL_FINISH_PUBLICATION */', publication)
    body = body.replace('/* ACTUAL_ALLOCATE */', function(header, '  void *\n  AllocateCommandData('))
    result = {}
    for name, candidate, vm_backing in (('baseline', False, False), ('bounded-malloc', True, False), ('bounded-vm', True, True)):
        selected = body.replace('/* ACTUAL_MAINTENANCE */', maintenance if candidate else '')
        selected = selected.replace('/* ACTUAL_COMMIT */', candidate_commit if candidate else baseline_commit)
        selected = selected.replace('CPU_BACKING_ALLOCATOR', 'CpuCommandBlockAllocator' if vm_backing else 'HostBufferBlockAllocator')
        main = MAIN.replace('POLICY_NAME', name).replace('PHYSICAL_SOURCE', 'task-phys-footprint' if sys.platform == 'darwin' else 'unavailable-nondarwin')
        result[name] = '#define CANDIDATE ' + str(int(candidate)) + '\n' + PRELUDE.replace('/* ACTUAL_PRESSURE_TYPES */', pressure) + actual_ring + selected + main
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-darwin', action='store_true')
    parser.add_argument('--emit-source', type=Path)
    args = parser.parse_args()
    sources = generated_sources()
    if args.emit_source:
        args.emit_source.write_text(sources['bounded-vm'])
        print('EMIT only: actual CPU-command fixture; no native physical result')
        return
    if sys.platform != 'darwin':
        if args.require_darwin:
            raise SystemExit('FAIL: actual Darwin task footprint is required')
        print('SKIP native CPU-command physical replay: Darwin required; no simulated physical result')
        return
    compiler = os.environ.get('CXX') or shutil.which('clang++')
    if not compiler:
        raise SystemExit('FAIL: native C++ compiler missing')
    results = {}
    with tempfile.TemporaryDirectory(prefix='madeira-cpu-command-native-') as temporary:
        temporary = Path(temporary)
        for name, source in sources.items():
            path, binary = temporary / (name + '.cpp'), temporary / name
            path.write_text(source)
            subprocess.run([compiler, '-std=c++20', '-O2', '-pthread', '-Wall', '-Wextra', '-Werror', str(path), '-o', str(binary)], check=True)
            if name == 'bounded-vm':
                backend = subprocess.run([str(binary), '--backend-test'], text=True, capture_output=True, check=True, timeout=30)
                print(backend.stdout, end='')
            completed = subprocess.run([str(binary)], text=True, capture_output=True, check=True, timeout=120)
            print(completed.stdout, end='')
            rows = [json.loads(line.removeprefix('CPU_COMMAND_NATIVE_RESULT ')) for line in completed.stdout.splitlines() if line.startswith('CPU_COMMAND_NATIVE_RESULT ')]
            assert len(rows) == 1 and rows[0]['policy'] == name and rows[0]['physical_source'] == 'task-phys-footprint'
            results[name] = rows[0]
    old, middle, new = results['baseline'], results['bounded-malloc'], results['bounded-vm']
    assert old['checksum'] == new['checksum'] and old['payload_bytes'] == new['payload_bytes']
    assert old['checksum'] == middle['checksum'] and old['payload_bytes'] == middle['payload_bytes']
    assert old['submissions'] == new['submissions'] == 25
    assert middle['submissions'] == 25
    assert old['owned_after_pressure_bytes'] == 64 << 20 and new['owned_after_pressure_bytes'] <= 4 << 20
    assert middle['owned_after_pressure_bytes'] <= 4 << 20
    assert old['owned_after_zero_bytes'] == 64 << 20 and new['owned_after_zero_bytes'] == 0
    print('PASS actual CPU-command/ring/owned backing: identical used bytes, pending protection, completed-only retention, zero-headroom drain, healthy recovery and balanced destruction')
    print('NOTE both cases perform the same initial command burst; its capacity peak is unchanged. The following physical samples test completed retention, not a guaranteed lower workload peak.')
    print('OBSERVED actual task footprint after completed pressure maintenance: baseline=' + str(old['footprint_after_pressure_bytes']) + ' bounded-malloc=' + str(middle['footprint_after_pressure_bytes']) + ' bounded-vm=' + str(new['footprint_after_pressure_bytes']) + ' bytes; separate fresh processes, controlled completion/pressure, not iPhone acceptance')
    old_drop = old['footprint_before_pressure_bytes'] - old['footprint_after_pressure_bytes']
    new_drop = new['footprint_before_pressure_bytes'] - new['footprint_after_pressure_bytes']
    middle_drop = middle['footprint_before_pressure_bytes'] - middle['footprint_after_pressure_bytes']
    print(f'OBSERVED within-process footprint drops at maintenance: baseline={old_drop} bounded-malloc={middle_drop} bounded-vm={new_drop} bytes; no capacity-to-physical equivalence assumed')
    if new['footprint_after_pressure_bytes'] >= old['footprint_after_pressure_bytes']:
        print('NOTE host allocator retention/noise did not yield a lower measured footprint; no physical-improvement claim')


if __name__ == '__main__':
    main()
