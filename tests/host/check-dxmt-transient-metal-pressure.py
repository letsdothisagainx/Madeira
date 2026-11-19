#!/usr/bin/env python3
"""Exercise staged transient rings with real Metal ownership and footprint.

Critical-pressure inputs are controlled. GPU completion, MTLBuffer allocations,
copied bytes and task phys_footprint are real on Darwin. The old completion
policy is frozen from tested a99940fb; the corrected completion policy, warm
budget helper and allocation wrappers are extracted from the current stage.
Both execute the actual staged ring. In the old policy its new completed-warm
slot stays empty, so the old natural-size/drain behavior is unchanged.

No whole-buffer touching is used to manufacture a physical-memory result:
every submission writes/copies/checks the same 3 MiB payload. Allocation traffic,
owned capacity, Metal allocated size and physical footprint remain separate.
This is a controlled host regression, not an iPhone or CS2 loading benchmark.
"""
import argparse
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


def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    tokens = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]'
    for token in re.finditer(tokens, source[brace:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[start:brace + token.end()]
    raise AssertionError('unterminated production function: ' + signature)


# Exact behavioral statements of the installed critical completion path.
# The unchanged DynamicBuffer visit is outside this transient-ring workload.
BASELINE_COMPLETION = r'''
    const auto pressure = initializer.transientMemoryPressureDecision();
    if (pressure.reclaim) {
      const bool critical = !pressure.valid || pressure.critical;
      staging_allocator.trim_completed(internal_seq, !critical);
      copy_temp_allocator.trim_completed(internal_seq, !critical);
      argbuf_allocator.trim_completed(internal_seq, !critical);
      initializer.trimMemoryPressure();
    } else {
      staging_allocator.free_blocks(internal_seq);
      copy_temp_allocator.free_blocks(internal_seq);
      argbuf_allocator.free_blocks(internal_seq);
    }
    DynamicBuffer::TrimCompletedForQueue(memoryDomain(), internal_seq, false);
'''


PRELUDE = r'''
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <mach/mach.h>
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <unistd.h>
#define WARN(...) ((void)0)
namespace dxmt {
using mutex = std::mutex;
template<class T, class U> size_t align(T v, U a) {
  return (size_t(v) + size_t(a) - 1) & ~(size_t(a) - 1);
}
constexpr size_t kStagingBlockSize = 32u << 20;
constexpr size_t kStagingBlockLifetime = 300;
size_t madeiraRingBlockSize(size_t natural) { return natural; }
bool ringOversizeReuseEnabled() { return false; }
}
namespace WMT { using Buffer = id<MTLBuffer>; }
static void *ptr_add(void *p, size_t n) { return static_cast<char *>(p) + n; }
static uint64_t physical_footprint() {
  task_vm_info_data_t info = {};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  assert(task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS);
  assert(count >= TASK_VM_INFO_REV1_COUNT);
  return info.phys_footprint;
}
struct Stats {
  id<MTLDevice> device;
  id<MTLSharedEvent> completed;
  uint64_t allocations = 0, frees = 0, requested = 0, owned = 0, owned_peak = 0;
  uint64_t footprint_base = 0, footprint_peak = 0, metal_base = 0, metal_peak = 0;
  std::map<uintptr_t, uint64_t> last_use;
  void sample() {
    footprint_peak = std::max(footprint_peak, physical_footprint());
    metal_peak = std::max<uint64_t>(metal_peak, device.currentAllocatedSize);
  }
  void begin() {
    footprint_base = footprint_peak = physical_footprint();
    metal_base = metal_peak = device.currentAllocatedSize;
  }
};
struct MetalAllocator {
  id<MTLDevice> device;
  MTLResourceOptions options;
  Stats *stats;
  bool placed = false;
  struct Block {
    id<MTLBuffer> buffer = nil;
    void *mapped_address = nullptr;
    void *owned_memory = nullptr;
    uint64_t gpu_address = 0;
    uint64_t capacity = 0;
    Stats *stats = nullptr;
    Block() = default;
    Block(const Block &) = delete;
    Block &operator=(const Block &) = delete;
    Block(Block &&other) noexcept
      : buffer(std::exchange(other.buffer, (id<MTLBuffer>)nil)), mapped_address(other.mapped_address),
        owned_memory(std::exchange(other.owned_memory, nullptr)),
        capacity(other.capacity), stats(other.stats) {}
    ~Block() {
      if (!buffer) return;
      auto found = stats->last_use.find((uintptr_t)buffer);
      // Native Metal retains its own command references. Independently require
      // the ring's owner not to retire before the real GPU completion frontier.
      assert(found == stats->last_use.end() || found->second <= stats->completed.signaledValue);
      stats->last_use.erase((uintptr_t)buffer);
      [buffer release];
      // Match StagingBufferBlockAllocator's no-copy ownership order: the
      // native buffer stops referring to supplied memory before it is freed.
      free(owned_memory);
      ++stats->frees;
      stats->owned -= capacity;
      stats->sample();
    }
  };
  Block allocate(size_t size) {
    Block result;
    if (placed) {
      result.owned_memory = malloc(size);
      const size_t page = size_t(sysconf(_SC_PAGESIZE));
      assert(result.owned_memory && page && !((uintptr_t)result.owned_memory % page) && !(size % page));
      result.buffer = [device newBufferWithBytesNoCopy:result.owned_memory length:size
                                              options:options deallocator:NULL];
    } else
      result.buffer = [device newBufferWithLength:size options:options];
    assert(result.buffer && result.buffer.length >= size);
    result.mapped_address = (options & MTLResourceStorageModePrivate) ? nullptr : result.buffer.contents;
    result.capacity = size;
    result.stats = stats;
    ++stats->allocations;
    stats->requested += size;
    stats->owned += size;
    stats->owned_peak = std::max(stats->owned_peak, stats->owned);
    stats->sample();
    return result;
  }
};
'''


QUEUE_PREFIX = r'''
namespace dxmt {
/* ACTUAL_PRESSURE_TYPES */
static MemoryPressureSnapshot fixture_pressure;
MemoryPressureSnapshot memoryPressureSnapshot() { return fixture_pressure; }
struct InitializerAdapter {
  MemoryPressureController controller;
  MemoryPressureDecision transientMemoryPressureDecision() {
    return controller.evaluate(memoryPressureSnapshot());
  }
  void trimMemoryPressure() {} // No private-initializer buffers in this queue workload.
};
struct DynamicBuffer {
  static void TrimCompletedForQueue(uint64_t, uint64_t frontier, bool) {
    (void)frontier; // No dynamic buffers are allocated by this fixture.
  }
};
class FixtureQueue {
public:
  id<MTLSharedEvent> event;
  InitializerAdapter initializer;
  RingBumpState<MetalAllocator> staging_allocator;
  RingBumpState<MetalAllocator> copy_temp_allocator;
  RingBumpState<MetalAllocator, 4u << 20> argbuf_allocator;
  std::atomic<size_t> transient_ring_minimum_{0};
  uint64_t ready_for_encode = 1;
  struct FenceAdapter {
    id<MTLSharedEvent> event;
    uint64_t signaledValue() const { return event.signaledValue; }
  } cpu_coherent;
  explicit FixtureQueue(id<MTLDevice> device, id<MTLSharedEvent> signal, Stats *stats)
    : event(signal),
      staging_allocator(MetalAllocator{device, MTLResourceStorageModeShared | MTLResourceCPUCacheModeWriteCombined, stats}),
      copy_temp_allocator(MetalAllocator{device, MTLResourceStorageModePrivate, stats}),
      argbuf_allocator(MetalAllocator{device, MTLResourceStorageModeShared | MTLResourceCPUCacheModeWriteCombined, stats, true}),
      cpu_coherent{signal} {}
  uint64_t memoryDomain() const { return 1; }
  uint64_t CoherentSeqId() const { return event.signaledValue; }
/* ACTUAL_WARM_BUDGET */
/* ACTUAL_STAGING_WRAPPER */
/* ACTUAL_COPY_WRAPPER */
/* ACTUAL_ARGUMENT_WRAPPER */
  void finish(uint64_t internal_seq) {
    assert(internal_seq <= event.signaledValue);
/* COMPLETION_POLICY */
  }
  void drain() {
    const uint64_t frontier = event.signaledValue;
    staging_allocator.trim_completed(frontier, false);
    copy_temp_allocator.trim_completed(frontier, false);
    argbuf_allocator.trim_completed(frontier, false);
  }
};
}
'''


MAIN = r'''
static void warm_driver(id<MTLDevice> device, id<MTLCommandQueue> commands) {
  @autoreleasepool {
    id<MTLBuffer> a = [device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    id<MTLBuffer> b = [device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    assert(a && b);
    memset(a.contents, 0x41, 64);
    id<MTLCommandBuffer> command = [commands commandBuffer];
    id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
    [blit copyFromBuffer:a sourceOffset:0 toBuffer:b destinationOffset:0 size:64];
    [blit endEncoding]; [command commit]; [command waitUntilCompleted];
    assert(command.status == MTLCommandBufferStatusCompleted && !memcmp(a.contents, b.contents, 64));
    [a release]; [b release];
  }
}
int main() {
  @autoreleasepool {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    assert(device && "actual Metal device required");
    id<MTLCommandQueue> commands = [device newCommandQueue];
    id<MTLSharedEvent> event = [device newSharedEvent];
    assert(commands && event);
    warm_driver(device, commands);
    Stats stats{device, event};
    stats.begin();
    const auto started = std::chrono::steady_clock::now();
    constexpr size_t payload = 3u << 20;
    constexpr unsigned submissions = 100;
    uint64_t checksum = 0;
    {
      dxmt::FixtureQueue queue(device, event, &stats);
      dxmt::fixture_pressure.valid = true;
      dxmt::fixture_pressure.reserve = uint64_t{768} << 20;
      dxmt::fixture_pressure.available = uint64_t{192} << 20;
      dxmt::fixture_pressure.limit = uint64_t{6144} << 20;
      dxmt::fixture_pressure.footprint = dxmt::fixture_pressure.limit - dxmt::fixture_pressure.available;
      dxmt::fixture_pressure.sampled_ns = 1;
      // The controlled episode is already critical before this repeated load.
      // The frontier remains the real initial GPU event value, zero.
      queue.finish(event.signaledValue);
      for (uint64_t seq = 1; seq <= submissions; ++seq) {
        @autoreleasepool {
          queue.ready_for_encode = seq;
          auto [staging, source_offset] = queue.AllocateStagingBuffer(payload, 256);
          auto [copy, copy_offset] = queue.AllocateTempBuffer(seq, payload, 256);
          auto [mapped_argument, argument, argument_offset] = queue.AllocateArgumentBuffer(seq, payload);
          assert(staging && copy && argument && mapped_argument);
          const uint8_t pattern = uint8_t(17 + seq);
          // Only legitimate input bytes are touched, never the unused tail.
          memset(static_cast<char *>(staging.contents) + source_offset, pattern, payload);
          stats.last_use[(uintptr_t)staging] = seq;
          stats.last_use[(uintptr_t)copy] = seq;
          stats.last_use[(uintptr_t)argument] = seq;
          const auto frees_before_pending_trim = stats.frees;
          const auto owned_before_pending_trim = stats.owned;
          queue.finish(event.signaledValue);
          assert(stats.frees == frees_before_pending_trim && stats.owned == owned_before_pending_trim);
          id<MTLCommandBuffer> command = [commands commandBuffer];
          id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
          [blit copyFromBuffer:staging sourceOffset:source_offset toBuffer:copy destinationOffset:copy_offset size:payload];
          [blit copyFromBuffer:copy sourceOffset:copy_offset toBuffer:argument destinationOffset:argument_offset size:payload];
          [blit endEncoding];
          [command encodeSignalEvent:event value:seq];
          [command commit];
          [command waitUntilCompleted];
          if (command.error) fprintf(stderr, "Metal failure: %s\n", command.error.description.UTF8String);
          assert(command.status == MTLCommandBufferStatusCompleted && event.signaledValue >= seq);
          assert(!memcmp(static_cast<char *>(staging.contents) + source_offset, mapped_argument, payload));
          checksum += uint64_t(pattern) * payload;
          ++dxmt::fixture_pressure.sampled_ns;
          queue.finish(event.signaledValue);
          // Ten bounded episodes also exercise explicit completed cache drains
          // used by allocation-failure/map-transition recovery. No active GPU
          // work is claimed complete to make these drains possible.
          if (seq % 10 == 0) {
            queue.drain();
            assert(stats.owned == 0);
          }
          stats.sample();
        }
        stats.sample(); // autoreleased command-buffer resource refs have drained.
      }
      queue.drain();
    }
    stats.sample();
    assert(stats.allocations == stats.frees && stats.owned == 0 && stats.last_use.empty());
    const uint64_t expected_checksum = (uint64_t{17} * submissions + submissions * (submissions + 1) / 2) * payload;
    assert(checksum == expected_checksum);
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count();
    const uint64_t after = physical_footprint();
    printf("METAL_PRESSURE_RESULT {\"policy\":\"POLICY_NAME\",\"submissions\":%u,\"pressure_cycles\":10,\"payload_bytes\":%zu,\"allocations\":%llu,\"frees\":%llu,\"allocation_traffic_bytes\":%llu,\"owned_peak_bytes\":%llu,\"metal_before_bytes\":%llu,\"sampled_metal_peak_bytes\":%llu,\"metal_after_bytes\":%llu,\"footprint_before_bytes\":%llu,\"sampled_footprint_peak_bytes\":%llu,\"footprint_after_bytes\":%llu,\"elapsed_us\":%lld,\"checksum\":%llu}\n",
           submissions, payload, (unsigned long long)stats.allocations, (unsigned long long)stats.frees,
           (unsigned long long)stats.requested, (unsigned long long)stats.owned_peak,
           (unsigned long long)stats.metal_base, (unsigned long long)stats.metal_peak,
           (unsigned long long)device.currentAllocatedSize, (unsigned long long)stats.footprint_base,
           (unsigned long long)stats.footprint_peak, (unsigned long long)after,
           (long long)elapsed, (unsigned long long)checksum);
    [event release]; [commands release]; [device release];
  }
}
'''


def generated_sources():
    spec = importlib.util.spec_from_file_location('metal_pressure_stage', ROOT / 'tools/build/stage-dxmt-upload-memory.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    ring = stage.stage_ring((DXMT / 'dxmt_ring_bump_allocator.hpp').read_text())
    start = ring.index('template <typename Allocator, size_t BlockSize =')
    end = ring.index('\nclass GpuPrivateBufferBlockAllocator', start)
    methods = ring.index('template <typename Allocator, size_t BlockSize, class mutex>\nstd::pair', end)
    ring = 'namespace dxmt {\n' + ring[start:end] + ring[methods:]
    pressure = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
    pressure = pressure[pressure.index('struct MemoryPressureSnapshot {'):pressure.index('namespace memory_pressure_detail {')]
    header = stage.stage_queue_header((DXMT / 'dxmt_command_queue.hpp').read_text())
    queue = stage.stage_queue((DXMT / 'dxmt_command_queue.cpp').read_text())
    beginning = queue.index('    const auto pressure = initializer.transientMemoryPressureDecision();')
    last = '    DynamicBuffer::TrimCompletedForQueue(memoryDomain(), internal_seq, false);'
    completion = queue[beginning:queue.index(last, beginning) + len(last)]
    assert 'trim_completed_budget' in completion and 'transient_ring_minimum_.store' in completion
    wrappers = {}
    for signature, key in (
        ('  static size_t TransientRingWarmBudget(', 'ACTUAL_WARM_BUDGET'),
        ('  std::tuple<WMT::Buffer, uint64_t>\n  AllocateStagingBuffer(', 'ACTUAL_STAGING_WRAPPER'),
        ('  std::pair<WMT::Buffer, uint64_t>\n  AllocateTempBuffer(', 'ACTUAL_COPY_WRAPPER'),
        ('  std::tuple<void *, WMT::Buffer, uint64_t>\n  AllocateArgumentBuffer(', 'ACTUAL_ARGUMENT_WRAPPER'),
    ):
        wrappers[key] = function(header, signature)
    prefix = QUEUE_PREFIX.replace('/* ACTUAL_PRESSURE_TYPES */', pressure)
    for key, value in wrappers.items():
        prefix = prefix.replace('/* ' + key + ' */', value)
    result = {}
    for name in ('baseline', 'bounded-reuse'):
        fixture_queue = prefix.replace('/* COMPLETION_POLICY */', BASELINE_COMPLETION if name == 'baseline' else completion)
        if name == 'baseline':
            # The old wrappers used four arguments and therefore natural32MiB
            # sizes. The actual corrected ring's unused warm slot stays empty.
            fixture_queue = fixture_queue.replace(', transient_ring_minimum_.load(std::memory_order_acquire)', '')
        result[name] = PRELUDE + ring + fixture_queue + MAIN.replace('POLICY_NAME', name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-darwin', action='store_true')
    parser.add_argument('--require-metal', action='store_true')
    parser.add_argument('--emit-source', type=Path)
    args = parser.parse_args()
    sources = generated_sources()
    if args.emit_source:
        args.emit_source.write_text(sources['bounded-reuse'])
        print('EMIT only: generated actual staged Metal pressure fixture; no native execution result')
        return
    if sys.platform != 'darwin':
        if args.require_darwin or args.require_metal:
            raise SystemExit('FAIL: real Darwin/Metal execution is required')
        print('SKIP actual Metal/physical-footprint validation: Darwin required; no simulated physical result')
        return
    compiler = os.environ.get('CXX') or shutil.which('clang++')
    if not compiler:
        raise SystemExit('FAIL: Objective-C++ compiler missing')
    results = {}
    with tempfile.TemporaryDirectory(prefix='madeira-transient-metal-') as temporary:
        temporary = Path(temporary)
        for name, source in sources.items():
            path, binary = temporary / (name + '.mm'), temporary / name
            path.write_text(source)
            subprocess.run([compiler, '-std=c++20', '-O2', '-fblocks', '-fno-objc-arc', '-pthread', str(path),
                            '-framework', 'Foundation', '-framework', 'Metal', '-o', str(binary)], check=True)
            completed = subprocess.run([str(binary)], text=True, capture_output=True, check=True, timeout=120)
            print(completed.stdout, end='')
            records = [json.loads(line.removeprefix('METAL_PRESSURE_RESULT '))
                       for line in completed.stdout.splitlines() if line.startswith('METAL_PRESSURE_RESULT ')]
            assert len(records) == 1 and records[0]['policy'] == name
            results[name] = records[0]
    old, new = results['baseline'], results['bounded-reuse']
    assert old['checksum'] == new['checksum'] and old['submissions'] == new['submissions'] == 100
    assert old['allocations'] == 300 and new['allocations'] == 30, results
    assert new['allocation_traffic_bytes'] < old['allocation_traffic_bytes']
    old_peak = old['sampled_footprint_peak_bytes'] - old['footprint_before_bytes']
    new_peak = new['sampled_footprint_peak_bytes'] - new['footprint_before_bytes']
    print('PASS actual Metal staged rings: identical valid payloads, real completion, pending ownership, ten completed drains; allocations 300->30')
    print(f'OBSERVED sampled task physical maximum deltas: baseline={old_peak} bounded-reuse={new_peak} bytes; '
          'these are measured host observations, not allocation-capacity arithmetic or iPhone acceptance')
    if new_peak >= old_peak:
        print('NOTE physical peak did not decrease on this host; allocation traffic reduction is not a physical-footprint claim')


if __name__ == '__main__':
    main()
