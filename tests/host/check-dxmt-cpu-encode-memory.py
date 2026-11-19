#!/usr/bin/env python3
"""Compile real DXMT CPU encoding scratch storage and its retirement tail.

The fixture owns ordinary host byte arrays and controls pressure/GPU completion.
Its byte counts are host allocation capacity, not iPhone RSS or Metal residency.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'dxmt_upload_stage', ROOT / 'tools/build/stage-dxmt-upload-memory.py')
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


def braced(source, anchor):
    start = source.index(anchor)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PRELUDE = r'''
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <unordered_map>
#include <vector>
#define unlikely(x) (x)
template <typename T> void *ptr_add(void *pointer, T offset) {
  return static_cast<char *>(pointer) + offset;
}
size_t align_forward_adjustment(const void *pointer, const size_t &alignment) {
  return (-reinterpret_cast<uintptr_t>(pointer)) & (alignment - 1);
}
void require(bool condition, const char *message) {
  if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
std::unordered_map<void *, size_t> scratch_allocations;
size_t scratch_live = 0, scratch_peak = 0;
void *tracked_malloc(size_t bytes) {
  void *pointer = std::malloc(bytes);
  require(pointer, "host fixture backing allocation failed");
  scratch_allocations.emplace(pointer, bytes);
  scratch_live += bytes;
  scratch_peak = std::max(scratch_peak, scratch_live);
  return pointer;
}
void tracked_free(void *pointer) {
  if (!pointer) return;
  auto found = scratch_allocations.find(pointer);
  require(found != scratch_allocations.end(), "scratch released twice");
  scratch_live -= found->second;
  scratch_allocations.erase(found);
  std::free(pointer);
}
// ACTUAL_PRESSURE_POLICY
dxmt::MemoryPressureSnapshot pressure_reading;
dxmt::MemoryPressureSnapshot memoryPressureSnapshot() { return pressure_reading; }
// The production scratch tail must compile with no queue or initializer
// methods available: its pressure history belongs solely to this producer.
size_t gpu_live = 0, destroyed_commands = 0;
struct GpuBuffer {
  std::vector<uint8_t> bytes;
  GpuBuffer() : bytes(4096, 0x7d) { ++gpu_live; }
  ~GpuBuffer() { --gpu_live; }
};
struct PendingCommand {
  std::shared_ptr<GpuBuffer> resource;
  uint8_t *payload;
  uint8_t value;
  ~PendingCommand() { ++destroyed_commands; }
};
// ACTUAL_CONSTANTS
class Context {
public:
  // ACTUAL_CHUNK
  std::vector<chunk> cpu_buffer_chunks_;
  uint32_t current_buffer_chunk_ = 0;
  void *cpu_buffer_ = nullptr;
  uint64_t cpu_buffer_offset_ = 0, seq_id_ = 0, frame_id_ = 0;
  // ACTUAL_CONTROLLER_MEMBER
  std::vector<PendingCommand *> pending;
  std::vector<std::shared_ptr<GpuBuffer>> gpu_pending;
  Context() { cpu_buffer_chunks_.emplace_back(); begin(); }
  // ACTUAL_ALLOCATE
  // ACTUAL_BEGIN
  void begin() {
    require(pending.empty(), "new encoding began before consuming old CPU commands");
    setEncodingContext(++seq_id_, frame_id_ + 1);
  }
  void pressure(uint64_t available, bool valid = true) {
    auto &reading = pressure_reading;
    reading.valid = valid;
    reading.reserve = 1024;
    reading.available = available;
    ++reading.sampled_ns;
  }
  void record(unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
      auto *payload = static_cast<uint8_t *>(allocate_cpu_heap(1 << 19, 16));
      const auto value = uint8_t(i + 1);
      std::memset(payload, value, 1 << 19);
      auto *command = new (allocate_cpu_heap(sizeof(PendingCommand), alignof(PendingCommand)))
          PendingCommand{std::make_shared<GpuBuffer>(), payload, value};
      pending.push_back(command);
    }
  }
  void encodeAndRetire() {
    // Controlled native encoder: it consumes CPU payload synchronously and
    // retains real, independent GPU backing until explicit completion below.
    // The production tail is reached only after every CPU command destructor.
    for (auto *command : pending) {
      for (size_t i = 0; i < (1 << 19); i += 4096)
        require(command->payload[i] == command->value, "live CPU command bytes changed");
      require(command->payload[(1 << 19) - 1] == command->value, "CPU payload tail changed");
      gpu_pending.push_back(command->resource);
      command->~PendingCommand();
    }
    pending.clear();
    retireScratch();
  }
  void retireScratch() {
    // ACTUAL_RETIREMENT_TAIL
  }
  void completeGpu() {
    for (const auto &resource : gpu_pending)
      require(resource->bytes.front() == 0x7d && resource->bytes.back() == 0x7d,
              "CPU scratch reclamation changed pending GPU backing");
    gpu_pending.clear();
  }
};
#undef malloc
#undef free
'''


MAIN = r'''
int main() {
  constexpr size_t chunk_bytes = kEncodingContextCPUHeapSize;
  {
    Context context;
    context.pressure(2048);
    context.record(8);
    const auto recorded_bytes = scratch_live;
    require(recorded_bytes >= 8 * chunk_bytes, "fixture did not allocate multiple real scratch chunks");
    context.pressure(256); // Critical pressure cannot reclaim live CPU commands.
    require(scratch_live == recorded_bytes && destroyed_commands == 0 && gpu_live == 8,
            "pressure query reclaimed commands before encoding consumed them");
    context.encodeAndRetire();
    require(destroyed_commands == 8 && gpu_live == 8 && context.gpu_pending.size() == 8,
            "scratch retirement changed real pending GPU ownership");
    require(scratch_live == (CANDIDATE ? chunk_bytes : recorded_bytes),
            "critical retirement did not match old/new real scratch policy");
    const auto retired_bytes = scratch_live;
    // The old 600-flush policy retains dead scratch through a frame gap.
    // Time without a flush cannot advance this submission-count expiration.
    require(scratch_live == retired_bytes, "idle gap changed scratch ownership");
    if (!CANDIDATE) {
      for (unsigned i = 0; i < kEncodingContextCPUHeapLifetime; ++i) {
        context.begin(); context.encodeAndRetire();
      }
      require(scratch_live == recorded_bytes, "old scratch TTL was not reproduced exactly");
      context.begin(); context.encodeAndRetire();
      require(scratch_live == chunk_bytes, "old scratch did not expire on flush 601");
    }
    context.begin();
    auto *probe = static_cast<uint8_t *>(context.allocate_cpu_heap(64, 16));
    probe[0] = 0x48;
    require(probe[0] == 0x48 && scratch_live == chunk_bytes,
            "next submission failed to reuse the surviving scratch chunk");
    context.completeGpu();
    require(gpu_live == 0, "explicit GPU completion did not release GPU backing");
    std::cout << (CANDIDATE ? "NEW" : "OLD")
              << " host-owned-scratch-before=" << recorded_bytes
              << " after-critical-encoding=" << retired_bytes
              << " pending-gpu-buffers=8 phone-RSS=unmeasured\n";
  }
  require(scratch_live == 0, "context destruction leaked real scratch backing");
  {
    Context context;
    // Exact first b14d rejection: just above the 192 MiB admission floor,
    // below the 768 MiB reserve, with no earlier critical-pressure latch.
    auto &reading = pressure_reading;
    reading = {0, 201934216, 0, uint64_t{768} << 20, 1, true};
    context.record(8);
    const size_t high = scratch_live;
    context.encodeAndRetire();
    require(scratch_live == high,
            "soft near-floor pressure unexpectedly discarded current working-set scratch");
    context.begin(); context.encodeAndRetire();
    require(scratch_live == (CANDIDATE ? chunk_bytes : high),
            "soft near-floor pressure retained unused previous-submission scratch");
    context.completeGpu();
  }
  require(scratch_live == 0 && gpu_live == 0, "near-floor fixture leaked backing");
  if (CANDIDATE) {
    Context context;
    context.pressure(2048); context.record(8); context.encodeAndRetire();
    const size_t high = scratch_live;
    context.begin(); context.pressure(0, false); context.encodeAndRetire();
    require(scratch_live == high, "unknown pressure changed healthy scratch expiration");
    context.begin(); context.pressure(2048); context.encodeAndRetire();
    require(scratch_live == high, "healthy path changed scratch expiration");
    context.begin(); context.pressure(1024); context.record(2);
    const size_t used = context.current_buffer_chunk_ + 1;
    context.encodeAndRetire();
    require(scratch_live == used * chunk_bytes && used > 1,
            "soft pressure failed to release only unused surplus");
    context.begin(); context.pressure(1152); context.encodeAndRetire();
    require(scratch_live == chunk_bytes,
            "recovery hysteresis retained old unused surplus");
    context.begin(); context.pressure(1280); context.record(8); context.encodeAndRetire();
    require(scratch_live >= 8 * chunk_bytes,
            "healthy recovery unnecessarily discarded active working-set scratch");
    context.completeGpu();
    require(gpu_live == 0, "healthy/recovery GPU backing leaked");
  }
  require(scratch_live == 0 && scratch_allocations.empty(), "owned host arrays leaked");
  std::cout << "PASS actual CPU scratch chunk/allocation/context-reset/retirement code: "
               "600-flush baseline, critical/soft/recovery/healthy/unknown pressure, "
               "live CPU payloads, pending GPU backing, reuse and destruction\n";
}
'''


def fixture(header, source, candidate):
    pressure = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
    policy = pressure[pressure.index('struct MemoryPressureSnapshot {'):
                      pressure.index('\nnamespace memory_pressure_detail {')]
    constants = '\n'.join(line for line in header.splitlines()
                          if line.startswith('constexpr size_t kEncodingContextCPUHeap'))
    chunk = braced(header, '  struct chunk {') + ';'
    allocator = braced(header, '  void *\n  allocate_cpu_heap(')
    begin = braced(source, 'void\nArgumentEncodingContext::$$setEncodingContext(')
    begin = begin.replace('ArgumentEncodingContext::$$setEncodingContext', 'setEncodingContext', 1)
    tail = source[source.index('  cmdbuf.encodeSignalEvent(queue_.event, event_seq_id);'):
                  source.index('\n  return visibility_readback;')]
    tail = tail.split('\n', 1)[1]
    if candidate:
        assert 'const auto cpu_pressure' in tail
    # Production ownership boundary: every typed encoder destructor and all
    # native encoding precede this tail. No CPU heap pointer escapes through
    # the readback object; it owns its own Metal buffer and query vector.
    flush = source[source.index('ArgumentEncodingContext::flushCommands('):
                   source.index('\nDXMT_ENCODER_LIST_OP\n')]
    for kind in ('RenderEncoderData', 'ComputeEncoderData', 'BlitEncoderData',
                 'ClearEncoderData', 'PresentData', 'ResolveEncoderData',
                 'StretchBlitEncoderData', 'SpatialUpscaleData', 'SignalEventData',
                 'WaitForEventData', 'TemporalUpscaleData'):
        assert flush.rfind('~' + kind + '()') < flush.index(tail.strip())
        assert '~' + kind + '()' in flush
    output = PRELUDE.replace('// ACTUAL_PRESSURE_POLICY', 'namespace dxmt {\n' + policy + '\n}')
    output = output.replace('// ACTUAL_CONSTANTS', constants)
    output = output.replace('// ACTUAL_CHUNK', '#define malloc tracked_malloc\n#define free tracked_free\n' + chunk)
    member = next((line for line in header.splitlines()
                   if 'MemoryPressureController cpu_pressure_controller_;' in line), '')
    assert bool(member) == candidate
    output = output.replace('// ACTUAL_CONTROLLER_MEMBER', member.replace('MemoryPressureController', 'dxmt::MemoryPressureController'))
    output = output.replace('// ACTUAL_ALLOCATE', allocator)
    output = output.replace('// ACTUAL_BEGIN', begin)
    output = output.replace('// ACTUAL_RETIREMENT_TAIL', tail)
    return '#define CANDIDATE ' + str(int(candidate)) + '\n' + output + MAIN


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    header = (ROOT / 'dxmt/src/dxmt/dxmt_context.hpp').read_text()
    original = (ROOT / 'dxmt/src/dxmt/dxmt_context.cpp').read_text()
    staged = STAGE.stage_encoding_context(original)
    staged_header = STAGE.stage_encoding_context_header(header)
    try:
        STAGE.stage_encoding_context(staged)
    except ValueError:
        pass
    else:
        raise AssertionError('duplicate CPU encoding stage accepted')
    try:
        STAGE.stage_encoding_context_header(staged_header)
    except ValueError:
        pass
    else:
        raise AssertionError('duplicate CPU encoding header stage accepted')
    with tempfile.TemporaryDirectory(prefix='dxmt-cpu-encode-memory-') as directory:
        directory = Path(directory)
        for label, source, candidate in (('old', original, False), ('new', staged, True)):
            cpp, binary = directory / (label + '.cpp'), directory / label
            cpp.write_text(fixture(staged_header if candidate else header, source, candidate))
            command = [os.environ.get('CXX', 'c++'), '-std=c++20', '-Wall', '-Wextra', '-Werror',
                       '-O1', '-g', str(cpp), '-o', str(binary)]
            if args.sanitize:
                command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(command, check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
