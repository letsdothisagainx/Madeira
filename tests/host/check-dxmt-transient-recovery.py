#!/usr/bin/env python3
"""Run admission reclamation against actual owned, completion-indexed rings.

GPU frontiers and physical-headroom readings are controlled inputs. Ring
allocation/destruction, the denial helper, the queue recovery latch and its
completion claim are production code. This is not an iPhone RSS measurement.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sanitize', action='store_true')
args = parser.parse_args()


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def declaration(text, signature):
    begin = text.index(signature)
    end = text.index('{', begin) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[begin:end] + '\n'


UPLOAD = module('transient_upload', 'tools/build/stage-dxmt-upload-memory.py')
ADMISSION = module('transient_admission', 'tools/build/stage-dxmt-texture-admission.py')
RINGS = module('transient_ring_fixture', 'tests/host/check-dxmt-upload-memory.py')
ring = UPLOAD.stage_ring((ROOT / 'dxmt/src/dxmt/dxmt_ring_bump_allocator.hpp').read_text())
queue = UPLOAD.stage_queue_header((ROOT / 'dxmt/src/dxmt/dxmt_command_queue.hpp').read_text())
current = declaration(ADMISSION.ADMISSION_HELPER, 'static void\nReclaimTextureGrowth(')
assert ADMISSION.ADMISSION_HELPER.count(
    'ReclaimTextureGrowth(queue, bytes, release_warm, permit.denied());') == 2
assert 'allocation_transient_frontier_' in queue

# Exact predecessor helper from a1ab80c2. Its one-time warm drain also
# accidentally gated all main-queue transient reclamation for the episode.
BASELINE = r'''static void
ReclaimTextureGrowth(CommandQueue &queue, uint64_t bytes, bool allocation_denied = false) {
  const auto pressure = memoryPressureSnapshot(true);
  const uint64_t coherent = queue.CoherentSeqId();
  const bool emergency = allocation_denied || (pressure.valid &&
      (pressure.available <= pressure.reserve / 4 || bytes >= pressure.available));
  struct SweepStamp {
    uint64_t domain = 0, coherent = 0, largest = 0;
    bool valid = false, emergency = false;
  };
  thread_local SweepStamp previous;
  if (allocation_denied || !previous.valid || previous.domain != queue.memoryDomain() ||
      previous.coherent != coherent || bytes > previous.largest ||
      (emergency && !previous.emergency)) {
    previous = {queue.memoryDomain(), coherent, bytes, pressure.valid, emergency};
    DynamicBuffer::TrimCompletedForQueue(queue.memoryDomain(), coherent, allocation_denied, nullptr, bytes);
    if (allocation_denied)
      queue.trimCompletedTransientMemory();
  }
  queue.initializer.trimMemoryPressure(allocation_denied);
}
'''

C = RINGS.PRELUDE + RINGS.ring_code(ring) + RINGS.ALLOCATOR + r'''
constexpr uint64_t MiB = uint64_t{1} << 20;
struct MemoryPressureSnapshot {
  uint64_t available = 0, reserve = 768 * MiB;
  bool valid = true;
};
static MemoryPressureSnapshot pressure;
static MemoryPressureSnapshot memoryPressureSnapshot(bool) { return pressure; }
struct DynamicBuffer {
  static inline std::atomic<unsigned> forced{0}, ordinary{0};
  static void TrimCompletedForQueue(uint64_t, uint64_t, bool critical, const void *, uint64_t) {
    if (critical) ++forced; else ++ordinary;
  }
};
struct Initializer {
  std::atomic<unsigned> calls{0}, forced{0};
  uint64_t trimMemoryPressure(bool critical) {
    ++calls; if (critical) ++forced; return 0;
  }
};
template<size_t Size> class ObservedRing : public dxmt::RingBumpState<CountingAllocator, Size> {
  using Parent = dxmt::RingBumpState<CountingAllocator, Size>;
public:
  std::atomic<unsigned> trims{0};
  ObservedRing() : Parent(CountingAllocator{}) {}
  uint64_t trim_completed(uint64_t coherent, bool keep) {
    ++trims; return Parent::trim_completed(coherent, keep);
  }
};
class CommandQueue {
  std::atomic<bool> allocation_recovery_latched_{false};
  std::atomic<uint64_t> allocation_transient_frontier_{UINT64_MAX};
  std::atomic<bool> cpu_command_release_requested_{false};
  static uint64_t NextMemoryDomain() {
    static std::atomic<uint64_t> next{1};
    return next.fetch_add(1);
  }
  uint64_t domain_ = NextMemoryDomain();
public:
  Initializer initializer;
  ObservedRing<32 * MiB> staging_allocator, copy_temp_allocator;
  ObservedRing<4 * MiB> argbuf_allocator;
  std::atomic<uint64_t> coherent{1};
  uint64_t CoherentSeqId() const { return coherent.load(); }
  uint64_t memoryDomain() const { return domain_; }
'''
C += declaration(queue, 'uint64_t trimCompletedTransientMemory(')
C += declaration(queue, 'bool allocationRecoveryDrain(')
C += r'''
  unsigned trimCalls() const {
    return staging_allocator.trims + copy_temp_allocator.trims + argbuf_allocator.trims;
  }
  void allocate(uint64_t seq, uint64_t completed) {
    staging_allocator.allocate(seq, completed, 32 * MiB, 256);
    copy_temp_allocator.allocate(seq, completed, 32 * MiB, 256);
    argbuf_allocator.allocate(seq, completed, 4 * MiB, 256);
  }
};
'''

MAIN = r'''
static void recover(CommandQueue &q, uint64_t bytes, bool actual_denial) {
  bool warm = actual_denial ? q.allocationRecoveryDrain(3) : q.allocationRecoveryDrain(2);
#ifdef BASELINE_RECOVERY
  ReclaimTextureGrowth(q, bytes, warm);
#else
  ReclaimTextureGrowth(q, bytes, warm, actual_denial);
#endif
}
static void firstDrain(CommandQueue &q) {
  q.allocate(1, 0);
  assert(counts.bytes == 68 * MiB);
  recover(q, MiB, true);
  assert(counts.bytes == 0 && DynamicBuffer::forced == 1 && q.trimCalls() == 3);
}
int main(int argc, char **argv) {
  assert(argc == 2);
  const unsigned scenario = std::strtoul(argv[1], nullptr, 10);
  const uint64_t requests[] = {22543008, 10485760, 10485760, 10485760, 22020096};
  const uint64_t available[] = {221808272, 209127080, 209077928, 208324264, 208209576};
  pressure.available = 209127080;
  CommandQueue q;
  if (scenario < 5) {
    const uint64_t floor = 201326592, bytes = requests[scenario];
    firstDrain(q);
    q.allocate(2, 1);
    auto &pending = q.staging_allocator.allocate(3, 1, 32 * MiB, 256).first;
    pending.payload->data[0] = 0xb2;
    q.coherent = 2;
    const size_t before = counts.bytes;
    pressure.available = available[scenario];
    assert(bytes > pressure.available - floor);
    recover(q, bytes, true);
#ifdef BASELINE_RECOVERY
    assert(counts.bytes == before && q.trimCalls() == 3);
    assert(bytes > pressure.available - floor);
    std::puts("BEFORE: latched warm recovery leaves newly GPU-completed transient backing owned; request remains above usable headroom");
#else
    const uint64_t freed = before - counts.bytes;
    assert(freed == 68 * MiB && counts.bytes == 32 * MiB && q.trimCalls() == 6);
    assert(bytes <= pressure.available + freed - floor);
    assert(DynamicBuffer::forced == 1);
    for (unsigned i = 0; i < 100; ++i) recover(q, bytes, true);
    assert(q.trimCalls() == 6 && counts.bytes == 32 * MiB && DynamicBuffer::forced == 1);
    std::printf("PASS request=%llu: released %llu actual owned bytes at new GPU frontier; pending 32MiB preserved; modeled headroom recovers without another dynamic warm drain\n",
                (unsigned long long)bytes, (unsigned long long)freed);
#endif
    assert(pending.payload->data[0] == 0xb2);
  } else if (scenario == 5) {
    q.allocate(1, 0);
    auto &pending = q.staging_allocator.allocate(2, 0, 32 * MiB, 256).first;
    pending.payload->data[0] = 0x72;
    q.coherent = 0;
    const size_t before = counts.bytes;
    recover(q, 22 * MiB, true);
    assert(counts.bytes == before && pending.payload->data[0] == 0x72);
    assert(q.trimCalls() == 3);
    std::puts("PASS absent completion frees no bytes and does not invent headroom");
  } else if (scenario == 6) {
    q.allocate(1, 0);
    q.coherent = 1;
    for (unsigned i = 0; i < 100; ++i) recover(q, 16384, false);
    assert(counts.bytes == 68 * MiB && q.trimCalls() == 0 && DynamicBuffer::forced == 0);
    std::puts("PASS 100 soft-pressure calls retain completed warm rings without allocation/destruction churn");
  } else {
    firstDrain(q);
    q.allocate(2, 1);
    q.coherent = 2;
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 8; ++i) workers.emplace_back([&] {
      for (unsigned n = 0; n < 100; ++n) recover(q, MiB, true);
    });
    for (auto &worker : workers) worker.join();
    assert(counts.bytes == 0 && q.trimCalls() == 6 && DynamicBuffer::forced == 1);
    std::puts("PASS eight denial workers claim the completed frontier once; no repeated dynamic emergency drain");
  }
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-transient-recovery-') as directory:
    flags = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if args.sanitize else []
    for name, helper in [('baseline', BASELINE), ('candidate', current)]:
        source, binary = Path(directory) / (name + '.cpp'), Path(directory) / name
        source.write_text(C + helper + MAIN)
        defines = ['-DBASELINE_RECOVERY'] if name == 'baseline' else []
        subprocess.run([*shlex.split(os.environ.get('CXX', 'c++')), '-std=c++20', '-O1', '-g', '-pthread',
                        '-Wall', '-Wextra', '-Werror', *flags, *defines,
                        str(source), '-o', str(binary)], check=True, timeout=90)
        for scenario in ([0] if name == 'baseline' else range(8)):
            subprocess.run([str(binary), str(scenario)], check=True, timeout=45)
print('NOTE GPU completion and physical-headroom inputs are controlled; no iPhone footprint or successful texture creation is claimed')
