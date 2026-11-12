#!/usr/bin/env python3
"""Stage completion-safe upload pressure control without editing pinned DXMT."""
import argparse
import hashlib
import json
from pathlib import Path


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError(f"DXMT upload contract changed: {before[:90]!r}")
    return source.replace(before, after, 1)


def stage_ring(source):
    source = replace_once(source, "    if (front.last_used_seq_id < coherent_id) {",
                          "    if (front.last_used_seq_id <= coherent_id) {")
    source = replace_once(source, "  void free_blocks(uint64_t coherent_id);", """  void free_blocks(uint64_t coherent_id);

  // A completion frontier is inclusive. Only its owner may supply it; a CPU
  // recording sequence or an arbitrary maximum is not a completion proof.
  // Pending/latest allocations above this frontier remain owned by the ring.
  uint64_t trim_completed(uint64_t coherent_id, bool keep_last_normal = false);

  // Admission accounts for an actual new block, rather than charging every
  // texture subresource for a complete staging block. Caller serializes its
  // producer; the ring lock also excludes the GPU completion thread's trims.
  size_t allocation_growth(uint64_t coherent_id, size_t size, size_t alignment) {
    std::lock_guard<mutex> lock(mutex_);
    if (!fifo.empty()) {
      const auto &latest = fifo.back();
      if (align(latest.allocated_size, alignment) + size <= latest.total_size)
        return 0;
      const auto &front = fifo.front();
      if (front.last_used_seq_id <= coherent_id && front.total_size >= std::max(size, ring_block_size()) &&
          (front.total_size == ring_block_size() || front.reusable_oversize))
        return 0;
    }
    return std::max(size, ring_block_size());
  }""")
    marker = "template <typename Allocator, size_t BlockSize, class mutex>\nRingBumpState<Allocator, BlockSize, mutex>::Allocation &"
    source = replace_once(source, marker, """template <typename Allocator, size_t BlockSize, class mutex>
uint64_t
RingBumpState<Allocator, BlockSize, mutex>::trim_completed(uint64_t coherent_id, bool keep_last_normal) {
  std::lock_guard<mutex> lock(mutex_);
  uint64_t released = 0;
  while (!fifo.empty() && fifo.front().last_used_seq_id <= coherent_id) {
    auto &front = fifo.front();
    // A bounded natural-size warm block avoids allocating a fresh 32MB Metal
    // upload buffer on every frame under sustained soft pressure. Critical
    // pressure drops it too. Never retain an arbitrarily large ad-hoc block.
    if (keep_last_normal && fifo.size() == 1 && front.total_size == ring_block_size() &&
        !front.reusable_oversize)
      break;
    released += front.total_size;
    if (front.reusable_oversize) --reusable_oversize_blocks_;
    fifo.pop();
  }
  return released;
}

""" + marker)
    return source


def stage_initializer_header(source):
    if "uint64_t trimMemoryPressure();" in source:
        raise ValueError("DXMT upload initializer header is already staged")
    source = replace_once(source, "  uint64_t flushToWait();", """  uint64_t flushToWait();

  // Only completed transient upload storage is reclaimable. Texture/SRV
  // ownership, pending CPU commands and live GPU uploads are unchanged.
  uint64_t trimMemoryPressure();""")
    source = replace_once(source, "  uint64_t flushInternal();", """  uint64_t flushInternal();
  uint64_t refreshCompletedLocked(bool trim);
  void prepareUploadLocked(size_t size);""")
    return source


def stage_initializer(source):
    source = replace_once(source, '#include "dxmt_resource_initializer.hpp"',
                          '#include "dxmt_resource_initializer.hpp"\n#include "memory_pressure.hpp"')
    source = replace_once(source, "  upload_queue_event_ = device.newSharedEvent();", """  upload_queue_event_ = device.newSharedEvent();
  Logger::info("[upload-memory-v1] inclusive-completion reuse; pressure-trim; bounded-upload-wait-ms=50");""")
    source = replace_once(source, "ResourceInitializer::~ResourceInitializer() {\n  free(cpu_command_heap);", """ResourceInitializer::~ResourceInitializer() {
  if (zero_buffer_census_)
    mem_census_sub(MEMOWN_INIT_UPLOAD, zero_buffer_census_);
  free(cpu_command_heap);""")
    source = replace_once(source,
        "    flushInternal();\n  do {\n    RETAIN(allocation);\n    ALLOC_BLIT(wmtcmd_blit_copy_from_buffer_to_texture, copy);\n    ALLOC_GPU(temp, total_bytes_needed);",
        "    flushInternal();\n  prepareUploadLocked(total_bytes_needed);\n  do {\n    RETAIN(allocation);\n    ALLOC_BLIT(wmtcmd_blit_copy_from_buffer_to_texture, copy);\n    ALLOC_GPU(temp, total_bytes_needed);")
    source = replace_once(source, "  cached_coherent_seq_id = upload_queue_event_.signaledValue();\n  gpu_command_heap_allocator.free_blocks(cached_coherent_seq_id);", """  refreshCompletedLocked(memoryPressureSnapshot().needsReclaim());""")
    old = """  if (idle()) {
    gpu_command_heap_allocator.free_blocks(cached_coherent_seq_id);
    if (cached_coherent_seq_id == current_seq_id_ - 1)
      return 0;
    cached_coherent_seq_id = upload_queue_event_.signaledValue();
    if (cached_coherent_seq_id == current_seq_id_ - 1)
      return 0;
    return current_seq_id_ - 1;
  }"""
    new = """  if (idle()) {
    // Sample the real GPU event BEFORE reclamation, including an idle queue:
    // no later submission may arrive to refresh yesterday's cached frontier.
    refreshCompletedLocked(memoryPressureSnapshot().needsReclaim());
    if (cached_coherent_seq_id >= current_seq_id_ - 1)
      return 0;
    return current_seq_id_ - 1;
  }"""
    source = replace_once(source, old, new)
    source = replace_once(source, "void\nResourceInitializer::reset() {", """uint64_t
ResourceInitializer::refreshCompletedLocked(bool trim) {
  cached_coherent_seq_id = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  uint64_t released = 0;
  if (trim) {
    const auto pressure = memoryPressureSnapshot();
    const bool keep_warm = pressure.valid && pressure.available >= pressure.reserve / 2;
    released = gpu_command_heap_allocator.trim_completed(cached_coherent_seq_id, keep_warm);
  } else
    gpu_command_heap_allocator.free_blocks(cached_coherent_seq_id);
  // zero_buffer_ can occur in several submitted and pending blits. Release
  // only after BOTH CPU command lists and ALL their GPU submissions finish.
  if (trim && idle() && cached_coherent_seq_id >= current_seq_id_ - 1 && zero_buffer_) {
    released += zero_buffer_census_;
    mem_census_sub(MEMOWN_INIT_UPLOAD, zero_buffer_census_);
    zero_buffer_census_ = 0;
    zero_buffer_size_ = 0;
    zero_buffer_ = nullptr;
  }
  return released;
}

uint64_t
ResourceInitializer::trimMemoryPressure() {
  if (!memoryPressureSnapshot().needsReclaim())
    return 0;
  std::lock_guard<dxmt::mutex> lock(mutex_);
  return refreshCompletedLocked(true);
}

void
ResourceInitializer::prepareUploadLocked(size_t size) {
  auto pressure = memoryPressureSnapshot();
  if (!pressure.valid)
    return; // An unavailable host measurement is not an invented limit.
  cached_coherent_seq_id = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  const size_t growth = gpu_command_heap_allocator.allocation_growth(
      cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment);
  if (!pressure.needsReclaim(growth))
    return;
  // Reusing/suballocating a real existing block needs no further wait. Still
  // let completion/idle paths trim unrelated completed transient storage.
  if (!growth)
    return;
  if (!idle())
    flushInternal();
  const uint64_t submitted = current_seq_id_ - 1;
  if (submitted > cached_coherent_seq_id) {
    // This is ONLY the private upload queue's GPU-signalled event, never the
    // main encoder's CPU fence. A failed GPU command may never signal: one
    // bounded wait avoids a deadlock or an endless memory-pressure loop.
    upload_queue_event_.waitUntilSignaledValue(submitted, 50);
  }
  refreshCompletedLocked(true);
  // The ordinary allocator must still provide genuine backing or fail. Live
  // textures are never evicted and unmet pressure never fabricates success.
}

void
ResourceInitializer::reset() {""")
    return source


def stage_queue(source):
    source = replace_once(source, '#include "dxmt_command_queue.hpp"',
                          '#include "dxmt_command_queue.hpp"\n#include "dxmt_dynamic.hpp"\n#include "memory_pressure.hpp"')
    source = replace_once(source, """    staging_allocator.free_blocks(internal_seq);
    copy_temp_allocator.free_blocks(internal_seq);
    argbuf_allocator.free_blocks(internal_seq);""", """    auto pressure = memoryPressureSnapshot();
    if (pressure.needsReclaim()) {
      // The command buffer has finished, completion targets ran and the chunk
      // released its CPU references before this inclusive coherence frontier.
      // Real ring mutexes protect producers; null_mutex CPU/deferred command
      // heaps are deliberately NOT trimmed from this finishing thread.
      const bool critical = pressure.available < pressure.reserve / 2;
      staging_allocator.trim_completed(internal_seq, !critical);
      copy_temp_allocator.trim_completed(internal_seq, !critical);
      argbuf_allocator.trim_completed(internal_seq, !critical);
      DynamicBuffer::TrimCompletedForQueue(memoryDomain(), internal_seq, critical);
      initializer.trimMemoryPressure();
    } else {
      staging_allocator.free_blocks(internal_seq);
      copy_temp_allocator.free_blocks(internal_seq);
      argbuf_allocator.free_blocks(internal_seq);
    }""")
    return source


def stage_queue_header(source):
    if "const uint64_t memory_domain_" in source:
        raise ValueError("DXMT command queue header is already staged")
    source = replace_once(source, "class CommandQueue {\n\nprivate:", """class CommandQueue {

private:
  // A resource may outlive its parent device through an internal reference.
  // An address is therefore not a queue identity: a later queue can occupy
  // the same address with an unrelated GPU completion sequence.
  static uint64_t NextMemoryDomain() {
    static std::atomic<uint64_t> next{1};
    return next.fetch_add(1, std::memory_order_relaxed);
  }
  const uint64_t memory_domain_ = NextMemoryDomain();""")
    source = replace_once(source, "  CommandQueue(WMT::Device device);", """  CommandQueue(WMT::Device device);

  uint64_t memoryDomain() const { return memory_domain_; }""")
    return source


STAGES = {
    "dxmt_ring_bump_allocator.hpp": stage_ring,
    "dxmt_resource_initializer.hpp": stage_initializer_header,
    "dxmt_resource_initializer.cpp": stage_initializer,
    "dxmt_command_queue.cpp": stage_queue,
    "dxmt_command_queue.hpp": stage_queue_header,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.source_dir.resolve() == args.output_dir.resolve():
        parser.error("pinned DXMT input must remain immutable")
    # Compute every output before publishing any, failing closed on drift.
    outputs = {}
    records = {}
    for name, transform in STAGES.items():
        original = (args.source_dir / name).read_bytes()
        outputs[name] = transform(original.decode()).encode()
        records[name] = {"source_sha256": hashlib.sha256(original).hexdigest(),
                         "output_sha256": hashlib.sha256(outputs[name]).hexdigest()}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in outputs.items():
        (args.output_dir / name).write_bytes(value)
    print(json.dumps({"stage": "dxmt-upload-memory-v1", "files": records}))


if __name__ == "__main__":
    main()
