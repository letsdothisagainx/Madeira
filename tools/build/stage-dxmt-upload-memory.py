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
    # Optional pressure sizing changes only new block growth. Existing blocks
    # retain their completion ownership and every healthy caller uses zero.
    source = replace_once(source,
        '  allocate(uint64_t seq_id, uint64_t coherent_id, size_t size, size_t alignment);',
        '  allocate(uint64_t seq_id, uint64_t coherent_id, size_t size, size_t alignment, size_t minimum_block = 0);')
    source = replace_once(source,
        '    uint64_t seq_id, uint64_t coherent_id, size_t size, size_t alignment\n)',
        '    uint64_t seq_id, uint64_t coherent_id, size_t size, size_t alignment, size_t minimum_block\n)')
    source = replace_once(source,
        'seq_id, coherent_id, std::max(size, ring_block_size()) // in case required size is larger than block size',
        'seq_id, coherent_id, std::max(size, minimum_block ? minimum_block : ring_block_size())')
    source = replace_once(source, '    bool reusable_oversize = false;',
        '    bool reusable_oversize = false;\n    bool compact = false;')
    source = replace_once(source,
        '    if (first.total_size == ring_block_size() && !first.reusable_oversize) {',
        '    if ((first.total_size == ring_block_size() || first.compact) && !first.reusable_oversize) {')
    source = replace_once(source,
        '      if (ringOversizeReuseEnabled() && front.total_size < block_size) {',
        '      if ((ringOversizeReuseEnabled() || front.compact) && front.total_size < block_size) {')
    source = replace_once(source,
        '      if (front.total_size != ring_block_size() && !front.reusable_oversize) {',
        '      if (front.total_size != ring_block_size() && !front.reusable_oversize && !front.compact) {')
    source = replace_once(source, '      .reusable_oversize = reusable_oversize,',
        '      .reusable_oversize = reusable_oversize,\n      .compact = block_size < ring_block_size(),')
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
  size_t allocation_growth(uint64_t coherent_id, size_t size, size_t alignment, size_t minimum_block = 0) {
    std::lock_guard<mutex> lock(mutex_);
    const size_t normal = minimum_block ? minimum_block : ring_block_size();
    if (!fifo.empty()) {
      const auto &latest = fifo.back();
      const size_t aligned = align(latest.allocated_size, alignment);
      if (aligned <= latest.total_size && size <= latest.total_size - aligned)
        return 0;
      const auto &front = fifo.front();
      if (front.last_used_seq_id <= coherent_id && front.total_size >= std::max(size, normal) &&
          (front.total_size == ring_block_size() || front.reusable_oversize || front.compact))
        return 0;
    }
    return std::max(size, normal);
  }

  // A texture's first (largest) subresource can fit the tail of a completed
  // latest block and mark it pending before the remaining mip batch arrives.
  // Do not promise whole-batch reuse merely because that same block could
  // have been recycled had the batch been a single allocation.
  size_t batch_growth(uint64_t coherent_id, size_t total, size_t first, size_t alignment, size_t minimum_block = 0) {
    std::lock_guard<mutex> lock(mutex_);
    if (!total)
      return 0;
    const size_t normal = minimum_block ? minimum_block : ring_block_size();
    const size_t growth = std::max(total, normal);
    if (!first) first = total;
    if (first > total || !alignment || (alignment & (alignment - 1)))
      return ~size_t{0};
    if (fifo.empty())
      return growth;
    const auto &latest = fifo.back();
    size_t latest_free = 0;
    if (latest.allocated_size <= ~size_t{0} - (alignment - 1)) {
      const size_t aligned = align(latest.allocated_size, alignment);
      if (aligned <= latest.total_size)
        latest_free = latest.total_size - aligned;
    }
    if (latest_free >= total)
      return 0;
    const auto &front = fifo.front();
    if (front.last_used_seq_id <= coherent_id && front.total_size >= growth &&
        (front.total_size == ring_block_size() || front.reusable_oversize || front.compact) &&
        (&front != &latest || latest_free < first))
      return 0;
    return growth;
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
    if (keep_last_normal && fifo.size() == 1 && (front.total_size == ring_block_size() || front.compact) &&
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
    if "uint64_t trimMemoryPressure(" in source:
        raise ValueError("DXMT upload initializer header is already staged")
    source = replace_once(source, '#include "dxmt_ring_bump_allocator.hpp"',
                          '#include "dxmt_ring_bump_allocator.hpp"\n#include "memory_pressure.hpp"')
    source = replace_once(source, "  uint64_t flushToWait();", """  uint64_t flushToWait();

  // Only completed transient upload storage is reclaimable. Texture/SRV
  // ownership, pending CPU commands and live GPU uploads are unchanged.
  uint64_t trimMemoryPressure(bool release_warm = false);

  // The initializer and its parent queue share one pressure history. Query
  // before taking its mutex; never hold a transient-ring lock around this.
  MemoryPressureDecision transientMemoryPressureDecision();

  // Estimate genuine additional upload backing at the real GPU frontier.
  // This is a synchronized forecast, not a reservation or completion signal.
  size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0, bool compact = false);

  // Conservatively cover every initialization operation observed so far,
  // including pending commands and other creators sharing this initializer.
  uint64_t initializationFence();""")
    source = replace_once(source, "  uint64_t flushInternal();", """  uint64_t flushInternal();
  uint64_t refreshCompletedLocked(bool trim, bool release_warm = false);
  void prepareUploadLocked(size_t size);""")
    source = replace_once(source, "  dxmt::mutex mutex_;", """  dxmt::mutex mutex_;
  MemoryPressureController transient_pressure_controller_;
  size_t texture_upload_minimum_ = 0;""")
    source = replace_once(source, '  ResourceInitializer(WMT::Device device);', '''  ResourceInitializer(WMT::Device device);

  // The factory already owns the initializer creation transaction. Restore
  // its allocation mode before releasing that transaction, including unwind
  // and nested creation. No backing or GPU lifetime is owned by this scope.
  class TextureUploadScope {
    ResourceInitializer &owner_;
    size_t previous_;
  public:
    explicit TextureUploadScope(ResourceInitializer &owner) : owner_(owner) {
      static const volatile char contract[] = "[texture-compact-upload-v1]";
      (void)contract[0];
      std::lock_guard<dxmt::mutex> lock(owner_.mutex_);
      previous_ = owner_.texture_upload_minimum_;
      owner_.texture_upload_minimum_ = 0;
    }
    TextureUploadScope(const TextureUploadScope &) = delete;
    ~TextureUploadScope() {
      std::lock_guard<dxmt::mutex> lock(owner_.mutex_);
      owner_.texture_upload_minimum_ = previous_;
    }
  };
  TextureUploadScope textureUploadScope() { return TextureUploadScope(*this); }''')
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
ResourceInitializer::refreshCompletedLocked(bool trim, bool release_warm) {
  cached_coherent_seq_id = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  uint64_t released = 0;
  if (trim) {
    const auto decision = transient_pressure_controller_.evaluate(memoryPressureSnapshot());
    const bool keep_warm = !release_warm && decision.valid && !decision.critical;
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
ResourceInitializer::trimMemoryPressure(bool release_warm) {
  const auto pressure = memoryPressureSnapshot();
  std::lock_guard<dxmt::mutex> lock(mutex_);
  const auto decision = transient_pressure_controller_.evaluate(pressure);
  if (!release_warm && (!decision.valid || !decision.reclaim))
    return 0;
  return refreshCompletedLocked(true, release_warm);
}

MemoryPressureDecision
ResourceInitializer::transientMemoryPressureDecision() {
  const auto pressure = memoryPressureSnapshot();
  std::lock_guard<dxmt::mutex> lock(mutex_);
  return transient_pressure_controller_.evaluate(pressure);
}

uint64_t
ResourceInitializer::initializationFence() {
  std::lock_guard<dxmt::mutex> lock(mutex_);
  return idle() ? current_seq_id_ - 1 : current_seq_id_;
}

size_t
ResourceInitializer::forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes, bool compact) {
  if (!total_payload_bytes)
    return 0;
  std::lock_guard<dxmt::mutex> lock(mutex_);
  if (total_payload_bytes > SIZE_MAX - (kResourceInitializerGpuUploadHeapAlignment - 1))
    return SIZE_MAX;
  texture_upload_minimum_ = compact ? align(total_payload_bytes, kResourceInitializerGpuUploadHeapAlignment) : 0;
  const uint64_t completed = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  return gpu_command_heap_allocator.batch_growth(
      completed, total_payload_bytes, first_subresource_bytes ? first_subresource_bytes : total_payload_bytes,
      kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
}

void
ResourceInitializer::prepareUploadLocked(size_t size) {
  // Most initial mip/slice uploads fit backing already owned by this ring.
  // That reuse needs no fresh native pressure or event call: the cached
  // completion frontier is conservative, and appending to the current tail
  // cannot overwrite bytes referenced by an earlier GPU upload. Sampling a
  // Metal shared event for every tiny mip otherwise crosses the PE/native
  // boundary thousands of times even though no new storage can be allocated.
  size_t growth = gpu_command_heap_allocator.allocation_growth(
      cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
  if (!growth)
    return;
  // Only a genuine capacity miss refreshes GPU completion. Recheck after
  // observing the real event: a formerly pending FIFO block may now be
  // reusable, without a wait, trim, new backing or physical-budget charge.
  cached_coherent_seq_id = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  growth = gpu_command_heap_allocator.allocation_growth(
      cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
  if (!growth)
    return;
  const auto pressure = memoryPressureSnapshot();
  if (!pressure.valid || !pressure.needsReclaim(growth))
    return; // Unknown pressure is not an invented limit or GPU completion.
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
    source = replace_once(source,
        '      current_seq_id_, cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment\n',
        '      current_seq_id_, cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_\n')
    return source


def stage_queue(source):
    source = replace_once(source, '#include "dxmt_command_queue.hpp"',
                          '#include "dxmt_command_queue.hpp"\n#include "dxmt_dynamic.hpp"\n#include "memory_pressure.hpp"')
    source = replace_once(source, """    staging_allocator.free_blocks(internal_seq);
    copy_temp_allocator.free_blocks(internal_seq);
    argbuf_allocator.free_blocks(internal_seq);""", """    const auto pressure = initializer.transientMemoryPressureDecision();
    if (pressure.reclaim) {
      // The command buffer has finished, completion targets ran and the chunk
      // released its CPU references before this inclusive coherence frontier.
      // Real ring mutexes protect producers; null_mutex CPU/deferred command
      // heaps are deliberately NOT trimmed from this finishing thread.
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
    // Dynamic caches have a serialized high/low-water controller. Visit it
    // at completion even in the recovery band; its healthy path returns
    // before a resource walk. The transient-ring rule must not force a drain.
    DynamicBuffer::TrimCompletedForQueue(memoryDomain(), internal_seq, false);""")
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
  const uint64_t memory_domain_ = NextMemoryDomain();
  std::atomic<bool> allocation_recovery_latched_{false};
  std::atomic<uint64_t> allocation_transient_frontier_{UINT64_MAX};""")
    source = replace_once(source, "  CommandQueue(WMT::Device device);", """  CommandQueue(WMT::Device device);

  uint64_t memoryDomain() const { return memory_domain_; }""")
    source = replace_once(source, '  uint64_t memoryDomain() const { return memory_domain_; }', '''  uint64_t memoryDomain() const { return memory_domain_; }

  // Final allocation-failure recovery drops only this queue's GPU-completed
  // transient blocks. The ring mutexes serialize their producers; the CPU
  // command heap is deliberately excluded. No live texture is evicted.
  uint64_t trimCompletedTransientMemory() {
    const uint64_t completed = CoherentSeqId();
    auto previous = allocation_transient_frontier_.load(std::memory_order_acquire);
    for (;;) {
      if (previous != UINT64_MAX && completed <= previous) return 0;
      if (allocation_transient_frontier_.compare_exchange_weak(
          previous, completed, std::memory_order_acq_rel, std::memory_order_acquire)) break;
    }
    return staging_allocator.trim_completed(completed, false) +
           copy_temp_allocator.trim_completed(completed, false) +
           argbuf_allocator.trim_completed(completed, false);
  }

  // Share denial recovery across resource workers. Once an episode has drained
  // its warm blocks, subsequent tiny creations may reuse them. Otherwise each
  // retry would allocate and discard a 32 MiB upload block. Only a native
  // healthy grant (already accounting for outstanding creators) rearms it.
  bool allocationRecoveryDrain(uint64_t native_status) {
    if (native_status == 1) {
      allocation_recovery_latched_.store(false, std::memory_order_release);
      return false;
    }
    if (native_status != 3 && native_status != 4)
      return false;
    return !allocation_recovery_latched_.exchange(true, std::memory_order_acq_rel);
  }''')
    return source


def stage_encoding_context_header(source):
    if 'cpu_pressure_controller_' in source or '#include "memory_pressure.hpp"' in source:
        raise ValueError('DXMT CPU encoding context header is already staged')
    source = replace_once(source, '#include "Metal.hpp"',
                          '#include "Metal.hpp"\n#include "memory_pressure.hpp"')
    return replace_once(source, '  std::vector<chunk> cpu_buffer_chunks_;', '''  // Only the encoding producer evaluates this history. Pressure sampling is
  // thread-cached; scratch retirement never takes an initializer/queue lock.
  MemoryPressureController cpu_pressure_controller_;
  std::vector<chunk> cpu_buffer_chunks_;''')


def stage_encoding_context(source):
    source = replace_once(source, '  cpu_buffer_chunks_.emplace_back();', '''  cpu_buffer_chunks_.emplace_back();
  Logger::info("[cpu-encode-memory-v1] pressure-only completed-encoding scratch trim; critical-warm-chunks=1");''')
    before = '''  for (size_t i = cpu_buffer_chunks_.size() - 1; i > current_buffer_chunk_; i--) {
    if (++cpu_buffer_chunks_[i].underused_times > kEncodingContextCPUHeapLifetime) {
      cpu_buffer_chunks_.pop_back();
    }
  }'''
    # This boundary follows every EncoderData destructor and the final native
    # encoder call. These are CPU encoding scratch chunks, not Metal argument
    # buffers, command-chunk closures, readback storage, or GPU allocations.
    # No other thread is permitted to reclaim the encoder's active storage.
    after = '''  const auto cpu_pressure = cpu_pressure_controller_.evaluate(memoryPressureSnapshot());
  if (cpu_pressure.reclaim) {
    // All CPU encoder commands have been consumed and their EncoderData
    // destructors ran above. Native Metal encoding copied their arguments;
    // real GPU buffers and allocation references still belong to the queue.
    // Soft pressure drops old surplus without waiting 600 more flushes.
    // Critical pressure also drops this submission's now-dead surplus before
    // a loading/frame gap, keeping one bounded 1 MiB scratch chunk warm.
    const size_t keep = cpu_pressure.critical ? 1 : size_t(current_buffer_chunk_) + 1;
    while (cpu_buffer_chunks_.size() > keep)
      cpu_buffer_chunks_.pop_back();
    if (current_buffer_chunk_ >= keep) {
      current_buffer_chunk_ = 0;
      cpu_buffer_ = cpu_buffer_chunks_[0].ptr;
      cpu_buffer_offset_ = 0;
    }
  } else {
''' + '\n'.join('  ' + line for line in before.splitlines()) + '''
  }'''
    return replace_once(source, before, after)


STAGES = {
    "dxmt_ring_bump_allocator.hpp": stage_ring,
    "dxmt_resource_initializer.hpp": stage_initializer_header,
    "dxmt_resource_initializer.cpp": stage_initializer,
    "dxmt_command_queue.cpp": stage_queue,
    "dxmt_command_queue.hpp": stage_queue_header,
    "dxmt_context.cpp": stage_encoding_context,
    "dxmt_context.hpp": stage_encoding_context_header,
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
