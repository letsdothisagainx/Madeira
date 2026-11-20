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


CPU_COMMAND_ALLOCATOR = r'''// Dedicated backing for the queue's private CPU command bytes. These are
// never guest-visible D3D11 resources or executable/FEX storage. Returning a
// completed block must return its pages, rather than retain malloc's high-water
// region in the native allocator. Other host/ref-tracker allocators are unchanged.
class CpuCommandBlockAllocator {
public:
  enum class Backend : uint8_t { None, Windows, Posix };
  struct ReleaseReports { std::atomic<unsigned> failures{0}; };

  class Block {
  public:
    void *ptr = nullptr;
    size_t allocation_size = 0;
    Backend backend = Backend::None;
    std::shared_ptr<ReleaseReports> reports;

    Block() = default;
    Block(const Block &) = delete;
    Block &operator=(const Block &) = delete;
    Block &operator=(Block &&) = delete;
    Block(Block &&other) noexcept : ptr(other.ptr), allocation_size(other.allocation_size), backend(other.backend), reports(std::move(other.reports)) {
      other.ptr = nullptr;
      other.allocation_size = 0;
      other.backend = Backend::None;
    }

    bool try_release() noexcept {
      if (!ptr) return true;
      bool released = false;
#if defined(_WIN32)
      const DWORD saved_error = GetLastError();
      if (backend == Backend::Windows)
        released = VirtualFree(ptr, 0, MEM_RELEASE) != 0;
      const unsigned long error = released ? 0 : GetLastError();
#else
      const int saved_error = errno;
      if (backend == Backend::Posix)
        released = munmap(ptr, allocation_size) == 0;
      const unsigned long error = released ? 0 : errno;
#endif
      // A failed OS operation retains the ownership metadata. It must never
      // masquerade as a successful physical release or unmap someone else's
      // pages through a fallback backend.
      if (!released && reports && reports->failures.fetch_add(1, std::memory_order_relaxed) < 8)
        std::fprintf(stderr, "[cpu-command-vm-v1] event=release-failed ptr=%p bytes=%zu backend=%u error=%lu physical-freed=unmeasured\n", ptr, allocation_size, unsigned(backend), error);
#if defined(_WIN32)
      SetLastError(saved_error);
#else
      errno = saved_error;
#endif
      if (!released) return false;
      ptr = nullptr;
      allocation_size = 0;
      backend = Backend::None;
      return true;
    }

    ~Block() noexcept { (void)try_release(); }
  };

  static size_t rounded_size(size_t bytes, size_t page_size) {
    if (!bytes || !page_size || (page_size & (page_size - 1)) ||
        bytes > std::numeric_limits<size_t>::max() - (page_size - 1))
      return 0;
    return (bytes + page_size - 1) & ~(page_size - 1);
  }

  Block allocate(size_t bytes) {
    static const volatile char contract[] = "[cpu-command-vm-v1]";
    (void)contract[0];
    size_t page_size = 0;
#if defined(_WIN32)
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    page_size = info.dwPageSize;
#else
    const long native_page_size = sysconf(_SC_PAGESIZE);
    if (native_page_size > 0) page_size = size_t(native_page_size);
#endif
    const size_t actual = rounded_size(bytes, page_size);
    if (!actual) throw std::bad_alloc();
    Block block;
    block.reports = reports_;
#if defined(_WIN32)
    block.ptr = VirtualAlloc(nullptr, actual, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!block.ptr) throw std::bad_alloc();
    block.backend = Backend::Windows;
#else
    void *mapping = mmap(nullptr, actual, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED) throw std::bad_alloc();
    block.ptr = mapping;
    block.backend = Backend::Posix;
#endif
    block.allocation_size = actual;
    return block;
  }
private:
  // Shared heap-owned reporting state survives the allocator member itself:
  // FIFO blocks may be destroyed later by RingBumpState member destruction.
  std::shared_ptr<ReleaseReports> reports_ = std::make_shared<ReleaseReports>();
};

'''


def stage_ring(source):
    source = replace_once(source, '#include <queue>', '#include <queue>\n#include <optional>')
    source = replace_once(source, '#include <optional>', '''#include <optional>
#include <exception>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <limits>
#include <memory>
#include <new>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif''')
    source = replace_once(source, 'class HostBufferBlockAllocator {', CPU_COMMAND_ALLOCATOR + 'class HostBufferBlockAllocator {')
    # The VM-backed CPU allocator reports allocation failure by exception.
    # Commit the reuse count only after backing and FIFO ownership succeed.
    source = replace_once(source, '  if (reusable_oversize) ++reusable_oversize_blocks_;\n  fifo.push({',
        '  fifo.push({')
    source = replace_once(source, '''      .block = allocator_.allocate(block_size),
  });
  return fifo.back();''', '''      .block = allocator_.allocate(block_size),
  });
  if (reusable_oversize) ++reusable_oversize_blocks_;
  return fifo.back();''')
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

  // Queue completion may keep one bounded, already completed spare even
  // while a newer FIFO tail remains pending. Pending entries never move.
  uint64_t trim_completed_budget(uint64_t coherent_id, size_t warm_budget);

  // Admission accounts for an actual new block, rather than charging every
  // texture subresource for a complete staging block. Caller serializes its
  // producer; the ring lock also excludes the GPU completion thread's trims.
  size_t allocation_growth(uint64_t coherent_id, size_t size, size_t alignment, size_t minimum_block = 0) {
    std::lock_guard<mutex> lock(mutex_);
    const size_t normal = minimum_block ? minimum_block : ring_block_size();
    const size_t required = std::max(size, normal);
    if (completed_warm_ && completed_warm_->total_size >= required)
      return 0;
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
    if (completed_warm_ && completed_warm_->total_size >= growth)
      return 0;
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
  if (completed_warm_ && !keep_last_normal) {
    released += completed_warm_->total_size;
    discard_completed_warm();
  }
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

template <typename Allocator, size_t BlockSize, class mutex>
uint64_t
RingBumpState<Allocator, BlockSize, mutex>::trim_completed_budget(uint64_t coherent_id, size_t warm_budget) {
  std::lock_guard<mutex> lock(mutex_);
  uint64_t released = 0;
  if (completed_warm_ && completed_warm_->total_size > warm_budget) {
    released += completed_warm_->total_size;
    discard_completed_warm();
  }
  while (!fifo.empty() && fifo.front().last_used_seq_id <= coherent_id) {
    auto &front = fifo.front();
    const bool reusable = front.total_size == ring_block_size() || front.compact || front.reusable_oversize;
    if (reusable && front.total_size <= warm_budget) {
      // Retain only the most recently completed eligible block. It has no
      // CPU/GPU consumer, unlike the FIFO entries beyond this frontier.
      if (completed_warm_) {
        released += completed_warm_->total_size;
        discard_completed_warm();
      }
      completed_warm_.emplace(std::move(front));
      completed_warm_->allocated_size = 0;
      completed_warm_->inc_time_to_live = 0;
    } else {
      released += front.total_size;
      if (front.reusable_oversize) --reusable_oversize_blocks_;
    }
    fifo.pop();
  }
  return released;
}

""" + marker)
    source = replace_once(source, '  std::queue<Allocation> fifo;', '''  std::queue<Allocation> fifo;
  std::optional<Allocation> completed_warm_;
  void discard_completed_warm() {
    if (completed_warm_ && completed_warm_->reusable_oversize) --reusable_oversize_blocks_;
    completed_warm_.reset();
  }''')
    source = replace_once(source, '''  free_blocks_keep_first() {
    std::lock_guard<mutex> lock(mutex_);''', '''  free_blocks_keep_first() {
    std::lock_guard<mutex> lock(mutex_);
    discard_completed_warm();''')
    source = replace_once(source, '''RingBumpState<Allocator, BlockSize, mutex>::free_blocks(uint64_t coherent_id) {
  std::lock_guard<mutex> lock(mutex_);''', '''RingBumpState<Allocator, BlockSize, mutex>::free_blocks(uint64_t coherent_id) {
  std::lock_guard<mutex> lock(mutex_);
  if (completed_warm_ && ((coherent_id >= completed_warm_->last_used_seq_id &&
      coherent_id - completed_warm_->last_used_seq_id > kStagingBlockLifetime) ||
      ++completed_warm_->inc_time_to_live > kStagingBlockLifetime || coherent_id == ~uint64_t{0}))
    discard_completed_warm();''')
    source = replace_once(source, '''  // Repeated image uploads just above the normal block size otherwise create''', '''  if (completed_warm_ && completed_warm_->total_size >= block_size) {
    completed_warm_->last_used_seq_id = seq_id;
    completed_warm_->allocated_size = 0;
    completed_warm_->inc_time_to_live = 0;
    fifo.push(std::move(*completed_warm_));
    completed_warm_.reset(); // ownership moved; the oversize count stays balanced
    return fifo.back();
  }
  // Repeated image uploads just above the normal block size otherwise create''')
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

  // Respect the configured ring class; this does not allocate or query GPU
  // completion. Large pressure batches stream through one such block.
  size_t uploadBlockSize() const { return gpu_command_heap_allocator.ring_block_size(); }

  // Conservatively cover every initialization operation observed so far,
  // including pending commands and other creators sharing this initializer.
  uint64_t initializationFence();""")
    source = replace_once(source, "  uint64_t flushInternal();", """  uint64_t flushInternal();
  uint64_t refreshCompletedLocked(bool trim, bool release_warm = false);
  bool prepareUploadLocked(size_t size);""")
    source = replace_once(source, "  dxmt::mutex mutex_;", """  dxmt::mutex mutex_;
  MemoryPressureController transient_pressure_controller_;
  size_t texture_upload_minimum_ = 0;
  size_t texture_upload_budget_ = 0, texture_upload_spent_ = 0;
  bool texture_upload_active_ = false;""")
    source = replace_once(source, '  ResourceInitializer(WMT::Device device);', '''  ResourceInitializer(WMT::Device device);

  // The factory already owns the initializer creation transaction. Restore
  // its allocation mode before releasing that transaction, including unwind
  // and nested creation. No backing or GPU lifetime is owned by this scope.
  class TextureUploadScope {
    ResourceInitializer &owner_;
    size_t previous_, previous_budget_, previous_spent_;
    bool previous_active_;
  public:
    explicit TextureUploadScope(ResourceInitializer &owner) : owner_(owner) {
      static const volatile char contract[] = "[texture-compact-upload-v1]";
      (void)contract[0];
      std::lock_guard<dxmt::mutex> lock(owner_.mutex_);
      previous_ = owner_.texture_upload_minimum_;
      previous_budget_ = owner_.texture_upload_budget_;
      previous_spent_ = owner_.texture_upload_spent_;
      previous_active_ = owner_.texture_upload_active_;
      owner_.texture_upload_minimum_ = 0;
      owner_.texture_upload_budget_ = owner_.texture_upload_spent_ = 0;
      owner_.texture_upload_active_ = false;
    }
    TextureUploadScope(const TextureUploadScope &) = delete;
    ~TextureUploadScope() {
      std::lock_guard<dxmt::mutex> lock(owner_.mutex_);
      owner_.texture_upload_minimum_ = previous_;
      owner_.texture_upload_budget_ = previous_budget_;
      owner_.texture_upload_spent_ = previous_spent_;
      owner_.texture_upload_active_ = previous_active_;
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
        "    flushInternal();\n  do {\n    // Preflight may submit/wait: run before retaining or linking this blit,\n    // including each CPU-command-space retry in the final staged producer.\n    if (!prepareUploadLocked(total_bytes_needed)) return 0;\n    RETAIN(allocation);\n    ALLOC_BLIT(wmtcmd_blit_copy_from_buffer_to_texture, copy);\n    ALLOC_GPU(temp, total_bytes_needed);")
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
    // Once actual uploads have started, the bounded batch owns one reusable
    // completed block until its creation scope exits. Before admission/first
    // upload, even an explicit denial drain remains free to release caches.
    const bool keep_warm = (texture_upload_budget_ && texture_upload_active_) ||
        (!release_warm && decision.valid && !decision.critical);
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
  const size_t natural = gpu_command_heap_allocator.ring_block_size();
  const bool bounded = compact && total_payload_bytes > natural &&
      first_subresource_bytes && first_subresource_bytes <= natural;
  texture_upload_budget_ = bounded ? natural : 0;
  texture_upload_spent_ = 0;
  texture_upload_active_ = false;
  texture_upload_minimum_ = bounded ? natural :
      compact ? align(total_payload_bytes, kResourceInitializerGpuUploadHeapAlignment) : 0;
  if (bounded) {
    static const volatile char contract[] = "[texture-bounded-upload-v1]";
    (void)contract[0];
    // Charge one complete block even when an existing block may be reused.
    // The producer below refuses additional growth after consuming this cap.
    return natural;
  }
  const uint64_t completed = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  return gpu_command_heap_allocator.batch_growth(
      completed, total_payload_bytes, first_subresource_bytes ? first_subresource_bytes : total_payload_bytes,
      kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
}

bool
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
    return true;
  // Only a genuine capacity miss refreshes GPU completion. Recheck after
  // observing the real event: a formerly pending FIFO block may now be
  // reusable, without a wait, trim, new backing or physical-budget charge.
  cached_coherent_seq_id = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  growth = gpu_command_heap_allocator.allocation_growth(
      cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
  if (!growth)
    return true;
  const auto pressure = memoryPressureSnapshot();
  if (!texture_upload_budget_ && (!pressure.valid || !pressure.needsReclaim(growth)))
    return true; // Unknown pressure is not an invented limit or GPU completion.
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
  if (texture_upload_budget_) {
    growth = gpu_command_heap_allocator.allocation_growth(
        cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
    if (texture_upload_spent_ > texture_upload_budget_ ||
        growth > texture_upload_budget_ - texture_upload_spent_)
      return false; // Real GPU completion did not make the charged block reusable.
  }
  // The ordinary allocator must still provide genuine backing or fail. Live
  // textures are never evicted and unmet pressure never fabricates success.
  return true;
}

void
ResourceInitializer::reset() {""")
    source = replace_once(source,
        '      current_seq_id_, cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment\n',
        '      current_seq_id_, cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_\n')
    source = replace_once(source, '''ResourceInitializer::allocateGpuHeap(size_t size, size_t &offset) {
  auto [block, offset_]''', '''ResourceInitializer::allocateGpuHeap(size_t size, size_t &offset) {
  // Never flush while the caller may be recording a command. Its preflight
  // runs before this transaction; this is only a nonflushing budget check.
  const size_t growth = texture_upload_budget_ ? gpu_command_heap_allocator.allocation_growth(
      cached_coherent_seq_id, size, kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_) : 0;
  if (texture_upload_budget_ && (texture_upload_spent_ > texture_upload_budget_ ||
      growth > texture_upload_budget_ - texture_upload_spent_))
    return {};
  auto [block, offset_]''')
    source = replace_once(source, '''  upload_bytes_since_flush_ += size;
  offset = offset_;
  return block.buffer;''', '''  if (texture_upload_budget_ && block.buffer) {
    texture_upload_spent_ += growth;
    texture_upload_active_ = true;
  }
  upload_bytes_since_flush_ += size;
  offset = offset_;
  return block.buffer;''')
    return source


def stage_queue(source):
    source = replace_once(source,
        '  cpu_command_allocator.free_blocks(cpu_coherent.signaledValue());',
        '  maintainCompletedCommandData(cpu_coherent.signaledValue());')
    source = replace_once(source, 'void\nCommandQueue::CommitChunkInternal(', '''uint64_t
CommandQueue::maintainCompletedCommandData(uint64_t completed) {
  static const volatile char contract[] = "[cpu-command-cache-v1]";
  (void)contract[0];
  // This ring intentionally uses null_mutex: only the serialized command
  // producer can maintain it. Finishing/denial threads may publish a request,
  // never touch its FIFO. The frontier is signalled only AFTER chunk.reset()
  // destroys CPU closures and the real GPU submission has completed.
  const bool forced = cpu_command_release_requested_.exchange(false, std::memory_order_acq_rel);
  const auto snapshot = memoryPressureSnapshot();
  const auto pressure = cpu_command_pressure_controller_.evaluate(snapshot);
  uint64_t released = 0;
  if (forced) {
    // The request can race the caller's earlier frontier sample. Acquire the
    // publication first, then refresh the genuine monotonic completion value;
    // otherwise consuming a new request with an old value loses its drain.
    completed = std::max(completed, cpu_coherent.signaledValue());
    released = cpu_command_allocator.trim_completed_budget(completed, 0);
  } else if (pressure.valid && pressure.reclaim) {
    // Completed command bytes are dead; keep at most one natural 4 MiB block
    // warm rather than the 300-submission high-water history. A genuine zero
    // headroom reading drains even that spare. Pending/current closures stay
    // owned, and no freed-capacity count is reported as physical reclamation.
    const size_t warm = std::min<uint64_t>(
        std::min<size_t>(cpu_command_allocator.ring_block_size(), size_t{4} << 20),
        std::min(snapshot.reserve / 64, snapshot.available / 16));
    released = cpu_command_allocator.trim_completed_budget(completed, warm);
  } else {
    cpu_command_allocator.free_blocks(completed);
    return 0;
  }
  if (released && cpu_command_pressure_reports_ < 8) {
    ++cpu_command_pressure_reports_;
    const auto after = memoryPressureSnapshot(true);
    const bool measured = snapshot.valid && after.valid;
    Logger::info(str::format("[cpu-command-cache-v1] event=trim domain=", memoryDomain(), " completed=", completed,
        " forced=", forced, " released-capacity=", released,
        " fp-before=", snapshot.footprint,
        " before-sampled-ns=", snapshot.sampled_ns,
        " fp-after=", after.footprint, " avail-after=", after.available,
        " delta-valid=", measured,
        " observed-drop=", measured && snapshot.footprint > after.footprint ? snapshot.footprint - after.footprint : 0,
        " physical-attribution=concurrent-observation coverage=first8-releases"));
  }
  return released;
}

void
CommandQueue::CommitChunkInternal(''')
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
      const auto snapshot = memoryPressureSnapshot();
      const size_t warm_budget = TransientRingWarmBudget(snapshot, pressure);
      // Use compact new blocks while pressure is latched, instead of
      // discarding/recreating 32MiB buffers for small updates every frame.
      size_t minimum = std::min<size_t>(4u << 20, decltype(argbuf_allocator)::ring_block_size());
      const size_t minimum_floor = std::min<size_t>(1u << 20, minimum);
      while (minimum > minimum_floor && minimum > warm_budget) minimum >>= 1;
      // Stay at the smallest class reached during this pressure episode;
      // headroom jitter must not repeatedly promote and evict the same cache.
      const size_t previous = transient_ring_minimum_.load(std::memory_order_relaxed);
      transient_ring_minimum_.store(previous ? std::min(previous, minimum) : minimum,
                                    std::memory_order_release);
      staging_allocator.trim_completed_budget(internal_seq, warm_budget);
      copy_temp_allocator.trim_completed_budget(internal_seq, warm_budget);
      argbuf_allocator.trim_completed_budget(internal_seq, warm_budget);
      initializer.trimMemoryPressure();
    } else {
      transient_ring_minimum_.store(0, std::memory_order_release);
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
    source = replace_once(source,
        'RingBumpState<HostBufferBlockAllocator, kCommandChunkCPUHeapSize, dxmt::null_mutex> cpu_command_allocator;',
        'RingBumpState<CpuCommandBlockAllocator, kCommandChunkCPUHeapSize, dxmt::null_mutex> cpu_command_allocator;')
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
  std::atomic<uint64_t> allocation_transient_frontier_{UINT64_MAX};
  std::atomic<size_t> transient_ring_minimum_{0};
  // Producer-owned history; other threads only publish the atomic request.
  MemoryPressureController cpu_command_pressure_controller_;
  std::atomic<bool> cpu_command_release_requested_{false};
  unsigned cpu_command_pressure_reports_ = 0;
  uint64_t maintainCompletedCommandData(uint64_t completed);

  static size_t TransientRingWarmBudget(const MemoryPressureSnapshot &snapshot,
                                       const MemoryPressureDecision &pressure) {
    static const volatile char contract[] = "[transient-reuse-v2]";
    (void)contract[0];
    if (!pressure.valid || !snapshot.valid) return 0;
    // One queue shares this budget across its three completion-owned rings.
    // Critical reuse is deliberately much smaller than the dynamic cache:
    // <=16MiB total, further reduced by actual remaining physical headroom.
    // Reusing this already-backed storage incurs no new allocation charge.
    const uint64_t total = pressure.critical
        ? std::min<uint64_t>(uint64_t{16} << 20, std::min(snapshot.reserve / 64, snapshot.available / 16))
        : pressure.warm_cache_budget;
    return total / 3;
  }""")
    source = replace_once(source, "  CommandQueue(WMT::Device device);", """  CommandQueue(WMT::Device device);

  uint64_t memoryDomain() const { return memory_domain_; }""")
    source = replace_once(source, '  uint64_t memoryDomain() const { return memory_domain_; }', '''  uint64_t memoryDomain() const { return memory_domain_; }

  // Final allocation-failure recovery drops only this queue's GPU-completed
  // transient blocks. The ring mutexes serialize their producers. The CPU
  // command heap can only be drained later by its serialized producer; this
  // call publishes that request and never accesses its null-mutex FIFO.
  uint64_t trimCompletedTransientMemory() {
    const uint64_t completed = CoherentSeqId();
    auto previous = allocation_transient_frontier_.load(std::memory_order_acquire);
    for (;;) {
      if (previous != UINT64_MAX && completed <= previous) return 0;
      if (allocation_transient_frontier_.compare_exchange_weak(
          previous, completed, std::memory_order_acq_rel, std::memory_order_acquire)) break;
    }
    cpu_command_release_requested_.store(true, std::memory_order_release);
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
    for old, new in (
        ('staging_allocator.allocate(ready_for_encode, cpu_coherent.signaledValue(), size, alignment)',
         'staging_allocator.allocate(ready_for_encode, cpu_coherent.signaledValue(), size, alignment, transient_ring_minimum_.load(std::memory_order_acquire))'),
        ('copy_temp_allocator.allocate(seq, cpu_coherent.signaledValue(), size, alignment)',
         'copy_temp_allocator.allocate(seq, cpu_coherent.signaledValue(), size, alignment, transient_ring_minimum_.load(std::memory_order_acquire))'),
        ('argbuf_allocator.allocate(seq, cpu_coherent.signaledValue(), size, 64)',
         'argbuf_allocator.allocate(seq, cpu_coherent.signaledValue(), size, 64, transient_ring_minimum_.load(std::memory_order_acquire))'),
    ):
        count = source.count(old)
        if count not in (1, 2):
            raise ValueError('DXMT transient allocation call shape changed: ' + old)
        source = source.replace(old, new)
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
