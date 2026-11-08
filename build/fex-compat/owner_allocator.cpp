// SPDX-License-Identifier: MIT
// Madeira's Windows FEX allocation boundary. Each PE image owns one explicit
// rpmalloc heap; the existing recursive allocator lock serializes its users.
// The heap is never installed in TLS or released by a thread's retirement.
#include "owner_allocator.h"

#include <rpmalloc/rpmalloc.h>
#include <windows.h>

#include <limits>

#if !defined(FEX_IOS_HOST) || !RPMALLOC_FIRST_CLASS_HEAPS
#error "The owner allocator requires the iOS Windows first-class heap build"
#endif

extern "C" {
void fex_ios_rpm_lock(void);
void fex_ios_rpm_unlock(void);
extern uintptr_t ios_fex_band_base;
extern uintptr_t ios_fex_band_end;
extern volatile int FEX_AllocWatch_Armed;
void FEX_AllocWatch_Event(const void*, unsigned);
}

namespace {
struct Guard {
  Guard() { fex_ios_rpm_lock(); }
  ~Guard() { fex_ios_rpm_unlock(); }
};

rpmalloc_heap_t* Heap;
bool Acquiring;
unsigned Reports;
MadeiraFEXOwnerAllocatorStats Stats {1, 0, 0, 0, 0};
constexpr size_t VallocAlignment = 64 * 1024;

void Append(char* buffer, size_t& used, const char* text) {
  while (*text && used < 254) buffer[used++] = *text++;
}

void Hex(char* buffer, size_t& used, uintptr_t value) {
  constexpr char digits[] = "0123456789abcdef";
  Append(buffer, used, "0x");
  for (unsigned shift = sizeof(value) * 8; shift; shift -= 4)
    if (used < 254) buffer[used++] = digits[(value >> (shift - 4)) & 15];
}

void Report(const char* reason, const void* pointer, size_t size) {
  if (Reports >= 16) return;
  ++Reports;
  char buffer[256];
  size_t used = 0;
  Append(buffer, used, "[fex-owner-allocator-v1] ");
  Append(buffer, used, reason);
  Append(buffer, used, " heap="); Hex(buffer, used, reinterpret_cast<uintptr_t>(Heap));
  Append(buffer, used, " pointer="); Hex(buffer, used, reinterpret_cast<uintptr_t>(pointer));
  Append(buffer, used, " size="); Hex(buffer, used, size);
  buffer[used++] = '\n';
  unsigned long written;
  WriteFile(GetStdHandle(static_cast<unsigned long>(-12)), buffer,
            static_cast<unsigned long>(used), &written, nullptr);
}

void Watch(const void* pointer, unsigned event) {
  if (pointer && FEX_AllocWatch_Armed) FEX_AllocWatch_Event(pointer, event);
}

bool ValidSize(size_t size) {
  // rpmalloc adds a span header, page rounding and sometimes alignment before
  // mapping a huge block. Reject impossible object sizes before that arithmetic.
  return size <= static_cast<size_t>((std::numeric_limits<ptrdiff_t>::max)()) - VallocAlignment;
}

bool ValidAlignment(size_t alignment) {
  return alignment && !(alignment & (alignment - 1)) && alignment < RPMALLOC_MAX_ALIGNMENT;
}

void* Failure(const char* reason, size_t size, bool argument = false) {
  ++Stats.allocation_failures;
  if (argument) ++Stats.rejected_arguments;
  Report(reason, nullptr, size);
  return nullptr;
}

rpmalloc_heap_t* EnsureHeap() {
  if (Heap) return Heap;
  if (Acquiring) return nullptr;
  // CRT_iOS initializes the default global configuration. A first allocation
  // from a constructor may precede it; rpmalloc's idempotent initializer uses
  // exactly the same default interface and configuration as CRT_iOS.
  Acquiring = true;
  if (!rpmalloc_config()->page_size && rpmalloc_initialize(nullptr)) {
    Acquiring = false;
    return nullptr;
  }
  Heap = rpmalloc_heap_acquire();
  Acquiring = false;
  if (Heap) {
    ++Stats.heap_acquires;
    Report("ready image-private=1 shared-tls=0", nullptr, 0);
  }
  return Heap;
}

bool Owns(void* pointer) {
  const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
  // Avoid calling rpmalloc's pointer decoder on ordinary guest/foreign CRT
  // memory. The inclusive published band is unchanged from the default mapper.
  // In-band inputs retain rpmalloc's valid-allocation-pointer precondition;
  // the public decoder verifies heap ownership, not arbitrary byte provenance.
  if (!Heap || !ios_fex_band_base || address < ios_fex_band_base || address > ios_fex_band_end ||
      rpmalloc_get_heap_for_ptr(pointer) != Heap) {
    ++Stats.rejected_owners;
    Report("foreign-pointer rejected", pointer, 0);
    return false;
  }
  return true;
}

void* Allocate(size_t size, size_t alignment, bool zero) {
  if (!ValidSize(size) || (alignment && (!ValidAlignment(alignment) ||
      size > (std::numeric_limits<size_t>::max)() - alignment)))
    return Failure("invalid-size-or-alignment", size, true);
  auto* heap = EnsureHeap();
  if (!heap) return Failure("heap-acquire-failed", size);
  void* result = alignment ? (zero ? rpmalloc_heap_aligned_calloc(heap, alignment, 1, size)
                                   : rpmalloc_heap_aligned_alloc(heap, alignment, size))
                           : (zero ? rpmalloc_heap_calloc(heap, 1, size) : rpmalloc_heap_alloc(heap, size));
  if (!result) return Failure("allocation-failed", size);
  Watch(result, 1);
  return result;
}
}

namespace FEXCore::Allocator {
void* malloc(size_t size) {
  Guard guard;
  return Allocate(size, 0, false);
}

void* calloc(size_t count, size_t size) {
  Guard guard;
  if (size && count > (std::numeric_limits<size_t>::max)() / size) {
    return Failure("calloc-overflow", size, true);
  }
  return Allocate(count * size, 0, true);
}

void* memalign(size_t alignment, size_t size) {
  Guard guard;
  if (!ValidAlignment(alignment)) {
    return Failure("invalid-alignment", size, true);
  }
  return Allocate(size, alignment, false);
}

void* valloc(size_t size) { return memalign(VallocAlignment, size); }

int posix_memalign(void** output, size_t alignment, size_t size) {
  Guard guard;
  // Numeric POSIX status values avoid touching CRT errno/TLS on early entries.
  if (!output || alignment < sizeof(void*) || !ValidAlignment(alignment)) {
    Failure("invalid-posix-alignment", size, true);
    return 22;
  }
  void* result = Allocate(size, alignment, false);
  if (!result) return 12;
  *output = result;
  return 0;
}

void* aligned_alloc(size_t alignment, size_t size) { return memalign(alignment, size); }

void free(void* pointer) {
  Guard guard;
  if (!pointer) return;
  // Preserve the pinned allocator's allocation watch and low-pointer diagnostic
  // before it decodes any span. Valid owner-zero heap frees are local under the
  // same serialization as allocation, including frees by another native thread.
  if (reinterpret_cast<uintptr_t>(pointer) < 0x10000000) {
    rpfree(pointer);
    return;
  }
  if (Owns(pointer)) rpfree(pointer);
}

void aligned_free(void* pointer) { free(pointer); }

size_t malloc_usable_size(void* pointer) {
  Guard guard;
  return pointer && Owns(pointer) ? rpmalloc_usable_size(pointer) : 0;
}

void* realloc(void* pointer, size_t size) {
  Guard guard;
  if (!pointer) return Allocate(size, 0, false);
  if (!ValidSize(size)) return Failure("invalid-realloc-size", size, true);
  if (!Owns(pointer)) return Failure("foreign-realloc rejected", size);
  if (!size) {
    rpfree(pointer);
    return nullptr;
  }
  // The explicit heap, rather than this thread's TLS heap, owns both buffers.
  void* result = rpmalloc_heap_realloc(Heap, pointer, size, 0);
  if (!result) return Failure("reallocation-failed", size);
  // A failed realloc retains its original allocation and emits no false free.
  if (result != pointer) {
    Watch(pointer, 2);
    Watch(result, 1);
  }
  return result;
}

void InitializeThread() {
  Guard guard;
  EnsureHeap();
}
}

extern "C" int MadeiraFEXOwnerAllocatorSnapshot(MadeiraFEXOwnerAllocatorStats* output, size_t size) {
  if (!output || size != sizeof(*output)) return 0;
  Guard guard;
  *output = Stats;
  return 1;
}
