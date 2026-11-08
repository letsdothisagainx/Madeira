/* SPDX-License-Identifier: MIT */
#ifndef MADEIRA_FEX_OWNER_ALLOCATOR_H
#define MADEIRA_FEX_OWNER_ALLOCATOR_H

#include <stddef.h>
#include <stdint.h>

/* Image-local failure/acquisition counters; no per-allocation counter writes.
 * Reservations and residency remain Wine's census. */
struct MadeiraFEXOwnerAllocatorStats {
  uint64_t version;
  uint64_t heap_acquires;
  uint64_t allocation_failures;
  uint64_t rejected_owners;
  uint64_t rejected_arguments;
};

#ifdef __cplusplus
extern "C" {
#endif
int MadeiraFEXOwnerAllocatorSnapshot(struct MadeiraFEXOwnerAllocatorStats* output, size_t size);
#ifdef __cplusplus
}

namespace FEXCore::Allocator {
void* malloc(size_t size);
void* calloc(size_t count, size_t size);
void* memalign(size_t alignment, size_t size);
void* valloc(size_t size);
int posix_memalign(void** output, size_t alignment, size_t size);
void* realloc(void* pointer, size_t size);
void free(void* pointer);
size_t malloc_usable_size(void* pointer);
void* aligned_alloc(size_t alignment, size_t size);
void aligned_free(void* pointer);
void InitializeThread();
}
#endif
#endif
