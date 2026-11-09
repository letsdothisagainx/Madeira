#ifndef MADEIRA_GRAPHICS_DIAGNOSTICS_H
#define MADEIRA_GRAPHICS_DIAGNOSTICS_H

/* Metal-boundary observations only. No object, error, pixel or format is changed.
 * A native-image global budget covers all pseudo-processes together. Upload
 * fingerprints sample at most 64 already-owned bytes, never a whole texture.
 * No paths, shader source, account data or arbitrary NSError text is emitted. */
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

enum md_graphics_op {
  MD_GFX_TEXTURE, MD_GFX_BUFFER_TEXTURE, MD_GFX_VIEW, MD_GFX_UPLOAD,
  MD_GFX_UPLOAD_REJECTED, MD_GFX_LIBRARY, MD_GFX_FUNCTION,
  MD_GFX_COMPUTE_PSO, MD_GFX_RENDER_PSO, MD_GFX_VERTEX_PSO, MD_GFX_MESH_PSO,
  MD_GFX_BIND_PSO, MD_GFX_SUBMIT, MD_GFX_COMPLETED, MD_GFX_PRESENT,
  MD_GFX_PRESENTED, MD_GFX_RENDER_PASS, MD_GFX_DRAW, MD_GFX_OP_COUNT
};
struct md_graphics_counter { _Atomic uint64_t calls, failures; };
static struct md_graphics_counter md_graphics_counters[MD_GFX_OP_COUNT];
static _Atomic unsigned md_graphics_lines;
enum { MD_GRAPHICS_LINE_BUDGET = 256, MD_GRAPHICS_HASH_BYTES = 64 };

/* Independent geometry budget: changing offscreen viewports cannot consume
 * drawable/layer observations or the existing API-error budget. Exact double
 * bits preserve fractional viewport sizes. At most eight changes per kind. */
enum md_graphics_geometry_op { MD_GEOM_LAYER, MD_GEOM_DRAWABLE, MD_GEOM_VIEWPORT,
                             MD_GEOM_ATTACHMENT, MD_GEOM_COUNT };
struct md_graphics_geometry_counter {
  _Atomic uint64_t width, height;
  _Atomic unsigned seen, changes;
};
static struct md_graphics_geometry_counter md_graphics_geometry[MD_GEOM_COUNT];
enum { MD_GRAPHICS_GEOMETRY_CHANGES = 8 };

static inline int md_graphics_geometry_take(enum md_graphics_geometry_op op,
                                           double width, double height, unsigned *change)
{
  if ((unsigned)op >= MD_GEOM_COUNT) return 0;
  union { double value; uint64_t bits; } w = {width}, h = {height};
  struct md_graphics_geometry_counter *counter = &md_graphics_geometry[op];
  if (atomic_load_explicit(&counter->changes, memory_order_relaxed) >= MD_GRAPHICS_GEOMETRY_CHANGES)
    return 0;
  unsigned seen = atomic_exchange_explicit(&counter->seen, 1, memory_order_relaxed);
  uint64_t previous_w = atomic_exchange_explicit(&counter->width, w.bits, memory_order_relaxed);
  uint64_t previous_h = atomic_exchange_explicit(&counter->height, h.bits, memory_order_relaxed);
  if (seen && previous_w == w.bits && previous_h == h.bits) return 0;
  *change = atomic_fetch_add_explicit(&counter->changes, 1, memory_order_relaxed) + 1;
  return *change <= MD_GRAPHICS_GEOMETRY_CHANGES;
}

static inline uint64_t md_graphics_now_ns(void)
{
  struct timespec time;
  if (clock_gettime(CLOCK_MONOTONIC, &time)) return 0;
  return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

static inline int md_graphics_diag_take(enum md_graphics_op op, int failed,
                                       uint64_t *calls, uint64_t *failures)
{
  if ((unsigned)op >= MD_GFX_OP_COUNT) return 0;
  *calls = atomic_fetch_add_explicit(&md_graphics_counters[op].calls, 1,
                                     memory_order_relaxed) + 1;
  *failures = failed
      ? atomic_fetch_add_explicit(&md_graphics_counters[op].failures, 1,
                                   memory_order_relaxed) + 1
      : atomic_load_explicit(&md_graphics_counters[op].failures, memory_order_relaxed);
  /* Successful samples are sparse. Failure samples retain the first eight and
   * powers of two, without turning repeated failures into a logging loop. */
  if (failed ? (*failures > 8 && (*failures & (*failures - 1)))
             : (*calls > 4 && (*calls % 1024))) return 0;
  unsigned used = atomic_load_explicit(&md_graphics_lines, memory_order_relaxed);
  while (used < MD_GRAPHICS_LINE_BUDGET)
    if (atomic_compare_exchange_weak_explicit(&md_graphics_lines, &used, used + 1,
                                             memory_order_relaxed, memory_order_relaxed)) return 1;
  return 0;
}

static inline uint64_t md_graphics_prefix_hash(const void *data, size_t available,
                                              size_t offset, unsigned *sampled)
{
  *sampled = 0;
  if (!data || offset >= available) return 0;
  size_t count = available - offset;
  if (count > MD_GRAPHICS_HASH_BYTES) count = MD_GRAPHICS_HASH_BYTES;
  const unsigned char *bytes = (const unsigned char *)data + offset;
  uint64_t hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < count; ++i) hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
  *sampled = (unsigned)count;
  return hash;
}

static inline void md_graphics_error_token(char output[65], const char *input)
{
  unsigned i = 0;
  if (input) for (; i < 64 && input[i]; ++i) {
    unsigned char c = (unsigned char)input[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
      static const char redacted[] = "redacted-domain";
      for (unsigned k = 0; k < sizeof(redacted); ++k) output[k] = redacted[k];
      return;
    }
    output[i] = (char)c;
  }
  output[i] = 0;
}
#endif
