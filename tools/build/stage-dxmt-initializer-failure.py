#!/usr/bin/env python3
"""Stage honest initializer failure/retry handling in owned DXMT build copies.

Compose after upload/core12 staging and before texture admission. Pinned source
stays immutable. Native backing failure cannot publish an initialized resource
or a partially linked blit; callers receive the reserved failure fence zero.
"""
import argparse
import hashlib
import json
from pathlib import Path

FILES = ('src/dxmt/dxmt_resource_initializer.cpp', 'src/dxmt/dxmt_resource_initializer.hpp')


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('DXMT initializer failure input changed: ' + repr(before[:100]))
    return source.replace(before, after, 1)


ZERO_SIZE = r'''// One size policy is shared by native allocation and the no-allocation
// forecast. Overflow saturates rather than wrapping a capacity/credit charge.
static size_t
zeroAllocationSize(size_t size) {
  static const bool pow2 = [] {
    const bool value = madeiraSwitch("DXMT_ZERO_BUFFER_POW2");
    if (value)
      Logger::info("[zero-buffer] ml1490 pow2-growth enabled (DXMT_ZERO_BUFFER_POW2=0 disables)");
    return value;
  }();
  if (!pow2)
    return size;
  size_t length = size_t(1) << 20;
  while (length < size) {
    if (length > SIZE_MAX / 2)
      return SIZE_MAX;
    length <<= 1;
  }
  return length;
}

'''

ZERO_BUFFER = r'''WMT::Buffer
ResourceInitializer::allocateZeroBuffer(size_t size) {
  zero_allocation_failed_ = false;
  if (zero_buffer_size_ < size) {
    if (zero_buffer_size_) {
      // The caller flushes the old zero-buffer users and retries once. Keep
      // the old native reference/census until a replacement is fully valid.
      zero_buffer_size_ = 0;
      return {};
    }
    const size_t length = zeroAllocationSize(size);
    if (length == SIZE_MAX) {
      zero_allocation_failed_ = true;
      return {};
    }
    WMTBufferInfo buffer_info;
    buffer_info.gpu_address = 0;
    buffer_info.length = length;
    buffer_info.memory.set(nullptr);
    buffer_info.options = WMTResourceStorageModePrivate | WMTResourceHazardTrackingModeUntracked;
    auto replacement = device_.newBuffer(buffer_info);
    if (!replacement) {
      zero_allocation_failed_ = true;
      return {};
    }
    // Never link a fill before genuine backing exists. If CPU command storage
    // is full, the local reference releases the unused replacement on return.
    wmtcmd_blit_fillbuffer *fill = nullptr;
    if (!allocateBlit(&fill))
      return {};
    fill->type = WMTBlitCommandFillBuffer;
    fill->buffer = replacement;
    fill->length = length;
    fill->offset = 0;
    fill->value = 0;
    if (zero_buffer_census_)
      mem_census_sub(MEMOWN_INIT_UPLOAD, zero_buffer_census_);
    zero_buffer_ = std::move(replacement);
    zero_buffer_size_ = length;
    zero_buffer_census_ = length;
    mem_census_add(MEMOWN_INIT_UPLOAD, length);
  }
  return zero_buffer_;
}'''

FORECAST_ZERO = r'''size_t
ResourceInitializer::forecastZeroGrowth(size_t bytes) {
  std::lock_guard<dxmt::mutex> lock(mutex_);
  return zero_buffer_size_ >= bytes ? 0 : zeroAllocationSize(bytes);
}

'''


def stage_cpp(source):
    if '[initializer-failure-v1]' in source or 'zero_allocation_failed_' in source:
        raise ValueError('DXMT initializer failure source is already staged')
    if 'ResourceInitializer::prepareUploadLocked(' not in source:
        raise ValueError('DXMT initializer failure must compose after upload memory staging')
    # All five operations used do/while(0), so a macro's continue silently
    # skipped the required initialization but returned a successful fence.
    old_tail = '  } while (0);\n\n  return current_seq_id_;'
    if source.count('  do {\n') != 5 or source.count(old_tail) != 5:
        raise ValueError('DXMT five initializer retry-loop contracts changed')
    source = source.replace('  do {\n', '  for (unsigned retry = 0; retry < 2; ++retry) {\n')
    source = source.replace(old_tail, '    return current_seq_id_;\n  }\n\n  return 0;')
    source = replace_once(source, '''  if (!(buffer = allocateGpuHeap(size, buffer##_offset))) {                                                            \\
    flushInternal();                                                                                                   \\
    continue;                                                                                                          \\
  }''', '''  if (!(buffer = allocateGpuHeap(size, buffer##_offset))) {                                                            \\
    return 0; /* Native backing failure; no partial blit is linked. */                                                   \\
  }''')
    source = replace_once(source, '''  if (!(buffer = allocateZeroBuffer(size))) {                                                                          \\
    flushInternal();''', '''  if (!(buffer = allocateZeroBuffer(size))) {                                                                          \\
    if (zero_allocation_failed_) return 0;                                                                              \\
    flushInternal();''')
    source = replace_once(source, '''    RETAIN(allocation);
    ALLOC_BLIT(wmtcmd_blit_copy_from_buffer_to_texture, copy);
    ALLOC_GPU(temp, total_bytes_needed);''', '''    // Allocate genuine upload backing before retaining the destination or
    // linking a blit. A native nil must not flush an uninitialized command.
    ALLOC_GPU(temp, total_bytes_needed);
    RETAIN(allocation);
    ALLOC_BLIT(wmtcmd_blit_copy_from_buffer_to_texture, copy);''')
    source = replace_once(source, 'ResourceInitializer::ResourceInitializer(WMT::Device device) :',
                          ZERO_SIZE + 'ResourceInitializer::ResourceInitializer(WMT::Device device) :')
    source = replace_once(source, '  cpu_command_heap = malloc(cpu_command_heap_size);',
                          '  cpu_command_heap = malloc(cpu_command_heap_size);\n  Logger::info("[initializer-failure-v1] bounded-cpu-retry honest-zero-fence transactional-zero-buffer");')
    start = source.index('WMT::Buffer\nResourceInitializer::allocateZeroBuffer(')
    end = source.index('\n} // namespace dxmt', start)
    original = source[start:end].strip()
    expected = 'cf15171ff21f7db7266cf74263f658136a39471047950e4a3f62843dc58ff635'
    if hashlib.sha256(original.encode()).hexdigest() != expected:
        raise ValueError('DXMT zero buffer source contract changed')
    source = source[:start] + FORECAST_ZERO + ZERO_BUFFER + '\n' + source[end:]
    # A factory holds this per-initializer transaction from forecast/admission
    # through all enqueue operations. Reclaimers and other creators cannot
    # invalidate the forecast, and nested same-creator calls remain legal.
    # Native GPU event signalling/waits do not acquire either CPU mutex.
    lock = '  std::lock_guard<dxmt::mutex> lock(mutex_);'
    if source.count(lock) != 11:
        raise ValueError('DXMT initializer public creation/forecast lock contracts changed')
    return source.replace(lock, '  std::lock_guard<std::recursive_mutex> creation_lock(creation_mutex_);\n' + lock)


def stage_header(source):
    if 'zero_allocation_failed_' in source or 'forecastZeroGrowth(' in source:
        raise ValueError('DXMT initializer failure header is already staged')
    if 'size_t forecastUploadGrowth(' not in source:
        raise ValueError('DXMT initializer failure header must compose after upload memory staging')
    source = replace_once(source, '#include "Metal.hpp"', '#include "Metal.hpp"\n#include <mutex>')
    source = replace_once(source, '  ResourceInitializer(WMT::Device device);', '''  ResourceInitializer(WMT::Device device);

  // One factory owns the forecast/admission/enqueue transaction. Recursive
  // locking is only for its calls back into this same initializer; all paths
  // take creation before initializer before ring locks. Native GPU completion
  // and private upload-event waits never require this CPU lock.
  std::unique_lock<std::recursive_mutex> lockTextureCreation() {
    return std::unique_lock<std::recursive_mutex>(creation_mutex_);
  }''')
    source = replace_once(source, '  dxmt::mutex mutex_;', '''  std::recursive_mutex creation_mutex_;
  dxmt::mutex mutex_;''')
    source = replace_once(source, '  size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0, bool compact = false);', '''  size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0, bool compact = false);

  // Only fresh zero backing is charged. This forecast neither allocates nor
  // flushes, and uses the exact native size policy under the initializer lock.
  size_t forecastZeroGrowth(size_t bytes);''')
    source = replace_once(source, '    if (aligned + size > kResourceInitializerCpuCommandHeapSize)',
                          '    if (!cpu_command_heap || aligned + size > kResourceInitializerCpuCommandHeapSize)')
    return replace_once(source, '  size_t zero_buffer_size_ = 0;', '''  size_t zero_buffer_size_ = 0;
  // Accessed only while mutex_ is held. False means retryable CPU storage or
  // cache growth; true is a real native backing/size failure, reported as 0.
  bool zero_allocation_failed_ = false;''')


def stage_file(name, source):
    if name == FILES[0]:
        return stage_cpp(source)
    if name == FILES[1]:
        return stage_header(source)
    raise ValueError('unknown initializer failure source: ' + name)


def stage(source_dir, output_dir, overlay_dir=None):
    if source_dir.resolve() == output_dir.resolve():
        raise ValueError('pinned DXMT input must remain immutable')
    outputs, records = {}, []
    for name in FILES:
        original = source_dir / name
        candidate = overlay_dir / name if overlay_dir else original
        path = candidate if candidate.is_file() else original
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 32 << 20:
            raise ValueError('missing, oversized or symlinked initializer source: ' + name)
        data = path.read_bytes()
        value = stage_file(name, data.decode()).encode()
        outputs[name] = value
        records.append({'path': name, 'source_sha256': hashlib.sha256(data).hexdigest(),
                        'output_sha256': hashlib.sha256(value).hexdigest()})
    for name, data in outputs.items():
        path = output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--overlay-dir', type=Path)
    args = parser.parse_args()
    print(json.dumps({'stage': 'dxmt-initializer-failure-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))
