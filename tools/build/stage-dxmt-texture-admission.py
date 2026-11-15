#!/usr/bin/env python3
"""Admit complete texture creations before Metal backing or initial uploads.

Only owned build copies change. A permit covers the complete synchronous
creation/enqueue window; it neither evicts live resources nor invents backing.
"""
import argparse
import hashlib
import json
from pathlib import Path

FILES = ('src/d3d11/d3d11_texture_device.cpp', 'src/dxmt/dxmt_resource_initializer.hpp')


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('DXMT texture admission input changed: ' + repr(before[:100]))
    return source.replace(before, after, 1)


ADMISSION_HELPER = r'''// Failures are exceptional, bounded and path-free. One non-template counter
// covers all factory instantiations; saturation avoids wraparound log bursts.
static void
ReportTextureFailure(const char *reason, uint64_t bytes, uint64_t available) {
  static std::atomic<uint32_t> reports{0};
  auto count = reports.load(std::memory_order_relaxed);
  while (count < 8 && !reports.compare_exchange_weak(
      count, count + 1, std::memory_order_relaxed)) {}
  if (count < 8)
    ERR("[texture-admission-v1] result=E_OUTOFMEMORY reason=", reason,
        " bytes=", bytes, " available=", available);
}

// A normal texture-growth request must not scan every dynamic buffer on
// every mip/resource while the same completion frontier is unchanged. This
// stamp suppresses only redundant reclamation, never native admission checks.
static void
ReclaimTextureGrowth(CommandQueue &queue, uint64_t bytes) {
  const auto pressure = memoryPressureSnapshot(true);
  const uint64_t coherent = queue.CoherentSeqId();
  const bool emergency = pressure.valid &&
      (pressure.available <= pressure.reserve / 4 || bytes >= pressure.available);
  struct SweepStamp {
    uint64_t domain = 0, coherent = 0, largest = 0;
    bool valid = false, emergency = false;
  };
  thread_local SweepStamp previous;
  if (!previous.valid || previous.domain != queue.memoryDomain() ||
      previous.coherent != coherent || bytes > previous.largest ||
      (emergency && !previous.emergency)) {
    previous = {queue.memoryDomain(), coherent, bytes, pressure.valid, emergency};
    // Only this queue's proven GPU-complete cache entries are eligible.
    // Existing hot leases and high/low-water hysteresis retain control.
    DynamicBuffer::TrimCompletedForQueue(queue.memoryDomain(), coherent, false, nullptr, bytes);
  }
  // Uploads have a private GPU event and can finish without a main-queue
  // present. Keep sampling that event rather than inferring its completion
  // from the main queue's unchanged coherence counter.
  queue.initializer.trimMemoryPressure();
}

// A creation credit covers destination backing and the complete initial-data
// enqueue window, not the texture's lifetime. The native side serializes fresh
// physical-headroom readings with other outstanding creation credits.
static bool
PrepareTextureGrowth(MTLD3D11Device *device, ResourceGrowthPermit &permit, uint64_t bytes) {
  if (!permit.denied() && !permit.needsReclaim())
    return true;
  auto &queue = device->GetDXMTDevice().queue();
  ReclaimTextureGrowth(queue, bytes);
  if (!permit.denied())
    return true;

  // No initializer mutex is held while waiting. FlushToWait publishes genuine
  // pending uploads; the event is GPU-signalled, never a CPU recording fence.
  const uint64_t submitted = queue.initializer.flushToWait();
  if (submitted)
    queue.initializer.waitForMemoryPressure(submitted, 50);
  ReclaimTextureGrowth(queue, bytes);
  permit = ResourceGrowthPermit(bytes);
  return !permit.denied();
}

'''


def stage_factory(source):
    source = replace_once(source, '#include "dxmt_texture.hpp"',
                          '#include "dxmt_texture.hpp"\n#include "dxmt_mem_census.hpp"\n#include "memory_pressure.hpp"')
    signature = 'template <typename tag>\nHRESULT CreateDeviceTextureInternal('
    source = replace_once(source, signature, ADMISSION_HELPER + signature)
    source = replace_once(source, '''                                    typename tag::COM_IMPL **ppTexture) {
  WMTTextureInfo info;''', '''                                    typename tag::COM_IMPL **ppTexture) {
  if (ppTexture)
    *ppTexture = nullptr;
  WMTTextureInfo info;''')
    source = replace_once(source,
        '  bool single_subresource = info.mipmap_level_count == 1 && info.array_length == 1 &&',
        '''  // Physical mip selection is complete before computing the charge. Native
  // BC resources use actual block sizes; unsupported devices charge decoded
  // backing instead. A saturated estimate cannot wrap an admission charge.
  const bool admission_native_bc = mem_census_bc_block_bytes(info.pixel_format) &&
      pDevice->GetMTLDevice().supportsBCTextureCompression();
  const uint64_t creation_bytes = mem_census_texture_bytes(info, admission_native_bc);
  if (creation_bytes == UINT64_MAX) {
    ReportTextureFailure("capacity-overflow", creation_bytes, memoryPressureSnapshot(true).available);
    return E_OUTOFMEMORY;
  }
  ResourceGrowthPermit creation_permit(creation_bytes);
  if (!PrepareTextureGrowth(pDevice, creation_permit, creation_bytes)) {
    ReportTextureFailure(creation_permit.nativeStatus() == 3 ? "physical-budget" : "creation-credit-or-owner",
                         creation_bytes, creation_permit.available());
    return E_OUTOFMEMORY;
  }

  bool single_subresource = info.mipmap_level_count == 1 && info.array_length == 1 &&''')
    source = replace_once(source, '''  auto initialize = [&](Rc<TextureAllocation> &&allocation) {
    texture->rename(std::move(allocation));''', '''  auto initialize = [&](Rc<TextureAllocation> &&allocation) -> bool {
    // A TextureAllocation wrapper can exist even when Metal returned nil.
    // Never rename, upload to, or publish that failed native allocation.
    if (!allocation || !allocation->texture()) {
      ReportTextureFailure("native-nil", creation_bytes, creation_permit.available());
      return false;
    }
    texture->rename(std::move(allocation));''')
    source = replace_once(source, '''      }
    }
  };

  auto shared_flag =''', '''      }
    }
    // Under pressure, publish all initial mip/slice uploads before releasing
    // creation credit. Keep the real GPU references owned by their queue;
    // flushing is not completion and does not manufacture initialized texels.
    // Healthy/unknown paths retain the existing batching policy.
    if (creation_permit.needsReclaim())
      initializer.flushToWait();
    return true;
  };

  auto shared_flag =''')
    source = replace_once(source, '''    auto allocation = texture->allocate(flags);

    mach_port_t mach_port = allocation->machPort;''', '''    auto allocation = texture->allocate(flags);
    if (!allocation || !allocation->texture()) {
      ReportTextureFailure("native-nil", creation_bytes, creation_permit.available());
      return E_OUTOFMEMORY;
    }

    mach_port_t mach_port = allocation->machPort;''')
    before = '      initialize(std::move(allocation));'
    source = replace_once(source, before,
                          '      if (!initialize(std::move(allocation)))\n        return E_OUTOFMEMORY;')
    source = replace_once(source, '    initialize(std::move(allocation));',
                          '    if (!initialize(std::move(allocation)))\n      return E_OUTOFMEMORY;')
    source = replace_once(source, '    initialize(renamable->getNext(0));',
                          '    if (!initialize(renamable->getNext(0)))\n      return E_OUTOFMEMORY;')
    return replace_once(source, '    initialize(texture->allocate(flags));',
                         '    if (!initialize(texture->allocate(flags)))\n      return E_OUTOFMEMORY;')


def stage_file(name, source):
    if 'PrepareTextureGrowth(' in source or 'waitForMemoryPressure(' in source:
        raise ValueError('DXMT texture admission input is already staged')
    if name == FILES[0]:
        return stage_factory(source)
    if name == FILES[1]:
        return replace_once(source, '  uint64_t trimMemoryPressure();', '''  uint64_t trimMemoryPressure();

  // Independent load threads must not race a read of cached_coherent_seq_id.
  // This pressure-only wait uses the genuine upload event directly, with its
  // caller-supplied finite timeout and no initializer mutex held.
  bool waitForMemoryPressure(uint64_t seq_id, uint64_t timeout) {
    return upload_queue_event_.waitUntilSignaledValue(seq_id, timeout);
  }''')
    raise ValueError('unknown texture admission source: ' + name)


def stage(source_dir, output_dir, overlay_dir=None):
    if source_dir.resolve() == output_dir.resolve():
        raise ValueError('pinned DXMT input must remain immutable')
    outputs = {}
    records = []
    for name in FILES:
        original = source_dir / name
        candidate = overlay_dir / name if overlay_dir else original
        path = candidate if candidate.is_file() else original
        data = path.read_bytes()
        result = stage_file(name, data.decode()).encode()
        outputs[name] = result
        records.append({'path': name, 'source_sha256': hashlib.sha256(data).hexdigest(),
                        'output_sha256': hashlib.sha256(result).hexdigest()})
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
    print(json.dumps({'stage': 'dxmt-texture-admission-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))
