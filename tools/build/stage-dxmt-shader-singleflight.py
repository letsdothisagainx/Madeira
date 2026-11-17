#!/usr/bin/env python3
"""Avoid duplicate preparation of concurrently requested identical shaders.

Only a Madeira-owned build copy changes. Cache identity, bytecode ownership,
SM50 validation, variant compilation and GPU lifetime remain unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path

FILES = ('src/d3d11/d3d11_pipeline_cache.cpp',)
MARKER = 'shader-prepare-singleflight-v1'


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('DXMT shader preparation input contract changed: ' + repr(old[:100]))
    return source.replace(old, new, 1)


def stage_file(name, source):
    if name not in FILES or MARKER in source:
        raise ValueError('unexpected or already staged DXMT shader preparation input')
    source = replace_once(source, '#include <shared_mutex>', '#include <array>\n#include <shared_mutex>')
    source = replace_once(source, '''  std::shared_mutex mutex_shares;
''', '''  std::shared_mutex mutex_shares;
  // Madeira shader-prepare-singleflight-v1: bounded, allocation-free stripes
  // protect preparation, not cache ownership. Identical requests share a
  // stripe; unrelated digests usually prepare concurrently. Existing cache
  // hits never acquire one. The cache map lock is never held while parsing.
  std::array<dxmt::mutex, 64> shader_prepare_mutexes_;
''')
    return replace_once(source, '''    sm50_error_t err;
    sm50_shader_t sm50;
    MTL_SHADER_REFLECTION reflection;
    if (SM50Initialize(pBytecode, BytecodeLength, &sm50, &reflection, &err)) {''', '''    // A cache miss previously parsed and copied bytecode before taking the
    // insertion lock. Racing requests for one digest all did that work, then
    // destroyed every losing copy. Serialize only that preparation and recheck
    // after waiting: the winning shader may already have been published.
    // RAII releases the stripe on validation failure too; failures stay
    // uncached and a subsequent genuine request can retry normally.
    std::lock_guard<dxmt::mutex> prepare_lock(
        shader_prepare_mutexes_[std::hash<Sha1Digest>{}(sha1) % shader_prepare_mutexes_.size()]);
    {
      std::shared_lock<std::shared_mutex> lock(mutex_shares);
      auto result = shaders_.find(sha1);
      if (result != shaders_.end())
        return result->second.get();
    }
    sm50_error_t err;
    sm50_shader_t sm50;
    MTL_SHADER_REFLECTION reflection;
    if (SM50Initialize(pBytecode, BytecodeLength, &sm50, &reflection, &err)) {''')


def stage(source_dir, output_dir, overlay_dir=None):
    if source_dir.resolve() == output_dir.resolve():
        raise ValueError('vendor input must remain immutable')
    rows = []
    for name in FILES:
        original = source_dir / name
        candidate = overlay_dir / name if overlay_dir else original
        path = candidate if candidate.is_file() else original
        data = path.read_bytes()
        generated = stage_file(name, data.decode()).encode()
        destination = output_dir / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(generated)
        rows.append({'path': name, 'input_sha256': hashlib.sha256(data).hexdigest(),
                     'output_sha256': hashlib.sha256(generated).hexdigest()})
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--overlay-dir', type=Path)
    args = parser.parse_args()
    print(json.dumps({'stage': 'dxmt-shader-singleflight-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))
