#!/usr/bin/env python3
"""Stage work-proportional shader scheduler wakes and synchronized shutdown.

Only an owned build copy changes. Task execution, dependency locking, worker
limits, priorities and ready publication remain the pinned implementation.
"""
import argparse
import hashlib
import json
from pathlib import Path

FILES = ('src/dxmt/dxmt_tasks.hpp',)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('DXMT task wake input contract changed: ' + repr(old[:100]))
    return source.replace(old, new, 1)


def stage_file(name, source):
    if name not in FILES or 'task-wake-proportional-v1' in source:
        raise ValueError('unexpected or already staged DXMT task wake input')
    source = replace_once(source, '#include <atomic>', '#include <algorithm>\n#include <atomic>')
    source = replace_once(source, '''  destroyed.store(true);
  worker_cond_.notify_all();''', '''  {
    // Madeira task-wake-proportional-v1: publish the wait predicate while
    // holding its mutex. An idle worker cannot check false, miss shutdown's
    // notification and then park forever between that check and wait.
    std::unique_lock<dxmt::mutex> lock(worker_mutex_);
    destroyed.store(true);
  }
  worker_cond_.notify_all();''')
    return replace_once(source, '''        worker_cond_.notify_all();
        continutation_buffer.clear();''', '''        // Only newly ready continuations require wakeups. Most completed
        // shader/cache tasks have no dependents: broadcasting then wakes every
        // idle TIME_CRITICAL compiler worker just to lock, observe no work and
        // park again. Publish the whole ready batch above before notifying.
        // Workers already running observe queued work on their next iteration.
        const uint64_t ready_count = continutation_buffer.size();
        const uint64_t wake_count = std::min<uint64_t>(ready_count, max_threads);
        for (uint64_t i = 0; i < wake_count; ++i)
          worker_cond_.notify_one();
        continutation_buffer.clear();''')


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
    print(json.dumps({'stage': 'dxmt-task-wake-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))
