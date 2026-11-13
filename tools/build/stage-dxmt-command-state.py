#!/usr/bin/env python3
"""Elide unchanged vertex commands and disabled release HUD formatting.

This changes only an owned build copy. Buffer identity, metadata changes,
renaming, dirty bits, restore operations, frame statistics and object lifetimes
remain intact.
"""
import argparse
import hashlib
import json
from pathlib import Path


FILES = ('src/d3d11/d3d11_context_impl.cpp', 'src/d3d11/d3d11_swapchain.cpp')

OLD = '''        if (!replaced) {
          if (pStrides && pStrides[slot - StartSlot] != entry.Stride) {
            VertexBuffers.set_dirty(slot);
            entry.Stride = pStrides[slot - StartSlot];
          }
          if (pOffsets && pOffsets[slot - StartSlot] != entry.Offset) {
            VertexBuffers.set_dirty(slot);
            entry.Offset = pOffsets[slot - StartSlot];
          }
          EmitST([=, offset = entry.Offset,
                stride = entry.Stride](ArgumentEncodingContext &enc) mutable {
            enc.bindVertexBufferOffset(slot, offset, stride);
          });
          continue;
        }'''

NEW = '''        if (!replaced) {
          // Madeira command-state-dedup-v1: the existing buffer object already
          // observes DISCARD renames. Repeating identical metadata needs no
          // command allocation or encoder callback. Restoration still records
          // complete bindings through RestoreEncodingContextState().
          bool metadata_changed = false;
          if (pStrides && pStrides[slot - StartSlot] != entry.Stride) {
            VertexBuffers.set_dirty(slot);
            entry.Stride = pStrides[slot - StartSlot];
            metadata_changed = true;
          }
          if (pOffsets && pOffsets[slot - StartSlot] != entry.Offset) {
            VertexBuffers.set_dirty(slot);
            entry.Offset = pOffsets[slot - StartSlot];
            metadata_changed = true;
          }
          if (metadata_changed) {
            EmitST([=, offset = entry.Offset,
                  stride = entry.Stride](ArgumentEncodingContext &enc) mutable {
              enc.bindVertexBufferOffset(slot, offset, stride);
            });
          }
          continue;
        }'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('DXMT command-state input contract changed: ' + repr(old[:100]))
    return source.replace(old, new, 1)


def stage_file(name, source):
    if 'command-state-dedup-v1' in source or 'release-hud-elision-v1' in source:
        raise ValueError('DXMT command-state input is already staged')
    if name == FILES[0]:
        return replace_once(source, OLD, NEW)
    if name != FILES[1]:
        raise ValueError('unexpected command-state source: ' + name)
    source = replace_once(source, '''    hud.begin();
    auto &frame = statistics.at(frame_id - 1); // show the previous one frame statistics
    auto &average = statistics.average();
    Flags<FeatureCompatibility> flags''', '''    auto &frame = statistics.at(frame_id - 1); // show the previous one frame statistics
    auto &average = statistics.average();
#ifdef DXMT_DEBUG
    // Madeira release-hud-elision-v1: HUD methods are no-ops in release.
    // Avoid formatting/allocating strings whose only consumer is disabled.
    hud.begin();
    Flags<FeatureCompatibility> flags''')
    source = replace_once(source,
        '    /* iOS-Madeira 2026-07-03: dump the same frame statistics to the log every',
        '#endif\n\n    /* iOS-Madeira 2026-07-03: dump the same frame statistics to the log every')
    source = replace_once(source, '    {\n      /* scaler info */',
                          '#ifdef DXMT_DEBUG\n    {\n      /* scaler info */')
    return replace_once(source, '    hud.end();\n  }', '    hud.end();\n#endif\n  }')


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
    print(json.dumps({'stage': 'dxmt-command-state-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))
