#!/usr/bin/env python3
"""Stage measured process pressure into the existing pointer-free runtime ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def stage(source):
    include = '#include "memory_pressure_native.h"'
    if include in source or 'case 40:' in source:
        raise ValueError('native memory-pressure input is already staged or op 40 is occupied')
    start = source.index('static NTSTATUS _madeira_ctl(void *args) {')
    end = source.index('\n/* ml2000: the other ops', start)
    body = source[start:end]
    anchor = '  default: break;\n  }\n  return STATUS_SUCCESS;\n}'
    if body.count(anchor) != 1:
        raise ValueError('DXMT native runtime-control contract changed')
    addition = '''  case 40: { /* madeira-memory-pressure-v1: real process footprint/headroom, pointer-free. */
    if (wmtr_enabled()) break;
    md_memory_pressure_query(a);
    break;
  }
'''
    body = body.replace(anchor, addition + anchor)
    staged = source[:start] + include + '\n' + body + source[end:]
    wow64 = '  if (a && a->op == 7) return _madeira_ctl(args);'
    if staged.count(wow64) != 1:
        raise ValueError('DXMT pointer-free WoW64 forwarding contract changed')
    return staged.replace(wow64, '  if (a && (a->op == 7 || a->op == 40)) return _madeira_ctl(args);')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--headers', type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('native input must remain immutable')
    original = args.source.read_bytes()
    output = stage(original.decode()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    shutil.copyfile(args.headers / 'memory_pressure_native.h', args.output.parent / 'memory_pressure_native.h')
    print(json.dumps({'stage': 'memory-pressure-v1', 'source_sha256': hashlib.sha256(original).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(), 'native_control_op': 40,
                      'old_op_7': 'unchanged', 'measurement': 'task-footprint+os-proc-available-memory'}))


if __name__ == '__main__':
    main()
