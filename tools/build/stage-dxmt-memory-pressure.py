#!/usr/bin/env python3
"""Stage measured process pressure into the existing pointer-free runtime ABI."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil


def stage_pressure_only(source):
    include = '#include "memory_pressure_native.h"'
    if include in source or any('case ' + str(op) + ':' in source for op in (40, 41, 42, 43)):
        raise ValueError('native memory-pressure input is already staged or an owned control op is occupied')
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
  case 41: { /* texture-growth-budget-v1: CPU creation admission, shared receipts. */
    if (wmtr_enabled()) break;
    md_resource_growth_acquire(a);
    break;
  }
  case 42: { /* release only the matching creation receipt, never live resource ownership. */
    if (wmtr_enabled()) break;
    md_resource_growth_release(a);
    break;
  }
  case 43: { /* GPU handoff: registered native event + target value, pointer-free. */
    if (wmtr_enabled()) break;
    md_resource_growth_handoff(a);
    break;
  }
'''
    body = body.replace(anchor, addition + anchor)
    staged = source[:start] + include + '\n' + body + source[end:]
    wow64 = '  if (a && a->op == 7) return _madeira_ctl(args);'
    if staged.count(wow64) != 1:
        raise ValueError('DXMT pointer-free WoW64 forwarding contract changed')
    staged = staged.replace(wow64, '  if (a && (a->op == 7 || a->op == 40 || a->op == 41 || a->op == 42 || a->op == 43)) return _madeira_ctl(args);')
    # Registration observes only the native result of the genuine factory.
    # Its remote branch returns before this hook and retains its old behavior.
    event_header = '#include "resource_growth_event_native.h"'
    signature = 'static NTSTATUS\n_MTLDevice_newSharedEvent(void *obj) {'
    anchor = '  params->ret = (obj_handle_t)[(id<MTLDevice>)params->handle newSharedEvent];'
    if event_header in staged or staged.count(signature) != 1 or staged.count(anchor) != 1:
        raise ValueError('native shared-event registration contract changed')
    staged = staged.replace(signature, event_header + '\n\n' + signature, 1)
    return staged.replace(anchor, anchor + '\n  madeira_growth_event_register_created((id<MTLSharedEvent>)(uintptr_t)params->ret);', 1)


def stage(source):
    # Keep the native build recipe and shader converter identity unchanged.
    # This owned pass composes after diagnostics/lifecycle and leaves their
    # command submission and completion ordering intact.
    path = Path(__file__).with_name('stage-dxmt-native-batch.py')
    spec = importlib.util.spec_from_file_location('madeira_native_batch', path)
    batch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(batch)
    return batch.stage(stage_pressure_only(source))


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
    shutil.copyfile(args.headers / 'resource_growth_event_native.h', args.output.parent / 'resource_growth_event_native.h')
    print(json.dumps({'stage': 'memory-pressure-v1', 'source_sha256': hashlib.sha256(original).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(), 'native_control_op': 40,
                      'growth_control_ops': [41, 42, 43], 'growth_scope': 'cpu-creation-to-real-gpu-event',
                      'old_op_7': 'unchanged', 'measurement': 'task-footprint+os-proc-available-memory'}))


if __name__ == '__main__':
    main()
