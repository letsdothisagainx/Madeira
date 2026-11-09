#!/usr/bin/env python3
"""Gate real native Metal submission in an owned copy, preserving vendor source."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def stage(source):
    if '#include "metal_lifecycle.h"' in source:
        raise ValueError('Metal lifecycle input is already staged')
    start = source.index('\n_MTLCommandBuffer_commit(void *obj) {')
    end = source.index('\n}', start) + 2
    part = source[start:end]
    anchor = '  [(id<MTLCommandBuffer>)params->handle commit];'
    if part.count(anchor) != 1:
        raise ValueError('DXMT native command submission contract changed')
    part = part.replace(anchor, '  md_metal_commit((id<MTLCommandBuffer>)params->handle);')
    # Observational diagnostics are attached before this call; a lifecycle
    # pause is part of its wall time, and the request is not yet GPU submission.
    part = part.replace('event=command-submit n=', 'event=command-submit-request n=')
    return '#include "metal_lifecycle.h"\n' + source[:start] + part + source[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--headers', type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('vendor/diagnostic input must remain immutable')
    source = args.source.read_bytes()
    output = stage(source.decode()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    for name in ('metal_lifecycle.h', 'metal_submission_gate.h'):
        shutil.copyfile(args.headers / name, args.output.parent / name)
    print(json.dumps({'stage': 'metal-lifecycle-v1', 'source_sha256': hashlib.sha256(source).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(),
                      'semantic_changes': ['defer-native-submit-until-active'],
                      'metal_status_and_completion': 'unchanged'}))


if __name__ == '__main__':
    main()
