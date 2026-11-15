#!/usr/bin/env python3
"""Balance the native vertex-descriptor creator reference in an owned copy.

MTLRenderPipelineDescriptor.vertexDescriptor copies its value. The original
alloc/init reference must therefore be released after assignment. Neither the
pipeline's retained descriptor nor any live texture/buffer is reclaimed here.
"""
import argparse
import hashlib
import json
from pathlib import Path


def stage(source):
    marker = 'madeira-vertex-descriptor-owner-v1'
    if marker in source:
        raise ValueError('Metal vertex-descriptor ownership input is already staged')
    signature = '\n_MTLDevice_newRenderPipelineStateVD(void *obj) {'
    if source.count(signature) != 1:
        raise ValueError('Metal vertex-descriptor factory contract changed')
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    function = source[start:end]
    before = '    descriptor.vertexDescriptor = vdesc;'
    if function.count(before) != 1 or function.count('[[MTLVertexDescriptor alloc] init]') != 1:
        raise ValueError('Metal vertex-descriptor assignment contract changed')
    after = before + '''
    // madeira-vertex-descriptor-owner-v1: the property copies/retains its
    // layout; release only the creator's reference, not the pipeline's copy.
    [vdesc release];
    static const volatile char descriptor_owner_contract[] = "[metal-vertex-descriptor-owner-v1]";
    (void)descriptor_owner_contract[0];'''
    function = function.replace(before, after, 1)
    return source[:start] + function + source[end:]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('vendor input must remain immutable')
    original = args.source.read_bytes()
    output = stage(original.decode()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print(json.dumps({'stage': 'metal-vertex-descriptor-owner-v1',
                      'source_sha256': hashlib.sha256(original).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(),
                      'lifetime': 'creator-reference-only; pipeline property ownership unchanged'}))
