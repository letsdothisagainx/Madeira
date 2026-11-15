#!/usr/bin/env python3
"""Exercise the production vertex-layout block with real Darwin Metal objects.

The unchanged original block is the leak negative control. The native test adds
only a weak observation of its alloc/init object and checks Metal's copied
attribute/layout properties after creator release. No game or GPU frame is run.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'dxmt/src/winemetal/unix/winemetal_unix.c'
spec = importlib.util.spec_from_file_location('descriptor_lifetime', ROOT / 'tools/build/stage-dxmt-descriptor-lifetime.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def layout_block(source):
    begin = source.index('    MTLVertexDescriptor *vdesc = [[MTLVertexDescriptor alloc] init];')
    end = source.index('\n  }', begin)
    return source[begin:end]


PRELUDE = r'''
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <cassert>
#include <cstdio>
#define DXMT_NATIVE
#include "winemetal.h"

static void check_layout(MTLVertexDescriptor *layout, unsigned variant) {
  assert(layout != nil);
  assert(layout.attributes[0].format == MTLVertexFormatFloat3);
  assert(layout.attributes[0].offset == 4 * variant);
  assert(layout.attributes[0].bufferIndex == 0);
  assert(layout.layouts[0].stride == 32);
  assert(layout.layouts[0].stepFunction == MTLVertexStepFunctionPerVertex);
  assert(layout.layouts[0].stepRate == 1);
  assert(layout.attributes[7].format == MTLVertexFormatFloat2);
  assert(layout.attributes[7].bufferIndex == 7);
  assert(layout.layouts[7].stride == 8);
  assert(layout.layouts[7].stepFunction == MTLVertexStepFunctionPerInstance);
  assert(layout.layouts[7].stepRate == 2);
  assert(layout.layouts[30].stepFunction == MTLVertexStepFunctionConstant);
  assert(layout.layouts[30].stepRate == 0);
}

static unsigned exercise(bool candidate) {
  unsigned leaked = 0;
  for (unsigned pass = 0; pass < 256; ++pass) {
    __weak MTLVertexDescriptor *observed = nil;
    MTLVertexDescriptor *original = nil; // non-owning; used only by old-control cleanup
    @autoreleasepool {
      MTLRenderPipelineDescriptor *descriptor = [[MTLRenderPipelineDescriptor alloc] init];
      WMTVertexDescriptorInfo vertex{};
      WMTVertexDescriptorInfo *vdi = &vertex;
      vertex.attribute_mask = (1u << 0) | (1u << 7);
      vertex.layout_mask = (1u << 0) | (1u << 7) | (1u << 30);
      vertex.attributes[0] = {(uint32_t)MTLVertexFormatFloat3, 4 * (pass % 4), 0, 0};
      vertex.attributes[7] = {(uint32_t)MTLVertexFormatFloat2, 0, 7, 0};
      vertex.layouts[0] = {32, (uint32_t)MTLVertexStepFunctionPerVertex, 0, 0};
      vertex.layouts[7] = {8, (uint32_t)MTLVertexStepFunctionPerInstance, 2, 0};
      vertex.layouts[30] = {4, (uint32_t)MTLVertexStepFunctionConstant, 3, 0};
      if (candidate) {
        CANDIDATE_BLOCK
      } else {
        ORIGINAL_BLOCK
      }
      // Metal still owns a correct layout when the creator reference is gone.
      check_layout(descriptor.vertexDescriptor, pass % 4);
      [descriptor release];
    }
    bool remains;
    // Drain any temporary retain from observing a zeroing weak reference.
    @autoreleasepool { remains = observed != nil; }
    if (candidate) {
      assert(!remains);
    } else {
      assert(remains);
      ++leaked;
      // Repair only the negative-control leak so this regression test itself
      // leaves no unbounded live allocations or deliberate sanitizer leak.
      [original release];
      @autoreleasepool { assert(observed == nil); }
    }
  }
  return leaked;
}
int main() {
  const unsigned before = exercise(false), after = exercise(true);
  assert(before == 256 && after == 0);
  std::printf("PASS real Metal vertex layouts: unbalanced creator references %u -> %u over256 pipeline descriptors; copied attributes/layouts preserved\n", before, after);
}
'''


def observed(block):
    anchor = '    MTLVertexDescriptor *vdesc = [[MTLVertexDescriptor alloc] init];'
    assert block.count(anchor) == 1
    return block.replace(anchor, anchor + '\n    observed = vdesc; original = vdesc;', 1)


def main():
    original = SOURCE.read_bytes()
    generated = stage.stage(original.decode())
    before, after = layout_block(original.decode()), layout_block(generated)
    assert after.count('[vdesc release];') == 1 and '[vdesc release];' not in before
    assert after.count('"[metal-vertex-descriptor-owner-v1]"') == 1
    assert '(void)descriptor_owner_contract[0];' in after
    anchor = '    descriptor.vertexDescriptor = vdesc;'
    assert after.index(anchor) < after.index('[vdesc release];')
    assert generated.replace(after, before, 1) == original.decode()
    for invalid in (generated, original.decode().replace(anchor, '    descriptor.vertexDescriptor = nil;')):
        try:
            stage.stage(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('changed or double-staged descriptor contract accepted')
    print('PASS exact native VD factory staging: creator release and retained capability only; remote/render/shader/resource paths unchanged')
    if platform.system() != 'Darwin':
        print('SKIP actual Metal descriptor ownership execution: requires Darwin Foundation/Metal; no GPU or iPhone result claimed')
        return
    code = PRELUDE.replace('CANDIDATE_BLOCK', observed(after)).replace('ORIGINAL_BLOCK', observed(before))
    with tempfile.TemporaryDirectory(prefix='madeira-metal-descriptor-') as directory:
        source = Path(directory) / 'lifetime.mm'
        output = Path(directory) / 'lifetime'
        source.write_text(code)
        compiler = shlex.split(os.environ.get('CXX', 'clang++'))
        subprocess.run([*compiler, '-std=c++20', '-O2', '-fno-objc-arc', '-fobjc-weak', '-fblocks',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-I', str(ROOT / 'dxmt/src/winemetal'), str(source),
                        '-framework', 'Foundation', '-framework', 'Metal', '-o', str(output)], check=True)
        subprocess.run([str(output)], check=True, timeout=30,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1'))
    assert hashlib.sha256(SOURCE.read_bytes()).digest() == hashlib.sha256(original).digest()


if __name__ == '__main__':
    main()
