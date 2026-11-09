#!/usr/bin/env python3
"""Exercise the production Metal staging contracts and bounded native helper.

This is not a graphics correctness test. The actual staged Objective-C source
is compiled into the iOS archive by build/dxmt-ios/build.sh. This host harness
checks unchanged API calls, result/error propagation, one draw-count increment,
bounded sampling, counter concurrency and ownership of the generated copy.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dxmt-root', type=Path, default=ROOT / 'dxmt')
args = parser.parse_args()
producer = args.dxmt_root / 'src/winemetal/unix/winemetal_unix.c'
assert producer.is_file(), 'Initialize the pinned DXMT submodule before this production staging test'
original = producer.read_text()
before = hashlib.sha256(producer.read_bytes()).hexdigest()
spec = importlib.util.spec_from_file_location('stage_metal', ROOT / 'tools/build/stage-dxmt-diagnostics.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
staged = module.stage(original)

assert staged != original and hashlib.sha256(producer.read_bytes()).hexdigest() == before
for marker in ('[metal-resource-v1]', '[metal-upload-v1]', '[metal-api-v1]', '[metal-progress-v1]',
               'meaning=encoded-not-submitted', 'meaning=gpu-completion-not-display',
               'meaning=display-event-not-menu-validation', 'archive-lookup-only='):
    assert marker in staged
for call in ('newTextureWithDescriptor:', 'newTextureViewWithPixelFormat:', 'replaceRegion:',
             'copyFromBuffer:', 'newLibraryWithData:', 'newComputePipelineStateWithDescriptor:',
             'newRenderPipelineStateWithDescriptor:', 'newRenderPipelineStateWithMeshDescriptor:',
             'setRenderPipelineState:', 'drawPrimitives:', 'drawIndexedPrimitives:',
             'presentDrawable:', 'params->ret_error = (obj_handle_t)err;',
             'return STATUS_SUCCESS;', 'texture_upload_pitch_ok('):
    assert staged.count(call) == original.count(call), 'Metal operation/result changed: ' + call
counter = 'atomic_fetch_add_explicit(&g_madeira_draw_calls, 1, memory_order_relaxed)'
assert staged.count(counter) == original.count(counter) == 4, 'draw counter must increment exactly once'
assert staged.count('event=first-draw-encode') == 4
assert staged.count('localizedDescription') == original.count('localizedDescription')
assert 'md_graphics_prefix_hash(md_contents,' in staged
assert 'md_available > body->bytes_per_row' in staged
assert 'body->src_offset <= md_length' in staged
assert 'int md_cpu_readable = md_mode == MTLStorageModeShared;' in staged
assert '#if !TARGET_OS_IOS\n          md_cpu_readable |= md_mode == MTLStorageModeManaged;\n#endif' in staged
assert 'const void *md_contents = md_cpu_readable ? [md_src contents] : NULL;' in staged
for corrupted in (original.replace('  info->mach_port = 0;', '  info->mach_port = 1;'), staged):
    try:
        module.stage(corrupted)
    except ValueError:
        pass
    else:
        raise AssertionError('changed or already-staged source must fail closed')

c = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "graphics_diagnostics.h"
static void reset(void) {
  for (unsigned i=0;i<MD_GFX_OP_COUNT;i++) {
    atomic_store(&md_graphics_counters[i].calls,0);
    atomic_store(&md_graphics_counters[i].failures,0);
  }
  atomic_store(&md_graphics_lines,0);
}
static void *contend(void *argument) {
  uintptr_t role=(uintptr_t)argument;
  unsigned emitted=0;
  for (unsigned i=0;i<100000;i++) {
    uint64_t calls, failures;
    emitted+=md_graphics_diag_take((enum md_graphics_op)((i+role)%MD_GFX_OP_COUNT),
                                   (i&1),&calls,&failures);
  }
  return (void *)(uintptr_t)emitted;
}
int main(void) {
  uint64_t calls, failures;
  assert(!md_graphics_diag_take(MD_GFX_OP_COUNT,1,&calls,&failures));
  for (unsigned i=1;i<=1024;i++) {
    int accepted=md_graphics_diag_take(MD_GFX_TEXTURE,0,&calls,&failures);
    assert(calls==i && failures==0 && accepted==(i<=4||i==1024));
  }
  for (unsigned i=1;i<=17;i++) {
    int accepted=md_graphics_diag_take(MD_GFX_VIEW,1,&calls,&failures);
    assert(calls==i && failures==i && accepted==(i<=8||!(i&(i-1))));
  }
  unsigned char data[128], copy[128];
  for (unsigned i=0;i<sizeof(data);i++) data[i]=(unsigned char)i;
  memcpy(copy,data,sizeof(data));
  unsigned count;
  uint64_t full=md_graphics_prefix_hash(data,sizeof(data),0,&count);
  assert(full && count==64);
  data[64]^=0xff;
  assert(md_graphics_prefix_hash(data,sizeof(data),0,&count)==full && count==64);
  assert(md_graphics_prefix_hash(data,3,1,&count) && count==2);
  assert(!md_graphics_prefix_hash(data,3,3,&count) && !count);
  assert(!md_graphics_prefix_hash(data,3,SIZE_MAX,&count) && !count);
  assert(!md_graphics_prefix_hash(NULL,SIZE_MAX,0,&count) && !count);
  data[64]^=0xff;
  assert(!memcmp(data,copy,sizeof(data)));
  char token[65];
  md_graphics_error_token(token,"MTLRenderPipelineErrorDomain");
  assert(!strcmp(token,"MTLRenderPipelineErrorDomain"));
  md_graphics_error_token(token,"/private/account/token");
  assert(!strcmp(token,"redacted-domain"));
  md_graphics_error_token(token,NULL); assert(!token[0]);
  assert(md_graphics_now_ns()>0);
  reset();
  pthread_t threads[8];
  for (uintptr_t i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,contend,(void *)i));
  unsigned total=0;
  for (unsigned i=0;i<8;i++) {void *got;assert(!pthread_join(threads[i],&got));total+=(unsigned)(uintptr_t)got;}
  assert(total==MD_GRAPHICS_LINE_BUDGET && atomic_load(&md_graphics_lines)==total);
  uint64_t observed=0;
  for (unsigned i=0;i<MD_GFX_OP_COUNT;i++) observed+=atomic_load(&md_graphics_counters[i].calls);
  assert(observed==800000);
  puts("PASS native Metal diagnostic helper:256-line concurrent budget,exact counters,sparse success/failure samples,64-byte read-only bounded hashes,domain privacy,monotonic clock");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-metal-diag-') as temp:
    path = Path(temp)
    source, exe = path / 'test.c', path / 'test'
    source.write_text(c)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                    '-I', str(ROOT / 'build/dxmt-ios'), str(source), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
    output = path / 'staged/winemetal_unix.c'
    subprocess.run(['python3', str(ROOT / 'tools/build/stage-dxmt-diagnostics.py'),
                    '--source', str(producer), '--output', str(output),
                    '--header', str(ROOT / 'build/dxmt-ios/graphics_diagnostics.h')], check=True)
    assert output.read_text() == staged
    assert (output.parent / 'graphics_diagnostics.h').read_bytes() == (ROOT / 'build/dxmt-ios/graphics_diagnostics.h').read_bytes()
    assert hashlib.sha256(producer.read_bytes()).hexdigest() == before
    if sys.platform == 'darwin':
        sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
        command = ['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', 'arm64', '-isysroot', sdk,
                   '-miphoneos-version-min=18.0', '-fblocks', '-x', 'objective-c', '-fsyntax-only']
        for include in ('include', 'libs', 'src/winemetal', 'src/airconv', 'src/winemetal/unix'):
            command += ['-I', str(args.dxmt_root / include)]
        command.append(str(output))
        compiled = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if compiled.returncode:
            print(compiled.stdout)
            raise AssertionError('actual staged iOS Objective-C producer did not compile')
        print('PASS actual staged Objective-C Metal producer compiles against the iPhoneOS SDK')
print('PASS actual DXMT staging: nil resource/view/upload/PSO boundaries and timing,draw/submit/GPU/display milestones; source immutable, API operations/returns/pitches/counting unchanged; no rendering-success claim')
