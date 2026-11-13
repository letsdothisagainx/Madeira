#!/usr/bin/env python3
"""Exercise the actual native residency replay branches and opt-in release probe.

Portable tests substitute only Objective-C message syntax. Darwin also compiles
the unchanged Objective-C branches, then uses real Metal indirect buffer reads.
These checks do not measure CS2 frame rate or the game's GPU utilization.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_batch', ROOT / 'tools/build/stage-dxmt-native-batch.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def function(source, name):
    return stage.function(source, name)[2]


def case(source, kind):
    name = '_MTL' + kind + 'CommandEncoder_encodeCommands'
    body = function(source, name)
    marker = '    case WMT' + ('Compute' if kind == 'Compute' else 'Render') + 'CommandUseResource: {'
    start = body.index(marker)
    end = body.index('\n    case ', start + len(marker))
    return body[start:end]


def portable(body):
    replacements = {
        'id<MTLResource>': 'obj_handle_t',
        '[encoder respondsToSelector:@selector(useResources:count:usage:)]': 'encoder_support',
        '[encoder respondsToSelector:@selector(useResources:count:usage:stages:)]': 'encoder_support',
        '[encoder useResources:resources count:run.count usage:(MTLResourceUsage)body->usage]':
            'record_many(resources, run.count, body->usage, 0)',
        '[encoder useResources:resources count:run.count usage:(MTLResourceUsage)body->usage\n                          stages:(MTLRenderStages)body->stages]':
            'record_many(resources, run.count, body->usage, body->stages)',
        '[encoder useResource:(obj_handle_t)body->resource usage:(MTLResourceUsage)body->usage]':
            'record_one(body->resource, body->usage, 0)',
        '[encoder useResource:(obj_handle_t)body->resource\n                     usage:(MTLResourceUsage)body->usage\n                    stages:(MTLRenderStages)body->stages]':
            'record_one(body->resource, body->usage, body->stages)',
    }
    for old, new in replacements.items():
        body = body.replace(old, new)
    assert '[encoder ' not in body, body
    return body


def replay(body, kind, name, objc=False):
    code = body if objc else portable(body)
    signature = ('id encoder' if objc else 'int encoder_support')
    return ('static void ' + name + '(const struct wmtcmd_base *next, ' + signature + ') {\n'
            '  int resource_batch_support = -1;\n'
            '  while (next) {\n'
            '    switch (next->type) {\n' + code + '\n'
            '    default: record_marker(next->type); break;\n'
            '    }\n    next = next->next.ptr;\n  }\n}\n')


PRELUDE = r'''
#define DXMT_NATIVE 1
#include "winemetal.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct event { uint64_t resource; unsigned usage, stages, type; };
static struct event events[4096];
static unsigned event_count, api_calls, stale_checks, maximum_batch;
static void reset(void) { event_count=api_calls=stale_checks=maximum_batch=0; }
static void record_resource(uint64_t resource, unsigned usage, unsigned stages) {
  assert(event_count < 4096);
  events[event_count++] = (struct event){resource, usage, stages, 0};
}
static void record_one(uint64_t resource, unsigned usage, unsigned stages) {
  ++api_calls; record_resource(resource, usage, stages);
}
static void record_many(const obj_handle_t *resources, unsigned count, unsigned usage, unsigned stages) {
  assert(count >= 2 && count <= 64); ++api_calls;
  if (count > maximum_batch) maximum_batch=count;
  for (unsigned i=0; i<count; ++i) record_resource(resources[i],usage,stages);
}
static void record_marker(unsigned type) {
  assert(event_count < 4096);
  events[event_count++] = (struct event){0, 0, 0, type};
}
static void wmt_stale_check(uint64_t resource, const char *where) {
  (void)resource; (void)where; ++stale_checks;
}
union node {
  struct wmtcmd_base base;
  struct wmtcmd_render_useresource render;
  struct wmtcmd_compute_useresource compute;
};
static uint32_t rng=1234567;
static uint32_t random_word(void) { rng=rng*1664525u+1013904223u;return rng; }
'''

PORTABLE_MAIN = r'''
static void check(unsigned kind, unsigned count, unsigned pattern, int support) {
  union node nodes[2048]; memset(nodes,0,sizeof nodes);
  for (unsigned i=0;i<count;++i) {
    unsigned usage = pattern==2 ? 1+(i/7)%7 : 1;
    unsigned stages = pattern==3 ? 1u<<((i/9)%5) : WMTRenderStageFragment;
    uint64_t resource = 1+(i%23); /* duplicates must remain present and ordered */
    if (pattern==4 && i%11==3) resource=0;
    if (pattern==5 && i%13==7) usage=0;
    if (pattern==6 && i%13==7) usage=128;
    if (pattern==7 && i%13==7) stages=0;
    if (pattern==8 && i%13==7) stages=128;
    if (pattern==9) { usage=random_word()%10; stages=random_word()%36;resource=random_word()%50; }
    nodes[i].render.type=WMTRenderCommandUseResource;
    nodes[i].render.resource=resource;
    nodes[i].render.usage=usage;
    nodes[i].render.stages=stages;
    if (kind) nodes[i].compute.type=WMTComputeCommandUseResource;
    if ((pattern==1 && i%17==5) || (pattern==9 && i%11==3)) nodes[i].base.type=0x7fff;
    nodes[i].base.next.ptr=i+1<count ? &nodes[i+1] : NULL;
  }
  struct event expected[4096];
  reset();
  if (kind) old_compute(count?&nodes[0].base:NULL,support);else old_render(count?&nodes[0].base:NULL,support);
  unsigned expected_n=event_count,old_calls=api_calls,old_checks=stale_checks;
  memcpy(expected,events,event_count*sizeof *events);
  reset();
  if (kind) new_compute(count?&nodes[0].base:NULL,support);else new_render(count?&nodes[0].base:NULL,support);
  assert(expected_n==event_count && !memcmp(expected,events,event_count*sizeof *events));
  assert(stale_checks==old_checks && api_calls<=old_calls && maximum_batch<=64);
  if (!support) assert(api_calls==old_calls && !maximum_batch);
  if (pattern==0 && count) {
    assert(api_calls==(support ? (count+63)/64 : count));
    if (count>1 && support) assert(maximum_batch>1);
  }
}
int main(void) {
  unsigned cases=0;
  for (unsigned kind=0;kind<2;++kind) for (unsigned support=0;support<2;++support)
    for (unsigned pattern=0;pattern<10;++pattern) {
      const unsigned bounds[]={0,1,2,3,63,64,65,127,128,129,2048};
      for (unsigned i=0;i<sizeof bounds/sizeof *bounds;++i) { check(kind,bounds[i],pattern,support);++cases; }
    }
  printf("PASS %u actual native replay cases: identical ordered resources/usage/stages, duplicate/nil/invalid/command boundaries, legacy fallback, max64; 2048 compatible calls ->32\n",cases);
}
'''


def release_body(source):
    body = source[source.index('static NTSTATUS\n_NSObject_release(NSObject **obj) {'):]
    body = body[:body.index('\n}\n')+3]
    local = body.index('  /* ml820: a guest-local autorelease pool')
    return 'static NTSTATUS\n_NSObject_release(NSObject **obj) {\n' + body[local:]


RELEASE_PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned NTSTATUS;
#define STATUS_SUCCESS 0
typedef struct object { unsigned refs; const char *name; } NSObject;
struct wmt_rel_rec { uintptr_t p; const char *cls; };
static struct wmt_rel_rec g_wmt_rel[16384];
static uint64_t g_wmt_rel_n;
static unsigned probe,queries,releases,deallocated,classes,freed;
static int wmtr_enabled(void) { return 0; }
static void wmtr_pool_drain(void) { assert(0); }
static int fake_is_pool(NSObject *o) { (void)o;return 0; }
static int wmt_stale_probe_on(void) { return probe; }
static unsigned fake_retain_count(NSObject *o) { ++queries;return o->refs; }
static const char *object_getClassName(NSObject *o) { ++classes;return o->name; }
static void wmt_freed_set(uintptr_t p,int add) { assert(p&&add==1);++freed; }
static void fake_release(NSObject *o) { if (!o) return;++releases;assert(o->refs);if (!--o->refs) ++deallocated; }
'''
RELEASE_MAIN = r'''
int main(void) {
  for (unsigned enabled=0;enabled<2;++enabled) {
    probe=enabled;queries=releases=deallocated=classes=freed=0;g_wmt_rel_n=0;
    NSObject object={2,"FixtureMetalBuffer"};NSObject *p=&object;
    assert(_NSObject_release(&p)==STATUS_SUCCESS && object.refs==1 && releases==1 && !deallocated);
    assert(_NSObject_release(&p)==STATUS_SUCCESS && !object.refs && releases==2 && deallocated==1);
    assert(queries==(enabled||IS_OLD?2:0));assert(classes==(enabled||IS_OLD?1:0));
    assert(g_wmt_rel_n==(enabled||IS_OLD?1:0));assert(freed==enabled);
    p=NULL;assert(_NSObject_release(&p)==STATUS_SUCCESS&&releases==2);
  }
  puts("PASS actual release body: same real release/deallocation count; disabled probe adds no retainCount/class/ring work; enabled probe preserved");
}
'''

OBJC_RECORDERS = r'''
@interface RecordingEncoder : NSObject { @public BOOL supports; }
@end
@implementation RecordingEncoder
- (BOOL)respondsToSelector:(SEL)selector {
  if (selector==@selector(useResources:count:usage:) || selector==@selector(useResources:count:usage:stages:)) return supports;
  return [super respondsToSelector:selector];
}
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage { record_one((uint64_t)resource,usage,0); }
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage stages:(MTLRenderStages)stages { record_one((uint64_t)resource,usage,stages); }
- (void)useResources:(const id<MTLResource> *)resources count:(NSUInteger)count usage:(MTLResourceUsage)usage {
  assert(supports && count>=2 && count<=64); ++api_calls;
  if (count>maximum_batch) maximum_batch=(unsigned)count;
  for (NSUInteger i=0;i<count;++i) record_resource((uint64_t)resources[i],usage,0);
}
- (void)useResources:(const id<MTLResource> *)resources count:(NSUInteger)count usage:(MTLResourceUsage)usage stages:(MTLRenderStages)stages {
  assert(supports && count>=2 && count<=64); ++api_calls;
  if (count>maximum_batch) maximum_batch=(unsigned)count;
  for (NSUInteger i=0;i<count;++i) record_resource((uint64_t)resources[i],usage,stages);
}
@end

// This normal client wrapper counts calls and forwards every argument to the
// genuine encoder. It is test-only; no game or runtime method is intercepted.
@interface MetalForwarder : NSObject { @public id target; unsigned calls; }
@end
@implementation MetalForwarder
- (BOOL)respondsToSelector:(SEL)selector {
  if (selector==@selector(useResources:count:usage:) || selector==@selector(useResources:count:usage:stages:))
    return [target respondsToSelector:selector];
  return [super respondsToSelector:selector];
}
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage { ++calls;[target useResource:resource usage:usage]; }
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage stages:(MTLRenderStages)stages { ++calls;[target useResource:resource usage:usage stages:stages]; }
- (void)useResources:(const id<MTLResource> *)resources count:(NSUInteger)count usage:(MTLResourceUsage)usage { ++calls;[target useResources:resources count:count usage:usage]; }
- (void)useResources:(const id<MTLResource> *)resources count:(NSUInteger)count usage:(MTLResourceUsage)usage stages:(MTLRenderStages)stages { ++calls;[target useResources:resources count:count usage:usage stages:stages]; }
@end
'''

OBJC_RELEASE = r'''
typedef unsigned NTSTATUS;
#define STATUS_SUCCESS 0
struct wmt_rel_rec { uintptr_t p; const char *cls; };
static struct wmt_rel_rec g_wmt_rel[16384];
static uint64_t g_wmt_rel_n;
static unsigned probe,queries,releases,deallocated,classes,freed;
static int wmtr_enabled(void) { return 0; }
static void wmtr_pool_drain(void) { assert(0); }
static int wmt_stale_probe_on(void) { return probe; }
static void wmt_freed_set(uintptr_t p,int add) { assert(p&&add==1);++freed; }
static const char *counted_class(id obj) { ++classes;return object_getClassName(obj); }
@interface FixtureMetalBuffer : NSObject
@end
@implementation FixtureMetalBuffer
- (NSUInteger)retainCount { ++queries;return [super retainCount]; }
- (oneway void)release { ++releases;[super release]; }
- (void)dealloc { ++deallocated;[super dealloc]; }
@end
'''

OBJC_RELEASE_MAIN = r'''
static void check_actual_release(void) {
  for(unsigned old=0;old<2;++old) for(unsigned enabled=0;enabled<2;++enabled) {
    probe=enabled;queries=releases=deallocated=classes=freed=0;g_wmt_rel_n=0;
    NSObject *object=[FixtureMetalBuffer new];[object retain];
    NTSTATUS (*release)(NSObject **)=old?old_release:new_release;
    assert(release(&object)==STATUS_SUCCESS && releases==1 && !deallocated);
    assert(release(&object)==STATUS_SUCCESS && releases==2 && deallocated==1);
    assert(queries==(old||enabled?2:0));assert(classes==(old||enabled?1:0));
    assert(g_wmt_rel_n==(old||enabled?1:0));assert(freed==enabled);
    object=nil;assert(release(&object)==STATUS_SUCCESS&&releases==2);
  }
  puts("PASS actual Objective-C release/deallocation with probe off/on: genuine NSObject ownership unchanged");
}
'''

METAL_SMOKE = r'''
static void gpu_complete(id<MTLCommandBuffer> command) {
  dispatch_semaphore_t done=dispatch_semaphore_create(0);
  [command addCompletedHandler:^(id<MTLCommandBuffer> completed) { (void)completed;dispatch_semaphore_signal(done); }];
  [command commit];
  assert(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC))==0);
  if (command.error) fprintf(stderr,"Metal error: %s\n",command.error.description.UTF8String);
  assert(command.status==MTLCommandBufferStatusCompleted && !command.error);
#if OS_OBJECT_USE_OBJC
  [(id)done release];
#else
  dispatch_release(done);
#endif
}

static void metal_case(id<MTLDevice> device,id<MTLLibrary> library,unsigned count,int compute,int modern) {
  id<MTLBuffer> input[130]; union node commands[130];memset(commands,0,sizeof commands);
  id<MTLFunction> function=[library newFunctionWithName:compute?@"gather":@"pixel"];
  assert(function);
  id<MTLArgumentEncoder> arguments=[function newArgumentEncoderWithBufferIndex:0];assert(arguments);
  id<MTLBuffer> argument_buffer=[device newBufferWithLength:arguments.encodedLength options:MTLResourceStorageModeShared];assert(argument_buffer);
  [arguments setArgumentBuffer:argument_buffer offset:0];
  for (unsigned i=0;i<count;++i) {
    uint32_t value=i+1;
    input[i]=[device newBufferWithBytes:&value length:sizeof value options:MTLResourceStorageModeShared];assert(input[i]);
    [arguments setBuffer:input[i] offset:0 atIndex:i];
    commands[i].render.type=WMTRenderCommandUseResource;
    commands[i].render.resource=(uint64_t)input[i];commands[i].render.usage=WMTResourceUsageRead;
    commands[i].render.stages=WMTRenderStageFragment;
    if (compute) commands[i].compute.type=WMTComputeCommandUseResource;
    commands[i].base.next.ptr=i+1<count?&commands[i+1]:NULL;
  }
  id<MTLCommandQueue> queue=[device newCommandQueue];assert(queue);
  id<MTLCommandBuffer> command=[queue commandBuffer];assert(command);
  MetalForwarder *forward=[MetalForwarder new];
  id<MTLBuffer> output=nil;
  id<MTLTexture> texture=nil;
  id compute_pipeline=nil,render_pipeline=nil,vertex=nil;
  NSError *error=nil;
  if (compute) {
    compute_pipeline=[device newComputePipelineStateWithFunction:function error:&error];
    if (error) fprintf(stderr,"compute pipeline: %s\n",error.description.UTF8String);
    assert(compute_pipeline&&!error);
    output=[device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];assert(output);
    memset(output.contents,0,sizeof(uint32_t));
    id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];assert(encoder);forward->target=encoder;
    [encoder setComputePipelineState:compute_pipeline];
    [encoder setBuffer:argument_buffer offset:0 atIndex:0];[encoder setBuffer:output offset:0 atIndex:1];
    if (modern) new_compute(&commands[0].base,forward);else old_compute(&commands[0].base,forward);
    [encoder dispatchThreads:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
    [encoder endEncoding];
  } else {
    vertex=[library newFunctionWithName:@"vertex_main"];assert(vertex);
    MTLRenderPipelineDescriptor *p=[MTLRenderPipelineDescriptor new];
    p.vertexFunction=vertex;p.fragmentFunction=function;p.colorAttachments[0].pixelFormat=MTLPixelFormatRGBA8Unorm;
    render_pipeline=[device newRenderPipelineStateWithDescriptor:p error:&error];[p release];
    if (error) fprintf(stderr,"render pipeline: %s\n",error.description.UTF8String);
    assert(render_pipeline&&!error);
    MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:4 height:4 mipmapped:NO];
    d.storageMode=MTLStorageModePrivate;d.usage=MTLTextureUsageRenderTarget;
    texture=[device newTextureWithDescriptor:d];assert(texture);
    MTLRenderPassDescriptor *pass=[MTLRenderPassDescriptor renderPassDescriptor];
    pass.colorAttachments[0].texture=texture;pass.colorAttachments[0].loadAction=MTLLoadActionClear;
    pass.colorAttachments[0].storeAction=MTLStoreActionStore;pass.colorAttachments[0].clearColor=MTLClearColorMake(0,0,0,0);
    id<MTLRenderCommandEncoder> encoder=[command renderCommandEncoderWithDescriptor:pass];assert(encoder);forward->target=encoder;
    [encoder setRenderPipelineState:render_pipeline];[encoder setFragmentBuffer:argument_buffer offset:0 atIndex:0];
    if (modern) new_render(&commands[0].base,forward);else old_render(&commands[0].base,forward);
    [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];[encoder endEncoding];
    output=[device newBufferWithLength:1024 options:MTLResourceStorageModeShared];assert(output);
    memset(output.contents,0,1024);
    id<MTLBlitCommandEncoder> blit=[command blitCommandEncoder];assert(blit);
    [blit copyFromTexture:texture sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0,0,0) sourceSize:MTLSizeMake(4,4,1)
               toBuffer:output destinationOffset:0 destinationBytesPerRow:256 destinationBytesPerImage:1024];[blit endEncoding];
  }
  assert(forward->calls==(modern?(count+63)/64:count));
  // With normal retained command buffers, the declarations keep every
  // indirectly addressed input alive until GPU completion, just like singles.
  for (unsigned i=0;i<count;++i) { [input[i] release];input[i]=nil; }
  gpu_complete(command);
  if (compute) assert(*(uint32_t *)output.contents==count*(count+1)/2);
  else {
    const uint8_t *bytes=output.contents;
    for (unsigned y=0;y<4;++y) for (unsigned x=0;x<4;++x) {
      const uint8_t *pixel=bytes+y*256+x*4;
      assert(pixel[0]==255 && pixel[1]>=63&&pixel[1]<=64 && pixel[2]>=127&&pixel[2]<=128 && pixel[3]==255);
    }
  }
  printf("PASS actual Metal %s %s: %u indirect resources, %u native declaration calls, GPU output exact, CPU references released before commit\n",
         compute?"compute":"render",modern?"batched":"legacy",count,forward->calls);
  [forward release];[texture release];[output release];[compute_pipeline release];[render_pipeline release];[vertex release];
  [queue release];[arguments release];[argument_buffer release];[function release];
}

static void run_real_metal(int required) {
  id<MTLDevice> device=MTLCreateSystemDefaultDevice();
  if (!device) {
    if (required) { fprintf(stderr,"Metal device required\n");abort(); }
    puts("SKIP actual Metal GPU execution: no Metal device; Objective-C replay checks still run");return;
  }
  const unsigned count=device.argumentBuffersSupport==MTLArgumentBuffersTier2?130:16;
  NSString *code=[NSString stringWithFormat:@"#include <metal_stdlib>\nusing namespace metal;\n"
    "struct Arguments { array<device uint *,%u> input [[id(0)]]; };\n"
    "kernel void gather(constant Arguments& args [[buffer(0)]],device uint *out [[buffer(1)]]) { uint sum=0; for(uint i=0;i<%u;i++) sum+=args.input[i][0]; out[0]=sum; }\n"
    "vertex float4 vertex_main(uint index [[vertex_id]]) { float2 p[3]={float2(-1,-1),float2(3,-1),float2(-1,3)}; return float4(p[index],0,1); }\n"
    "fragment float4 pixel(constant Arguments& args [[buffer(0)]]) { uint sum=0; for(uint i=0;i<%u;i++) sum+=args.input[i][0]; return float4(float(sum)/%u.0,0.25,0.5,1); }\n",
    count,count,count,count*(count+1)/2];
  NSError *error=nil;id<MTLLibrary> library=[device newLibraryWithSource:code options:nil error:&error];
  if (error) fprintf(stderr,"shader compile: %s\n",error.description.UTF8String);
  assert(library&&!error);
  for (unsigned compute=0;compute<2;++compute) for(unsigned modern=0;modern<2;++modern) metal_case(device,library,count,compute,modern);
  [library release];[device release];
}
'''


def run_darwin(tmp, original, changed, actual_helpers, require_metal):
    source='#import <Foundation/Foundation.h>\n#import <Metal/Metal.h>\n#import <dispatch/dispatch.h>\n#import <objc/runtime.h>\n'
    source+=PRELUDE+actual_helpers+OBJC_RECORDERS
    for kind in ('Render','Compute'):
        source+=replay(case(original,kind),kind,'old_'+kind.lower(),True)
        source+=replay(case(changed,kind),kind,'new_'+kind.lower(),True)
    matrix=PORTABLE_MAIN.replace('int main(void)', 'static void run_recording_matrix(void)')
    matrix=matrix.replace('  union node nodes[2048];', '  RecordingEncoder *encoder=[RecordingEncoder new];encoder->supports=support;\n  union node nodes[2048];')
    matrix=matrix.replace(',support);', ',encoder);')
    matrix=matrix.replace('\n}\nstatic void run_recording_matrix', '\n  [encoder release];\n}\nstatic void run_recording_matrix')
    source+=matrix+METAL_SMOKE+OBJC_RELEASE
    for name,input_source in (('old_release',original),('new_release',changed)):
        source+=release_body(input_source).replace('_NSObject_release',name).replace('object_getClassName(*obj)','counted_class(*obj)')
    source+=OBJC_RELEASE_MAIN
    source+='\nint main(void) { @autoreleasepool { run_recording_matrix();check_actual_release();run_real_metal('+('1' if require_metal else '0')+'); } return 0; }\n'
    file=tmp/'native.m';file.write_text(source)
    binary=tmp/'native'
    subprocess.run([clang(),'-std=gnu11','-O2','-fblocks','-fno-objc-arc','-Wno-unused-variable','-Wno-unused-function',
                    '-I',str(ROOT/'dxmt/src/winemetal'),str(file),'-framework','Foundation','-framework','Metal','-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=90)


def clang():
    configured = os.environ.get('CC')
    if configured:
        return configured
    result = shutil.which('clang')
    if result:
        return result
    bundled = Path('/tmp/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64/bin/clang')
    if bundled.is_file():
        return str(bundled)
    raise RuntimeError('Clang is required for the production fixed-width command enums')


def run_c(tmp, name, source):
    path = tmp/(name+'.c');path.write_text(source)
    output=tmp/name
    subprocess.run([clang(),'-std=gnu11','-O2','-Wall','-Wextra','-Wno-unused-variable','-Wno-unused-function','-Wno-unused-parameter',
                    '-DDXMT_NATIVE','-I',str(ROOT/'dxmt/src/winemetal'),str(path),'-o',str(output)],check=True)
    subprocess.run([str(output)],check=True,timeout=30)


def check_stage_composition(original, changed):
    """Exercise the exact native staging chain used by the production build."""
    def producer(name):
        spec=importlib.util.spec_from_file_location(name,ROOT/('tools/build/stage-dxmt-'+name+'.py'))
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    diagnostics=producer('diagnostics')
    lifecycle=producer('lifecycle')
    pressure=producer('memory-pressure')
    complete=pressure.stage(lifecycle.stage(diagnostics.stage(original)))
    assert stage.MARKER in complete, 'production native pressure stage must compose resource batching'
    assert complete.count('/* '+stage.MARKER)==1
    assert complete.count('case 40:')==1
    assert complete.count('#include "graphics_diagnostics.h"')==1
    assert complete.count('#include "metal_lifecycle.h"')==1
    assert complete.count('#include "memory_pressure_native.h"')==1
    assert 'md_metal_commit((id<MTLCommandBuffer>)params->handle);' in complete
    for kind in ('Render','Compute'):
        assert case(complete,kind)==case(changed,kind)
    assert release_body(complete)==release_body(changed)
    print('PASS production diagnostics -> lifecycle -> pressure -> batch staging composition; native control, lifecycle and both replay branches coexist')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-metal',action='store_true')
    args=parser.parse_args()
    original_path=ROOT/'dxmt'/stage.SOURCE
    original=original_path.read_text();digest=hashlib.sha256(original_path.read_bytes()).hexdigest()
    changed=stage.stage(original)
    with tempfile.TemporaryDirectory(prefix='madeira-native-batch-') as directory:
        tmp=Path(directory)
        actual_helpers=changed[changed.index('/* '+stage.MARKER):changed.index('static NTSTATUS\n_MTLComputeCommandEncoder_encodeCommands')]
        code=PRELUDE+actual_helpers
        for kind in ('Render','Compute'):
            code+=replay(case(original,kind),kind,'old_'+kind.lower())
            code+=replay(case(changed,kind),kind,'new_'+kind.lower())
        run_c(tmp,'replay',code+PORTABLE_MAIN)
        for old,source in ((True,original),(False,changed)):
            body=release_body(source)
            body=body.replace('[*obj retainCount]','fake_retain_count(*obj)').replace('[*obj release]','fake_release(*obj)')
            body=body.replace('[*obj isKindOfClass:[NSAutoreleasePool class]]','fake_is_pool(*obj)')
            run_c(tmp,'release-'+str(old),RELEASE_PRELUDE+body+RELEASE_MAIN.replace('IS_OLD','1' if old else '0'))
        if sys.platform=='darwin':
            run_darwin(tmp,original,changed,actual_helpers,args.require_metal)
        elif args.require_metal:
            raise RuntimeError('--require-metal needs an Apple Metal host')
        else:
            print('SKIP actual Objective-C/Metal execution: requires Darwin; portable replay does not prove GPU execution')
    assert hashlib.sha256(original_path.read_bytes()).hexdigest()==digest
    try: stage.stage(changed)
    except ValueError: pass
    else: raise AssertionError('double native batching accepted')
    broken=original.replace(stage.RENDER_OLD,'changed_render_contract',1)
    try: stage.stage(broken)
    except ValueError: pass
    else: raise AssertionError('changed native input contract accepted')
    # All existing native handlers outside the two declaration cases and debug
    # probe condition are unchanged, including commit/wait/remote operations.
    inverse=changed.replace(stage.HELPERS,'')
    inverse=inverse.replace('\n  int resource_batch_support = -1;','')
    inverse=inverse.replace(stage.COMPUTE_NEW,stage.COMPUTE_OLD).replace(stage.RENDER_NEW,stage.RENDER_OLD)
    inverse=inverse.replace('  if (*obj && wmt_stale_probe_on() && [*obj retainCount] == 1) {   /* ml1155: opt-in release probe */',
                            '  if (*obj && [*obj retainCount] == 1) {   /* ml1155: this release frees it */')
    assert inverse==original
    print('PASS immutable vendor input, fail-closed staging and byte-identical remaining native/remote/commit/completion paths')
    check_stage_composition(original,changed)


if __name__=='__main__':
    main()
