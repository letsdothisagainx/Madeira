#!/usr/bin/env python3
"""Add bounded, observational Metal diagnostics to an owned DXMT build copy.

Input is never edited. Every splice names an exact upstream function/anchor;
changed upstream contracts fail the build instead of silently dropping probes.
The resulting source still calls the identical Metal operations and returns
their original values. Native Metal errors are not D3D11 HRESULTs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile


def function_span(source, name):
    marker = '\n' + name + '(void *obj) {'
    if source.count(marker) != 1:
        raise ValueError('DXMT function contract changed: ' + name)
    begin = source.index(marker) + 1
    end = source.index('\n}', begin) + 2
    return begin, end


def modify(source, name, anchor, addition, *, before=False, count=1, replace=False):
    begin, end = function_span(source, name)
    part = source[begin:end]
    if part.count(anchor) != count:
        raise ValueError('DXMT splice contract changed: ' + name + ': ' + anchor[:72])
    part = part.replace(anchor, addition if replace else (addition + anchor if before else anchor + addition))
    return source[:begin] + part + source[end:]


def error_trace(op, result, kind, extra='', extra_args=''):
    return f'''
  {{
    uint64_t md_n, md_errors;
    if (md_graphics_diag_take({op}, !({result}), &md_n, &md_errors)) {{
      char md_domain[65];
      md_graphics_error_token(md_domain, err ? [[err domain] UTF8String] : "none");
      fprintf(stderr, "[metal-api-v1] op={kind} n=%llu errors=%llu mono-ns=%llu elapsed-ns=%llu "
                      "result=%s error-domain=%s error-code=%lld{extra}\\n",
              (unsigned long long)md_n, (unsigned long long)md_errors,
              (unsigned long long)md_graphics_now_ns(),
              (unsigned long long)(md_graphics_now_ns() - md_graphics_started),
              ({result}) ? "object" : "nil", md_domain, (long long)(err ? [err code] : 0){extra_args});
    }}
  }}
'''


def stage(source):
    if '[metal-resource-v1]' in source or '#include "graphics_diagnostics.h"' in source:
        raise ValueError('DXMT diagnostics input is already staged')
    source = '#include "graphics_diagnostics.h"\n' + source
    for name, op, kind, result in (
        ('_MTLDevice_newLibrary', 'MD_GFX_LIBRARY', 'library', 'params->ret_library'),
        ('_MTLDevice_newComputePipelineState', 'MD_GFX_COMPUTE_PSO', 'compute-pso', 'params->ret_pso'),
        ('_MTLDevice_newRenderPipelineState', 'MD_GFX_RENDER_PSO', 'render-pso', 'params->ret_pso'),
        ('_MTLDevice_newRenderPipelineStateVD', 'MD_GFX_VERTEX_PSO', 'vertex-pso', 'params->ret_pso'),
        ('_MTLDevice_newMeshRenderPipelineState', 'MD_GFX_MESH_PSO', 'mesh-pso', 'params->ret_pso')):
        begin, end = function_span(source, name)
        part = source[begin:end]
        opening = part.index('{') + 1
        part = part[:opening] + '\n  uint64_t md_graphics_started = md_graphics_now_ns();' + part[opening:]
        source = source[:begin] + part + source[end:]
        source = modify(source, name, '  params->ret_error = (obj_handle_t)err;',
                        error_trace(op, result, kind,
                                    ' archive-lookup-only=%u' if kind.endswith('pso') else '',
                                    ', (unsigned)info->fail_on_binary_archive_miss' if kind.endswith('pso') else ''))
    source = modify(source, '_MTLLibrary_newFunctionWithConstants',
                    '  struct unixcall_mtllibrary_newfunction_with_constants *params = obj;',
                    '\n  uint64_t md_graphics_started = md_graphics_now_ns();')
    source = modify(source, '_MTLLibrary_newFunctionWithConstants',
                    '  params->ret_error = (obj_handle_t)err;',
                    error_trace('MD_GFX_FUNCTION', 'params->ret', 'function-constants'))

    for name, op, kind in (('_MTLDevice_newTexture', 'MD_GFX_TEXTURE', 'texture'),
                            ('_MTLBuffer_newTexture', 'MD_GFX_BUFFER_TEXTURE', 'buffer-texture')):
        source = modify(source, name, '\n  info->mach_port = 0;\n', f'''
  {{
    uint64_t md_n, md_errors;
    if (md_graphics_diag_take({op}, !ret, &md_n, &md_errors))
      fprintf(stderr, "[metal-resource-v1] op={kind} n=%llu errors=%llu mono-ns=%llu result=%s "
                      "requested-format=%u physical-format=%lu width=%u height=%u depth=%u "
                      "mips=%u slices=%u usage=%u gpu-id=%llu\\n",
              (unsigned long long)md_n, (unsigned long long)md_errors,
              (unsigned long long)md_graphics_now_ns(), ret ? "object" : "nil",
              (unsigned)info->pixel_format, (unsigned long)(ret ? [ret pixelFormat] : 0),
              info->width, info->height, info->depth, info->mipmap_level_count,
              info->array_length, (unsigned)info->usage, (unsigned long long)info->gpu_resource_id);
  }}
''')
    source = modify(source, '_MTLTexture_newTextureView', '  params->gpu_resource_id = [ret gpuResourceID]._impl;', r'''
  {
    uint64_t md_n, md_errors;
    if (md_graphics_diag_take(MD_GFX_VIEW, !ret, &md_n, &md_errors))
      fprintf(stderr, "[metal-resource-v1] op=view n=%llu errors=%llu mono-ns=%llu result=%s "
                      "parent-format=%lu requested-format=%u physical-format=%lu "
                      "first-mip=%llu mips=%llu first-slice=%llu slices=%llu gpu-id=%llu\n",
              (unsigned long long)md_n, (unsigned long long)md_errors,
              (unsigned long long)md_graphics_now_ns(), ret ? "object" : "nil",
              (unsigned long)[texture pixelFormat], (unsigned)params->format,
              (unsigned long)(ret ? [ret pixelFormat] : 0),
              (unsigned long long)params->level_start, (unsigned long long)params->level_count,
              (unsigned long long)params->slice_start, (unsigned long long)params->slice_count,
              (unsigned long long)params->gpu_resource_id);
  }
''')
    source = modify(source, '_MTLTexture_replaceRegion',
                    '  if (!texture_upload_pitch_ok(tex, params->size.width, params->bytes_per_row))\n    return STATUS_SUCCESS;', r'''
  {
    int md_rejected = !texture_upload_pitch_ok(tex, params->size.width, params->bytes_per_row);
    uint64_t md_n, md_errors;
    if (md_graphics_diag_take(md_rejected ? MD_GFX_UPLOAD_REJECTED : MD_GFX_UPLOAD,
                             md_rejected, &md_n, &md_errors)) {
      unsigned md_sampled = 0;
      uint64_t md_hash = (md_rejected || !params->size.width || !params->size.height || !params->size.depth)
                                   ? 0 : md_graphics_prefix_hash(params->data.ptr,
                                   params->bytes_per_row, 0, &md_sampled);
      fprintf(stderr, "[metal-upload-v1] op=replace-region n=%llu errors=%llu mono-ns=%llu "
                      "outcome=%s physical-format=%lu width=%llu height=%llu depth=%llu "
                      "mip=%llu slice=%llu row-pitch=%llu image-pitch=%llu sampled=%u prefix-fnv64=%llx\n",
              (unsigned long long)md_n, (unsigned long long)md_errors,
              (unsigned long long)md_graphics_now_ns(), md_rejected ? "pitch-rejected" : "api-request",
              (unsigned long)[tex pixelFormat], (unsigned long long)params->size.width,
              (unsigned long long)params->size.height, (unsigned long long)params->size.depth,
              (unsigned long long)params->level, (unsigned long long)params->slice,
              (unsigned long long)params->bytes_per_row, (unsigned long long)params->bytes_per_image,
              md_sampled, (unsigned long long)md_hash);
    }
    if (md_rejected) return STATUS_SUCCESS;
  }
''', replace=True)
    source = modify(source, '_MTLBlitCommandEncoder_encodeCommands',
                    '      wmt_stale_check(body->src, "blit copy src"); wmt_stale_check(body->dst, "blit copy dst");\n      [encoder copyFromBuffer:(id<MTLBuffer>)body->src\n                 sourceOffset:body->src_offset\n            sourceBytesPerRow:body->bytes_per_row', r'''
      {
        uint64_t md_n, md_errors;
        if (md_graphics_diag_take(MD_GFX_UPLOAD, !dst || !body->src, &md_n, &md_errors)) {
          id<MTLBuffer> md_src = (id<MTLBuffer>)body->src;
          unsigned md_sampled;
          size_t md_length = [md_src length];
          size_t md_available = body->src_offset <= md_length ? md_length - body->src_offset : 0;
          if (md_available > body->bytes_per_row) md_available = body->bytes_per_row;
          MTLStorageMode md_mode = [md_src storageMode];
          const void *md_contents = (md_mode == MTLStorageModeShared || md_mode == MTLStorageModeManaged)
                                     ? [md_src contents] : NULL;
          uint64_t md_hash = md_graphics_prefix_hash(md_contents,
              body->src_offset <= md_length ? body->src_offset + md_available : 0,
              body->src_offset, &md_sampled);
          fprintf(stderr, "[metal-upload-v1] op=buffer-to-texture n=%llu errors=%llu mono-ns=%llu "
                          "outcome=encode-request physical-format=%lu width=%u height=%u depth=%u "
                          "mip=%u slice=%u row-pitch=%u image-pitch=%u sampled=%u prefix-fnv64=%llx\n",
                  (unsigned long long)md_n, (unsigned long long)md_errors,
                  (unsigned long long)md_graphics_now_ns(), (unsigned long)[dst pixelFormat],
                  body->size.width, body->size.height, body->size.depth, body->level, body->slice,
                  body->bytes_per_row, body->bytes_per_image, md_sampled, (unsigned long long)md_hash);
        }
      }
''', before=True)
    source = modify(source, '_MTLRenderCommandEncoder_encodeCommands',
                    '      [encoder setRenderPipelineState:(id<MTLRenderPipelineState>)body->pso];', r'''
      {
        uint64_t md_n, md_errors;
        if (md_graphics_diag_take(MD_GFX_BIND_PSO, !body->pso, &md_n, &md_errors))
          fprintf(stderr, "[metal-api-v1] op=bind-render-pso n=%llu errors=%llu mono-ns=%llu result=%s\n",
                  (unsigned long long)md_n, (unsigned long long)md_errors,
                  (unsigned long long)md_graphics_now_ns(), body->pso ? "object" : "nil");
      }
''', before=True)
    source = modify(source, '_MTLCommandBuffer_renderCommandEncoder', '  [descriptor release];', r'''
  {
    uint64_t md_n, md_errors;
    if (md_graphics_diag_take(MD_GFX_RENDER_PASS, !params->ret, &md_n, &md_errors)) {
      unsigned md_colors = 0;
      for (unsigned md_i = 0; md_i < 8; ++md_i) if (info->colors[md_i].texture) md_colors |= 1u << md_i;
      fprintf(stderr, "[metal-api-v1] op=render-pass n=%llu errors=%llu mono-ns=%llu result=%s "
                      "color-mask=%x color0-format=%lu depth-format=%lu stencil-format=%lu\n",
              (unsigned long long)md_n, (unsigned long long)md_errors,
              (unsigned long long)md_graphics_now_ns(), params->ret ? "object" : "nil", md_colors,
              (unsigned long)[descriptor.colorAttachments[0].texture pixelFormat],
              (unsigned long)[descriptor.depthAttachment.texture pixelFormat],
              (unsigned long)[descriptor.stencilAttachment.texture pixelFormat]);
    }
  }
''', before=True)
    # Direct draw encoding is a milestone, not proof of GPU completion/display.
    source = modify(source, '_MTLRenderCommandEncoder_encodeCommands',
        '      atomic_fetch_add_explicit(&g_madeira_draw_calls, 1, memory_order_relaxed);', r'''
      if (!atomic_fetch_add_explicit(&g_madeira_draw_calls, 1, memory_order_relaxed)) {
        uint64_t md_n, md_errors;
        if (md_graphics_diag_take(MD_GFX_DRAW, 0, &md_n, &md_errors))
          fprintf(stderr, "[metal-progress-v1] event=first-draw-encode mono-ns=%llu opcode=%u "
                          "meaning=encoded-not-submitted\n", (unsigned long long)md_graphics_now_ns(), next->type);
      }
''', before=False, count=4)
    # Remove the original counter increment left by the generic append helper;
    # each real draw must still increment its existing counter exactly once.
    source = source.replace('      atomic_fetch_add_explicit(&g_madeira_draw_calls, 1, memory_order_relaxed);\n'
                            '      if (!atomic_fetch_add_explicit(&g_madeira_draw_calls, 1, memory_order_relaxed))',
                            '      if (!atomic_fetch_add_explicit(&g_madeira_draw_calls, 1, memory_order_relaxed))')
    source = modify(source, '_MTLCommandBuffer_commit',
        '  [(id<MTLCommandBuffer>)params->handle commit];', r'''
  {
    uint64_t md_n, md_errors;
    uint64_t md_start = md_graphics_now_ns();
    if (md_graphics_diag_take(MD_GFX_SUBMIT, !params->handle, &md_n, &md_errors))
      fprintf(stderr, "[metal-progress-v1] event=command-submit n=%llu errors=%llu mono-ns=%llu\n",
              (unsigned long long)md_n, (unsigned long long)md_errors, (unsigned long long)md_start);
    [(id<MTLCommandBuffer>)params->handle addCompletedHandler:^(id<MTLCommandBuffer> md_buffer) {
      uint64_t md_calls, md_failures;
      if (md_graphics_diag_take(MD_GFX_COMPLETED, md_buffer.status == MTLCommandBufferStatusError,
                               &md_calls, &md_failures)) {
        char md_domain[65];
        NSError *md_error = md_buffer.error;
        md_graphics_error_token(md_domain, md_error ? [[md_error domain] UTF8String] : "none");
        fprintf(stderr, "[metal-progress-v1] event=command-completed n=%llu errors=%llu "
                        "mono-ns=%llu wall-ns=%llu status=%lu gpu-ms=%.3f error-domain=%s error-code=%lld "
                        "meaning=gpu-completion-not-display\n",
                (unsigned long long)md_calls, (unsigned long long)md_failures,
                (unsigned long long)md_graphics_now_ns(),
                (unsigned long long)(md_graphics_now_ns() - md_start), (unsigned long)md_buffer.status,
                (md_buffer.GPUEndTime - md_buffer.GPUStartTime) * 1000.0, md_domain,
                (long long)(md_error ? [md_error code] : 0));
      }
    }];
  }
''', before=True)
    source = modify(source, '_MTLCommandBuffer_presentDrawable', '  int mode = g_madeira_vsync_mode;', r'''
  {
    uint64_t md_n, md_errors;
    if (md_graphics_diag_take(MD_GFX_PRESENT, !params->arg, &md_n, &md_errors))
      fprintf(stderr, "[metal-progress-v1] event=present-request n=%llu errors=%llu mono-ns=%llu "
                      "meaning=request-not-display\n", (unsigned long long)md_n,
              (unsigned long long)md_errors, (unsigned long long)md_graphics_now_ns());
    id<MTLDrawable> md_drawable = (id<MTLDrawable>)params->arg;
    if ([md_drawable respondsToSelector:@selector(addPresentedHandler:)])
      [md_drawable addPresentedHandler:^(id<MTLDrawable> md_presented) {
        uint64_t md_calls, md_failures;
        if (md_graphics_diag_take(MD_GFX_PRESENTED, md_presented.presentedTime <= 0.0,
                                 &md_calls, &md_failures))
          fprintf(stderr, "[metal-progress-v1] event=drawable-presented n=%llu errors=%llu "
                          "mono-ns=%llu presented-time=%.6f meaning=display-event-not-menu-validation\n",
                  (unsigned long long)md_calls, (unsigned long long)md_failures,
                  (unsigned long long)md_graphics_now_ns(), md_presented.presentedTime);
      }];
  }
''', before=True)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--header', required=True, type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('source must remain immutable; output must be an owned build copy')
    original = args.source.read_bytes()
    output = stage(original.decode()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as temp:
        temp.write(output)
        temporary = Path(temp.name)
    temporary.replace(args.output)
    shutil.copyfile(args.header, args.output.parent / 'graphics_diagnostics.h')
    print(json.dumps({'stage': 'metal-diagnostics-v1', 'source_sha256': hashlib.sha256(original).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(), 'semantic_changes': False,
                      'line_budget': 256, 'upload_sample_limit': 64}))


if __name__ == '__main__':
    main()
