#!/usr/bin/env python3
"""Batch adjacent native Metal residency declarations without reordering work.

This changes an owned build copy of winemetal_unix.c. Remote transport,
resource ownership, command submission and completion remain untouched.
"""
import argparse
from pathlib import Path


SOURCE = 'src/winemetal/unix/winemetal_unix.c'
MARKER = 'madeira-native-resource-batch-v1'

HELPERS = r'''/* madeira-native-resource-batch-v1: declaration runs are bounded and cannot
 * cross a draw, binding, fence, encoder or command-buffer boundary. */
#define MADEIRA_RESOURCE_BATCH_MAX 64u
struct madeira_resource_run {
  const struct wmtcmd_base *after;
  unsigned count;
};

static void madeira_resource_batch_note(void) {
  static _Atomic int reported;
  if (!atomic_load_explicit(&reported, memory_order_relaxed) &&
      !atomic_exchange_explicit(&reported, 1, memory_order_relaxed))
    fprintf(stderr, "[metal-resource-batch-v1] max=64 release-probe=opt-in\n");
}

static int madeira_resource_usage_valid(unsigned usage) {
  const unsigned allowed = WMTResourceUsageRead | WMTResourceUsageWrite | WMTResourceUsageSample;
  return usage && !(usage & ~allowed);
}

static struct madeira_resource_run
madeira_compute_resource_run(const struct wmtcmd_base *first) {
  struct madeira_resource_run run = {first, 0};
  const struct wmtcmd_compute_useresource *seed = (const void *)first;
  if (!seed->resource || !madeira_resource_usage_valid(seed->usage)) return run;
  while (run.after && run.count < MADEIRA_RESOURCE_BATCH_MAX &&
         run.after->type == WMTComputeCommandUseResource) {
    const struct wmtcmd_compute_useresource *entry = (const void *)run.after;
    if (!entry->resource || entry->usage != seed->usage) break;
    ++run.count;
    run.after = entry->next.ptr;
  }
  return run;
}

static struct madeira_resource_run
madeira_render_resource_run(const struct wmtcmd_base *first) {
  struct madeira_resource_run run = {first, 0};
  const struct wmtcmd_render_useresource *seed = (const void *)first;
  const unsigned stages = WMTRenderStageVertex | WMTRenderStageFragment |
                          WMTRenderStageTile | WMTRenderStageObject | WMTRenderStageMesh;
  if (!seed->resource || !madeira_resource_usage_valid(seed->usage) ||
      !seed->stages || (seed->stages & ~stages)) return run;
  while (run.after && run.count < MADEIRA_RESOURCE_BATCH_MAX &&
         run.after->type == WMTRenderCommandUseResource) {
    const struct wmtcmd_render_useresource *entry = (const void *)run.after;
    if (!entry->resource || entry->usage != seed->usage || entry->stages != seed->stages) break;
    ++run.count;
    run.after = entry->next.ptr;
  }
  return run;
}

'''

COMPUTE_OLD = r'''    case WMTComputeCommandUseResource: {
      struct wmtcmd_compute_useresource *body = (struct wmtcmd_compute_useresource *)next;
      wmt_stale_check(body->resource, "compute useResource");
      [encoder useResource:(id<MTLResource>)body->resource usage:(MTLResourceUsage)body->usage];
      break;
    }'''

COMPUTE_NEW = r'''    case WMTComputeCommandUseResource: {
      struct wmtcmd_compute_useresource *body = (struct wmtcmd_compute_useresource *)next;
      if (resource_batch_support != 0) {
        const struct madeira_resource_run run = madeira_compute_resource_run(next);
        if (run.count > 1) {
          if (resource_batch_support < 0)
            resource_batch_support = [encoder respondsToSelector:@selector(useResources:count:usage:)] ? 1 : 0;
          if (resource_batch_support) {
            madeira_resource_batch_note();
            id<MTLResource> resources[MADEIRA_RESOURCE_BATCH_MAX];
            const struct wmtcmd_base *entry = next;
            for (unsigned i = 0; i < run.count; ++i, entry = entry->next.ptr) {
              const struct wmtcmd_compute_useresource *item = (const void *)entry;
              wmt_stale_check(item->resource, "compute useResource");
              resources[i] = (id<MTLResource>)item->resource;
            }
            [encoder useResources:resources count:run.count usage:(MTLResourceUsage)body->usage];
            next = run.after;
            continue;
          }
        }
      }
      wmt_stale_check(body->resource, "compute useResource");
      [encoder useResource:(id<MTLResource>)body->resource usage:(MTLResourceUsage)body->usage];
      break;
    }'''

RENDER_OLD = r'''    case WMTRenderCommandUseResource: {
      struct wmtcmd_render_useresource *body = (struct wmtcmd_render_useresource *)next;
      wmt_stale_check(body->resource, "render useResource");
      [encoder useResource:(id<MTLResource>)body->resource
                     usage:(MTLResourceUsage)body->usage
                    stages:(MTLRenderStages)body->stages];
      break;
    }'''

RENDER_NEW = r'''    case WMTRenderCommandUseResource: {
      struct wmtcmd_render_useresource *body = (struct wmtcmd_render_useresource *)next;
      if (resource_batch_support != 0) {
        const struct madeira_resource_run run = madeira_render_resource_run(next);
        if (run.count > 1) {
          if (resource_batch_support < 0)
            resource_batch_support = [encoder respondsToSelector:@selector(useResources:count:usage:stages:)] ? 1 : 0;
          if (resource_batch_support) {
            madeira_resource_batch_note();
            id<MTLResource> resources[MADEIRA_RESOURCE_BATCH_MAX];
            const struct wmtcmd_base *entry = next;
            for (unsigned i = 0; i < run.count; ++i, entry = entry->next.ptr) {
              const struct wmtcmd_render_useresource *item = (const void *)entry;
              wmt_stale_check(item->resource, "render useResource");
              resources[i] = (id<MTLResource>)item->resource;
            }
            [encoder useResources:resources count:run.count usage:(MTLResourceUsage)body->usage
                          stages:(MTLRenderStages)body->stages];
            next = run.after;
            continue;
          }
        }
      }
      wmt_stale_check(body->resource, "render useResource");
      [encoder useResource:(id<MTLResource>)body->resource
                     usage:(MTLResourceUsage)body->usage
                    stages:(MTLRenderStages)body->stages];
      break;
    }'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('native batch input contract changed: ' + repr(old[:110]))
    return source.replace(old, new, 1)


def function(source, name):
    start = source.index('static NTSTATUS\n' + name + '(void *obj)')
    end = source.index('\n}\n', start) + 3
    return start, end, source[start:end]


def stage(source):
    if MARKER in source:
        raise ValueError('native resource batching is already staged')
    # Diagnostics are opt-in. The actual local/remote release paths stay exact;
    # avoid retainCount, class queries and ring writes with the probe disabled.
    source = replace_once(source, '  if (*obj && [*obj retainCount] == 1) {   /* ml1155: this release frees it */',
                          '  if (*obj && wmt_stale_probe_on() && [*obj retainCount] == 1) {   /* ml1155: opt-in release probe */')
    for name, encoder, old, new in (
        ('_MTLComputeCommandEncoder_encodeCommands', 'MTLComputeCommandEncoder', COMPUTE_OLD, COMPUTE_NEW),
        ('_MTLRenderCommandEncoder_encodeCommands', 'MTLRenderCommandEncoder', RENDER_OLD, RENDER_NEW),
    ):
        start, end, body = function(source, name)
        declaration = '  id<' + encoder + '> encoder = (id<' + encoder + '>)params->encoder;'
        body = replace_once(body, declaration, declaration + '\n  int resource_batch_support = -1;')
        body = replace_once(body, old, new)
        source = source[:start] + body + source[end:]
    return replace_once(source, 'static NTSTATUS\n_MTLComputeCommandEncoder_encodeCommands(void *obj)',
                        HELPERS + 'static NTSTATUS\n_MTLComputeCommandEncoder_encodeCommands(void *obj)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('vendor source must remain immutable')
    changed = stage(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(changed)


if __name__ == '__main__':
    main()
