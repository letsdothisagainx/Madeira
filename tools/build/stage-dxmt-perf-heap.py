#!/usr/bin/env python3
"""Move DXMT draw/BC diagnostic atomics into module-owned writable heap storage.

Only an owned build copy changes. Counter operations, report cadence and draw
behavior stay intact. The detached refill workers retain their original image
lifetime timer sink; sampled draw/BC counters use writable heap storage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


FILES = (
    'src/dxmt/dxmt_command_queue.hpp',
    'src/dxmt/dxmt_command_queue.cpp',
    'src/d3d11/d3d11_context_impl.cpp',
    'src/d3d11/d3d11_context_imm.cpp',
)

BC_NAMES = (
    'g_bc_stream_ok', 'g_bc_stream_fail', 'g_bc_clamp_xlated',
    'g_bc_clamp_dropped', 'g_cp_xlated', 'g_cp_dropped', 'g_cp_lost',
    'g_cp_refilled', 'g_cp_tex_tex', 'g_cp_stg_tex', 'g_cp_tex_stg',
    'g_cp_stg_stg', 'g_cp_bc_stg_unsupported', 'g_cp_bc_stg_decoded',
    'g_cp_bc_stg_fail',
)

BC_MEMBERS = '''
  // Existing BC diagnostics, including the report's 1024-call cadence.
  std::atomic<uint32_t> bc_stream_ok[16]{};
  std::atomic<uint32_t> bc_stream_fail{0}, bc_clamp_xlated{0}, bc_clamp_dropped{0};
  std::atomic<uint32_t> cp_xlated{0}, cp_dropped{0}, cp_lost{0}, cp_refilled{0};
  std::atomic<uint32_t> cp_tex_tex{0}, cp_stg_tex{0}, cp_tex_stg{0}, cp_stg_stg{0};
  std::atomic<uint32_t> cp_bc_stg_unsupported{0}, cp_bc_stg_decoded{0}, cp_bc_stg_fail{0};
  std::atomic<uint32_t> bc_stream_report_tick{0};
'''

LIFETIME = '''// Madeira perf-heap-v1: sampled draw/BC atomics target native RW heap.
namespace perf_detail {
extern PerfCounters *state;
class Lifetime {
public:
  Lifetime();
  ~Lifetime();
  Lifetime(const Lifetime &) = delete;
  Lifetime &operator=(const Lifetime &) = delete;
};
// One internal-linkage anchor per including TU precedes its later statics and
// outlives their destruction. PE frees the owner after its last anchor; the
// fixed DXMT_NATIVE app image retains one small owner through process exit so
// queued native callbacks preserve the former BSS lifetime during teardown.
[[maybe_unused]] static const Lifetime lifetime;
} // namespace perf_detail

inline PerfCounters &
perfCounters() noexcept {
  return *perf_detail::state;
}'''

WORKER_SINK = 'g_perf_refill_worker_ns'

OWNER = '''
// Detached refill threads may finish/start timers after the final TU anchor.
// Preserve this one sink's original image lifetime; no heap owner is consulted
// by those workers. Reporting exchanges the same atomic through a reference.
constinit std::atomic<uint64_t> g_perf_refill_worker_ns{0};

namespace perf_detail {
// Constant initialization precedes every TU's dynamic lifetime anchor.
constinit PerfCounters *state = nullptr;
static constinit unsigned users = 0;

Lifetime::Lifetime() {
  if (!state)
    state = new PerfCounters{};
  ++users;
}

Lifetime::~Lifetime() {
  if (--users == 0) {
#ifndef DXMT_NATIVE
    delete state;
    state = nullptr;
#endif
  }
}
} // namespace perf_detail
'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('DXMT perf heap input contract changed: ' + repr(old[:100]))
    return source.replace(old, new, 1)


def stage_file(name, source):
    if 'perf-heap-v1' in source or 'perfCounters()' in source:
        raise ValueError('DXMT perf heap input is already staged: ' + name)
    if name == FILES[0]:
        source = replace_once(source, 'struct PerfCounters {',
            'extern std::atomic<uint64_t> ' + WORKER_SINK + ';\n\nstruct PerfCounters {')
        source = replace_once(source,
            '  std::atomic<uint64_t> refill_worker_ns{0}, refill_queued{0}, refill_applied{0}, refill_stale{0},',
            '  std::atomic<uint64_t> &refill_worker_ns = ' + WORKER_SINK + ';\n'
            '  std::atomic<uint64_t> refill_queued{0}, refill_applied{0}, refill_stale{0},')
        source = replace_once(source,
            '      refill_overbudget{0};   /* ml1256: the off-thread refill */\n};',
            '      refill_overbudget{0};   /* ml1256: the off-thread refill */' + BC_MEMBERS + '};')
        source = replace_once(source, 'inline PerfCounters g_perf;', LIFETIME)
    elif name == FILES[1]:
        source = replace_once(source, 'namespace dxmt {\n', 'namespace dxmt {\n' + OWNER)
    elif name == FILES[2]:
        source = replace_once(source, '        PerfTimer _t{g_perf.refill_worker_ns};',
                              '        PerfTimer _t{' + WORKER_SINK + '};')
        for old in BC_NAMES:
            declaration = (r'^inline std::atomic<uint32_t> ' + old
                           + (r'\[16\];' if old == 'g_bc_stream_ok' else r'\{0\};'))
            source, count = re.subn(declaration, '', source, flags=re.MULTILINE)
            if count != 1:
                raise ValueError('DXMT BC counter declaration changed: ' + old)
        source = replace_once(source, '  static std::atomic<uint32_t> tick{0};',
                              '  auto &tick = perfCounters().bc_stream_report_tick;')
        for old in BC_NAMES:
            source = re.sub(r'\b' + old + r'\b', 'perfCounters().' + old[2:], source)
    if name != FILES[0]:
        if not re.search(r'\bg_perf\b', source):
            raise ValueError('DXMT perf counter producers changed: ' + name)
        source = re.sub(r'\bg_perf\b', 'perfCounters()', source)
    return source


def stage(source_dir, output_dir, overlay_dir=None):
    if source_dir.resolve() == output_dir.resolve():
        raise ValueError('vendor input must remain immutable')
    prepared = []
    # Validate every input before publishing any staged output.
    for name in FILES:
        original = source_dir / name
        candidate = overlay_dir / name if overlay_dir else original
        path = candidate if candidate.is_file() else original
        data = path.read_bytes()
        prepared.append((name, data, stage_file(name, data.decode()).encode()))
    rows = []
    for name, data, staged in prepared:
        output = output_dir / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(staged)
        rows.append({'path': name, 'input_sha256': hashlib.sha256(data).hexdigest(),
                     'output_sha256': hashlib.sha256(staged).hexdigest()})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--overlay-dir', type=Path)
    args = parser.parse_args()
    if args.source_dir.resolve() == args.output_dir.resolve():
        parser.error('vendor input must remain immutable')
    print(json.dumps({'stage': 'dxmt-perf-heap-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))


if __name__ == '__main__':
    main()
