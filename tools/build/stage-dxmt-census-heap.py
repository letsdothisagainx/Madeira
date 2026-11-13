#!/usr/bin/env python3
"""Keep DXMT's existing census writes in one module-owned heap allocation.

The pinned sources stay immutable. Apply this after dynamic-memory staging so
both existing and injected counter producers use the same storage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


FILES = (
    'src/dxmt/dxmt_mem_census.hpp',
    'src/dxmt/dxmt_mem_census.cpp',
    'src/dxmt/dxmt_dynamic.cpp',
    'src/dxmt/dxmt_buffer.cpp',
)

NAMES = {
    'g_mem_census': 'census',
    'g_dyn_stats': 'dynamic',
    'g_buf_sites': 'sites',
    'g_live_dynbuf': 'live_dynbuf',
    'g_live_buffer': 'live_buffer',
    'g_live_bufalloc': 'live_bufalloc',
    'g_trim_total_n': 'trim_total_n',
    'g_trim_total_bytes': 'trim_total_bytes',
    'g_trim_regret': 'trim_regret',
    'g_dyn_next_id': 'dynamic_next_id',
    'g_census_device': 'device',
    'g_census_device_valid': 'device_valid',
}

DECLARATIONS = (
    'extern BufSite g_buf_sites[BSITE_SLOTS];',
    'extern DynStat g_dyn_stats[DYN_CENSUS_SLOTS];',
    'extern std::atomic<uint32_t> g_dyn_next_id;',
    'extern LiveCount g_live_dynbuf, g_live_buffer, g_live_bufalloc;',
    'extern std::atomic<uint64_t> g_trim_total_n, g_trim_total_bytes, g_trim_regret;',
)

STATE = r'''// Madeira census-heap-v1: preserve every counter and native atomic write.
struct MemCensusState {
  MemCensus census{};
  DynStat dynamic[DYN_CENSUS_SLOTS]{};
  BufSite sites[BSITE_SLOTS]{};
  LiveCount live_dynbuf{}, live_buffer{}, live_bufalloc{};
  std::atomic<uint64_t> trim_total_n{0}, trim_total_bytes{0}, trim_regret{0};
  std::atomic<uint32_t> dynamic_next_id{0};
  WMT::Device device{}; // Borrowed handle, exactly as in the former census global.
  bool device_valid = false;
  std::atomic<uint64_t> last_report_ns{0}, last_reported_seq{0};
};

namespace census_detail {
extern MemCensusState *state;
class Lifetime {
public:
  Lifetime();
  ~Lifetime();
  Lifetime(const Lifetime &) = delete;
  Lifetime &operator=(const Lifetime &) = delete;
};
// Each including translation unit constructs this anchor before its later
// statics and destroys it after them. The last PE anchor frees the state on
// legal module unload, after resource users stop. DXMT_NATIVE is linked once
// into the app image: its state survives CRT teardown so native queue workers
// can finish while exit() runs, and the OS reclaims it with that process.
// No lazy guard, allocation, or image write occurs per draw.
// This is deliberately internal linkage: each TU contributes one lifetime.
[[maybe_unused]] static const Lifetime lifetime;
} // namespace census_detail

inline MemCensusState &
memCensusState() {
  return *census_detail::state;
}'''

OWNER = r'''namespace census_detail {
// Constant initialization precedes every TU's dynamic lifetime anchor. The
// module loader serializes these CRT constructors/destructors; resource worker
// threads use only state, never this startup/teardown reference count.
constinit MemCensusState *state = nullptr;
static constinit unsigned users = 0;

Lifetime::Lifetime() {
  if (!state)
    state = new MemCensusState{};
  ++users;
}

Lifetime::~Lifetime() {
  if (--users == 0) {
#ifndef DXMT_NATIVE
    delete state;
    state = nullptr;
#endif
    // The native archive has one owner per app image, not per guest DLL load.
    // Keep that fixed block through process exit: live native CommandQueue
    // threads need not have stopped before C++ static finalizers run. Retaining
    // the pointer also prevents a late native anchor from allocating again.
  }
}
} // namespace census_detail'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('DXMT census input contract changed: ' + repr(old[:120]))
    return source.replace(old, new, 1)


def stage_file(name, source):
    if 'census-heap-v1' in source or 'memCensusState()' in source:
        raise ValueError('DXMT census input is already staged')
    if name == FILES[0]:
        for declaration in DECLARATIONS:
            source = replace_once(source, declaration, '')
        source = replace_once(source, 'extern MemCensus g_mem_census;', STATE)
    elif name == FILES[1]:
        source = replace_once(source, '''MemCensus g_mem_census{};
DynStat g_dyn_stats[DYN_CENSUS_SLOTS]{};
BufSite g_buf_sites[BSITE_SLOTS]{};
LiveCount g_live_dynbuf{}, g_live_buffer{}, g_live_bufalloc{};
std::atomic<uint64_t> g_trim_total_n{0}, g_trim_total_bytes{0}, g_trim_regret{0};''', OWNER)
        source = replace_once(source, 'std::atomic<uint32_t> g_dyn_next_id{0};', '')
        source = replace_once(source, '''static WMT::Device g_census_device {};
static bool g_census_device_valid = false;''', '')
        source = replace_once(source, '  static std::atomic<uint64_t> last_ns{0};',
                              '  auto &last_ns = memCensusState().last_report_ns;')
        # Scratch belongs to one report. Static arrays both fault on writes and
        # allow concurrent reports to corrupt one another's ranking cursors.
        source = replace_once(source, '  for (int rank = 0; rank < 10; rank++) {',
                              '  int shown[10]{}; int nshown = 0;\n  for (int rank = 0; rank < 10; rank++) {')
        source = replace_once(source, '    static int shown[10]; static int nshown;\n    if (rank == 0) nshown = 0;\n', '')
        source = replace_once(source, '  for (int rank = 0; rank < 8; rank++) {',
                              '  uint32_t shown[8]{}; int nshown = 0;\n  for (int rank = 0; rank < 8; rank++) {')
        source = replace_once(source, '    static uint32_t shown[8]; static int nshown;\n    if (rank == 0) nshown = 0;\n', '')
    elif name == FILES[2]:
        source = replace_once(source, '    static std::atomic<uint64_t> last_reported{0};',
                              '    auto &last_reported = memCensusState().last_reported_seq;')
    for old, member in NAMES.items():
        source = re.sub(r'\b' + old + r'\b', 'memCensusState().' + member, source)
    return source


def stage(source_dir, output_dir, overlay_dir=None):
    rows = []
    for name in FILES:
        original = source_dir / name
        candidate = overlay_dir / name if overlay_dir else original
        path = candidate if candidate.is_file() else original
        data = path.read_bytes()
        staged = stage_file(name, data.decode()).encode()
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
    print(json.dumps({'stage': 'dxmt-census-heap-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))


if __name__ == '__main__':
    main()
