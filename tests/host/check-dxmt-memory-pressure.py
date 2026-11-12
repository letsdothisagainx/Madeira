#!/usr/bin/env python3
"""Exercise the production process-pressure policy, native query, and ABI stage."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dxmt-root', type=Path, default=ROOT / 'dxmt')
args = parser.parse_args()
native_source = args.dxmt_root / 'src/winemetal/unix/winemetal_unix.c'
original = native_source.read_bytes()


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ('tools/build/stage-dxmt-' + name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


producer = module('memory-pressure')
staged = producer.stage(original.decode())
assert staged.count('case 40:') == 1
assert 'md_memory_pressure_query(a);' in staged
assert '(a->op == 7 || a->op == 40)' in staged
old_op7 = original.decode().split('  case 7: {')[1].split('  case 8: {')[0]
assert staged.split('  case 7: {')[1].split('  case 8: {')[0] == old_op7
assert 'if (wmtr_enabled()) break;\n    md_memory_pressure_query(a);' in staged
assert staged.count('return STATUS_SUCCESS;') == original.decode().count('return STATUS_SUCCESS;')
for bad in (staged, original.decode().replace('  default: break;\n  }\n  return STATUS_SUCCESS;\n}',
                                             '  default: return STATUS_SUCCESS;\n  }\n  return STATUS_SUCCESS;\n}')):
    try:
        producer.stage(bad)
    except ValueError:
        pass
    else:
        raise AssertionError('occupied op or changed native control path must fail closed')

abi = (args.dxmt_root / 'src/winemetal/winemetal.h').read_text()
abi = abi[abi.index('struct madeira_ctl_args {'):abi.index('WINEMETAL_API void MadeiraCtl')]

CPP = r'''
#include "memory_pressure.hpp"
#include <atomic>
#include <cassert>
#include <cstddef>
#include <thread>
#include <vector>
static constexpr uint64_t MiB = uint64_t{1} << 20;
static std::atomic<unsigned> calls{0};
static thread_local madeira_ctl_args reply{40, 1, 5376 * MiB, 768 * MiB, {0}};
void MadeiraCtl(madeira_ctl_args *args) {
  assert(args->op == 40 && args->ret == 0 && !args->ptr && !args->len);
  calls.fetch_add(1, std::memory_order_relaxed);
  *args = reply;
}
int main() {
  static_assert(offsetof(madeira_ctl_args, ptr) == 8);
  static_assert(offsetof(madeira_ctl_args, len) == 16);
  static_assert(offsetof(madeira_ctl_args, name) == 24);
  auto s = dxmt::memoryPressureSnapshot();
  assert(s.valid && s.limit == 6144 * MiB && s.reserve == 768 * MiB);
  assert(s.needsReclaim());
  assert(calls == 1);
  for (unsigned i = 0; i < 1000; ++i) dxmt::memoryPressureSnapshot();
  assert(calls == 1);
  reply.ptr = 6142 * MiB; reply.len = 2 * MiB;
  s = dxmt::memoryPressureSnapshot(true);
  assert(s.valid && s.reserve == 768 * MiB && s.needsReclaim());
  reply.ptr = 6144 * MiB; reply.len = 0;
  s = dxmt::memoryPressureSnapshot(true);
  assert(s.valid && s.available == 0 && s.needsReclaim());
  reply.ptr = 4096 * MiB; reply.len = 2048 * MiB;
  s = dxmt::memoryPressureSnapshot(true);
  assert(s.valid && !s.needsReclaim() && !s.needsReclaim(1279 * MiB));
  assert(s.needsReclaim(1280 * MiB) && s.needsReclaim(UINT64_MAX));
  reply.ptr = 128 * MiB; reply.len = 128 * MiB;
  s = dxmt::memoryPressureSnapshot(true);
  assert(s.reserve == 128 * MiB);
  reply.ptr = 4096 * MiB; reply.len = 12288 * MiB;
  s = dxmt::memoryPressureSnapshot(true);
  assert(s.reserve == 1024 * MiB);
  for (unsigned bad = 0; bad != 4; ++bad) {
    reply.ret = bad == 0 ? 0 : 1;
    reply.ptr = bad == 1 ? 0 : bad == 2 ? UINT64_MAX - 3 : 4096 * MiB;
    reply.len = bad == 2 ? 10 : bad == 3 ? UINT64_MAX : 512 * MiB;
    s = dxmt::memoryPressureSnapshot(true);
    assert(!s.valid && !s.footprint && !s.available && !s.limit && !s.reserve);
    assert(!s.needsReclaim(UINT64_MAX));
  }
  const unsigned before = calls;
  std::vector<std::thread> workers;
  for (unsigned i = 0; i < 8; ++i) workers.emplace_back([] {
    const auto initial = dxmt::memoryPressureSnapshot();
    assert(initial.valid);
    for (unsigned n = 0; n < 1000; ++n) assert(dxmt::memoryPressureSnapshot().limit == initial.limit);
  });
  for (auto &worker : workers) worker.join();
  assert(calls == before + 8);
  reply = {40, 1, 4096 * MiB, 2048 * MiB, {0}};
  dxmt::memoryPressureSnapshot(true);
  const unsigned timed = calls;
  std::this_thread::sleep_for(std::chrono::milliseconds(110));
  assert(dxmt::memoryPressureSnapshot().valid && calls == timed + 1);
}
'''

NATIVE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "winemetal.h"
#include "memory_pressure_native.h"
static int task_failure, sysctl_failure, short_count, short_size;
static uint64_t measured_footprint, measured_available, installed;
static unsigned available_queries;
int mach_task_self(void) { return 1; }
int task_info(int task, int flavor, task_info_t data, mach_msg_type_number_t *count) {
  assert(task == 1 && flavor == TASK_VM_INFO);
  errno = 41;
  ((task_vm_info_data_t *)data)->phys_footprint = measured_footprint;
  *count = short_count ? TASK_VM_INFO_REV1_COUNT - 1 : TASK_VM_INFO_COUNT;
  return task_failure;
}
size_t os_proc_available_memory(void) { ++available_queries; errno = 42; return measured_available; }
int sysctlbyname(const char *key, void *out, size_t *size, void *in, size_t in_size) {
  assert(!strcmp(key, "hw.memsize") && !in && !in_size);
  *(uint64_t *)out = installed;
  *size = short_size ? 1 : sizeof(installed);
  errno = 43;
  return sysctl_failure;
}
static struct madeira_ctl_args sample(void) {
  struct madeira_ctl_args args = {40, 123, 456, 789, {0}};
  errno = 72;
  md_memory_pressure_query(&args);
  assert(errno == 72);
  return args;
}
int main(void) {
  const uint64_t mib = (uint64_t)1 << 20;
  installed = 7672 * mib;
  measured_footprint = 6142 * mib; measured_available = 2 * mib;
  struct madeira_ctl_args result = sample();
  assert(result.ret == 1 && result.ptr == measured_footprint && result.len == measured_available);
  measured_available = 0;
  result = sample(); assert(result.ret == 1 && result.ptr == measured_footprint && !result.len);
  measured_footprint = installed + mib;
  result = sample(); assert(result.ret == 1 && !result.len);
  measured_footprint = 6142 * mib;
  for (unsigned failure = 0; failure != 8; ++failure) {
    task_failure = failure == 0;
    short_count = failure == 1;
    sysctl_failure = failure == 2;
    short_size = failure == 3;
    installed = failure == 4 ? 0 : 7672 * mib;
    measured_footprint = failure == 5 ? 0 : failure == 7 ? UINT64_MAX - 4 : 6142 * mib;
    measured_available = failure == 6 ? UINT64_MAX : failure == 7 ? 8 : 2 * mib;
    result = sample();
    assert(result.ret == 0 && result.ptr == 0 && result.len == 0);
  }
  assert(available_queries > 0);
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-dxmt-pressure-') as directory:
    temp = Path(directory)
    (temp / 'winemetal.h').write_text('#pragma once\n#include <stdint.h>\n' + abi + '\nvoid MadeiraCtl(struct madeira_ctl_args *);\n')
    (temp / 'mach').mkdir()
    (temp / 'mach/mach.h').write_text('''#pragma once
#include <stdint.h>
typedef struct { uint64_t phys_footprint; } task_vm_info_data_t;
typedef unsigned mach_msg_type_number_t;
typedef int *task_info_t;
#define TASK_VM_INFO_COUNT 42
#define TASK_VM_INFO_REV1_COUNT 12
#define TASK_VM_INFO 22
#define KERN_SUCCESS 0
int mach_task_self(void);
int task_info(int, int, task_info_t, mach_msg_type_number_t *);
''')
    (temp / 'os').mkdir()
    (temp / 'os/proc.h').write_text('#pragma once\n#include <stddef.h>\nsize_t os_proc_available_memory(void);\n')
    (temp / 'sys').mkdir()
    (temp / 'sys/sysctl.h').write_text('#pragma once\n#include <stddef.h>\nint sysctlbyname(const char *, void *, size_t *, void *, size_t);\n')
    for name, code, compiler, standard in (
        ('policy', CPP, os.environ.get('CXX', 'c++'), '-std=c++17'),
        ('native', NATIVE, os.environ.get('CC', 'cc'), '-std=c11'),
    ):
        source = temp / (name + ('.cpp' if name == 'policy' else '.c'))
        source.write_text(code)
        executable = temp / name
        subprocess.run([compiler, standard, '-O1', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                        '-I', str(temp), '-I', str(ROOT / 'build/dxmt-ios'), str(source), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, timeout=30)
        if name == 'native':
            assert b'madeira-memory-pressure-v1' in executable.read_bytes()
    source = temp / 'native-input.c'
    source.write_bytes(original)
    output = temp / 'staged/winemetal_unix.c'
    subprocess.run(['python3', str(ROOT / 'tools/build/stage-dxmt-memory-pressure.py'),
                    '--source', str(source), '--output', str(output),
                    '--headers', str(ROOT / 'build/dxmt-ios')], check=True)
    assert output.read_text() == staged
    assert (output.parent / 'memory_pressure_native.h').read_bytes() == (ROOT / 'build/dxmt-ios/memory_pressure_native.h').read_bytes()
    assert hashlib.sha256(native_source.read_bytes()).digest() == hashlib.sha256(original).digest()
print('PASS actual pressure policy/native helper: measured 6144MiB, valid zero headroom, unknown/sentinels/overflow, errno, concurrent 100ms cache; native op40/WoW64 staged without altering op7/vendor input. iPhone allocations and map loading remain unverified.')
