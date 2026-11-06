#!/usr/bin/env python3
"""Execute the shipped DXMT conditional maximum loop through real Mach faults.

The complete captured native instruction sequence executes unchanged. The
production recovery, ownership-generation accessor, alias and host-protection
validators are compiled verbatim. This is a hardware gate, not an exclusive
monitor model; an independent RW writer deterministically forces CAS failure.
"""
from pathlib import Path
import argparse
import os
import platform
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-arm64-darwin', action='store_true')
args = parser.parse_args()
if platform.system() != 'Darwin' or platform.machine().lower() not in ('arm64', 'aarch64'):
    if args.require_arm64_darwin:
        raise SystemExit('FAIL: actual Apple ARM64/Mach execution is required')
    print('SKIP conditional exclusive hardware: actual Apple ARM64/Mach required')
    raise SystemExit(0)

signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
virtual = (root / 'build/ntdll-unix/virtual_ios.c').read_text()


def function(source, name):
    found = re.search(r'(?m)^(?:static )?(?:int|unsigned(?: long long)?|uintptr_t|void \*)\s*'
                      + re.escape(name) + r'\s*\(', source)
    assert found, name
    return source[found.start():source.index('\n}', found.start()) + 2] + '\n'


first = virtual.index('#define IOS_JIT_MAX_MAPPINGS')
last = virtual.index('static int ios_jit_mapping_count = 0;', first)
ledger = virtual[first:last + len('static int ios_jit_mapping_count = 0;')]
first = signal.index('                        /* Advance PC past the emulated instruction */')
pc_advance = signal[first:signal.index('                        static volatile int emul_count', first)]
header = ledger + r'''
void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
static int ios_jit_low_contains(uintptr_t address) { (void)address; return 0; }
uintptr_t ios_jit_anon_alias_lookup(uintptr_t address) { (void)address; return 0; }
int ios_page_expected_prot(const void *address) { (void)address; return -1; }
static void conditional_before_cas(void);
static uint64_t conditional_successes, conditional_conflicts;
'''
for name in ('ios_jit_new_generation', 'ios_jit_code_bounds', 'ios_jit_pool_access_token'):
    header += function(virtual, name)
for name in ('ios_write_alias', 'ios_alias_write_is_trapped', 'ios_alias_exclusive_span',
             'ios_exclusive_code_readable', 'ios_mach_emulate_exclusive_conditional_loop'):
    header += function(signal, name)
header += r'''
static int baseline_emulate(uint32_t insn, uintptr_t fault_pc, uintptr_t fault_addr,
                            uintptr_t rw_addr, arm_thread_state64_t *input)
{
    arm_thread_state64_t state = *input;
    uint64_t gpr[32], original[32];
    uint32_t flags = state.__cpsr;
    unsigned status = (insn >> 16) & 31;
    int handled = 0;
    (void)rw_addr;
    memcpy(gpr, state.__x, sizeof(state.__x));
    gpr[29] = state.__fp; gpr[30] = state.__lr; gpr[31] = state.__sp;
    memcpy(original, gpr, sizeof(gpr));
    conditional_before_cas();
    if (!ios_mach_emulate_exclusive_conditional_loop(insn, fault_pc, fault_addr,
                                                    gpr, flags, &active)) return 0;
    for (unsigned reg = 0; reg < 32; ++reg)
        assert(reg == status ? gpr[reg] <= 1 : gpr[reg] == original[reg]);
    if (gpr[status]) __atomic_add_fetch(&conditional_conflicts, 1, __ATOMIC_RELAXED);
    else __atomic_add_fetch(&conditional_successes, 1, __ATOMIC_RELAXED);
    memcpy(state.__x, gpr, sizeof(state.__x));
    state.__fp = gpr[29]; state.__lr = gpr[30]; state.__sp = gpr[31];
''' + pc_advance + r'''
    assert(handled && arm_thread_state64_get_pc(state) == fault_pc + 4);
    assert(state.__cpsr == flags);
    *input = state;
    return handled;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-conditional-mach-') as folder:
    work = Path(folder)
    (work / 'production-atomic-emulation.h').write_text(header)
    binary = work / 'conditional-mach'
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-pthread', '-I', str(work), '-I', str(root / 'build/ntdll-unix'),
                    str(root / 'tests/host/jit_alias_exclusive_conditional_hardware.c'),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=90)
