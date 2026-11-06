#!/usr/bin/env python3
"""Execute the production native-atomic plan against real Darwin RX/RW aliases.

Apple ARM64 measures actual Mach write exceptions before the fresh-image plan,
then executes its rewritten ADRP without exceptions. The baseline uses the
production LSE helper and retained-load exclusive-store decoder, not a model.
Other hosts explicitly skip the hardware benchmark; portable planner coverage
lives in check-native-atomic-alias.py.
"""
from pathlib import Path
import argparse
import os
import platform
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-arm64-darwin', action='store_true')
args = parser.parse_args()
if platform.system() != 'Darwin' or platform.machine().lower() not in ('arm64', 'aarch64'):
    if args.require_arm64_darwin:
        raise SystemExit('FAIL: this gate requires actual Apple ARM64 Mach exceptions')
    print('SKIP native atomic throughput: actual Apple ARM64/Mach execution required')
    raise SystemExit(0)

source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
first = source.index('#define IOS_MACH_RMW(type)')
last = source.index('#undef IOS_MACH_RMW', first) + len('#undef IOS_MACH_RMW')
helper = source[first:last] + '\n'
first = source.index('                    else if ((insn & 0x3fe07c00) == 0x08007c00)')
last = source.index('                    /* iOS-Madeira ml626: SWP', first)
exclusive = source[first:last].replace('else if', 'if', 1)

with tempfile.TemporaryDirectory(prefix='madeira-native-atomic-') as tmp:
    work = Path(tmp)
    (work / 'production-atomic-emulation.h').write_text(helper + r'''
static int baseline_emulate(uint32_t insn, uintptr_t fault_pc, uintptr_t fault_addr,
                            uintptr_t rw_addr, arm_thread_state64_t *input)
{
    arm_thread_state64_t state = *input;
    uint64_t gpr[32];
    int emulated = 0;
    memcpy(gpr, state.__x, sizeof(state.__x));
    gpr[29] = state.__fp; gpr[30] = state.__lr; gpr[31] = state.__sp;
    if (ios_mach_emulate_rmw(insn, rw_addr, gpr)) {
        memcpy(state.__x, gpr, sizeof(state.__x));
        state.__fp = gpr[29]; state.__lr = gpr[30];
        *input = state;
        return 1;
    }
#define IOS_STORE_SRC(r) ((r) == 31 ? 0ULL : state.__x[r])
''' + exclusive + r'''
#undef IOS_STORE_SRC
    *input = state;
    return emulated;
}
''')
    cc = os.environ.get('CC', 'clang')
    binary = work / 'native-atomic-throughput'
    subprocess.run([cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                    '-I', str(work), '-I', str(root / 'build/ntdll-unix'),
                    str(root / 'tests/host/native-atomic-alias-performance.c'),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=60)
