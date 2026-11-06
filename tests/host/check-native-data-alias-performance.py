#!/usr/bin/env python3
"""Run the captured recursive RPM guard with the production native-data planner.

The pinned native FEX image supplies every memory operation and branch. Fixture
ADRP relocation points at real owned RX/RW data; two TEB reads instead consume
the normal function argument as a thread identity, because macOS reserves X18.
All store decoding, span validation and base writeback come from production.
Only the fixture's known mapping/protection metadata is adapted. No FEX source
or Valve executable is edited.
"""
from pathlib import Path
import argparse
import hashlib
import os
import platform
import re
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-arm64-darwin', action='store_true')
args = parser.parse_args()
if platform.system() != 'Darwin' or platform.machine().lower() not in ('arm64', 'aarch64'):
    if args.require_arm64_darwin:
        raise SystemExit('FAIL: recursive RPM guard gate requires actual Apple ARM64 Mach exceptions')
    print('SKIP recursive RPM guard throughput: actual Apple ARM64/Mach execution required')
    raise SystemExit(0)

source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(name):
    match = re.search(r'(?m)^static (?:int|uintptr_t) ' + name + r'\(', source)
    assert match, name
    return source[match.start():source.index('\n}', match.start()) + 2] + '\n'


def case(start, end):
    first = source.index(start)
    return source[first:source.index(end, first)].replace('else if', 'if', 1)


first = source.index('#define IOS_MACH_RMW(type)')
last = source.index('#undef IOS_MACH_RMW', first) + len('#undef IOS_MACH_RMW')
helpers = source[first:last] + '\n' + function('ios_alias_write') + function('ios_alias_store_immediate')
exclusive = case('                    else if ((insn & 0x3fe07c00) == 0x08007c00)',
                 '                    /* iOS-Madeira ml626: SWP')
scalar = case('                    else if ((insn & 0xffc00000) == 0xb9000000)',
              '                    /* STRB (immediate, unsigned offset, 8-bit)')
release = case('                    else if ((insn & 0xfffffc00) == 0xc89ffc00)',
               '                    /* STLR (Store-Release Register, 32-bit)')
immediate = case('                    else if ((insn & 0x3fe00000u) == 0x38000000u && ((insn >> 10) & 3) != 2)',
                 '                    /* SIMD/FP STR (immediate, post/pre-index, D-reg')

image = (root / 'app/Madeira/arm64ec-windows/xtajit64.dll').read_bytes()
assert hashlib.sha256(image).hexdigest() == 'cc887fcc717be62d83e835e2b982651a74b2061d0fbddd1a2b828ac89b256ef9'
pe = struct.unpack_from('<I', image, 0x3c)[0]
sections, optional = struct.unpack_from('<H', image, pe + 6)[0], struct.unpack_from('<H', image, pe + 20)[0]


def words(rva, size):
    for index in range(sections):
        offset = pe + 24 + optional + 40 * index
        _, base, length, raw = struct.unpack_from('<IIII', image, offset + 8)
        if base <= rva and rva - base + size <= length:
            return struct.unpack_from('<' + 'I' * (size // 4), image, raw + rva - base)
    raise AssertionError(f'captured native RVA not file backed: {rva:#x}')


with tempfile.TemporaryDirectory(prefix='madeira-native-data-') as tmp:
    work = Path(tmp)
    captured = []
    for name, rva, length in [('lock', 0x154110, 0x80), ('unlock', 0x154194, 0x4c)]:
        values = words(rva, length)
        captured.append(f'static const uint32_t captured_rpm_{name}[] = {{' +
                        ','.join(f'0x{word:08x}u' for word in values) + '};\n')
    (work / 'captured-rpm-functions.h').write_text(''.join(captured))
    (work / 'production-atomic-emulation.h').write_text(helpers + r'''
static int baseline_emulate(uint32_t insn, uintptr_t fault_pc, uintptr_t fault_addr,
                            uintptr_t rw_addr, arm_thread_state64_t *input)
{
    arm_thread_state64_t state = *input;
    uint64_t gpr[32];
    uintptr_t alias_fault = 0;
    int emulated = 0, honor_guest_prot = 1;
    memcpy(gpr, state.__x, sizeof(state.__x));
    gpr[29] = state.__fp; gpr[30] = state.__lr; gpr[31] = state.__sp;
    if (ios_mach_emulate_rmw(insn, rw_addr, gpr)) {
        memcpy(state.__x, gpr, sizeof(state.__x));
        state.__fp = gpr[29]; state.__lr = gpr[30];
        *input = state;
        return 1;
    }
#define IOS_STORE_SRC(r) ((r) == 31 ? 0ULL : state.__x[r])
''' + exclusive + scalar.replace('if (', 'else if (', 1) +
        release.replace('if (', 'else if (', 1) + immediate.replace('if (', 'else if (', 1) + r'''
#undef IOS_STORE_SRC
    *input = state;
    return emulated;
}
''')
    binary = work / 'native-data-throughput'
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                    '-I', str(work), '-I', str(root / 'build/ntdll-unix'),
                    str(root / 'tests/host/native-data-alias-performance.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=60)
