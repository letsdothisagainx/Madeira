#!/usr/bin/env python3
"""Execute the actual ARM64EC transition probes with real Apple Mach faults.

Only the assembly's object-format relocations and callable ABI wrapper differ
from Module.S. The copied probe instructions, native atomics, shard selection,
sampling branch and ring store execute unchanged. This focused fixture measures
exception removal; it does not predict game frame rate.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def macro(source, name):
    start = source.index('.macro ' + name + ' ')
    return source[start:source.index('.endm', start) + len('.endm')]


def probes(source):
    start = source.index('ExitFunctionECJit:\n') + len('ExitFunctionECJit:\n')
    lean = source[start:source.index('  ldr x17, [x28, #IOS_FRAME_CPU_AREA]', start)]
    start = source.index('  // ml1131: count this x64->EC call')
    start = source.index('\n', source.index('  // call boundary)', start)) + 1
    full = source[start:source.index('  IOS_LOAD_TEB x17', start)]
    return lean, full


def function(source, signature):
    start = source.index(signature)
    body = source.index('{', start)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def boundary_regression(work):
    """Run the actual fixture adapter and production span writer on any host."""
    fixture = (ROOT / 'tests/host/native-fex-transition-writer-performance.c').read_text()
    atomic = (ROOT / 'tests/host/native-atomic-alias-performance.c').read_text()
    production = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
    adapter = function(fixture, 'static uintptr_t ios_write_alias(uintptr_t address)\n')
    source = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
enum { FEX_DIAG_TRANSITION=0x8000,TRANSITION_BYTES=35968,IMAGE_BYTES=0x20000 };
static struct {unsigned char *rx,*rw;} active;
static unsigned transition_operation,transition_mode;
static _Alignas(8) unsigned char canonical[IMAGE_BYTES],writable[IMAGE_BYTES];
/* This fixture contains native DATA only, outside all private code guards. */
static int ios_jit_code_guard_contains(uintptr_t address,size_t length)
{(void)address;(void)length;return 0;}
static int quiet_dprintf(int fd,const char *format,...)
{(void)fd;(void)format;return 0;}
#define dprintf quiet_dprintf
'''
    source += function(atomic, 'static int inside(') + '\n' + adapter + '\n'
    source += function(fixture, 'static int ios_alias_write_is_trapped(uintptr_t address){') + '\n'
    source += function(production, 'static int ios_alias_write( uintptr_t addr,') + '\n'
    source += function(fixture, 'static void transition_require(') + '\n'
    source += function(fixture, 'static void transition_boundary_checks(void)') + '\n'
    source += r'''
int main(void)
{
    struct rlimit core={0,0};assert(!setrlimit(RLIMIT_CORE,&core));
    memset(canonical,0xa5,sizeof(canonical));memset(writable,0xa5,sizeof(writable));
    active.rx=canonical;active.rw=writable;transition_boundary_checks();
    for(size_t i=0;i<IMAGE_BYTES;i++)assert(canonical[i]==0xa5&&writable[i]==0xa5);
    puts("PASS actual transition adapter and production span writer: last eight-byte ring slot and byte accepted; one-past and crossing-end writes refused without mutation");
}
'''
    cc = os.environ.get('CC', 'cc')
    flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    path, binary = work / 'transition-boundary.c', work / 'transition-boundary'
    path.write_text(source)
    subprocess.run([cc, *flags, str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    # Demonstrate that this portable gate detects the exact adapter regression
    # which previously prevented the Apple fixture reaching its measurements.
    legacy = adapter.replace('inside(address,1,', 'inside(address,8,')
    assert legacy != adapter
    path.write_text(source.replace(adapter, legacy, 1))
    subprocess.run([cc, *flags, str(path), '-o', str(binary)], check=True)
    failed = subprocess.run([str(binary)], capture_output=True, text=True)
    assert failed.returncode != 0 and 'last payload byte alias' in failed.stderr
    print('PASS transition boundary negative control rejects the former eight-byte endpoint lookup', flush=True)


def prepare(work):
    stage = load(ROOT / 'tools/build/stage-fex-compat.py', 'transition_stage')
    staged = work / 'staged'
    stage.stage(staged, ROOT / 'FEX', 'arm64ec')
    relative = 'Source/Windows/ARM64EC/Module.S'
    old = (ROOT / 'FEX' / relative).read_text()
    new = (staged / relative).read_text()
    old_count, count = macro(old, 'IOS_XP_COUNT'), macro(new, 'IOS_XP_COUNT')
    writer = macro(new, 'IOS_XP_WRITER')
    canonical = '  adrp \\a, IosXpFex\n  add \\a, \\a, #:lo12:IosXpFex'
    assert count.replace('  IOS_XP_WRITER \\a', canonical) == old_count
    old_probes, new_probes = probes(old), probes(new)
    canonical = '  adrp x16, IosXpFex\n  add x16, x16, #:lo12:IosXpFex'
    for before, after in zip(old_probes, new_probes):
        assert after.replace('  IOS_XP_WRITER x16', canonical) == before
    assert '  ldar \\reg, [\\reg]\n  cbnz \\reg,' in writer
    assert 'MadeiraFEXTransitionWriteContract' in writer and '  add \\reg, \\reg, #24' in writer
    assert new_probes[0].count('stadd x4, [x17]') == 1
    assert new_probes[0].count('ldadd x4, x23, [x17]') == 1
    assert new_probes[1].count('ldadd x4, x23, [x17]') == 2
    for probe in new_probes:
        assert 'str x9, [x17, x23, lsl #3]' in probe
        assert 'and x23, x23, #4095' in probe
    cpp = (staged / 'Source/Windows/ARM64EC/Module.cpp').read_text()
    assert 'static_assert(sizeof(IosXpFex) == 35968);' in cpp
    assert 'MadeiraFEXTransitionTag, sizeof(IosXpFex), 64, IosXpFex, 0' in cpp

    def macho(text):
        # Mach-O spells the same ADRP/ADD relocations differently. These local
        # labels occupy the exact contract/payload offsets in the copied image.
        text = text.replace('MadeiraFEXTransitionWriteContract', 'Ltransition_contract')
        text = text.replace('IosXpFex', 'Ltransition_payload')
        text = re.sub(r'(adrp\s+[^,]+,\s*)(Ltransition_\w+)', r'\1\2@PAGE', text)
        return re.sub(r'#:lo12:(Ltransition_\w+)', r'\1@PAGEOFF', text)

    source = '.text\n.p2align 14\n.globl _madeira_transition_template\n_madeira_transition_template:\n'
    source += '#define IOS_FRAME_XP_COUNT 4088\n.arch_extension lse\n'
    source += macho(old_count.replace('IOS_XP_COUNT', 'IOS_XP_COUNT_OLD')) + '\n'
    source += macho(writer) + '\n' + macho(count) + '\n'
    for operation in range(4):
        for bound in range(2):
            offset = 0x2000 + (operation * 2 + bound) * 0x100
            name = 'Ltransition_probe_' + str(operation) + '_' + str(bound)
            source += f'.space {offset} - (. - _madeira_transition_template)\n{name}:\n'
            source += '  stp x23, x28, [sp, #-32]!\n  stp x29, x30, [sp, #16]\n'
            source += '  mov x28, x0\n  mov x9, x1\n  msr nzcv, x2\n'
            if operation < 2:
                source += f'  IOS_XP_COUNT{"" if bound else "_OLD"} {1088 if operation == 0 else 2112}, x16, x23\n'
            else:
                source += macho((new_probes if bound else old_probes)[operation - 2])
            source += '  mov x0, sp\n  ubfx x0, x0, #16, #4\n  mrs x3, nzcv\n  orr x0, x0, x3\n'
            source += '  ldp x29, x30, [sp, #16]\n  ldp x23, x28, [sp], #32\n  ret\n'
    source += '.space 0x5100 - (. - _madeira_transition_template)\nLtransition_contract:\n.space 32\n'
    source += '.space 0x8000 - (. - _madeira_transition_template)\nLtransition_payload:\n'
    source += '.space 0x20000 - (. - _madeira_transition_template)\n'
    (work / 'production-fex-transition.S').write_text(source)
    existing = load(ROOT / 'tests/host/check-fex-native-diagnostics-performance.py', 'transition_emulation')
    existing.emulation_header(work)
    existing.prepare(work / 'diagnostic-fixture')
    fixture = (work / 'diagnostic-fixture/production-fex-diagnostics-fixture.h').read_text()
    # The transition template has a larger image and a complete transition
    # payload; share the production-binder PE fixture used by diagnostic tests.
    assert 'FEX_DIAG_TRANSITION=0x8000' in fixture
    (work / 'production-fex-diagnostics-fixture.h').write_text(fixture)
    print('PASS actual staged transition writer: all counter/ring probe statements and native atomics preserved', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-arm64-darwin', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='madeira-fex-transition-mach-') as folder:
        work = Path(folder)
        prepare(work)
        boundary_regression(work)
        if platform.system() != 'Darwin' or platform.machine().lower() not in ('arm64', 'aarch64'):
            if args.require_arm64_darwin:
                raise SystemExit('FAIL FEX transition benchmark requires real Apple ARM64/Mach')
            print('SKIP FEX transition benchmark: actual Apple ARM64/Mach execution required')
            return
        flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-pthread',
                 '-mcpu=generic', '-march=armv8-a', '-mno-outline-atomics',
                 '-I', str(work), '-I', str(ROOT / 'build/ntdll-unix'), '-I', str(ROOT / 'tests/host')]
        cc = os.environ.get('CC', 'clang')
        assembly = work / 'transition.o'
        subprocess.run([cc, *flags, '-c', str(work / 'production-fex-transition.S'), '-o', str(assembly)], check=True)
        binary = work / 'fex-transition-throughput'
        subprocess.run([cc, '-std=c11', *flags, str(ROOT / 'tests/host/native-fex-transition-writer-performance.c'),
                        str(assembly), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=90)


if __name__ == '__main__':
    main()
