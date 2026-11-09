#!/usr/bin/env python3
"""Measure the actual source-built SRW history producer on Apple ARM64.

The baseline completes real protected-alias faults with extracted production
store/atomic emulation. The bound phase runs the same history increment and
stores via the production unpublished-copy writer contract. Mapping/TEB/code
identity plumbing is a controlled fixture; no Windows lock is bypassed.
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
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-arm64-darwin', action='store_true')
args = parser.parse_args()
if platform.system() != 'Darwin' or platform.machine().lower() not in ('arm64', 'aarch64'):
    if args.require_arm64_darwin:
        raise SystemExit('FAIL SRW history benchmark requires real Apple ARM64/Mach')
    print('SKIP SRW history benchmark: actual Apple ARM64/Mach execution required')
    raise SystemExit(0)

spec = importlib.util.spec_from_file_location('srw_source_fixture', ROOT / 'tests/host/check-native-srw-history.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
source = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(name):
    match = re.search(r'(?m)^static (?:int|uintptr_t) ' + name + r'\(', source)
    assert match, name
    return source[match.start():source.index('\n}', match.start()) + 2] + '\n'


def case(pattern):
    start = source.index(pattern)
    brace = source.index('{', start)
    end = brace + 1
    depth = 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[start:end].replace('else if', 'if', 1)


first = source.index('#define IOS_MACH_RMW(type)')
last = source.index('#undef IOS_MACH_RMW', first) + len('#undef IOS_MACH_RMW')
helpers = source[first:last] + '\n' + function('ios_alias_write') + function('ios_alias_store_immediate') + function('ios_alias_store_pair')
patterns = [
    '                    else if ((insn & 0x3fe07c00) == 0x08007c00)',
    '                    else if ((insn & 0xffc00000) == 0xf9000000)',
    '                    else if ((insn & 0xffc00000) == 0xb9000000)',
    '                    else if ((insn & 0xffe00c00) == 0xf8200800)',
    '                    else if ((insn & 0xffe00c00) == 0xb8200800)',
    '                    else if ((insn & 0x3fe00000u) == 0x38000000u && ((insn >> 10) & 3) != 2)',
    '                    else if ((insn & 0x7e400000u) == 0x28000000u)',
    '                    else if ((insn & 0xfffffc00) == 0xc89ffc00)',
    '                    else if ((insn & 0xfffffc00) == 0x889ffc00)',
]
cases = [case(pattern) for pattern in patterns]
with tempfile.TemporaryDirectory(prefix='madeira-native-srw-mach-') as folder:
    work = Path(folder)
    fixture.write_headers(work)
    (work / 'production-atomic-emulation.h').write_text(helpers + r'''
static int baseline_emulate(uint32_t insn,uintptr_t fault_pc,uintptr_t fault_addr,
                            uintptr_t rw_addr,arm_thread_state64_t *input)
{
    arm_thread_state64_t state=*input;
    uint64_t gpr[32];uintptr_t alias_fault=0;int emulated=0,honor_guest_prot=1;
    memcpy(gpr,state.__x,sizeof(state.__x));gpr[29]=state.__fp;gpr[30]=state.__lr;gpr[31]=state.__sp;
    if(ios_mach_emulate_rmw(insn,rw_addr,gpr)){
        memcpy(state.__x,gpr,sizeof(state.__x));state.__fp=gpr[29];state.__lr=gpr[30];*input=state;return 1;
    }
#define IOS_STORE_SRC(r) ((r)==31?0ULL:state.__x[r])
''' + cases[0] + '\n' + '\n'.join(block.replace('if (', 'else if (', 1) for block in cases[1:]) + r'''
#undef IOS_STORE_SRC
    *input=state;return emulated;
}
''')
    binary = work / 'srw-history-throughput'
    # Match the captured Wine LL/SC producer rather than benchmarking Apple's
    # default LSE lowering. Assert the actual generated bodies, not CPU names.
    compiler = [os.environ.get('CC', 'clang'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                '-Wno-unused-function', '-mcpu=generic', '-march=armv8-a', '-mno-outline-atomics',
                '-I', str(work), '-I', str(ROOT / 'build/ntdll-unix'), '-I', str(ROOT / 'tests/host')]
    source_path = str(ROOT / 'tests/host/native-srw-history-performance.c')
    assembly_path = work / 'srw-history.s'
    subprocess.run(compiler + ['-S', source_path, '-o', str(assembly_path)], check=True)
    assembly = assembly_path.read_text()
    bodies = {}
    for name in ('srw_note_original', 'srw_note_bound'):
        label = re.search(r'(?m)^_' + name + r':[^\n]*\n', assembly)
        assert label, 'actual source producer function must remain callable'
        end = re.search(r'(?m)^\s*\.cfi_endproc\b|^Lfunc_end[0-9]+:', assembly[label.end():])
        assert end, 'bounded native producer assembly required'
        body = assembly[label.end():label.end()+end.start()]
        bodies[name] = body
    try:
        for name, body in bodies.items():
            load = re.search(r'\bldaxr\s+w([0-9]+),\s*\[x([0-9]+)\]', body)
            assert load, name + ' must execute the captured 32-bit acquire-exclusive load'
            store = re.search(r'\bstlxr\s+w([0-9]+),\s*w[0-9]+,\s*\[x' + load[2] + r'\]', body)
            assert store and re.search(r'\bcbnz\s+w' + store[1] + r',', body), name + ' must retain real 32-bit exclusive status/retry'
            assert re.search(r'\bstr\s+x[0-9]+,\s*\[x[0-9]+', body), name + ' must retain its pointer history store'
            assert re.search(r'\bstr\s+w[0-9]+,\s*\[x[0-9]+,\s*#8\]', body), name + ' must retain its tid/mode history store'
            assert not re.search(r'\b(?:ldadd|swp|cas)[a-z]*\s', body), 'captured-family benchmark must not use LSE instead'
    except AssertionError:
        # Preserve the actual compiler output before changing any contract.
        # The CI upload step retains this full assembly; stdout stays bounded.
        diagnostics = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())) / 'madeira-srw-history-diagnostics'
        diagnostics.mkdir(parents=True, exist_ok=True)
        (diagnostics / 'srw-history.s').write_text(assembly)
        for name, body in bodies.items():
            print('SRW_ACTUAL_ASSEMBLY_BEGIN ' + name, flush=True)
            for line in body.splitlines()[:48]:
                print(line, flush=True)
            print('SRW_ACTUAL_ASSEMBLY_END ' + name, flush=True)
        raise
    print('PASS actual source SRW assembly: old and bound native bodies retain LDAXR W/STLXR W/CBNZ retry and both GPR history stores')
    subprocess.run(compiler + [source_path, '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=90)
