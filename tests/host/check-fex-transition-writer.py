#!/usr/bin/env python3
"""Stage the real transition assembly and attest its ARM64EC COFF consumers."""
import argparse
from collections import Counter
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--toolchain', type=Path)
parser.add_argument('--require-arm64-coff', action='store_true')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('transition_stage', ROOT / 'tools/build/stage-fex-compat.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def coff(path):
    data = path.read_bytes()
    machine, sections, _, symbols, count, optional, _ = struct.unpack_from('<HHIIIHH', data)
    assert machine == 0xa641 and not optional, 'expected actual ARM64EC COFF'
    strings = symbols + count * 18
    names = {}
    at = 0
    while at < count:
        start = symbols + at * 18
        raw = data[start:start + 8]
        if raw[:4] == bytes(4):
            offset = strings + struct.unpack_from('<I', raw, 4)[0]
            name = data[offset:data.index(0, offset)].decode()
        else:
            name = raw.rstrip(b'\0').decode()
        names[at] = name
        at += 1 + data[start + 17]
    for index in range(sections):
        section = 20 + index * 40
        if data[section:section + 8].rstrip(b'\0') != b'.text':
            continue
        size, raw, relocations = struct.unpack_from('<III', data, section + 16)
        number = struct.unpack_from('<H', data, section + 32)[0]
        text = data[raw:raw + size]
        relocs = {}
        for at in range(relocations, relocations + 10 * number, 10):
            offset, symbol, kind = struct.unpack_from('<IIH', data, at)
            relocs[offset] = (names[symbol], kind)
        return struct.unpack('<' + 'I' * (len(text) // 4), text), relocs
    raise AssertionError('missing native .text')


with tempfile.TemporaryDirectory(prefix='madeira-transition-writer-') as directory:
    work = Path(directory)
    name = 'Source/Windows/ARM64EC/Module.S'
    original = (ROOT / 'FEX' / name).read_bytes()
    stage.stage(work / 'stage', ROOT / 'FEX', 'arm64ec')
    staged = (work / 'stage' / name).read_text()
    assert (ROOT / 'FEX' / name).read_bytes() == original
    assert name in stage.files_for('arm64ec')
    assert staged.count('  IOS_XP_WRITER ') == 3
    assert staged.count('  adrp \\reg, IosXpFex') == 1
    assert '  ldar \\reg, [\\reg]\n  cbnz \\reg, .Lmadeira_xp_ready\\@' in staged
    old = original.decode()
    for instruction in ('stadd x4, [x17]', 'ldadd x4, x23, [x17]',
                        'str x9, [x17, x23, lsl #3]', 'stadd \\b, [\\a]'):
        assert staged.count(instruction) == old.count(instruction), instruction
    contract = (work / 'stage/Source/Windows/ARM64EC/Module.cpp').read_text()
    assert 'MadeiraFEXTransitionTag, sizeof(IosXpFex), 64, IosXpFex, 0' in contract
    assert 'static_assert(sizeof(IosXpFex) == 35968)' in contract

    candidates = []
    if args.toolchain:
        candidates.append(args.toolchain / 'bin/arm64ec-w64-mingw32-clang')
    found = shutil.which('arm64ec-w64-mingw32-clang')
    if found:
        candidates.append(Path(found))
    candidates.extend(ROOT.glob('toolchains/llvm-mingw-*/bin/arm64ec-w64-mingw32-clang'))
    compiler = next((path for path in candidates if os.access(path, os.X_OK)), None)
    if not compiler:
        assert not args.require_arm64_coff, 'actual ARM64EC LLVM-MinGW compiler required'
        print('PASS staged transition source/descriptor: all atomics and payload layout preserved; SKIP actual COFF compilation (LLVM-MinGW unavailable)')
    else:
        for label, source in [('original', ROOT / 'FEX' / name), ('writer', work / 'stage' / name)]:
            result = subprocess.run([str(compiler), '-DFEX_IOS_HOST', '-c', str(source), '-o', str(work / (label + '.obj'))], capture_output=True, text=True)
            assert result.returncode == 0, result.stdout + result.stderr
        before, _ = coff(work / 'original.obj')
        after, relocations = coff(work / 'writer.obj')
        stencil = (0x90000010, 0x91000210, 0x91006210, 0xc8dffe10, 0xb5000070, 0x90000010, 0x91000210)
        sites = [index for index in range(len(after) - 6) if after[index:index + 7] == stencil]
        assert len(sites) == 4, 'all four actual native consumers must use the private writer'
        for index in sites:
            for offset, symbol, kind in [(0, 'MadeiraFEXTransitionWriteContract', 4),
                                         (4, 'MadeiraFEXTransitionWriteContract', 6),
                                         (20, 'IosXpFex', 4), (24, 'IosXpFex', 6)]:
                assert relocations[index * 4 + offset] == (symbol, kind)
        # These are the real emitted probe writes. Their atomic width/order,
        # sources, destination registers and dynamic ring indexing stay exact.
        for opcode in (0xf831021f, 0xf824023f, 0xf8240237, 0xf8377a29):
            assert Counter(before)[opcode] == Counter(after)[opcode] > 0, hex(opcode)
        print('PASS actual staged ARM64EC COFF: four relocated LDAR writer/null-fallback consumers; native STADD/LDADD and indexed ring stores unchanged')
