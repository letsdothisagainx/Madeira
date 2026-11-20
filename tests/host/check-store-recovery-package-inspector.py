#!/usr/bin/env python3
"""Read non-executable Mach-O fixtures; never execute ARM64 or inject faults."""
import importlib.util
from pathlib import Path
import struct

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('recovery_package', root / 'tools/check-store-recovery-package.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def image(interleaved=True, completion_clock=True):
    vm = 0x100000000
    names = ['_ios_stuck_store_check', '_ios_stuck_store_hot_check',
             '_ios_stuck_store_recovery_poll', '_clock_gettime']
    strings = bytearray(b'\0')
    offsets = []
    for name in names:
        offsets.append(len(strings)); strings.extend(name.encode() + b'\0')
    section = lambda name, addr, size, offset, flags=0, r1=0, r2=0: struct.pack(
        '<16s16sQQIIIIIIII', name, b'__TEXT', addr, size, offset, 2, 0, 0, flags, r1, r2, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 232, b'__TEXT', vm, 0x200, 0, 0x400, 5, 5, 2, 0)
    segment += section(b'__text', vm, 0x30, 0x200)
    segment += section(b'__stubs', vm + 0x100, 12, 0x300, 8, 0, 12)
    symtab = struct.pack('<6I', 2, 24, 0x400, 4, 0x440, len(strings))
    dysymtab = [0] * 20
    dysymtab[0:2] = [0xb, 80]; dysymtab[14:16] = [0x500, 1]
    commands = segment + symtab + struct.pack('<20I', *dysymtab)
    data = bytearray(0x504)
    data[:32] = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 3, len(commands), 0, 0)
    data[32:32 + len(commands)] = commands
    for i in range(0, 0x30, 4): struct.pack_into('<I', data, 0x200 + i, 0xd503201f)
    def call(at, target): struct.pack_into('<I', data, 0x200 + at, 0x94000000 | (((target - at) // 4) & 0x3ffffff))
    if interleaved: call(0, 0x10)
    if completion_clock: call(0x20, 0); call(0x24, 0x100)
    else: call(0x20, 0x100); call(0x24, 0)
    for i, at in enumerate((0, 0x10, 0x20, None)):
        struct.pack_into('<IBBHQ', data, 0x400 + i * 16, offsets[i], 0xe if at is not None else 1,
                         1 if at is not None else 0, 0, vm + at if at is not None else 0)
    data[0x440:0x440 + len(strings)] = strings
    struct.pack_into('<I', data, 0x500, 3)
    return bytes(data)


result = module.inspect(image())
assert result['interleavedDiscovery'] and result['postDiscoveryClockFunctions'] == ['_ios_stuck_store_recovery_poll']
for arguments in ((False, True), (True, False)):
    try:
        module.inspect(image(*arguments))
    except ValueError:
        continue
    raise AssertionError('inspector accepted a missing production call path')
print('PASS read-only Mach-O inspector: ARM64 call targets, import stubs, discovery interleaving and post-scan clock order; no code executed')
