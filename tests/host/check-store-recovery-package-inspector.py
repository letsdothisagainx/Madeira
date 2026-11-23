#!/usr/bin/env python3
"""Read non-executable Mach-O fixtures; never execute ARM64 or inject faults."""
import importlib.util
from pathlib import Path
import struct

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('recovery_package', root / 'tools/check-store-recovery-package.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def image(interleaved=True, completion_clock=True, inlined=False):
    vm = 0x100000000
    names = ['_ios_stuck_store_recovery_main' if inlined else '_ios_stuck_store_check', '_ios_stuck_store_hot_check',
             '_ios_stuck_store_recovery_poll', '_clock_gettime', '_task_threads', '_vm_deallocate']
    strings = bytearray(b'\0')
    offsets = []
    for name in names:
        offsets.append(len(strings)); strings.extend(name.encode() + b'\0')
    section = lambda name, addr, size, offset, flags=0, r1=0, r2=0: struct.pack(
        '<16s16sQQIIIIIIII', name, b'__TEXT', addr, size, offset, 2, 0, 0, flags, r1, r2, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 232, b'__TEXT', vm, 0x200, 0, 0x400, 5, 5, 2, 0)
    segment += section(b'__text', vm, 0x60, 0x200)
    segment += section(b'__stubs', vm + 0x100, 36, 0x300, 8, 0, 12)
    symtab = struct.pack('<6I', 2, 24, 0x400, 6, 0x480, len(strings))
    dysymtab = [0] * 20
    dysymtab[0:2] = [0xb, 80]; dysymtab[14:16] = [0x600, 3]
    commands = segment + symtab + struct.pack('<20I', *dysymtab)
    data = bytearray(0x60c)
    data[:32] = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 3, len(commands), 0, 0)
    data[32:32 + len(commands)] = commands
    for i in range(0, 0x60, 4): struct.pack_into('<I', data, 0x200 + i, 0xd503201f)
    def call(at, target): struct.pack_into('<I', data, 0x200 + at, 0x94000000 | (((target - at) // 4) & 0x3ffffff))
    if inlined:
        if completion_clock:
            call(0, 0x10c)
            if interleaved: call(4, 0x40)
            call(8, 0x118); call(12, 0x100)
        else:
            call(0, 0x100); call(4, 0x10c)
            if interleaved: call(8, 0x40)
            call(12, 0x118)
    else:
        if interleaved: call(0, 0x40)
        if completion_clock: call(0x50, 0); call(0x54, 0x100)
        else: call(0x50, 0x100); call(0x54, 0)
    for i, at in enumerate((0, 0x40, 0x50, None, None, None)):
        struct.pack_into('<IBBHQ', data, 0x400 + i * 16, offsets[i], 0xe if at is not None else 1,
                         1 if at is not None else 0, 0, vm + at if at is not None else 0)
    data[0x480:0x480 + len(strings)] = strings
    struct.pack_into('<3I', data, 0x600, 3, 4, 5)
    return bytes(data)


result = module.inspect(image())
assert result['interleavedDiscovery'] and result['postDiscoveryClockFunctions'] == ['_ios_stuck_store_recovery_poll']
assert module.inspect(image(inlined=True))['discoveryInlined']
# Normal non-executable metadata for the newly packaged Run14 callback. The
# inspector proves linkage/markers, not a live pressure event or memory saving.
pressure = bytearray(image(inlined=True))
stroff, strlen = 0x480, struct.unpack_from('<I', pressure, 32 + 232 + 20)[0]
callback = b'_madeira_pressure_boundary_request\0'
struct.pack_into('<I', pressure, 32 + 232 + 12, 7)
struct.pack_into('<I', pressure, 32 + 232 + 20, strlen + len(callback))
struct.pack_into('<IBBHQ', pressure, 0x460, strlen, 0xf, 1, 0, 0x10000005c)
pressure[stroff + strlen:stroff + strlen + len(callback)] = callback
pressure.extend(b'[pressure-boundary-v1]\0[pressure-owner-v1]\0')
assert module.inspect(bytes(pressure), require_pressure_boundary=True)['pressureBoundaryRequired']
# Non-executable metadata also requires the new linked helper and phase markers.
scoped = bytearray(pressure)
name = b'_ios_store_split_crossing_timed\0'
scoped[stroff + strlen:stroff + strlen + len(callback)] = name.ljust(len(callback), b'\0')
scoped.extend(b'[store-recovery-scope-v1] advisory=unheld commit=fresh-held held-qos=user-interactive '
              b'write0-us= write1-us= prepare-read-us= suspend-us= recovery-worker=')
assert module.inspect(bytes(scoped), require_recovery_scope=True)['recoveryScopeRequired']
try:
    module.inspect(image(), require_recovery_scope=True)
except ValueError:
    pass
else:
    raise AssertionError('missing scope producer accepted')
for arguments in ((False, True, False), (True, False, False), (False, True, True), (True, False, True)):
    try:
        module.inspect(image(*arguments))
    except ValueError:
        continue
    raise AssertionError('inspector accepted a missing production call path')
print('PASS read-only Mach-O inspector: ARM64 call targets, import stubs, discovery interleaving and post-scan clock order; no code executed')
