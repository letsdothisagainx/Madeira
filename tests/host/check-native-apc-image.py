#!/usr/bin/env python3
"""Check exact-image native fault inspection with file/VM offsets that differ."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import uuid

root = Path(__file__).resolve().parents[2]
tool = root / 'tools/inspect-native-apc.py'
spec = importlib.util.spec_from_file_location('native_apc', tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix='madeira-native-apc-') as temp:
    path = Path(temp) / 'image'
    base, fileoff, symbol = 0x100000000, 0x1000, 0x100000080
    identity = uuid.UUID('C785040B-848D-37AD-985C-832B8923F782')
    data = bytearray(0x2000)
    struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x0100000c, 0, 6, 3, 120, 0, 0)
    struct.pack_into('<II16s4Q4I', data, 32, 0x19, 72, b'__TEXT', base, 0x800,
                     fileoff, 0x800, 5, 5, 0, 0)
    struct.pack_into('<II16s', data, 104, 0x1b, 24, identity.bytes)
    strings = b'\0_invoke_system_apc\0'
    struct.pack_into('<6I', data, 128, 2, 24, 0x1800, 1, 0x1810, len(strings))
    struct.pack_into('<IBBHQ', data, 0x1800, 1, 0x0e, 1, 0, symbol)
    data[0x1810:0x1810 + len(strings)] = strings
    for offset in range(0x800 // 4):
        struct.pack_into('<I', data, fileoff + offset * 4, 0xd503201f)  # nop
    struct.pack_into('<I', data, fileoff + symbol - base + 0x578, 0xb9000408)
    struct.pack_into('<I', data, fileoff + symbol - base + 0x564, 0xffffffff)  # unknown instruction
    path.write_bytes(data)
    actual, lines = module.inspect(path, 0x578)
    assert actual == str(identity).upper()
    target = [line for line in lines if 'FAULT-OFFSET' in line]
    assert len(target) == 1 and 'str w8, [x0, #4]' in target[0], target
    assert any('+0564 ffffffff .inst 0xffffffff' in line for line in lines)
    result = subprocess.run([sys.executable, str(tool), str(path), '--expected-uuid',
                             '00000000-0000-0000-0000-000000000000'],
                            env=os.environ, capture_output=True, text=True)
    assert result.returncode and 'UUID does not match' in result.stderr
    try:
        module.inspect(path, 0x10000)
        raise AssertionError('unbacked fault range accepted')
    except ValueError:
        pass
    struct.pack_into('<I', data, 4, 0x01000007)
    path.write_bytes(data)
    try:
        module.inspect(path, 0x578)
        raise AssertionError('wrong architecture accepted')
    except ValueError:
        pass
print('PASS: file offsets, exact native symbol, fault instruction, UUID mismatch and unbacked range')
