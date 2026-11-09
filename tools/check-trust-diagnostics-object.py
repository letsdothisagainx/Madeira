#!/usr/bin/env python3
"""Require the observer's actual native budget code to use supported CAS32."""
import argparse
import importlib.util
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coff_code', ROOT / 'tools/check-fex-subfloor-atomics.py')
coff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coff)
coff.STEMS = coff.REQUIRED = ('madeira_trust_reserve',)


def verify(path):
    functions = coff.controlled_code(Path(path).read_bytes())
    count = 0
    for name, code in functions:
        for (word,) in struct.iter_unpack('<I', code):
            if (word & 0x3fe07c00) == 0x08007c00 or (word & 0xbfe00000) == 0x88200000:
                raise ValueError('unexpected exclusive-store family in trust budget: ' + name)
            if (word & 0x3fa07c00) == 0x08a07c00:
                if word >> 30 != 2 or (word & 0x00408000) != 0x00408000:
                    raise ValueError('trust budget must use 32-bit acquire/release CASAL')
                rs, rt = (word >> 16) & 31, word & 31
                if rs in (29, 30) or rt in (29, 30):
                    raise ValueError('trust CAS requires unsupported FP/LR operand')
                count += 1
    if count != 2:
        raise ValueError('trust budget must contain exactly two ordinary CAS32 instructions')
    print('PASS trust budget native COFF: CASAL32=2, supported registers, exclusive-stores=0')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object', type=Path)
    args = parser.parse_args()
    try:
        verify(args.object)
    except (ValueError, UnicodeError, struct.error, OSError) as error:
        parser.error(str(error))
