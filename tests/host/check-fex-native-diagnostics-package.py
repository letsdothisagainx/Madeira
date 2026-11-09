#!/usr/bin/env python3
"""Exercise the final-package FEX writer gate, including honest BSS payloads."""
from pathlib import Path
import importlib.util
import struct

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


checker = module('madeira_fex_diagnostic_package', ROOT / 'tools/check-io-abi-package.py')
fixtures = module('madeira_fex_diagnostic_fixture', ROOT / 'tests/host/check-fex-subfloor-package.py')
count = 0
for backend in ('wow64', 'arm64ec'):
    original, meta = fixtures.fex_fixture(backend)
    found = checker.fex_diagnostics_contracts(original)
    assert found == meta['diagnostics']
    assert found[b'MadeiraFEXHistoryWriteContract'][2] == 192
    checker.fex_cpu(bytes(original), backend)
    raw, opt = meta['raw'], meta['opt']

    def reject(edit, expected):
        global count
        data = bytearray(original)
        edit(data)
        try:
            checker.fex_diagnostics_contracts(data)
        except (AssertionError, IndexError, struct.error) as error:
            assert expected in str(error), (backend, expected, str(error))
            count += 1
        else:
            raise AssertionError('accepted invalid diagnostics package: ' + expected)

    for name, (contract, payload, length) in found.items():
        at = raw(contract)
        reject(lambda b: struct.pack_into('<Q', b, at, 0), 'differs from source ABI')
        reject(lambda b: struct.pack_into('<I', b, at + 8, length - 1), 'differs from source ABI')
        reject(lambda b: struct.pack_into('<I', b, at + 12, 4), 'differs from source ABI')
        reject(lambda b: struct.pack_into('<Q', b, at + 24, 0x348002300), 'NULL in package')
        reject(lambda b: struct.pack_into('<Q', b, at + 16, 0x1000), 'foreign native diagnostic payload')
        reject(lambda b: struct.pack_into('<Q', b, at + 16, 0x180003000), 'wholly private')
        reject(lambda b: struct.pack_into('<Q', b, at + 16, 0x180002ffc), 'wholly private')
        reject(lambda b: struct.pack_into('<Q', b, at + 16, 0x180000000 + contract), 'spans overlap')
        reject(lambda b: b.__setitem__(meta['strings'][name], ord('x')), 'missing private diagnostic contracts')
        def relocate_writer(b):
            # This fixture has free metadata space; an actual DIR64 over the
            # private writer would undo the loader's unpublished binding.
            struct.pack_into('<II', b, opt + 152, 0x1900, 12)
            struct.pack_into('<IIHH', b, raw(0x1900), contract & ~0xfff, 12,
                             0xa000 | ((contract + 24) & 0xfff), 0)
        reject(relocate_writer, 'loader relocation')
    # Zero-fill payloads are real mapped native DATA. Initialized descriptors
    # retain their full source file bytes, including NULL writer fields.
    bss = bytearray(original)
    struct.pack_into('<I', bss, meta['sections']['.data'] + 16, 0x200)
    for i, (name, (contract, _, length)) in enumerate(found.items()):
        struct.pack_into('<Q', bss, raw(contract) + 16, 0x180002800 + i * 0x100)
    checker.fex_diagnostics_contracts(bss)
    reject(lambda b: struct.pack_into('<I', b, meta['sections']['.data'] + 16, 0x110), 'file-backed')
    reject(lambda b: b.__setitem__(raw(0x17c0), ord('x')), 'foreign native diagnostics module')
    reject(lambda b: struct.pack_into('<I', b, meta['sections']['.data'] + 36, 0xe0000040), 'non-executable RW DATA')

print(f'PASS final-package diagnostic contracts: real ARM64/ARM64EC descriptors and BSS payloads; {count} stale/foreign/modified/relocated/wrong-protection cases rejected')
