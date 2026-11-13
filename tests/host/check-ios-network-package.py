#!/usr/bin/env python3
"""Exercise the real networking packaging gate with non-executable fixtures."""
from pathlib import Path
import importlib.util
import struct
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('network_package', ROOT / 'tools/check-ios-network-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

with tempfile.TemporaryDirectory(prefix='madeira-network-package-') as temporary:
    root = Path(temporary)
    native = root / 'Madeira.debug.dylib'
    ipa = root / 'Madeira.ipa'
    original = struct.pack('<II', 0xfeedfacf, 0x100000c) + b'fixture-not-executable\0' + b'\0'.join(package.MARKERS)
    native.write_bytes(original)
    with zipfile.ZipFile(ipa, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(package.ENTRY, original)
    package.check(native, ipa)
    def rejected():
        try:
            package.check(native, ipa)
        except AssertionError:
            return
        raise AssertionError('stale native fixture passed actual network gate')
    for marker in package.MARKERS:
        native.write_bytes(original.replace(marker, b'old-marker'))
        rejected()
    native.write_bytes(struct.pack('<II', 0xfeedfacf, 0x1000007) + original[8:])
    rejected()
    native.write_bytes(original)
    with zipfile.ZipFile(ipa, 'w') as archive:
        archive.writestr(package.ENTRY, original[:-1] + b'!')
    rejected()
    print('PASS actual network package gate: every stale marker, wrong CPU and divergent ZIP image rejected; fixtures do not execute Wine or prove SDR access')
