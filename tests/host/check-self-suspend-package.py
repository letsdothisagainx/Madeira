#!/usr/bin/env python3
"""Exercise the actual packaging gate with explicitly non-executable fixtures."""
from pathlib import Path
import importlib.util
import io
import struct
import tempfile
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('self_suspend_package', ROOT / 'tools/check-self-suspend-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
HEADER = struct.pack('<II', 0xfeedfacf, 0x100000c)
IMAGE = HEADER + b'non-executable-marker-fixture\0' + b'\0'.join(package.MARKERS)


def rejected(action):
    try:
        action()
    except AssertionError:
        return
    raise AssertionError('invalid self-suspend package passed the real gate')


class BoundedReader(io.BytesIO):
    def read(self, count=-1):
        assert 0 < count <= package.BLOCK, 'unbounded native image read'
        return super().read(count)


with tempfile.TemporaryDirectory(prefix='madeira-self-suspend-package-') as temporary:
    root = Path(temporary)
    native, ipa = root / 'Madeira.debug.dylib', root / 'Madeira.ipa'

    def archive(*entries):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(ipa, 'w', compression=zipfile.ZIP_DEFLATED) as output:
                for name, data in entries:
                    output.writestr(name, data)

    native.write_bytes(IMAGE)
    archive((package.ENTRY, IMAGE))
    package.check(native, ipa)
    package.check(native=native)
    package.check(ipa=ipa)
    for marker in package.MARKERS:
        stale = IMAGE.replace(marker, b'old-contract')
        native.write_bytes(stale)
        rejected(lambda: package.check(native=native))
        archive((package.ENTRY, stale))
        rejected(lambda: package.check(ipa=ipa))
    native.write_bytes(IMAGE)
    for entries in [(), (('Payload/Madeira.app/other', IMAGE),),
                    ((package.ENTRY, IMAGE), (package.ENTRY, IMAGE)),
                    ((package.ENTRY, b''),), ((package.ENTRY, HEADER[:7]),),
                    ((package.ENTRY, IMAGE[:-1]),)]:
        archive(*entries)
        rejected(lambda: package.check(native, ipa))
    archive((package.ENTRY, IMAGE + b'different-copy'))
    rejected(lambda: package.check(native, ipa))
    archive((package.ENTRY, IMAGE))
    ipa.write_bytes(ipa.read_bytes()[:-17])
    rejected(lambda: package.check(ipa=ipa))
    native.write_bytes(struct.pack('<II', 0xfeedfacf, 0x1000007) + IMAGE[8:])
    rejected(lambda: package.check(native=native))
    real = root / 'real'
    real.write_bytes(IMAGE)
    native.unlink()
    native.symlink_to(real)
    rejected(lambda: package.check(native=native))
    native.unlink()
    boundary = bytearray(HEADER)
    boundary.extend(b'x' * (package.BLOCK - 7 - len(boundary)))
    boundary.extend(package.MARKERS[0])
    boundary.extend(b'y' * (2 * package.BLOCK - 5 - len(boundary)))
    boundary.extend(package.MARKERS[1])
    for marker in package.MARKERS[2:]:
        boundary.extend(marker)
    measured = package.scan(BoundedReader(boundary))
    assert measured[0] == len(boundary)
    native.write_bytes(boundary)
    archive((package.ENTRY, boundary))
    package.check(native, ipa)
    rejected(lambda: package.scan(BoundedReader(b'')))
    rejected(lambda: package.check())
print('PASS actual self-suspend package gate: stale producer/observer, missing/duplicate/empty/truncated '
      'IPA entry, wrong CPU, symlink and divergent copy rejected; bounded cross-block scanning passed. '
      'Fixtures provide no executable or iPhone result.')
