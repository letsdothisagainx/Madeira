#!/usr/bin/env python3
"""Exercise the actual topology package gate with non-executable fixtures."""
from pathlib import Path
import importlib.util
import io
import struct
import tempfile
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('apple_topology_package', ROOT / 'tools/check-apple-cpu-topology-package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
HEADER = struct.pack('<II', 0xfeedfacf, 0x100000c)
IMAGE = HEADER + b'non-executable-marker-fixture\0' + b'\0'.join(package.MARKERS)


def rejected(action):
    try:
        action()
    except AssertionError:
        return
    raise AssertionError('invalid topology package passed the real gate')


class BoundedReader(io.BytesIO):
    def read(self, count=-1):
        assert 0 < count <= package.BLOCK, 'unbounded native image read'
        return super().read(count)


with tempfile.TemporaryDirectory(prefix='madeira-topology-package-') as temporary:
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
    stale = IMAGE.replace(package.MARKERS[0], b'old-topology-contract')
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
    boundary = HEADER + b'x' * (package.BLOCK - 7 - len(HEADER)) + package.MARKERS[0]
    measured = package.scan(BoundedReader(boundary))
    assert measured[0] == len(boundary)
    native.write_bytes(boundary)
    archive((package.ENTRY, boundary))
    package.check(native, ipa)
    rejected(lambda: package.scan(BoundedReader(b'')))
    rejected(lambda: package.check())

# Native Unix is rebuilt on every real app build; its inputs intentionally do
# not invalidate the independent Windows/LLVM/FEX component caches. The whole
# IPA key includes the complete source tree. Cached IPA gates need a checkout
# before they can run current source tools on a clean worker.
workflow = (ROOT / '.github/workflows/build.yml').read_text()
reuse = workflow.split('\n  reuse:\n', 1)[1].split('\n  llvm:', 1)[0]
assert reuse.index('uses: actions/checkout@v4') < reuse.index('name: Validate cached IPA')
assert 'python3 tools/check-apple-cpu-topology-package.py --ipa dist/Madeira.ipa' in reuse
assert "$(git rev-parse 'HEAD^{tree}')" in workflow
final_job = workflow.split('\n  scm-rpc-abi:\n', 1)[1]
assert 'python3 tools/check-apple-cpu-topology-package.py --ipa scm-ipa/Madeira.ipa' in final_job
entry = (ROOT / 'tools/build-ipa.sh').read_text()
assert entry.index('"$ROOT/build/ntdll-unix/build.sh"') < entry.index('"$ROOT/tools/build/package-ipa.sh"')
script = (ROOT / 'tools/build/package-ipa.sh').read_text()
assert 'python3 "$ROOT/tools/check-apple-cpu-topology-package.py" \\\n  --native "$APP/Madeira.debug.dylib" --ipa "$DIST/Madeira.ipa"' in script
print('PASS actual Apple topology package gate: missing/stale contract, invalid native/IPA and divergent '
      'copies rejected; bounded scan, native rebuild and cached/final IPA source gates covered. '
      'Fixtures provide no executable or iPhone result.')
