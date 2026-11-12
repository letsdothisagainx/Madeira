#!/usr/bin/env python3
"""Execute the real staging/build transaction with owned compiler adapters.

Source patching, cache invalidation, source restoration and failure propagation
are real. Compiler and package adapters are deliberately not Wine execution.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = (('build-macos', 'aarch64', 'aarch64-windows'),
           ('build-arm64ec', 'arm64ec', 'arm64ec-windows'),
           ('build-i386', 'i686', 'i386-windows'))


def setup(directory):
    root = Path(directory) / 'repo'
    for name in ('build/wine-pe/build-registry-security.sh', 'build/wine-pe/registry-security-views.patch',
                 'build/wine-pe/registry-security-views.json', 'tools/build/stage-registry-security-views.py'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
    source = root / 'wine/dlls/advapi32/security.c'
    source.parent.mkdir(parents=True)
    original = (ROOT / 'wine/dlls/advapi32/security.c').read_bytes()
    source.write_bytes(original)
    (root / 'original').write_bytes(original)
    tools = root / 'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin'
    tools.mkdir(parents=True)
    make = tools / 'make'
    make.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
r=Path(os.environ['ROOT']);build=Path(sys.argv[2]);target=sys.argv[-1];farm=target.split('/')[-2]
assert target=='dlls/advapi32/'+farm+'/advapi32.dll'
source=(r/'wine/dlls/advapi32/security.c').read_text()
assert source.count('case SE_REGISTRY_WOW64_32KEY:')>=2
assert source.count('case SE_REGISTRY_WOW64_64KEY:')>=2
assert 'SetSecurityInfo( handle, SE_REGISTRY_KEY, SecurityInfo' in source
assert 'GetSecurityInfo( handle, SE_REGISTRY_KEY, info' in source
folder=build/'dlls/advapi32'/farm
assert not (folder/'security.o').exists(),'stale object survived'
assert not (folder/'advapi32.dll').exists(),'stale DLL survived'
with (r/'compile.jsonl').open('a') as output:output.write(json.dumps([build.name,farm,target])+'\\n')
if os.environ.get('FAIL_FARM')==farm:raise SystemExit(37)
(folder/'security.o').write_bytes(b'owned fresh object')
(folder/'advapi32.dll').write_bytes(b'owned fresh DLL')
''')
    make.chmod(0o755)
    checker = root / 'tools/check-registry-security-package.py'
    checker.write_text('''import os
from pathlib import Path
r=Path(os.environ['ROOT'])
assert (r/'wine/dlls/advapi32/security.c').read_bytes()==(r/'original').read_bytes(),'checker ran before restoration'
(r/'package-checked').write_text('owned package adapter, real checker tested separately')
''')
    for tree, triple, farm in CONFIGS:
        build = root / 'wine' / tree
        build.mkdir()
        (build / 'Makefile').write_text('# owned make adapter\n')
        folder = build / 'dlls/advapi32' / farm
        folder.mkdir(parents=True)
        for name in ('security.o', 'advapi32.dll'):
            (folder / name).write_bytes(b'stale compiler output')
        target = root / 'app/Madeira' / farm
        target.mkdir(parents=True)
        (target / 'advapi32.dll').write_bytes(b'previous DLL')
        strip = tools / (triple + '-w64-mingw32-strip')
        strip.write_text('''#!/usr/bin/env python3
import shutil,sys
assert sys.argv[1:3]==['--strip-debug','-o']
shutil.copyfile(sys.argv[4],sys.argv[3])
''')
        strip.chmod(0o755)
    return root, original


def run(root, **extra):
    return subprocess.run(['bash', str(root / 'build/wine-pe/build-registry-security.sh')],
                          env=dict(os.environ, ROOT=str(root), JOBS='2', **extra),
                          capture_output=True, text=True, timeout=45)


with tempfile.TemporaryDirectory(prefix='madeira-registry-build-') as directory:
    root, original = setup(directory)
    result = run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / 'wine/dlls/advapi32/security.c').read_bytes() == original
    assert (root / 'package-checked').is_file()
    calls = [json.loads(line) for line in (root / 'compile.jsonl').read_text().splitlines()]
    assert calls == [[tree, farm, 'dlls/advapi32/' + farm + '/advapi32.dll'] for tree, _, farm in CONFIGS]
    for _, _, farm in CONFIGS:
        target = root / 'app/Madeira' / farm
        assert (target / 'advapi32.dll').read_bytes() == b'owned fresh DLL'
        assert not (target / 'advapi32.dll.pending').exists()

for _, _, farm in CONFIGS:
    with tempfile.TemporaryDirectory(prefix='madeira-registry-build-failure-') as directory:
        root, original = setup(directory)
        result = run(root, FAIL_FARM=farm)
        assert result.returncode == 37, result.stdout + result.stderr
        assert (root / 'wine/dlls/advapi32/security.c').read_bytes() == original
        assert not (root / 'package-checked').exists()
        assert (root / 'app/Madeira' / farm / 'advapi32.dll').read_bytes() == b'previous DLL'

print('PASS actual registry security build transaction: all 3 targeted recompiles invalidate stale objects; exact source restoration before package evidence; failures in every farm retain previous DLL and propagate without publishing evidence')
