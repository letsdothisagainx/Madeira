#!/usr/bin/env python3
"""Run the production build transaction with owned compiler/package adapters.

The source overlays and restoration are real. Compilation and binary checks
are separate boundaries: Actions builds the actual DLLs, and the package
checker has independent COFF/PE tests. This test claims neither execution of
Wine nor a trusted publisher or secure-server result.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FILES = ('dlls/crypt32/crypt32_private.h', 'dlls/crypt32/encode.c',
         'dlls/crypt32/msg.c', 'dlls/kernelbase/debug.c')
CONFIGS = (('build-macos', 'aarch64', 'aarch64-windows'),
           ('build-arm64ec', 'arm64ec', 'arm64ec-windows'),
           ('build-i386', 'i686', 'i386-windows'))


def setup(directory):
    root = directory / 'repo'
    for relative in ('build/wine-pe/build-security-compat.sh',
                     'build/wine-pe/crypt32-authattrs-order.patch',
                     'build/wine-pe/crypt32-authattrs-order.json',
                     'build/wine-pe/mapped-filename-contract.patch',
                     'tools/build/stage-crypt32-authattrs.py',
                     'tools/build/stage-mapped-filename-contract.py'):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for relative in FILES:
        target = root / 'wine' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'wine' / relative, target)
    original = {relative: (root/'wine'/relative).read_bytes() for relative in FILES}
    (root/'original.json').write_text(json.dumps({k: v.hex() for k, v in original.items()}))
    # Existing system-program transaction is independently executed by
    # check-system-program-build.py. Here verify the outer overlay is present
    # when that boundary is called, and invalidate the actual debug object.
    nested = root/'build/wine-pe/build-system-programs.sh'
    nested.write_text('''#!/usr/bin/env bash
set -eu
python3 - <<'PY'
import os
from pathlib import Path
r=Path(os.environ['ROOT']);w=r/'wine'
assert 'return min( len, size );' in (w/'dlls/kernelbase/debug.c').read_text()
assert 'CRYPT_AsnEncodePKCSAttributesUnsorted(' in (w/'dlls/crypt32/msg.c').read_text()
for tree,farm in [('build-macos','aarch64-windows'),('build-arm64ec','arm64ec-windows'),('build-i386','i386-windows')]:
 p=w/tree/'dlls/kernelbase'/farm/'debug.o'
 assert not p.exists(),'stale debug object survived'
 p.write_bytes(b'fresh debug object')
PY
''')
    nested.chmod(0o755)
    checker = root/'tools/check-security-compat-package.py'
    checker.write_text('''import json,os
from pathlib import Path
r=Path(os.environ['ROOT'])
for p,v in json.loads((r/'original.json').read_text()).items():
 assert (r/'wine'/p).read_bytes()==bytes.fromhex(v),'checker ran before exact source restoration'
(r/'package-checked').write_text('owned package adapter; real checker tested separately')
''')
    tools = root/'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin'
    tools.mkdir(parents=True)
    make = tools/'make'
    make.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
r=Path(os.environ['ROOT']);b=Path(sys.argv[2]);target=sys.argv[-1]
farm=target.split('/')[-2]
assert target=='dlls/crypt32/'+farm+'/crypt32.dll'
assert 'CRYPT_AsnEncodePKCSAttributesUnsorted(' in (r/'wine/dlls/crypt32/msg.c').read_text()
folder=b/'dlls/crypt32'/farm
for n in ('encode.o','msg.o','crypt32.dll'):assert not (folder/n).exists(),'stale compiler output survived'
with (r/'compile.jsonl').open('a') as out:out.write(json.dumps([b.name,farm,target])+'\\n')
if os.environ.get('FAIL_FARM')==farm:raise SystemExit(37)
for n in ('encode.o','msg.o','crypt32.dll'):(folder/n).write_bytes(('fresh '+n).encode())
''')
    make.chmod(0o755)
    for tree,triple,farm in CONFIGS:
        build = root/'wine'/tree
        build.mkdir()
        (build/'Makefile').write_text('# owned compiler adapter\n')
        folder = build/'dlls/crypt32'/farm
        folder.mkdir(parents=True)
        for name in ('encode.o','msg.o','crypt32.dll'):
            (folder/name).write_bytes(b'stale compiler output')
        debug = build/'dlls/kernelbase'/farm/'debug.o'
        debug.parent.mkdir(parents=True)
        debug.write_bytes(b'stale debug object')
        dest = root/'app/Madeira'/farm
        dest.mkdir(parents=True)
        (dest/'crypt32.dll').write_bytes(b'previous DLL')
        strip = tools/(triple+'-w64-mingw32-strip')
        strip.write_text('''#!/usr/bin/env python3
import shutil,sys
assert sys.argv[1:3]==['--strip-debug','-o']
shutil.copyfile(sys.argv[4],sys.argv[3])
''')
        strip.chmod(0o755)
    return root,original


def run(root, **extra):
    return subprocess.run(['bash',str(root/'build/wine-pe/build-security-compat.sh')],
                          env=dict(os.environ,ROOT=str(root),JOBS='2',**extra),
                          capture_output=True,text=True,timeout=45)


def restored(root, original):
    for relative, data in original.items():
        assert (root/'wine'/relative).read_bytes()==data, relative


with tempfile.TemporaryDirectory(prefix='madeira-security-build-') as tmp:
    root,original=setup(Path(tmp))
    result=run(root)
    assert result.returncode==0,result.stdout+result.stderr
    restored(root,original)
    assert (root/'package-checked').is_file()
    calls=[json.loads(line) for line in (root/'compile.jsonl').read_text().splitlines()]
    assert [line[1] for line in calls]==[row[2] for row in CONFIGS]
    for _,_,farm in CONFIGS:
        assert (root/'app/Madeira'/farm/'crypt32.dll').read_bytes()==b'fresh crypt32.dll'
        assert not (root/'app/Madeira'/farm/'crypt32.dll.pending').exists()
    print('PASS production security build: nested filename overlay, all three targeted recompiles, stale object invalidation, exact restore before package evidence')

for _,_,farm in CONFIGS:
    with tempfile.TemporaryDirectory(prefix='madeira-security-build-failure-') as tmp:
        root,original=setup(Path(tmp))
        result=run(root,FAIL_FARM=farm)
        assert result.returncode==37,result.stdout+result.stderr
        restored(root,original)
        assert not (root/'package-checked').exists()
        assert (root/'app/Madeira'/farm/'crypt32.dll').read_bytes()==b'previous DLL'
print('PASS real build failures in every architecture restore all source and cannot publish package evidence')
