#!/usr/bin/env python3
"""Actual isolated Wine I386 creator/AMD64 opener and named-section lifetime.

This is a Windows API fixture, not a fake Steam helper, authenticated session,
CEF startup test or claim that the device's missing section is repaired.
The request76/response72 fixed layout is independently proved from pinned images.
"""
from pathlib import Path
import os
import argparse
import importlib.util
import shutil
import struct
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official',action='store_true',help='Allow the production-pinned 2.7MB official helper archive download for static contract verification')
parser.add_argument('--official-helper',type=Path,help='Use a locally supplied helper only if it matches the exact production SHA256')
args=parser.parse_args()
if not args.download_official and not args.official_helper:parser.error('explicit --download-official or --official-helper is required; no implicit network access')
spec=importlib.util.spec_from_file_location('contract',ROOT/'tests/integration/htmlipc/contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
for name in ['wine','wineserver','i686-w64-mingw32-gcc','x86_64-w64-mingw32-gcc']:
    assert shutil.which(name), 'required integration tool unavailable: '+name
wine64=shutil.which('wine64') or next((str(p) for p in [Path('/usr/lib/wine/wine64'),Path('/usr/lib64/wine/wine64')] if p.is_file()),None)
assert wine64, 'explicit AMD64 Wine loader unavailable'
with tempfile.TemporaryDirectory(prefix='madeira-htmlipc-') as folder:
    temp=Path(folder);env={**os.environ,'WINEPREFIX':str(temp/'prefix'),'WINEARCH':'win64',
        'WINEDEBUG':'-all,err+module','WINEDLLOVERRIDES':'mscoree,mshtml='}
    for key in list(env):
        if any(word in key.upper() for word in ['TOKEN','PASSWORD','SECRET','CREDENTIAL']):env.pop(key)
    def run(args,timeout=90):
        result=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
        assert len(result.stdout)<256*1024,'fixture diagnostic bound exceeded'
        if result.returncode:
            safe=[s.replace(str(temp),'<fixture>')[:300] for s in result.stdout.decode(errors='replace').splitlines() if '[htmlipc-fixture]' in s or 'error:' in s]
            raise AssertionError(f'fixture failed code={result.returncode} metadata={safe[-12:]!r}')
        return result.stdout.decode(errors='replace')
    try:
        contract.header(ROOT,temp,download=args.download_official,helper=args.official_helper)
        fixtures=[]
        for arch,compiler,machine in [('32','i686-w64-mingw32-gcc',0x14c),('64','x86_64-w64-mingw32-gcc',0x8664)]:
            image=temp/f'bootstrap{arch}.exe'
            run([compiler,'-std=c11','-O1','-Wall','-Wextra','-Werror','-municode','-static','-Wl,--no-insert-timestamp','-I'+str(temp),str(ROOT/'tests/integration/htmlipc/bootstrap.c'),'-o',str(image)])
            data=image.read_bytes();pe=struct.unpack_from('<I',data,0x3c)[0]
            assert data[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',data,pe+4)[0]==machine
            fixtures.append(image)
        run([wine64,'wineboot.exe','--init'],timeout=120)
        windows_helper='Z:'+str(fixtures[0]).replace('/','\\')
        for iteration in range(3):
            output=run([wine64,str(fixtures[1]),windows_helper])
            assert '[htmlipc-fixture] PASS' in output
            print(f'PASS real Wine AMD64->I386 bootstrap/lifetime round {iteration+1}; missing-before-create does not imply namespace incompatibility',flush=True)
    finally:
        subprocess.run(['wineserver','-k'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
