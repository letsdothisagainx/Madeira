#!/usr/bin/env python3
"""Exercise the real hash-pinned installer on old and updated official cores.

Downloads bounded public HTTPS Valve packages only with --download-official.
Never loads/executes Valve code and never accesses a Wine prefix or account.
The native fixture maps PE sections, applies real DIR64 relocations, and uses
owned Linux mmap/mprotect ranges. It is not an actual Windows SEC_IMAGE loader.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official',action='store_true')
parser.add_argument('--archive-cache',type=Path,default=None)
parser.add_argument('--baseline-revision',default='51963bfcbd6b7cb57fc468d139c67853e54d896e')
args=parser.parse_args()
if not args.download_official:parser.error('--download-official required; no implicit network')
if sys.platform!='linux' or platform.machine().lower() not in ('x86_64','amd64'):
    parser.error('actual native fixture requires Linux AMD64 with 4 KiB pages')
spec=importlib.util.spec_from_file_location('steam_browser_inspector',ROOT/'tools/inspect-steam-browser-update.py')
inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
NEW=('bins_win64.zip.f16fd7ffa58d880db946cdee49a663dc79a0b9b4',64658068,
     'ee61ec96e1f91222ed2282f72e330154d6c2f501df1bd989e2adc7380de0ef5a')
NEW_CORE='7afabbd8fae70a1b9831546d4c126ebd74c18796457e3a12fa259f529f7f2266'
def file_digest(path):
    state=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(1<<20):state.update(chunk)
    return state.hexdigest()
with tempfile.TemporaryDirectory(prefix='madeira-official-bridge-profiles-') as folder:
    temporary=Path(folder)
    cache=args.archive_cache or Path(os.environ.get('MADEIRA_VALVE_ARCHIVE_CACHE',temporary/'archives'))
    cache.mkdir(parents=True,exist_ok=True)
    files=[]
    for label,package,digest in [('legacy',inspector.OLD,inspector.OLD_CORE_SHA),('updated',NEW,NEW_CORE)]:
        name,size,archive_sha=package;archive=cache/name
        if not archive.is_file():inspector.fetch(name,archive,128<<20,size,archive_sha)
        assert archive.stat().st_size==size and file_digest(archive)==archive_sha, 'cached archive provenance mismatch'
        selected=inspector.select(archive,{'bin/chromehtml.dll'})
        assert set(selected)=={'bin/chromehtml.dll'}
        data=selected['bin/chromehtml.dll'];assert hashlib.sha256(data).hexdigest()==digest
        image=inspector.PE(data);assert image.machine==0x8664 and image.bits==64
        file=temporary/(label+'.dll');file.write_bytes(data);files.append(file)
        print(f'Pinned HTTPS package SHA-256 + exact selected core: {label} bytes={len(data)} sha256={digest}',flush=True)
    baseline=temporary/'baseline';baseline.mkdir()
    for name in ('installer.cpp','installer.h'):
        content=subprocess.check_output(['git','-C',str(ROOT),'show',args.baseline_revision+':build/htmlipc/stream-install/'+name])
        (baseline/name).write_bytes(content)
    install=ROOT/'build/htmlipc/stream-install'
    for label,directory,defines in [('baseline',baseline,['-DMADEIRA_BASELINE_PROFILE=1']),('corrected',install,[])]:
        binary=temporary/label
        subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-D_WIN64=1',*defines,
            '-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie',
            '-I'+str(directory),'-I'+str(install),str(directory/'installer.cpp'),
            str(ROOT/'tests/integration/htmlipc/bridge_profile_fixture.cpp'),'-o',str(binary)],check=True)
        subprocess.run([str(binary),*[str(file) for file in files]],check=True,timeout=90)
print('PASS official bridge profiles: old rejection reproduced, both production profiles installed against full original PE files; no Valve code executed')
