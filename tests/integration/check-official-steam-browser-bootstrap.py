#!/usr/bin/env python3
"""Real official I386 CEF/helper startup and its actual master-section creation.

Runs once in a new disposable Wine prefix, without an account, real Steam
installation or game files. The AMD64 peer only opens the helper-created section;
it never creates a Steam object, invents a CEF response or reports UI readiness.
This stock-Wine control cannot prove iOS/FEX runtime compatibility.
"""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('official_archive',ROOT/'tests/integration/htmlipc/official_archive.py')
archive_policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive_policy)

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official',action='store_true')
args=parser.parse_args()
if not args.download_official:parser.error('--download-official is required; no implicit downloads')
for tool in ['wine','wineserver','x86_64-w64-mingw32-gcc']:
    assert shutil.which(tool),'required integration tool unavailable: '+tool
wine64=shutil.which('wine64') or next((str(p) for p in [Path('/usr/lib/wine/wine64'),Path('/usr/lib64/wine/wine64')] if p.is_file()),None)
assert wine64,'explicit AMD64 Wine loader unavailable'
source=(ROOT/'app/Madeira/SteamBrowserRuntime.swift').read_text()
packages=[(name,int(size.replace('_','')),digest) for name,size,digest in re.findall(
    r'Package\(file: "([A-Za-z0-9_.-]+)", bytes: ([0-9_]+),\s*sha256: "([0-9a-f]{64})"',source)]
assert len(packages)==3 and sum(size for _,size,_ in packages)<200*1024**2
# The exact current core package used in the independently recorded Nov4
# genuine-login control. It supplies the real AMD64 root SDL3 (so the I386
# helper's optional absolute-root preload sees the same architecture conflict)
# and the genuine current I386 SteamClient dependency. No binaries are patched.
core=('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8',64_309_479,
      'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236')
keys={name:digest for name,digest in re.findall(r'Key\(name: "([A-Za-z0-9_.]+)", sha256: "([0-9a-f]{64})"',source)}
assert set(keys)=={'steamwebhelper.exe','libcef.dll','chrome_elf.dll','SDL3.dll','msdia140.dll'}
def sha(data):return hashlib.sha256(data).hexdigest()
def machine(data):
    assert len(data)>=64 and data[:2]==b'MZ'
    nt=struct.unpack_from('<I',data,0x3c)[0]
    assert data[nt:nt+4]==b'PE\0\0'
    return struct.unpack_from('<H',data,nt+4)[0]
def windows(path):
    if path.is_relative_to(prefix/'drive_c'):
        return 'C:\\'+path.relative_to(prefix/'drive_c').as_posix().replace('/','\\')
    return 'Z:'+str(path).replace('/','\\')
with tempfile.TemporaryDirectory(prefix='madeira-official-browser-') as folder:
    temporary=Path(folder);prefix=temporary/'prefix';steam=temporary/'Steam';cache=temporary/'archives'
    recipe=re.search(r'id: "(official-i386-[A-Za-z0-9_.-]+)"',source)
    assert recipe,'production browser cache recipe identity changed'
    browser=prefix/'drive_c/windows/madeira-compat/SteamBrowserRuntime'/recipe[1]/'bin/cef/cef.win7'
    logs=temporary/'logs';profile=temporary/'profile'
    for p in [steam,browser,cache,logs,profile]:p.mkdir(parents=True)
    # The official child receives only ordinary runtime/display variables;
    # Actions secrets, connector credentials and unrelated account settings are
    # never inherited, regardless of how a credential variable is named.
    env={key:os.environ[key] for key in ['PATH','DISPLAY','XAUTHORITY','HOME','USER','LOGNAME','TMPDIR','LANG','LC_ALL'] if key in os.environ}
    env.update(WINEPREFIX=str(prefix),WINEARCH='win64',WINEDEBUG='-all,+loaddll',WINEDLLOVERRIDES='mscoree,mshtml=')
    def command(argv,timeout=90):
        result=subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
        assert len(result.stdout)<2*1024*1024,'fixture command output bound exceeded'
        assert result.returncode==0,'fixture setup failed code='+str(result.returncode)
        return result.stdout
    def fetch(package):
        name,size,digest=package;path=cache/name
        shared=Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE'])/name if os.environ.get('MADEIRA_VALVE_ARCHIVE_CACHE') else None
        if shared and shared.is_file():shutil.copyfile(shared,path)
        else:
            url='https://client-update.akamai.steamstatic.com/'+name
            with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=90) as response:
                assert response.status==200 and response.url==url
                data=response.read(size+1)
            assert len(data)==size and sha(data)==digest
            path.write_bytes(data)
        assert path.stat().st_size==size and sha(path.read_bytes())==digest
        print('[official-browser] package-sha-verified=1 bytes='+str(size),flush=True)
        return path
    def old_rejection(raw,canonical):
        # Called only after fetch() verifies the entire official package SHA.
        # Names are public archive metadata, escaped and capped; no user paths.
        if not old_rejection.reported:
            print('[official-browser] old-path-predicate-rejected raw='+ascii(raw)[:120]+' canonical='+ascii(canonical)[:120],flush=True)
            old_rejection.reported=True
    old_rejection.reported=False
    def members(archive):
        return archive_policy.validated_members(archive,on_legacy_rejection=old_rejection)
    peer=temporary/'browser-witness.exe';process=None;raw_log=temporary/'private-wine.log'
    try:
        browser_names=set()
        for index,package in enumerate(packages):
            with zipfile.ZipFile(fetch(package)) as archive:
                for entry,path in members(archive):
                    if index==2:
                        if str(path)!='SDL3.dll':continue
                        relative=PurePosixPath('SDL3.dll')
                    else:
                        relative=path.relative_to('bin/cef/cef.win7')
                    assert relative.parts and relative.as_posix().casefold() not in browser_names
                    browser_names.add(relative.as_posix().casefold());destination=browser.joinpath(*relative.parts)
                    destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(archive.read(entry))
        assert len(browser_names)==79
        browser_hashes={path.relative_to(browser).as_posix():sha(path.read_bytes()) for path in browser.rglob('*') if path.is_file()}
        for name,digest in keys.items():
            data=(browser/name).read_bytes();assert sha(data)==digest
            assert machine(data)==(0x8664 if name=='msdia140.dll' else 0x14c)
        with zipfile.ZipFile(fetch(core)) as archive:
            for entry,path in members(archive):
                destination=steam.joinpath(*path.parts);destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(archive.read(entry))
        assert machine((steam/'SDL3.dll').read_bytes())==0x8664
        assert machine((steam/'steamclient.dll').read_bytes())==0x14c
        assert sha((steam/'steamclient.dll').read_bytes())=='a9b8b9905889888787f9da18aa91550814cc36708129b3956af66e5dc037dc3f'
        assert sha((steam/'bin/chromehtml.dll').read_bytes())=='37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
        command(['x86_64-w64-mingw32-gcc','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-municode','-static','-Wl,--no-insert-timestamp',str(ROOT/'tests/integration/htmlipc/official_helper_witness.c'),'-o',str(peer)])
        assert machine(peer.read_bytes())==0x8664
        command([wine64,'wineboot.exe','--init'],timeout=120)
        command(['wine','winecfg.exe','-v','win10'],timeout=30)
        command(['wine','reg.exe','add',r'HKCU\Software\Valve\Steam\ActiveProcess','/v','SteamClientDll','/t','REG_SZ','/d',windows(steam/'steamclient.dll'),'/f'])
        env.update(MADEIRA_HTMLIPC_HELPER=windows(browser/'steamwebhelper.exe'),MADEIRA_HTMLIPC_CACHE_DIR=windows(browser))
        with raw_log.open('wb') as log:
            process=subprocess.Popen([wine64,str(peer),windows(browser/'steamwebhelper.exe'),windows(steam),windows(profile),windows(logs)],env=env,cwd=steam,stdout=log,stderr=subprocess.STDOUT)
            begin=time.monotonic()
            while process.poll() is None:
                assert time.monotonic()-begin<150,'genuine helper observation exceeded deadline'
                assert raw_log.stat().st_size<16*1024*1024,'genuine helper diagnostic bound exceeded'
                time.sleep(.2)
        output=raw_log.read_text(errors='replace')
        witness=[line for line in output.splitlines() if line.startswith('[official-browser]')]
        # Output only fixed witnesses/error codes, never raw CEF logs, URLs,
        # paths, command lines, DOM, QR codes or authentication material.
        for line in witness[-8:]:print(line[:400],flush=True)
        assert process.returncode==0 and any('genuine-master-created=1' in line for line in witness),'official helper did not create its master section'
        assert len(browser_hashes)==79
        for name,digest in browser_hashes.items():
            assert sha((browser/name).read_bytes())==digest,'official component changed during startup'
        actual={path.relative_to(browser).as_posix() for path in browser.rglob('*') if path.is_file()}
        extra=actual-set(browser_hashes)
        # Stock Wine deliberately has no Madeira iOS native hook. This is the
        # genuine executable's baseline output, not a redirected-write claim.
        # A separate actual-staged-NtCreateFile fixture proves routing and strict
        # production Swift reuse; device execution remains an acceptance check.
        print('[official-browser] baseline-default-log-created='+str(int('debug.log' in extra))+
              ' official-components-unchanged=79 extra-file-count='+str(len(extra))+
              ' native-ios-file-hook=absent',flush=True)
        assert extra<= {'debug.log'},'genuine helper produced unexpected immutable-tree output'

        print('PASS unmodified official I386 helper created the observed cross-architecture master section; completed CEF rendering/account/UI/Library/CS2 and iOS success are not claimed',flush=True)
    finally:
        if process and process.poll() is None:process.terminate()
        subprocess.run(['wineserver','-k'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        if process:
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
