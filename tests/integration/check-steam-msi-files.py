#!/usr/bin/env python3
"""Real isolated Wine MSI/CAB extraction after the production stale-link repair.

Builds owned PE32/PE64 clients, genuine MSI databases and embedded MSZIP CABs.
The identical portable production migration runs on the owned temporary prefix;
Wine's NtCreateFile, cabinet.dll, msi.dll, rollback and registry APIs are real.
This Linux-Wine control does not claim iOS/FEX or official VC installer success.
"""
from pathlib import Path
import os
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
import zlib

ROOT=Path(__file__).resolve().parents[2]
for name in ('wine','wineserver','i686-w64-mingw32-gcc','x86_64-w64-mingw32-gcc','cc'):
    assert shutil.which(name),'required integration tool unavailable: '+name
WINE64=shutil.which('wine64') or next((str(p) for p in (Path('/usr/lib/wine/wine64'),Path('/usr/lib64/wine/wine64')) if p.is_file()),None)
assert WINE64,'explicit AMD64 Wine loader unavailable'
HEADER=ROOT/'app/Madeira/StaleRuntimeLinks.h'
assert HEADER.is_file(),'production stale runtime link migration header missing'


def guid():return '{'+str(uuid.uuid4()).upper()+'}'
def win(path):return 'Z:'+str(path).replace('/',chr(92))
def system_path(leaf):return chr(92).join(('C:','windows','system32',leaf))
def cabinet(name,payload):
    """One genuine MSZIP folder/file/block, checksum zero is CAB's optional CRC."""
    compressor=zlib.compressobj(level=6,wbits=-15)
    packed=b'CK'+compressor.compress(payload)+compressor.flush()
    member=name.encode('ascii')+b'\0';files_offset=44;block_offset=files_offset+16+len(member)
    size=block_offset+8+len(packed)
    header=struct.pack('<4sIIIII BBHHHHH',b'MSCF',0,size,0,files_offset,0,3,1,1,1,0,0x730,0)
    folder=struct.pack('<IHH',block_offset,1,1)
    entry=struct.pack('<IIHHHH',len(payload),0,0,0x5d61,0,0x20)+member
    return header+folder+entry+struct.pack('<IHH',0,len(packed),len(payload))+packed


with tempfile.TemporaryDirectory(prefix='madeira-msi-files-') as directory:
    temporary=Path(directory);prefix=temporary/'prefix';prefix.mkdir()
    env={**os.environ,'WINEPREFIX':str(prefix),'WINEARCH':'win64','WINEDEBUG':'-all,err+msi,err+module',
         'WINEDLLOVERRIDES':'mscoree,mshtml='}
    for key in list(env):
        if any(word in key.upper() for word in ('TOKEN','PASSWORD','SECRET','CREDENTIAL')):env.pop(key)
    def command(argv,timeout=120,allowed=(0,)):
        result=subprocess.run([str(x) for x in argv],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
        assert len(result.stdout)<=4*1024*1024,'fixture output exceeded diagnostic bound'
        output=result.stdout.decode(errors='replace')
        if result.returncode not in allowed:
            safe=output.replace(str(temporary),'<fixture>').replace(str(ROOT),'<repo>')
            raise AssertionError('fixture command failed code='+str(result.returncode)+'; '+safe[-4500:])
        for line in output.splitlines():
            if '[msi-files]' in line:print(line[:450],flush=True)
        diagnostics=[line for line in output.splitlines() if 'err:msi:' in line]
        for line in diagnostics[-12:]:
            safe=line.replace(str(temporary),'<fixture>').replace(str(ROOT),'<repo>')
            print('[msi-files] wine-diagnostic '+safe[:400],flush=True)
        return output
    clients={}
    for bits,compiler in ((32,'i686-w64-mingw32-gcc'),(64,'x86_64-w64-mingw32-gcc')):
        client=temporary/('client'+str(bits)+'.exe')
        command([compiler,'-std=c11','-O1','-Wall','-Wextra','-Werror','-municode','-static',
                 '-Wl,--no-insert-timestamp',ROOT/'tests/integration/steam-msi-files.c','-lmsi','-lole32','-o',client])
        image=client.read_bytes();pe=struct.unpack_from('<I',image,0x3c)[0]
        assert struct.unpack_from('<H',image,pe+4)[0]==(0x14c if bits==32 else 0x8664)
        clients[bits]=client
    helper_source=temporary/'repair.c'
    helper_source.write_text('#define _GNU_SOURCE\n#include <stdio.h>\n#include "StaleRuntimeLinks.h"\nint main(int n,char **v){if(n!=3)return 2;printf("[msi-files] production-repair count=%u\\n",madeira_repair_stale_runtime_links(v[1],v[2]));return 0;}\n')
    helper=temporary/'repair'
    command(['cc','-std=c11','-Wall','-Wextra','-Werror','-I'+str(HEADER.parent),helper_source,'-o',helper])
    def client(bits,*args):return command([WINE64 if bits==64 else 'wine',clients[bits],*args])
    def repair(bundle):
        # Production invokes migration before Wine starts. End only this owned
        # fixture's server and wait for every client/service to quiesce first.
        # Wine server/main.c exits !kill_lock_owner(): -k returns1 when
        # already stopped. The subsequent lock wait must still succeed.
        command(['wineserver','-k'],allowed=(0,1));command(['wineserver','-w'],timeout=30)
        print('[msi-files] owned-prefix-server-quiescent lock-wait=complete',flush=True)
        return command([helper,prefix,bundle])
    try:
        command([WINE64,'wineboot.exe','--init'])
        drive=prefix/'drive_c';system32=drive/'windows/system32';syswow64=drive/'windows/syswow64'
        assert system32.is_dir() and syswow64.is_dir()
        bundle_root=temporary/'Containers/Bundle/Application';old_id=str(uuid.uuid4()).upper();new_id=str(uuid.uuid4()).upper()
        old=bundle_root/old_id/'Madeira.app';current=bundle_root/new_id/'Madeira.app'
        (current/'x86_64-vcruntime').mkdir(parents=True)
        sentinels={drive/'fixture-private-login':b'fixture-auth-preserved',drive/'fixture-appmanifest-730':b'fixture-game-preserved'}
        for p,data in sentinels.items():p.write_bytes(data)
        def tables(folder,leaf,product,component,package,is64):
            folder.mkdir();payload=(b'owned authentic CAB payload\0'+leaf.encode()+bytes(range(256)))*3
            (folder/'cab1.cab').write_bytes(cabinet('FixtureFile',payload))
            selected='System64Folder' if is64 else 'SystemFolder'
            entries={
              'Directory':'Directory\tDirectory_Parent\tDefaultDir\ns72\tS72\tl255\nDirectory\tDirectory\nTARGETDIR\t\tSourceDir\n'+selected+'\tTARGETDIR\t.\n',
              'Component':'Component\tComponentId\tDirectory_\tAttributes\tCondition\tKeyPath\ns72\tS38\ts72\ti2\tS255\tS72\nComponent\tComponent\nFixtureComponent\t'+component+'\t'+selected+'\t'+('256' if is64 else '0')+'\t\tFixtureFile\n',
              'Feature':'Feature\tFeature_Parent\tTitle\tDescription\tDisplay\tLevel\tDirectory_\tAttributes\ns38\tS38\tL64\tL255\tI2\ti2\tS72\ti2\nFeature\tFeature\nMain\t\tOwned fixture\t\t1\t1\t\t0\n',
              'FeatureComponents':'Feature_\tComponent_\ns38\ts72\nFeatureComponents\tFeature_\tComponent_\nMain\tFixtureComponent\n',
              'File':'File\tComponent_\tFileName\tFileSize\tVersion\tLanguage\tAttributes\tSequence\ns72\ts72\tl255\ti4\tS72\tS20\ti2\ti2\nFile\tFile\nFixtureFile\tFixtureComponent\t'+leaf+'\t'+str(len(payload))+'\t1.0.0.0\t\t16384\t1\n',
              'Media':'DiskId\tLastSequence\tDiskPrompt\tCabinet\tVolumeLabel\tSource\ni2\ti4\tL64\tS255\tS32\tS72\nMedia\tDiskId\n1\t1\t\t#cab1.cab\t\t\n',
              'Property':'Property\tValue\ns72\tl0\nProperty\tProperty\nProductCode\t'+product+'\nProductName\tOwned Madeira MSI file fixture\nProductVersion\t1.0.0\nProductLanguage\t1033\nManufacturer\tMadeira integration tests\nALLUSERS\t1\nINSTALLLEVEL\t1\n',
              'CustomAction':'Action\tType\tSource\tTarget\ns72\ti2\tS72\tS255\nCustomAction\tAction\nFailOwnedFixture\t19\t\tIntentional owned fixture rollback\n',
              'InstallExecuteSequence':'Action\tCondition\tSequence\ns72\tS255\ti2\nInstallExecuteSequence\tAction\nCostInitialize\t\t800\nFileCost\t\t900\nCostFinalize\t\t1000\nInstallValidate\t\t1400\nInstallInitialize\t\t1500\nProcessComponents\t\t1600\nRemoveFiles\t\t3500\nInstallFiles\t\t4000\nInstallExecute\t\t4500\nFailOwnedFixture\tFAILOWNEDFIXTURE=1\t4550\nRegisterProduct\t\t6100\nPublishFeatures\t\t6300\nPublishProduct\t\t6400\nInstallFinalize\t\t6600\n'}
            for name,text in entries.items():(folder/(name+'.idt')).write_text(text,encoding='ascii')
            msi=folder/'owned.msi';client(64,'--build',win(msi),win(folder),'x64;1033' if is64 else 'Intel;1033',package)
            return msi,payload
        for bits in (64,32):
            leaf='madeira-msi-vcamp-'+uuid.uuid4().hex[:10]+'.dll';target=(system32 if bits==64 else syswow64)/leaf
            native_source=current/'x86_64-vcruntime'/leaf;native_bytes=b'owned immutable current bundle source';native_source.write_bytes(native_bytes);native_source.chmod(0o444)
            stale=old/'x86_64-vcruntime'/leaf
            product=guid();msi,payload=tables(temporary/('msi'+str(bits)),leaf,product,guid(),guid(),bits==64)
            request=system_path(leaf)
            if bits==64:
                target.symlink_to(stale)
                client(bits,'--native-create',request,'c000000f')
                baseline_output=client(bits,'--install',win(msi),'REINSTALLMODE=amus','1603')
                # Require the genuine cabinet/create path, not an invented
                # result or an earlier MSI validation action.
                raw=(Path(str(msi)+'.log')).read_bytes()
                codec='utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else ('utf-16-le' if raw and raw.count(0)>len(raw)//4 else 'utf-8')
                log=raw.decode(codec,errors='replace')
                cabinet_failure=any('cabinet_copy_file failed to create' in line and leaf in line and '(error 2)' in line for line in baseline_output.splitlines())
                valid_stage=('InstallFiles' in log and cabinet_failure and 'FDICopy failed' in baseline_output and
                    'ACTION_InstallFiles Failed to extract cabinet' in baseline_output and
                    'action L\"InstallFiles\" returned 1603' in baseline_output and
                    '[msi-files] genuine-MsiInstallProduct result=1603' in baseline_output)
                print('[msi-files] baseline-witness cabinet-error=2 fdi-failed='+str('FDICopy failed' in baseline_output)+' installfiles-api=1603 log-bytes='+str(len(raw))+' encoding='+codec,flush=True)
                if not valid_stage:
                    safe=log.replace(str(temporary),'<fixture>').replace(str(ROOT),'<repo>')
                    print('[msi-files] baseline-log-tail '+repr(safe[-6000:]),flush=True)
                assert valid_stage,'real MSI failed before the expected cabinet extraction stage; see bounded log above'
                if not target.is_symlink():
                    assert not target.exists(),'failed owned install replaced the source unexpectedly'
                    target.symlink_to(stale)
                    print('INFO actual MSI rollback removed owned stale leaf; restored same stale fixture for production migration control',flush=True)
                output=repair(current);assert 'production-repair count=1' in output
                assert not target.exists() and not target.is_symlink() and native_source.read_bytes()==native_bytes
            # Actual PE32 SystemFolder redirection is independent of migration:
            # production repairs only Madeira's system32/sysx64 link farms.
            client(bits,'--native-create',request,'0')
            assert target.is_file() and target.stat().st_size==0;target.unlink()
            client(bits,'--install',win(msi),'REINSTALLMODE=amus','0')
            assert target.read_bytes()==payload and not target.is_symlink()
            assert 'production-repair count=0' in repair(current)
            assert target.read_bytes()==payload and native_source.read_bytes()==native_bytes
            assert not ((syswow64 if bits==64 else system32)/leaf).exists(),'MSI architecture routed to wrong system directory'
            client(bits,'--state',product,'5')
            client(bits,'--sharing',system_path(leaf))
            client(bits,'--install',win(msi),'REINSTALL=ALL REINSTALLMODE=amus','0');assert target.read_bytes()==payload
            client(bits,'--uninstall',product);client(bits,'--state',product,'-1')
            assert not target.exists() and native_source.read_bytes()==native_bytes
            # Explicit immediate error follows InstallExecute, after the actual
            # deferred InstallFiles script. Actual rollback removes the fresh
            # owned leaf, while an existing neighboring file remains intact.
            rollback_leaf='madeira-msi-rollback-'+uuid.uuid4().hex[:8]+'.dll';rollback_target=(system32 if bits==64 else syswow64)/rollback_leaf
            assert not rollback_target.exists()
            neighbour=rollback_target.with_suffix('.keep');original=b'owned existing neighbour must survive rollback';neighbour.write_bytes(original)
            rollback_product=guid();rollback_msi,rollback_payload=tables(temporary/('rollback'+str(bits)),rollback_leaf,rollback_product,guid(),guid(),bits==64)
            checkpoint=temporary/('rollback-installed-checkpoint'+str(bits))
            client(bits,'--install',win(rollback_msi),'FAILOWNEDFIXTURE=1 REINSTALLMODE=amus','1603',
                   system_path(rollback_leaf),win(checkpoint))
            assert checkpoint.read_bytes()==rollback_payload,'rollback fixture never actually extracted the cabinet payload'
            assert not rollback_target.exists(),'actual MSI rollback did not remove the newly extracted owned file'
            assert neighbour.read_bytes()==original,'rollback changed an unrelated existing file'
            client(bits,'--state',rollback_product,'-1')
            assert all(p.read_bytes()==data for p,data in sentinels.items())
            print('PASS real Wine '+str(bits)+'-bit MSI: '+('stale-link NtCreateFile/CAB1603 -> production quarantine; ' if bits==64 else 'independent absent-leaf WoW64 control; ')+'actual extraction/repair, system-directory routing, sharing protection, product registration/uninstall and observed rollback; source/auth/game fixture bytes preserved',flush=True)
        # The 32-bit front end also invokes a genuine 64-bit MSI engine/package;
        # its 64-bit component must still be installed in system32, not syswow64.
        crossleaf='madeira-msi-cross-'+uuid.uuid4().hex[:8]+'.dll';crossproduct=guid()
        crossmsi,crossbytes=tables(temporary/'cross-32-client-64-msi',crossleaf,crossproduct,guid(),guid(),True)
        client(32,'--install',win(crossmsi),'REINSTALLMODE=amus','0')
        assert (system32/crossleaf).read_bytes()==crossbytes and not (syswow64/crossleaf).exists()
        client(32,'--state',crossproduct,'5');client(32,'--uninstall',crossproduct)
        print('PASS real Wine I386 frontend -> AMD64 MSI component/engine routing; no fabricated installer completion or registry state',flush=True)
        # Genuine negative/native controls remain independent of MSI success.
        # None is a candidate for the ownership migration.
        control_leaf='madeira-msi-control-'+uuid.uuid4().hex[:8]+'.dll'
        control=system32/control_leaf;control.write_bytes(b'owned writable control')
        client(64,'--native-create',system_path(control_leaf),'0')
        assert control.is_file() and control.stat().st_size==0
        control.write_bytes(b'owned existing writable bytes')
        assert 'production-repair count=0' in repair(current)
        assert control.read_bytes()==b'owned existing writable bytes'
        missing_parent='C:'+chr(92)+'madeira-msi-missing-'+uuid.uuid4().hex+chr(92)+'child'+chr(92)+'file.dll'
        client(64,'--native-create',missing_parent,'c000003a')
        live_leaf='madeira-msi-live-'+uuid.uuid4().hex[:8]+'.dll'
        live_source=current/'x86_64-vcruntime'/live_leaf
        live_bytes=b'owned live readonly catalog source';live_source.write_bytes(live_bytes);live_source.chmod(0o444)
        live=system32/live_leaf;live.symlink_to(live_source)
        foreign_leaf='madeira-msi-foreign-'+uuid.uuid4().hex[:8]+'.dll'
        (current/'x86_64-vcruntime'/foreign_leaf).write_bytes(b'catalog name alone is insufficient')
        foreign_target=temporary/'unowned-missing-parent'/foreign_leaf
        foreign=system32/foreign_leaf;foreign.symlink_to(foreign_target)
        assert 'production-repair count=0' in repair(current)
        assert live.is_symlink() and os.readlink(live)==str(live_source)
        assert foreign.is_symlink() and os.readlink(foreign)==str(foreign_target)
        client(64,'--native-create',system_path(live_leaf),'c0000022')
        client(64,'--native-create',system_path(foreign_leaf),'c000000f')
        assert live.is_symlink() and live_source.read_bytes()==live_bytes and foreign.is_symlink()
        assert all(p.read_bytes()==data for p,data in sentinels.items())
        print('PASS actual stock-Wine native controls: invalid-parent PATH_NOT_FOUND, writable overwrite, live readonly-link ACCESS_DENIED, unowned dangling-link NO_SUCH_FILE; migration preserves every noncandidate and sentinel. Existing iOS readonly-replacement semantics are covered separately by production host tests.',flush=True)
    finally:
        for operation in ('-k','-w'):
            subprocess.run(['wineserver',operation],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
print('PASS isolated stock-Wine MSI/CAB integration; on-device iOS/FEX and official VC installer completion remain unverified')
