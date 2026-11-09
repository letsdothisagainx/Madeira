#!/usr/bin/env python3
"""Run the real utility build transaction with explicit make/strip adapters.

The adapters supply owned PE fixtures, not executable compilation. This proves
target selection, unchanged I386 utilities, source restoration and error paths;
the Actions worker must still compile and validate the actual Wine programs.
"""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('registration_build_fixtures',ROOT/'tests/host/check-native-registration-tools.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


def setup(directory):
    # Apple's temporary root may be /var/folders, whose physical cwd is
    # /private/var/folders. Treat owned fixture locations by directory identity.
    directory=directory.resolve()
    root=directory/'repo';root.mkdir()
    stage,source,unused_app,unused_ipa=fixture.fixture_tree(directory/'fixtures')
    shutil.copytree(stage,root/'app/Madeira');shutil.copytree(source,root/'wine')
    for relative in ('build/wine-pe/build-system-programs.sh','build/wine-pe/process_lookup_trace.h',
                     'tools/build/stage-process-lookup.py','tools/check-system-programs.py'):
        target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
    process=root/'wine/dlls/kernelbase/process.c';process.parent.mkdir(parents=True)
    process.write_bytes((ROOT/'wine/dlls/kernelbase/process.c').read_bytes())
    subprocess.run(['git','init','-q',str(root/'wine')],check=True)
    subprocess.run(['git','-C',str(root/'wine'),'add','.'],check=True)
    subprocess.run(['git','-C',str(root/'wine'),'-c','user.name=Owned Fixture','-c','user.email=fixture@example.invalid','commit','-qm','owned stock source fixture'],check=True)
    for tree,farm in (('build-macos','aarch64-windows'),('build-arm64ec','arm64ec-windows'),('build-i386','i386-windows')):
        build=root/'wine'/tree;build.mkdir();(build/'Makefile').write_text('# owned build adapter\n')
        for part,name in (('dlls/kernelbase','kernelbase.dll'),('programs/regsvr32','regsvr32.exe'),('programs/rundll32','rundll32.exe')):
            path=build/part/farm/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((stage/farm/name).read_bytes())
            saved=root/'prebuilt'/farm/name;saved.parent.mkdir(parents=True,exist_ok=True);saved.write_bytes(path.read_bytes())
        (build/'dlls/kernelbase'/farm/'process.o').write_bytes(b'owned stale build object')
        if farm!='i386-windows':
            for program in ('regsvr32','rundll32'):(root/'app/Madeira'/farm/(program+'.exe')).unlink()
    toolchain=root/'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin';toolchain.mkdir(parents=True)
    make=r'''#!/usr/bin/env python3
import json,os,sys,shutil
from pathlib import Path
root=Path(os.environ['ROOT']).resolve();process=root/'wine/dlls/kernelbase/process.c'
assert 'madeira_process_lookup_trace.h' in process.read_text()
assert (process.parent/'madeira_process_lookup_trace.h').is_file()
with (root/'calls.jsonl').open('a') as stream:stream.write(json.dumps(sys.argv[1:])+'\n')
if os.environ.get('FAIL_MAKE_TREE','!') in sys.argv[2]:raise SystemExit(37)
build=Path(sys.argv[2])
for name in sys.argv[3:]:
 if not name.endswith(('.exe','.dll')):continue
 target=build/name;farm=target.parent.name
 if target.name=='kernelbase.dll':
  assert not target.exists(),'stale patched DLL was not removed'
  assert not target.with_name('process.o').exists(),'stale patched process object was not removed'
 shutil.copyfile(root/'prebuilt'/farm/target.name,target)
 if target.name=='kernelbase.dll':target.with_name('process.o').write_bytes(b'owned current build object')
'''
    strip=r'''#!/usr/bin/env python3
import shutil,sys
assert sys.argv[1:3]==['--strip-debug','-o']
shutil.copyfile(sys.argv[4],sys.argv[3])
'''
    for name,text in [('make',make),*[(triple+'-w64-mingw32-strip',strip) for triple in ('aarch64','arm64ec','i686')]]:
        path=toolchain/name;path.write_text(text);path.chmod(0o755)
    (root/'tmp').mkdir()
    configure=root/'wine/configure'
    configure.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
root=Path(os.environ['ROOT']).resolve()
assert Path.cwd().resolve()==(root/'wine/build-i386').resolve()
assert sys.argv[1:]==['--enable-archs=i386','--without-x','--without-vulkan','--without-freetype','--without-gnutls','--disable-tests','--enable-winegstreamer']
(Path.cwd()/'Makefile').write_text('# owned configured tree\\n')
(root/'configure-calls.json').write_text(json.dumps(sys.argv[1:]))
''');configure.chmod(0o755)
    return root,process


def run(root,**extra):
    result=subprocess.run(['bash',str(root/'build/wine-pe/build-system-programs.sh')],
                          env={**os.environ,'ROOT':str(root),'JOBS':'2','TMPDIR':str(root/'tmp'),**extra},
                          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
    assert len(result.stdout)<1024*1024,'unbounded build fixture output'
    return result


with tempfile.TemporaryDirectory(prefix='madeira-system-program-build-') as directory:
    root,process=setup(Path(directory));before=process.read_bytes()
    i386={p.name:p.read_bytes() for p in(root/'app/Madeira/i386-windows').glob('*.exe')}
    result=run(root);assert result.returncode==0,result.stdout.decode(errors='replace')
    calls=[json.loads(line) for line in(root/'calls.jsonl').read_text().splitlines()]
    assert len(calls)==3
    targets=[argument for call in calls for argument in call if argument.endswith(('.exe','.dll'))]
    assert len(targets)==7
    for farm in ('aarch64-windows','arm64ec-windows'):
        for program in ('regsvr32','rundll32'):assert 'programs/'+program+'/'+farm+'/'+program+'.exe' in targets
    assert not any('/i386-windows/' in t and t.endswith('.exe') for t in targets)
    assert all((root/'app/Madeira/i386-windows'/name).read_bytes()==data for name,data in i386.items())
    assert process.read_bytes()==before and not(process.parent/'madeira_process_lookup_trace.h').exists()
    fixture.check(root/'app/Madeira',root/'wine')
    (root/'calls.jsonl').unlink()
    (root/'wine/build-i386/Makefile').unlink()
    # Exercise the same physical/logical temporary-path distinction on Linux
    # too, instead of waiting for another macOS runner to expose it.
    alias=root.parent/'repo-alias';alias.symlink_to(root,target_is_directory=True)
    result=run(alias);assert result.returncode==0,result.stdout.decode(errors='replace')
    assert (root/'configure-calls.json').is_file() and (root/'wine/build-i386/Makefile').is_file()
    assert len((root/'calls.jsonl').read_text().splitlines())==3
    assert all((root/'app/Madeira/i386-windows'/name).read_bytes()==data for name,data in i386.items())
    assert process.read_bytes()==before and not(process.parent/'madeira_process_lookup_trace.h').exists()
    (root/'calls.jsonl').unlink()
    result=run(root,FAIL_MAKE_TREE='build-arm64ec');assert result.returncode==37,result.stdout.decode(errors='replace')
    assert process.read_bytes()==before and not(process.parent/'madeira_process_lookup_trace.h').exists()
    assert len((root/'calls.jsonl').read_text().splitlines())==2
    (root/'calls.jsonl').unlink()
    stock=root/'wine/programs/regsvr32/regsvr32.c';stock.write_bytes(stock.read_bytes()+b'\n/* owned mutation */\n')
    result=run(root);assert result.returncode and b'Refusing modified stock registration program' in result.stdout
    assert not(root/'calls.jsonl').exists() and process.read_bytes()==before
print('PASS actual registration build transaction: warm-cache I386 configure-only recovery, stale process object/DLL removal, four native stock program targets + three kernelbase targets, preserved I386 tools, strict PE/package checks, exact source restoration after successful/failed builds, modified stock sources refused')
print('Make/strip are explicit adapters; actual cross-compilation and official DirectX execution remain Actions/device checks')
