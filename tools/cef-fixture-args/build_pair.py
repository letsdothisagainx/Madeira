#!/usr/bin/env python3
"""Build matched control/source-wire test DLLs in an isolated source copy."""
from pathlib import Path
import argparse,difflib,json,shutil,subprocess,sys
here=Path(__file__).resolve().parent
native_root=next((parent for parent in here.parents if (parent/'build/ntdll-unix/steam_cef_policy.h').is_file()),None)
if native_root is None:raise SystemExit('native Steam policy source header not found in repository ancestors')
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--provider-root',type=Path,required=True,help='htmlipc-dispatch source root; read only')
p.add_argument('--tier0',type=Path,required=True)
p.add_argument('--tier0-sha256',required=True)
p.add_argument('--test-token',required=True)
p.add_argument('--map-source',type=Path,required=True)
a=p.parse_args();provider=a.provider_root.resolve()
copy=here/'build'/'paired-provider-source';copy.mkdir(parents=True,exist_ok=True)
for name in ('runtime-shim','stream-install','stream-codec','wire-codec','domain-routing'):
    source=provider/name;target=copy/name;target.mkdir(exist_ok=True)
    for source_file in source.iterdir():
        if source_file.suffix in ('.cpp','.h','.py','.def') and source_file.is_file():shutil.copy2(source_file,target/source_file.name)
proxy=provider/'runtime-smoke/version-proxy.def'
control=here/'ControlSameFlags'/'version.dll';control.parent.mkdir(exist_ok=True)
subprocess.run([sys.executable,str(here/'build_fixture.py'),'--experimental-test-only',
    '--tier0',str(a.tier0.resolve()),'--tier0-sha256',a.tier0_sha256,'--test-token',a.test_token,
    '--version-proxy',str(proxy),'--output',str(control)],check=True)
pin_include=here/'build'/'version'
patches=[]
def edit(relative,changes):
    path=copy/relative;old=path.read_text();new=old
    for before,after in changes:
        if new.count(before)!=1:raise SystemExit(f'Integration anchor changed: {relative}: {before!r}')
        new=new.replace(before,after,1)
    path.write_text(new);patches.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
        fromfile='a/'+relative,tofile='b/'+relative))
edit('stream-install/loader.cpp',[
    ('using namespace madeira_stream_install;','using namespace madeira_stream_install;\nextern "C" void MadeiraCefFixtureAttach(void *);'),
    ('extern "C" int DllMain(void *module,U32 reason,void *reserved){\n    if(reason==1){',
     'extern "C" int DllMain(void *module,U32 reason,void *reserved){\n    if(reason==1){\n        MadeiraCefFixtureAttach(module);')])
extra_sources=[here/name for name in ('fixture_args.cpp','iat_install.cpp','windows_loader.cpp','freestanding.cpp')]
edit('runtime-shim/build_runtime.py',[
    ("if args.experimental:flags+=", "flags += "+repr(['-DMADEIRA_CEF_ARGS_TEST_ONLY=1','-DMADEIRA_CEF_ARGS_EMBEDDED=1',
        '-I'+str(here/'compat'),'-I'+str(pin_include),'-I'+str(native_root/'build/ntdll-unix')])+"\nif args.experimental:flags+="),
    ('if args.map_source:sources.append(args.map_source.resolve())',
     'sources += [Path(s) for s in '+repr(list(map(str,extra_sources)))+']\nif args.map_source:sources.append(args.map_source.resolve())'),
    ("libraries=[]", "kernel_exports += ['GetFullPathNameW','GetEnvironmentVariableW','SetLastError']\nlibraries=[]"),
    ("    '    MadeiraResolveCurrentController\\n    MadeiraRuntimeGetStatus\\n')",
     "    '    MadeiraResolveCurrentController\\n    MadeiraRuntimeGetStatus\\n    MadeiraCefFixtureStatus\\n    MadeiraCefFixtureTransformed\\n')")])
(here/'integration.patch').write_text(''.join(patches))
bridge=here/'SourceWireSameFlags'/'version.dll';bridge.parent.mkdir(exist_ok=True)
subprocess.run([sys.executable,str(copy/'runtime-shim/build_runtime.py'),'--experimental',
    '--map-source',str(a.map_source.resolve()),'--version-proxy',str(proxy),'--output',str(bridge)],check=True)
report={'scope':'Build only; no Wine prefix or executable modified; runtime unverified',
        'control':str(control),'candidate':str(bridge),'test_token_env':'MADEIRA_CEF_ARGS_TEST_TOKEN',
        'tier0_sha256':a.tier0_sha256,'policy':'same native Steam browser arguments in both arms',
        'original_provider_root_read_only':str(provider),'source_integration_patch':str(here/'integration.patch')}
(here/'pair.build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
