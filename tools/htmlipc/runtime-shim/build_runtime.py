#!/usr/bin/env python3
"""Build a real freestanding MSVC-ABI guest PE DLL, disarmed by default."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
import pefile
here=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('--experimental',action='store_true',help='compile early provider auto-arm with actual proven map')
parser.add_argument('--map-source',type=Path,help='actual independently proven MadeiraRuntimeGetWireMap implementation')
parser.add_argument('--version-proxy',type=Path,help='real VERSION export-forwarder .def for isolated smoke prefix')
parser.add_argument('--zig',default=os.environ.get('MADEIRA_ZIG','/workspace/madeira-tools/bin/python-zig'))
parser.add_argument('--linker',default=os.environ.get('MADEIRA_PE_LD','ld'))
parser.add_argument('--objcopy',default=os.environ.get('MADEIRA_PE_OBJCOPY','objcopy'))
parser.add_argument('--output',type=Path,default=here/'MadeiraHtmlIPCBridge.dll')
args=parser.parse_args()
if args.experimental and not args.map_source:parser.error('--experimental requires --map-source; no fixture/default map is provided')
if args.map_source and not args.experimental:parser.error('--map-source requires explicit --experimental')
output=args.output.resolve();output.parent.mkdir(parents=True,exist_ok=True)
build=here/'build'/output.stem;build.mkdir(parents=True,exist_ok=True)
environment=dict(os.environ)
if Path('/workspace/madeira-tools').is_dir():environment['PYTHONPATH']='/workspace/madeira-tools'
flags=['-target','x86_64-windows-msvc','-std=c++20','-O2','-ffreestanding',
       '-fno-exceptions','-fno-rtti','-fno-builtin','-fno-strict-aliasing',
       '-Wall','-Wextra','-Werror','-Wno-unused-command-line-argument','-g0']
if args.experimental:flags+=['-DMADEIRA_RUNTIME_PROVIDER=1','-DMADEIRA_RUNTIME_HAS_PROVEN_MAP=1']
sources=[here/'runtime_provider.cpp',here.parent/'stream-install/installer.cpp',
         here.parent/'stream-install/loader.cpp',here.parent/'stream-codec/stream_codec.cpp',
         here.parent/'wire-codec/wire_codec.cpp']
if args.map_source:sources.append(args.map_source.resolve())
objects=[]
for source in sources:
    obj=build/(source.parent.name+'-'+source.name+'.obj');objects.append(obj)
    subprocess.run([args.zig,'c++',*flags,'-c',str(source),'-o',str(obj)],env=environment,check=True)
    # GNU PE ld does not consume Clang's MSVC /EXPORT directives. Export the
    # same public names using an explicit .def; remove only that linker data.
    subprocess.run([args.objcopy,'--remove-section','.drectve',str(obj)],check=True)
kernel_exports=['GetCurrentProcessId','GetCurrentThreadId','GetModuleFileNameW',
    'GetModuleHandleW','GetModuleHandleExW','GetProcAddress','GetProcessHeap',
    'HeapAlloc','HeapFree','TryAcquireSRWLockExclusive','ReleaseSRWLockExclusive',
    'Sleep','CreateFileW','GetFileSizeEx','ReadFile','WriteFile','CloseHandle',
    'GetStdHandle','VirtualQuery','VirtualProtect','GetLastError','DisableThreadLibraryCalls']
libraries=[]
for name,exports in [('KERNEL32',kernel_exports),('NTDLL',['__C_specific_handler'])]:
    definition=build/(name+'.def');library=build/(name+'.lib')
    definition.write_text('LIBRARY '+name+'.dll\nEXPORTS\n'+''.join('    '+e+'\n' for e in exports))
    subprocess.run([args.zig,'dlltool','-m','i386:x86-64','-d',str(definition),'-l',str(library)],env=environment,check=True)
    libraries.append(library)
link=[args.linker,'-mi386pep','--dll','--entry=DllMain','--subsystem=windows',
      '--image-base=0x180000000','--no-insert-timestamp','--dynamicbase','--nxcompat',
      '--high-entropy-va','--exclude-all-symbols','-o',str(output),*map(str,objects),*map(str,libraries)]
definition=build/'runtime-exports.def'
definition.write_text((args.version_proxy.read_text() if args.version_proxy else 'LIBRARY MadeiraHtmlIPCBridge\nEXPORTS\n')+
    '\n    MadeiraArmStreamInstaller\n    MadeiraStreamInstallerStatus\n'+
    '    MadeiraResolveCurrentController\n    MadeiraRuntimeGetStatus\n')
link.append(str(definition))
subprocess.run(link,check=True)
raw=output.read_bytes();pe=pefile.PE(data=raw)
assert pe.FILE_HEADER.Machine==0x8664
assert pe.OPTIONAL_HEADER.AddressOfEntryPoint
assert not any(s.Characteristics&0x20000000 and s.Characteristics&0x80000000 for s in pe.sections)
imports={d.dll.decode():[e.name.decode() if e.name else '#'+str(e.ordinal) for e in d.imports]
         for d in pe.DIRECTORY_ENTRY_IMPORT}
assert set(name.lower() for name in imports)<= {'kernel32.dll','ntdll.dll'}
exports={e.name.decode():(e.forwarder.decode() if e.forwarder else hex(e.address))
         for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
assert 'MadeiraRuntimeGetStatus' in exports
assert 'MadeiraArmStreamInstaller' in exports
assert not any(s.Name.rstrip(b'\0') in (b'.CRT',b'.ctors') and s.Misc_VirtualSize for s in pe.sections)
report={'scope':'source-built guest AMD64 DLL; no app activation or Steam startup assertion',
        'experimental_auto_arm':args.experimental,'output':str(output),
        'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'compiler_target':'x86_64-windows-msvc',
        'sources':{str(p.relative_to(here.parent)) if p.is_relative_to(here.parent) else str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        'imports':imports,'exports':exports,'writable_executable_sections':False,
        'static_constructor_sections':False,'proven_map_required_for_auto_arm':True}
output.with_suffix('.build.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS built guest AMD64 PE DLL:',output,hashlib.sha256(raw).hexdigest())
