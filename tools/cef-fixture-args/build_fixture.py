#!/usr/bin/env python3
"""Build source-only, disarmed by default; never stages or edits a Wine prefix."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess
import pefile
here=Path(__file__).resolve().parent
native_root=next((parent for parent in here.parents if (parent/'build/ntdll-unix/steam_cef_policy.h').is_file()),None)
if native_root is None:raise SystemExit('native Steam policy source header not found in repository ancestors')
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--experimental-test-only',action='store_true')
p.add_argument('--tier0',type=Path,help='exact untouched official AMD64 tier0_s64.dll')
p.add_argument('--tier0-sha256',help='full independently verified official SHA256, required')
p.add_argument('--test-token',help='32+ hexadecimal chars; same env token required to arm')
p.add_argument('--version-proxy',type=Path,help='source .def forwarding original VERSION exports')
p.add_argument('--output',type=Path,default=here/'MadeiraCefFixtureArgs.dll')
p.add_argument('--zig',default=os.environ.get('MADEIRA_ZIG','/workspace/madeira-tools/bin/python-zig'))
p.add_argument('--linker',default=os.environ.get('MADEIRA_PE_LD','/usr/bin/ld'))
p.add_argument('--objcopy',default=os.environ.get('MADEIRA_PE_OBJCOPY','/usr/bin/objcopy'))
a=p.parse_args()
pin_args=(a.tier0,a.tier0_sha256,a.test_token)
if a.experimental_test_only and not all(pin_args):p.error('experimental test build requires --tier0, --tier0-sha256, --test-token')
if not a.experimental_test_only and any(pin_args):p.error('pin/token input requires --experimental-test-only')
out=a.output.resolve()
if not out.is_relative_to(here):p.error('output must remain under this isolated fixture directory')
build=here/'build'/out.stem;build.mkdir(parents=True,exist_ok=True)
pin=None
if a.experimental_test_only:
    if not re.fullmatch(r'[0-9a-fA-F]{64}',a.tier0_sha256):p.error('full SHA256 required')
    if not re.fullmatch(r'[0-9a-fA-F]{32,96}',a.test_token):p.error('test token must be 32..96 hexadecimal characters')
    raw=a.tier0.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=a.tier0_sha256.lower():p.error('official tier0 SHA256 mismatch')
    pe=pefile.PE(data=raw)
    if pe.FILE_HEADER.Machine!=0x8664:p.error('tier0 must be AMD64')
    imports=[dict(module=d.dll.decode(),name=e.name.decode() if e.name else None,rva=e.address-pe.OPTIONAL_HEADER.ImageBase)
             for d in pe.DIRECTORY_ENTRY_IMPORT for e in d.imports if e.name==b'CreateProcessW']
    if len(imports)!=1 or imports[0]['module'].lower()!='kernel32.dll':p.error('exactly one ordinary KERNEL32!CreateProcessW import required')
    section=pe.get_section_by_rva(imports[0]['rva'])
    if section is None or section.Characteristics&(0x20000000|0x80000000):p.error('CreateProcessW IAT must be in nonexecutable, nonwritable data section')
    pin={'file':str(a.tier0.resolve()),'sha256':digest,'size':len(raw),'machine':hex(pe.FILE_HEADER.Machine),
         'timestamp':hex(pe.FILE_HEADER.TimeDateStamp),'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'create_process_import':imports[0]}
    (build/'fixture_pin.h').write_text('/* Explicit isolated test configuration. */\n'+
        'static constexpr unsigned char fixture_sha256[32]={'+','.join(hex(v) for v in bytes.fromhex(digest))+'};\n'+
        f'static constexpr long long fixture_file_size={len(raw)};\n'+
        'static constexpr char fixture_test_token[]="'+a.test_token+'";\n')
env=dict(os.environ)
if Path('/workspace/madeira-tools').is_dir():env['PYTHONPATH']='/workspace/madeira-tools'
flags=['-target','x86_64-windows-msvc','-std=c++20','-O2','-ffreestanding','-fno-exceptions','-fno-rtti',
       '-fno-builtin','-fno-strict-aliasing','-Wall','-Wextra','-Werror','-Wno-unused-command-line-argument',
       '-g0','-I'+str(here/'compat'),'-I'+str(build),'-I'+str(native_root/'build/ntdll-unix')]
if a.experimental_test_only:flags+=['-DMADEIRA_CEF_ARGS_TEST_ONLY=1']
sources=[here/name for name in ('fixture_args.cpp','iat_install.cpp','windows_loader.cpp','freestanding.cpp')]
objects=[]
for source in sources:
    obj=build/(source.stem+'.obj');objects.append(obj)
    subprocess.run([a.zig,'c++',*flags,'-c',str(source),'-o',str(obj)],env=env,check=True)
    subprocess.run([a.objcopy,'--remove-section','.drectve',str(obj)],check=True)
exports=['GetModuleHandleW','GetModuleHandleExW','GetProcAddress','GetModuleFileNameW','GetEnvironmentVariableW',
         'GetFullPathNameW','GetLastError','SetLastError','VirtualQuery','VirtualProtect','DisableThreadLibraryCalls',
         'GetProcessHeap','HeapAlloc','HeapFree','CreateFileW','GetFileSizeEx','ReadFile','CloseHandle','OutputDebugStringA']
definition=build/'KERNEL32.def';library=build/'KERNEL32.lib'
definition.write_text('LIBRARY KERNEL32.dll\nEXPORTS\n'+''.join('    '+n+'\n' for n in exports))
subprocess.run([a.zig,'dlltool','-m','i386:x86-64','-d',str(definition),'-l',str(library)],env=env,check=True)
definition=build/'fixture_exports.def'
definition.write_text((a.version_proxy.read_text() if a.version_proxy else 'LIBRARY MadeiraCefFixtureArgs\nEXPORTS\n')+
    '\n    MadeiraCefFixtureStatus\n    MadeiraCefFixtureTransformed\n')
subprocess.run([a.linker,'-mi386pep','--dll','--entry=DllMain','--subsystem=windows','--image-base=0x180000000',
    '--no-insert-timestamp','--dynamicbase','--nxcompat','--high-entropy-va','--exclude-all-symbols',
    '-o',str(out),*map(str,objects),str(library),str(definition)],check=True)
raw=out.read_bytes();pe=pefile.PE(data=raw)
assert pe.FILE_HEADER.Machine==0x8664
assert not any(s.Characteristics&0x20000000 and s.Characteristics&0x80000000 for s in pe.sections)
assert not any(s.Name.rstrip(b'\0') in (b'.CRT',b'.ctors') and s.Misc_VirtualSize for s in pe.sections)
imports={d.dll.decode():[e.name.decode() if e.name else '#'+str(e.ordinal) for e in d.imports] for d in pe.DIRECTORY_ENTRY_IMPORT}
assert set(k.lower() for k in imports)<= {'kernel32.dll'}
report={'scope':'Stock Linux Wine isolated test only; no process security gates; no prefix changes',
        'experimental_test_only':a.experimental_test_only,'sha256':hashlib.sha256(raw).hexdigest(),
        'pin':pin,'imports':imports,'writable_executable_sections':False,
        'native_policy_header_sha256':hashlib.sha256((native_root/'build/ntdll-unix/steam_cef_policy.h').read_bytes()).hexdigest(),
        'native_steam_source_sha256':hashlib.sha256((native_root/'build/ntdll-unix/process_ios.c').read_bytes()).hexdigest(),
        'headers':{name:hashlib.sha256((here/name).read_bytes()).hexdigest() for name in ('fixture_args.h','sha256.h','compat/string.h')},
        'sources':{str(s.relative_to(here)):hashlib.sha256(s.read_bytes()).hexdigest() for s in sources}}
out.with_suffix('.build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'result':'PASS','output':str(out),'sha256':report['sha256'],'experimental':a.experimental_test_only,'pin':pin}))
