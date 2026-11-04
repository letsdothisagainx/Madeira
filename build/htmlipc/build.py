#!/usr/bin/env python3
"""Build/package the guarded guest AMD64 source bridge with an MSVC ABI.

The maintained LLVM-MinGW toolchain supplies Clang, DLLTool, Objcopy and LLD.
The --zig dispatcher override exercises equivalent LLVM tools on research hosts;
it does not change the guest target, runtime mode, ABI or packaging gates.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def digest(data):return hashlib.sha256(data).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain',type=Path,default=Path(os.environ.get('LLVM_MINGW',ROOT/'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin')))
    parser.add_argument('--output-dir',type=Path,default=ROOT/'app/Madeira/arm64ec-windows')
    parser.add_argument('--build-dir',type=Path,default=HERE/'obj')
    parser.add_argument('--zig',type=Path,help='explicit local LLVM tool dispatcher override')
    parser.add_argument('--objcopy',type=Path,help='explicit COFF objcopy override')
    args=parser.parse_args()
    validator=ROOT/'tools/check-htmlipc-image.py'
    spec=importlib.util.spec_from_file_location('htmlipc_image',validator)
    image=importlib.util.module_from_spec(spec);spec.loader.exec_module(image)
    def command(tool):
        if args.zig:
            return [str(args.zig),{'compiler':'c++','dlltool':'dlltool','linker':'lld-link'}[tool]]
        name={'compiler':'x86_64-w64-mingw32-clang++','dlltool':'llvm-dlltool','linker':'lld-link'}[tool]
        path=args.toolchain/name
        if not path.is_file():parser.error('required LLVM-MinGW tool missing: '+str(path))
        return [str(path)]
    compiler=command('compiler');dlltool=command('dlltool');linker=command('linker')
    objcopy=args.objcopy or args.toolchain/'llvm-objcopy'
    if not objcopy.is_file():parser.error('required COFF objcopy missing: '+str(objcopy))
    sources=[HERE/'runtime/runtime_provider.cpp',HERE/'runtime/ready_state.cpp',
             HERE/'stream-install/installer.cpp',HERE/'runtime/loader.cpp',
             HERE/'stream-codec/stream_codec.cpp',HERE/'wire-codec/wire_codec.cpp',
             HERE/'runtime/proven_map.cpp']
    sources.append(HERE/'domain-routing/domain_registry.cpp')
    headers=sorted(HERE.rglob('*.h'))
    abi=ROOT/'build/scm-rpc/htmlipc_ready_abi.h'
    closure=sources+headers+[abi,HERE/'runtime/cache-contract.txt',HERE/'runtime/proven-map-manifest.json',HERE/'source-provenance.json']
    source_hashes={path.relative_to(ROOT).as_posix():digest(path.read_bytes()) for path in sorted(set(closure))}
    source_hash=digest(json.dumps(source_hashes,sort_keys=True,separators=(',',':')).encode())
    installer=(HERE/'stream-install/installer.cpp').read_text()
    pinned=re.search(r'static constexpr U8 digest\[32\]=\{([^}]+)\}',installer)
    if not pinned:parser.error('missing current core digest in reviewed installer')
    core=bytes(int(n.strip(),0) for n in pinned[1].split(',')).hex()
    if core!=image.CORE_SHA256:parser.error('current core source pin differs from image/package gate')
    proof=json.loads((HERE/'runtime/proven-map-manifest.json').read_text())
    if proof.get('maintained_source_sha256')!=digest((HERE/'runtime/proven_map.cpp').read_bytes()):
        parser.error('actual proven map differs from its reviewed maintained source hash')
    provider=(HERE/'runtime/runtime_provider.cpp').read_text()
    contract=re.search(r'static constexpr char cache_contract\[\]\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*)+);',provider)
    if not contract:parser.error('missing provider cache contract')
    compiled_contract=''.join(json.loads(s) for s in re.findall(r'"(?:[^"\\]|\\.)*"',contract[1])).encode()
    marker=(HERE/'runtime/cache-contract.txt').read_bytes()
    if compiled_contract!=marker:parser.error('provider and host cache marker contracts differ')
    cache_hash=digest(marker)
    flags=['-target','x86_64-windows-msvc','-std=c++20','-O2','-ffreestanding',
           '-fno-exceptions','-fno-rtti','-fno-builtin','-fno-strict-aliasing',
           '-Wall','-Wextra','-Werror','-Wno-unused-command-line-argument','-g0',
           '-DMADEIRA_RUNTIME_PROVIDER=1','-DMADEIRA_RUNTIME_HAS_PROVEN_MAP=1','-DMADEIRA_RUNTIME_NATIVE_OWNER=1']
    args.output_dir.mkdir(parents=True,exist_ok=True);args.build_dir.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='htmlipc-build-',dir=args.build_dir) as folder:
        build=Path(folder);objects=[]
        for source in sources:
            obj=build/(source.parent.name+'-'+source.name+'.obj');objects.append(obj)
            subprocess.run([*compiler,*flags,'-c',str(source),'-o',str(obj)],check=True)
            # Explicit .def owns exports; retain normal code/unwind/data sections.
            subprocess.run([str(objcopy),'--remove-section','.drectve',str(obj)],check=True)
        kernel=['OutputDebugStringA','GetCurrentProcessId','GetCurrentThreadId','GetModuleFileNameW',
            'GetModuleHandleW','GetModuleHandleExW','GetEnvironmentVariableW','GetProcAddress','GetProcessHeap',
            'HeapAlloc','HeapFree','TryAcquireSRWLockExclusive','ReleaseSRWLockExclusive','Sleep',
            'CreateFileW','GetFileSizeEx','ReadFile','WriteFile','CloseHandle','GetStdHandle',
            'VirtualQuery','VirtualProtect','GetLastError','DisableThreadLibraryCalls']
        libraries=[]
        for name,exports in [('KERNEL32',kernel),('NTDLL',['__C_specific_handler','NtQueryInformationProcess'])]:
            definition=build/(name+'.def');library=build/(name+'.lib')
            definition.write_text('LIBRARY '+name+'.dll\nEXPORTS\n'+''.join('    '+e+'\n' for e in exports))
            subprocess.run([*dlltool,'-m','i386:x86-64','-d',str(definition),'-l',str(library)],check=True)
            libraries.append(library)
        definition=build/'bridge.def'
        definition.write_text('LIBRARY madeira-htmlipc-bridge\nEXPORTS\n'+''.join('    '+name+(' DATA' if name=='MadeiraRuntimeReady' else '')+'\n' for name in sorted(image.EXPORTS)))
        output=build/image.FILENAME
        subprocess.run([*linker,'/dll','/entry:DllMain','/subsystem:windows','/machine:x64',
                        '/nodefaultlib','/dynamicbase','/nxcompat','/highentropyva','/timestamp:0',
                        '/opt:ref','/opt:icf','/incremental:no','/base:0x180000000',
                        '/out:'+str(output),'/def:'+str(definition),*map(str,objects),*map(str,libraries)],check=True)
        raw=output.read_bytes();summary=image.inspect_image(raw);abi_hash=digest(abi.read_bytes())
        report={'format':1,'scope':'source-built native-owner AMD64 bridge; runtime/Steam UI unclaimed',
            'experimental_auto_arm':True,'native_owner':True,'stock_wine_test':False,
            'compiler_target':'x86_64-windows-msvc','sha256':summary['sha256'],'size':len(raw),
            'sources':source_hashes,'imports':summary['imports'],'exports':summary['exports'],
            'writable_executable_sections':False,'static_constructor_sections':False,
            'ready_data':{'name':'MadeiraRuntimeReady','size':80,'version':1,'abi_sha256':abi_hash,
                          'forwarder':False,'executable':False,'shared_section':False},
            'owner_query_class':'0x4d480001','cache_environment':'MADEIRA_HTMLIPC_CACHE_DIR',
            'core_sha256':core,'cache_marker_sha256':cache_hash,'diagnostics_merged':True,
            'tools':{'compiler':compiler,'dlltool':dlltool,'linker':linker,'objcopy':str(objcopy)}}
        manifest={'format':1,'mode':'native-owner','filename':image.FILENAME,'bytes':len(raw),
                  'sha256':summary['sha256'],'coreSHA256':core,
                  'readinessABI':{'version':1,'size':80,'sha256':abi_hash},
                  'sourceSHA256':source_hash,'cacheMarkerSHA256':cache_hash}
        manifest_path=build/'madeira-htmlipc-bridge.manifest.json';manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
        report_path=build/'madeira-htmlipc-bridge.build.json';report_path.write_text(json.dumps(report,indent=2)+'\n')
        image.check(output,manifest_path,abi,report_path,ROOT)
        # Only verified generated outputs replace the staged resources. Runtime
        # prefix ownership/copy happens later in the Steam-specific frontend.
        for path,destination in [(output,args.output_dir/image.FILENAME),
                                 (manifest_path,args.output_dir/manifest_path.name),
                                 (report_path,args.build_dir/report_path.name)]:
            os.replace(path,destination)
    print('PASS built/staged native-owner AMD64 source DLL + Ready DATA80 manifest:',summary['sha256'])

if __name__=='__main__':main()
