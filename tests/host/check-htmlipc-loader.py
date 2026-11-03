#!/usr/bin/env python3
"""Compile exact maintained native/PE selection headers with host sanitizers."""
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
def run(command,**kw):subprocess.run([str(x) for x in command],check=True,**kw)
with tempfile.TemporaryDirectory(prefix='madeira-htmlipc-loader-') as folder:
    tmp=Path(folder)
    for name in ('test_policy','test_ready_reader','test_native','test_pe_loader'):
        flags=['-fshort-wchar'] if name=='test_pe_loader' else []
        run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
             '-fsanitize=address,undefined','-fno-omit-frame-pointer','-g',*flags,
             '-I'+str(ROOT/'build/scm-rpc'),'-I'+str(ROOT/'build/ntdll-unix'),
             ROOT/'tests/host/htmlipc'/(name+'.c'),'-o',tmp/name])
        run([tmp/name])
    wine=tmp/'wine';(wine/'dlls/ntdll').mkdir(parents=True)
    for name in ('loader.c','unixlib.h'):
        (wine/'dlls/ntdll'/name).write_bytes((ROOT/'wine/dlls/ntdll'/name).read_bytes())
    run(['git','-C',wine,'init','-q'])
    run(['git','-C',wine,'apply',ROOT/'build/scm-rpc/loader.patch'])
    run(['git','-C',wine,'apply','--check',ROOT/'build/scm-rpc/htmlipc-loader.patch'])
process=(ROOT/'build/ntdll-unix/process_ios.c').read_text()
create=process[process.index('NTSTATUS WINAPI NtCreateUserProcess('):process.index('iOS-Madeira ml661')]
assert create.index('ios_htmlipc_redirect(')<create.index('unixdir = get_unix_curdir( params );')<create.index('get_pe_file_info(')
assert create.index('pe_info.machine != IMAGE_FILE_MACHINE_I386')<create.index('if (!machine)')
assert 'machine = IMAGE_FILE_MACHINE_I386' not in create
assert create.index('if (htmlipc_redirected)\n        {')<create.index('!fork_and_exec(')
assert 'machine, parent, &htmlipc_path' in create
assert 'case (PROCESSINFOCLASS)MADEIRA_HTMLIPC_OWNER_LEASE_CLASS:' in process
native=(ROOT/'build/ntdll-unix/htmlipc_native.h').read_text()
assert 'ios_jit_translate_addr_for_owner' not in native and 'GetStatus' not in native
assert 'a.installed_module==core_module' in native
run(['bash','-n',ROOT/'tools/build/build-scm-rpc.sh'])
print('PASS HTMLIPC loader: scope/readiness/lease/argv/bitness, every read failure, recursion and composed Wine overlays')
