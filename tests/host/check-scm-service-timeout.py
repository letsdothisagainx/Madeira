#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply the staged SCM overlay in a temporary tree and run its real C paths."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-scm-source-') as directory:
    tree = Path(directory)
    source_path = tree / 'programs/services/services.c'
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes((root / 'wine/programs/services/services.c').read_bytes())
    subprocess.run(['git', '-C', str(tree), 'apply', '--check', str(root / 'build/scm-rpc/services.patch')], check=True)
    subprocess.run(['git', '-C', str(tree), 'apply', str(root / 'build/scm-rpc/services.patch')], check=True)
    source = source_path.read_text()

def function(signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

default = re.search(r'^DWORD service_pipe_timeout = [^;]+;', source, re.M).group(0)
code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef uint32_t DWORD; typedef int32_t LONG; typedef uint16_t WCHAR;
typedef int BOOL; typedef unsigned char BYTE; typedef uint64_t ULONGLONG;
typedef void *HANDLE; typedef void *HKEY;
typedef const WCHAR *LPCWSTR;
typedef struct {DWORD Offset,OffsetHigh;HANDLE hEvent;} OVERLAPPED;
#define TRUE 1
#define FALSE 0
#define MAXDWORD UINT32_MAX
#define INFINITE UINT32_MAX
#define REG_SZ 1
#define REG_DWORD 4
#define REG_QWORD 11
#define REG_EXPAND_SZ 2
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define WAIT_FAILED UINT32_MAX
#define ERROR_SUCCESS 0
#define ERROR_IO_PENDING 997
#define ERROR_PIPE_CONNECTED 535
#define ERROR_SERVICE_REQUEST_TIMEOUT 1053
#define ERROR_NOT_ENOUGH_SERVER_MEMORY 1130
#define SERVICE_CONTROL_START 0x100
#define HKEY_LOCAL_MACHINE ((HKEY)1)
#define WINE_TRACE(...) ((void)0)
#define WINE_ERR(...) ((void)0)
static DWORD service_kill_timeout=60000,autostart_delay=120000;
''' + default + r'''
static unsigned registry_open_error,registry_query_error,registry_closes;
static DWORD registry_type,registry_bytes;
static BYTE registry_data[256];
static int wide_is(const WCHAR *value,const char *ascii) {
    while (*ascii) if (*value++!=(unsigned char)*ascii++) return 0;
    return !*value;
}
static LONG RegOpenKeyW(HKEY root,const WCHAR *name,HKEY *key) {
    assert(root==HKEY_LOCAL_MACHINE&&wide_is(name,"System\\CurrentControlSet\\Control"));
    if (!registry_open_error) *key=(HKEY)2;
    return registry_open_error;
}
static LONG RegQueryValueExW(HKEY key,const WCHAR *name,void *reserved,DWORD *type,BYTE *out,DWORD *count) {
    assert(key==(HKEY)2&&!reserved);
    if (!wide_is(name,"ServicesPipeTimeout")) return 2;
    if (registry_query_error) return registry_query_error;
    *type=registry_type;
    if (*count<registry_bytes) {*count=registry_bytes;return 234;}
    memcpy(out,registry_data,registry_bytes);*count=registry_bytes;return 0;
}
static LONG RegCloseKey(HKEY key) {assert(key==(HKEY)2);registry_closes++;return 0;}
/* Only unrelated legacy values call wcstol; their fixture queries are absent. */
static long unused_wcstol(const WCHAR *value,WCHAR **end,int radix) {
    (void)value;(void)end;(void)radix;assert(0);return 0;
}
#define wcstol unused_wcstol
''' + function('static BOOL parse_service_pipe_timeout(') + '\n' + function('static void load_registry_parameters(') + r'''
static DWORD last_error,wait_result,connect_error,overlap_error,protocol_result;
static BOOL connect_result,overlap_result,protocol_ok;
static unsigned waits,cancels,overlaps,controls,reports;
static DWORD diagnostic_wait,diagnostic_error,diagnostic_timeout;
static BOOL diagnostic_connected;
static char diagnostic_outcome[32];
static ULONGLONG tick;
static LONG InterlockedIncrement(LONG *n) {return ++*n;}
static ULONGLONG GetTickCount64(void) {return tick;}
static int record_diagnostic(const char *format,...) {
    assert(strstr(format,"[scm-pipe-wait-v1]"));
    va_list ap;va_start(ap,format);
    const char *outcome=va_arg(ap,const char *);
    snprintf(diagnostic_outcome,sizeof(diagnostic_outcome),"%s",outcome);
    diagnostic_wait=(DWORD)va_arg(ap,unsigned long);
    (void)va_arg(ap,unsigned long long);
    diagnostic_timeout=(DWORD)va_arg(ap,unsigned long);
    diagnostic_connected=(BOOL)va_arg(ap,unsigned long);
    diagnostic_error=(DWORD)va_arg(ap,unsigned long);va_end(ap);
    reports++; last_error=87; /* logging must not corrupt the captured I/O error */
    return 0;
}
#undef WINE_ERR
#define WINE_ERR record_diagnostic
''' + function('static void trace_service_pipe_wait(') + r'''
#undef WINE_ERR
#define WINE_ERR(...) ((void)0)
struct process_entry {HANDLE control_pipe,overlapped_event,process;};
static BOOL ConnectNamedPipe(HANDLE pipe,OVERLAPPED *o) {
    assert(pipe==(HANDLE)3&&o->hEvent==(HANDLE)4);last_error=connect_error;return connect_result;
}
static DWORD GetLastError(void) {return last_error;}
static DWORD WaitForMultipleObjects(DWORD count,const HANDLE *handles,BOOL all,DWORD timeout) {
    assert(count==2&&handles[0]==(HANDLE)4&&handles[1]==(HANDLE)5&&!all);
    assert(timeout==service_pipe_timeout&&timeout&&timeout!=INFINITE);waits++;tick+=37;return wait_result;
}
static BOOL CancelIo(HANDLE pipe) {assert(pipe==(HANDLE)3);cancels++;last_error=995;return TRUE;}
static BOOL GetOverlappedResult(HANDLE pipe,OVERLAPPED *o,DWORD *len,BOOL wait) {
    assert(pipe==(HANDLE)3&&o->hEvent==(HANDLE)4&&!wait);overlaps++;*len=0;
    last_error=overlap_error;return overlap_result;
}
static DWORD lstrlenW(const WCHAR *s) {DWORD n=0;while(s[n])n++;return n;}
static WCHAR *lstrcpyW(WCHAR *out,const WCHAR *in) {WCHAR *r=out;while((*out++=*in++)) {} return r;}
static BOOL process_send_control(struct process_entry *p,BOOL shared,const WCHAR *name,DWORD command,
                                const BYTE *data,DWORD len,DWORD *result) {
    assert(p->control_pipe==(HANDLE)3&&!shared&&wide_is(name,"Steam Client Service"));
    assert(command==SERVICE_CONTROL_START&&len>=sizeof(WCHAR)*22&&data);
    controls++;*result=protocol_result;return protocol_ok;
}
''' + function('static DWORD process_send_start_message(') + r'''
static DWORD start(void) {
    struct process_entry process={(HANDLE)3,(HANDLE)4,(HANDLE)5};
    return process_send_start_message(&process,FALSE,L"Steam Client Service",NULL,0);
}
static void reset_wait(void) {
    connect_result=FALSE;connect_error=ERROR_IO_PENDING;
    overlap_result=TRUE;overlap_error=0;protocol_ok=TRUE;protocol_result=0;
    wait_result=WAIT_OBJECT_0;waits=cancels=overlaps=controls=0;tick=100;
}
static DWORD reg_string(const char *ascii,WCHAR *out) {
    DWORD n=0;do {out[n]=(unsigned char)ascii[n];} while(ascii[n++]);return n*sizeof(WCHAR);
}
static void invalid(DWORD type,const void *data,DWORD count) {
    DWORD unchanged=0x12345678;
    assert(!parse_service_pipe_timeout(type,data,count,&unchanged)&&unchanged==0x12345678);
}
int main(void) {
    assert(sizeof(WCHAR)==2&&service_pipe_timeout==30000);
    DWORD parsed=0,value;
    const DWORD valid[]={1,10000,30000,45000,60000,UINT32_MAX-1};
    for(unsigned i=0;i<sizeof(valid)/sizeof(*valid);i++) {
        value=valid[i];assert(parse_service_pipe_timeout(REG_DWORD,&value,sizeof(value),&parsed)&&parsed==value);
    }
    BYTE unaligned[8]={0};value=45000;memcpy(unaligned+1,&value,4);
    assert(parse_service_pipe_timeout(REG_DWORD,unaligned+1,4,&parsed)&&parsed==45000);
    value=0;invalid(REG_DWORD,&value,4);value=INFINITE;invalid(REG_DWORD,&value,4);
    value=30000;invalid(REG_DWORD,&value,3);invalid(REG_DWORD,&value,8);
    assert(!parse_service_pipe_timeout(REG_DWORD,&value,4,NULL));
    invalid(REG_QWORD,&value,4);invalid(REG_EXPAND_SZ,&value,4);invalid(REG_DWORD,NULL,4);
    WCHAR text[80];
    const char *good[]={"1","30000","+45000"," \t+60000\r\n","4294967294"};
    const DWORD expected[]={1,30000,45000,60000,UINT32_MAX-1};
    for(unsigned i=0;i<sizeof(good)/sizeof(*good);i++) {
        DWORD count=reg_string(good[i],text);
        assert(parse_service_pipe_timeout(REG_SZ,text,count,&parsed)&&parsed==expected[i]);
    }
    const char *bad[]={"","0","000","-1","-30000","+"," \t\r\n","30000ms","30 000","4294967295","4294967296","999999999999999999999999"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++)invalid(REG_SZ,text,reg_string(bad[i],text));
    DWORD count=reg_string("30000",text);invalid(REG_SZ,text,count-1);invalid(REG_SZ,text,count-2);
    reg_string("30000",text);text[6]='x';text[7]=0;invalid(REG_SZ,text,16); /* embedded NUL */

    registry_open_error=2;load_registry_parameters();assert(service_pipe_timeout==30000&&!registry_closes);
    registry_open_error=0;registry_query_error=2;load_registry_parameters();assert(service_pipe_timeout==30000&&registry_closes==1);
    registry_query_error=0;registry_type=REG_DWORD;registry_bytes=4;value=45000;memcpy(registry_data,&value,4);
    load_registry_parameters();assert(service_pipe_timeout==45000&&registry_closes==2);
    service_pipe_timeout=30000;value=0;memcpy(registry_data,&value,4);
    load_registry_parameters();assert(service_pipe_timeout==30000);
    registry_type=REG_SZ;registry_bytes=reg_string("60000",text);memcpy(registry_data,text,registry_bytes);
    load_registry_parameters();assert(service_pipe_timeout==60000);
    assert(service_kill_timeout==60000&&autostart_delay==120000);

    /* Finite configured DWORD duration reaches the actual SCM wait unchanged. */
    service_pipe_timeout=45000;reset_wait();assert(start()==0&&waits==1&&!cancels&&overlaps==1&&controls==1);
    assert(diagnostic_wait==WAIT_OBJECT_0&&diagnostic_timeout==45000&&diagnostic_connected&&diagnostic_error==0&&!strcmp(diagnostic_outcome,"event"));
    reset_wait();wait_result=WAIT_OBJECT_0+1;overlap_result=FALSE;overlap_error=995;
    assert(start()==1053&&waits==1&&cancels==1&&overlaps==1&&!controls);
    assert(diagnostic_error==995&&!diagnostic_connected&&!strcmp(diagnostic_outcome,"process-exit"));
    reset_wait();wait_result=WAIT_TIMEOUT;overlap_result=FALSE;overlap_error=995;
    assert(start()==1053&&cancels==1&&!controls&&!strcmp(diagnostic_outcome,"timeout"));
    reset_wait();wait_result=WAIT_FAILED;overlap_result=FALSE;overlap_error=6;
    assert(start()==1053&&cancels==1&&!controls&&diagnostic_error==6&&!strcmp(diagnostic_outcome,"wait-error"));
    reset_wait();wait_result=WAIT_TIMEOUT; /* connection completed at the timeout boundary */
    assert(start()==0&&cancels==1&&controls==1);
    reset_wait();connect_result=TRUE;assert(!start()&&!waits&&!cancels&&!overlaps&&controls==1);
    reset_wait();connect_error=ERROR_PIPE_CONNECTED;assert(!start()&&!waits&&controls==1);
    reset_wait();connect_error=5;assert(start()==1053&&!waits&&!controls);
    reset_wait();protocol_ok=FALSE;assert(start()==1053&&controls==1);
    reset_wait();protocol_result=193;assert(start()==193&&controls==1);
    for(unsigned i=0;i<100;i++) {reset_wait();assert(!start());}
    assert(reports==32); /* bounded per process; no names/account data printed */
    puts("PASS patched SCM: Windows 30s default, finite DWORD/legacy string configuration and malformed-value rejection; real event/process-exit/timeout/error/race outcomes, protocol failures and bounded diagnostics");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-scm-test-') as directory:
    path=Path(directory);(path/'test.c').write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    str(path/'test.c'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)

# Run the real staging script against a disposable miniature Wine checkout.
# Builders are mocked, not the trap, dirty-source guard, overlay application,
# cache removal, architecture validation or native producer selection.
import shutil
import struct
with tempfile.TemporaryDirectory(prefix='madeira-scm-build-') as directory:
    fake=Path(directory);wine=fake/'wine'
    paths=('dlls/ntdll/loader.c','dlls/ntdll/unixlib.h',
           'dlls/sechost/Makefile.in','programs/services/services.c')
    originals={p:(root/'wine'/p).read_bytes() for p in paths}
    for p,data in originals.items():
        dest=wine/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    subprocess.run(['git','-C',str(wine),'init','-q'],check=True)
    subprocess.run(['git','-C',str(wine),'add','.'],check=True)
    subprocess.run(['git','-C',str(wine),'-c','user.name=SCM Fixture','-c','user.email=scm-fixture@example.invalid',
                    'commit','-qm','pinned fixture'],check=True)
    for relative in ('tools/build/build-scm-rpc.sh','build/scm-rpc/loader.patch',
                     'build/scm-rpc/services.patch','build/scm-rpc/aux-slot.h',
                     'build/scm-rpc/htmlipc-loader.patch','build/scm-rpc/htmlipc_pe_loader.h',
                     'build/scm-rpc/htmlipc_policy.h','build/scm-rpc/htmlipc_ready_abi.h'):
        dest=fake/relative;dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(root/relative,dest)
    build=wine/'build-macos';build.mkdir();(build/'config.status').write_text('fixture')
    native=fake/'app/Madeira/aarch64-windows/services.exe';native.parent.mkdir(parents=True)
    native.write_bytes(b'previous native SCM')
    tc=fake/'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin';tc.mkdir(parents=True)
    def executable(relative,body):
        dest=fake/relative;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(body);dest.chmod(0o755)
    executable('tools/assert-scm-overlays.py',r'''import os
from pathlib import Path
r=Path(os.environ['FAKE_SCM_ROOT'])
s=(r/'wine/programs/services/services.c').read_text()
assert 'DWORD service_pipe_timeout = 30000;' in s and '[scm-pipe-wait-v1]' in s
assert 'parse_service_pipe_timeout' in s
assert (r/'wine/dlls/ntdll/madeira_scm_aux_slot.h').read_bytes()==(r/'build/scm-rpc/aux-slot.h').read_bytes()
assert 'madeira_scm_aux_slot.h' in (r/'wine/dlls/ntdll/loader.c').read_text()
assert 'madeira_htmlipc_before_chromehtml' in (r/'wine/dlls/ntdll/loader.c').read_text()
for source,target in [('htmlipc_pe_loader.h','madeira_htmlipc_pe_loader.h'),('htmlipc_policy.h','htmlipc_policy.h'),('htmlipc_ready_abi.h','htmlipc_ready_abi.h')]:
    assert (r/'wine/dlls/ntdll'/target).read_bytes()==(r/'build/scm-rpc'/source).read_bytes()
''')
    for phase,name in [('ntdll','build-ntdll.sh'),('sechost','build-modules.sh')]:
        executable('build/wine-pe/'+name,
                   '#!/usr/bin/env bash\nset -e\npython3 "$FAKE_SCM_ROOT/tools/assert-scm-overlays.py"\n'
                   +f'if [[ "${{FAKE_SCM_FAIL:-}}" == "{phase}" ]]; then exit 17; fi\n')
    executable('tools/check-scm-rpc-image.py','pass\n')
    executable(str(tc.relative_to(fake)/'aarch64-w64-mingw32-strip'),
               '#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n'
               'assert sys.argv[1]=="--strip-debug" and Path(sys.argv[2]).is_file()\n')
    executable(str(tc.relative_to(fake)/'make'),r'''#!/usr/bin/env python3
import os,struct,subprocess,sys
from pathlib import Path
r=Path(os.environ['FAKE_SCM_ROOT'])
subprocess.run([sys.executable,str(r/'tools/assert-scm-overlays.py')],check=True)
assert sys.argv[-1]=='programs/services/aarch64-windows/services.exe'
b=Path(sys.argv[sys.argv.index('-C')+1]);assert b==r/'wine/build-macos'
out=b/sys.argv[-1]
assert not out.exists() and not out.with_suffix('.o').exists(),'stale SCM cache was not invalidated'
if os.environ.get('FAKE_SCM_FAIL')=='services':sys.exit(18)
data=bytearray(512);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
data[0x80:0x84]=b'PE\0\0';struct.pack_into('<H',data,0x84,0x8664 if os.environ.get('FAKE_SCM_BAD_MACHINE') else 0xaa64)
if not os.environ.get('FAKE_SCM_NO_MARKER'):data[0x100:0x112]=b'[scm-pipe-wait-v1]'
out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
''')
    def staged_run(extra=None):
        stale=build/'programs/services/aarch64-windows/services.exe'
        stale.parent.mkdir(parents=True,exist_ok=True);stale.write_bytes(b'stale cached SCM')
        stale.with_suffix('.o').write_bytes(b'stale object')
        return subprocess.run(['bash',str(fake/'tools/build/build-scm-rpc.sh')],cwd=fake,
                              env=dict(os.environ,FAKE_SCM_ROOT=str(fake),JOBS='2',**(extra or {})),
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    def restored():
        for p,data in originals.items():assert (wine/p).read_bytes()==data,p
        assert not (wine/'dlls/ntdll/madeira_scm_aux_slot.h').exists()
        for header in ('madeira_htmlipc_pe_loader.h','htmlipc_policy.h','htmlipc_ready_abi.h'):
            assert not (wine/'dlls/ntdll'/header).exists()
        assert not (fake/'app/Madeira/arm64ec-windows/services.exe').exists(),'new hybrid SCM producer changed architecture selection'
    result=staged_run();assert result.returncode==0,result.stdout;restored()
    image=native.read_bytes();assert b'[scm-pipe-wait-v1]' in image
    assert struct.unpack_from('<H',image,0x84)[0]==0xaa64
    for failure in ('ntdll','sechost','services'):
        result=staged_run({'FAKE_SCM_FAIL':failure});assert result.returncode,result.stdout;restored()
        assert native.read_bytes()==image,'failed build replaced the staged SCM'
    for failure in ('FAKE_SCM_BAD_MACHINE','FAKE_SCM_NO_MARKER'):
        result=staged_run({failure:'1'});assert result.returncode,result.stdout;restored()
        assert native.read_bytes()==image,'invalid/stale producer replaced the staged SCM'
    dirty=wine/'programs/services/services.c';changed=dirty.read_bytes()+b'\n/* caller-owned modification */\n';dirty.write_bytes(changed)
    result=staged_run();assert result.returncode and 'Refusing to overwrite local Wine changes' in result.stdout
    assert dirty.read_bytes()==changed,'dirty caller-owned source was overwritten'
    for p,data in originals.items():
        if p!='programs/services/services.c':assert (wine/p).read_bytes()==data
print('PASS real SCM build overlay: pinned sources restored on success/failure, dirty source preserved, stale target rebuilt, wrong/stale PE rejected, only existing native AA64 producer staged')
