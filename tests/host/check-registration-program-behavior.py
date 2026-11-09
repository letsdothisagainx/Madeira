#!/usr/bin/env python3
"""Exercise stock Wine regsvr32 source, with explicit host-side Win32 plumbing.

This compiles the real LoadProc, registration/unregistration/install functions,
argument parser, output selection and wmain from the pinned vendor input. The
OS loaders/resources and the DLL exports are owned fixtures. It does not run
Windows, DXSETUP or iOS, and cannot prove DirectX's missing executable name.

Optional --wine additionally invokes installed stock Wine's regsvr32/rundll32
against a compiled, owned COM fixture in a fresh temporary test prefix. It never
reads or modifies Madeira's Wine prefix, official DLLs or installer state.
"""
from pathlib import Path
import argparse
import os
import shlex
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT / 'wine/programs/regsvr32/regsvr32.c'
SOURCE = PRODUCTION.read_text()


def function(signature):
    start = SOURCE.index(signature)
    return SOURCE[start:SOURCE.index('\n}', start) + 2] + '\n'


functions = '\n'.join(function(signature) for signature in (
    'static void WINAPIV output_write(', 'static VOID *LoadProc(',
    'static int RegisterDll(', 'static int UnregisterDll(', 'static int InstallDll(',
    'static WCHAR *parse_command_line(', 'int __cdecl wmain('))
typedefs = SOURCE[SOURCE.index('typedef HRESULT (WINAPI *DLLREGISTER)'):
                  SOURCE.index('static BOOL Silent;')]

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include "regsvr32.h"
/* Host wchar_t is intentional: this tests program logic, not Windows UTF16 ABI. */
typedef wchar_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef int BOOL;
typedef int32_t HRESULT;
typedef uint16_t WORD;
typedef uint32_t DWORD, UINT, LCID;
typedef uintptr_t ULONG_PTR;
typedef void VOID;
typedef void *HMODULE;
typedef struct { struct { WORD Machine; } FileHeader; } IMAGE_NT_HEADERS;
#define WINAPI
#define WINAPIV
#define __cdecl
#define TRUE 1
#define FALSE 0
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define FAILED(h) ((HRESULT)(h) < 0)
#define SUCCEEDED(h) (!FAILED(h))
#define LOAD_WITH_ALTERED_SEARCH_PATH 8
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE 32
#define ERROR_BAD_EXE_FORMAT 193
#define ERROR_MOD_NOT_FOUND 126
#define ERROR_NO_WORK_DONE 235
#define FORMAT_MESSAGE_FROM_STRING 0x400
#define LANG_ENGLISH 9
#define SUBLANG_ENGLISH_US 1
#define SORT_DEFAULT 0
#define MAKELANGID(p,s) ((p)|((s)<<10))
#define MAKELCID(l,s) ((l)|((s)<<16))
#define MB_OK 0
#define WINE_FIXME(...) ((void)0)
#define MESSAGE(...) fixture_message()
static unsigned console_messages, dialogs, loads, lookups, frees, ole_start, ole_stop;
static unsigned registers, unregisters, installs, registry_value, registry_writes;
static unsigned output_id, exits, reexecs;
static DWORD last_error, exited_status;
static WORD reexec_machine;
static LCID locale=0x777;
static BOOL Silent;
static jmp_buf escape;
static WCHAR installed_argument[128];
static BOOL installed_flag;
static char order[32];
static unsigned order_n;
struct fixture {
    const WCHAR *name;
    HRESULT reg_hr, unreg_hr, install_hr;
    unsigned absent, bad_arch, no_register, no_unregister, no_install;
    unsigned registrations;
};
static struct fixture fixtures[3], *active;
static _Alignas(8) IMAGE_NT_HEADERS fixture_image;
static void add_order(char value) {assert(order_n+1<sizeof(order));order[order_n++]=value;order[order_n]=0;}
static HRESULT fixture_register(void) {
    assert(active); registers++;active->registrations++;add_order('R');
    if(SUCCEEDED(active->reg_hr)){registry_value=1;registry_writes++;}
    return active->reg_hr;
}
static HRESULT fixture_unregister(void) {
    assert(active);unregisters++;add_order('U');
    if(SUCCEEDED(active->unreg_hr)){registry_value=0;registry_writes++;}
    return active->unreg_hr;
}
static HRESULT fixture_install(BOOL install, LPCWSTR argument) {
    assert(active&&argument);installs++;installed_flag=install;add_order(install?'I':'D');
    assert(wcslen(argument)<ARRAY_SIZE(installed_argument));wcscpy(installed_argument,argument);
    if(SUCCEEDED(active->install_hr))registry_writes++;
    return active->install_hr;
}
static DWORD GetLastError(void){return last_error;}
static HMODULE LoadLibraryExW(LPCWSTR name,void *file,DWORD flags) {
    assert(!file);loads++;
    for(unsigned i=0;i<ARRAY_SIZE(fixtures);i++)if(fixtures[i].name&&!wcscmp(name,fixtures[i].name)) {
        if(fixtures[i].absent){last_error=ERROR_MOD_NOT_FOUND;return NULL;}
        if(fixtures[i].bad_arch){
            last_error=ERROR_BAD_EXE_FORMAT;
            if(flags==LOAD_LIBRARY_AS_IMAGE_RESOURCE)return (void *)((uintptr_t)&fixture_image|1);
            return NULL;
        }
        assert(flags==LOAD_WITH_ALTERED_SEARCH_PATH);return &fixtures[i];
    }
    last_error=ERROR_MOD_NOT_FOUND;return NULL;
}
static void *GetProcAddress(HMODULE module,const char *name) {
    lookups++;active=module;
    if(!strcmp(name,"DllRegisterServer"))return active->no_register?NULL:(void *)fixture_register;
    if(!strcmp(name,"DllUnregisterServer"))return active->no_unregister?NULL:(void *)fixture_unregister;
    if(!strcmp(name,"DllInstall"))return active->no_install?NULL:(void *)fixture_install;
    assert(!"unexpected export");return NULL;
}
static BOOL FreeLibrary(HMODULE module){assert(module);frees++;return TRUE;}
static _Noreturn void ExitProcess(DWORD status){exits++;exited_status=status;longjmp(escape,1);}
static IMAGE_NT_HEADERS *RtlImageNtHeader(HMODULE module){assert(module==&fixture_image);return module;}
/* Re-exec OS machinery is outside this harness; LoadProc's real decision and
 * the selected PE machine are tested, without inventing a child result. */
static void reexec_self(WORD machine){reexecs++;reexec_machine=machine;}
static LCID GetThreadLocale(void){return locale;}
static BOOL SetThreadLocale(LCID value){locale=value;return TRUE;}
static HMODULE GetModuleHandleW(LPCWSTR name){assert(!name);return (void *)1;}
static int LoadStringW(HMODULE module,UINT id,WCHAR *buffer,int count){
    assert(module==(void *)1&&count>1);output_id=id;buffer[0]='x';buffer[1]=0;return 1;
}
static DWORD FormatMessageW(DWORD flags,const WCHAR *format,DWORD unused,LCID language,
                            WCHAR *buffer,DWORD count,va_list *arguments){
    assert(flags==FORMAT_MESSAGE_FROM_STRING&&format&&!unused&&!language&&count>1&&arguments);
    buffer[0]='x';buffer[1]=0;return 1;
}
static int MessageBoxW(void *window,const WCHAR *message,const WCHAR *title,UINT flags){
    assert(!window&&message&&title&&!flags&&!Silent);dialogs++;return 1;
}
static void fixture_message(void){assert(Silent&&locale==0x409);console_messages++;}
static int lstrlenW(LPCWSTR value){return (int)wcslen(value);}
static HRESULT OleInitialize(void *reserved){assert(!reserved);ole_start++;return 0;}
static void OleUninitialize(void){ole_stop++;}
TYPEDEFS
FUNCTIONS
static void reset(void) {
    console_messages=dialogs=loads=lookups=frees=ole_start=ole_stop=0;
    registers=unregisters=installs=registry_value=registry_writes=0;
    output_id=exits=reexecs=0;last_error=exited_status=0;reexec_machine=0;
    locale=0x777;Silent=FALSE;active=NULL;order_n=0;order[0]=0;
    installed_argument[0]=0;installed_flag=FALSE;
    fixtures[0]=(struct fixture){.name=L"one.dll"};
    fixtures[1]=(struct fixture){.name=L"two.dll"};
    fixtures[2]=(struct fixture){.name=L"three.dll"};
    fixture_image.FileHeader.Machine=0x8664;
}
static int command(unsigned count,const WCHAR *const *input) {
    WCHAR storage[16][128],*arguments[16];assert(count<ARRAY_SIZE(arguments));
    for(unsigned i=0;i<count;i++){assert(wcslen(input[i])<ARRAY_SIZE(storage[i]));wcscpy(storage[i],input[i]);arguments[i]=storage[i];}
    if(setjmp(escape))return (int)exited_status;
    return wmain((int)count,arguments);
}
#define RUN(...) command(ARRAY_SIZE(((const WCHAR *[]){__VA_ARGS__})),(const WCHAR *[]){__VA_ARGS__})
int main(void) {
    reset();assert(RegisterDll(L"one.dll",TRUE)==0);
    assert(registers==1&&fixtures[0].registrations==1&&registry_value==1&&registry_writes==1&&frees==1);
    reset();fixtures[0].reg_hr=1;assert(RegisterDll(L"one.dll",TRUE)==0&&registers==1&&registry_writes==1); /* S_FALSE succeeds genuinely. */
    reset();fixtures[0].reg_hr=(HRESULT)0x80004005u;assert(RegisterDll(L"one.dll",TRUE)==DLLSERVER_FAILED);
    assert(registers==1&&!registry_value&&!registry_writes&&output_id==STRING_REGISTER_FAILED);
    reset();fixtures[0].no_register=1;assert(RegisterDll(L"one.dll",TRUE)==GETPROCADDRESS_FAILED);
    assert(!registers&&!registry_writes&&frees==1&&output_id==STRING_PROC_NOT_IMPLEMENTED);
    reset();fixtures[0].absent=1;assert(RUN(L"regsvr32",L"one.dll")==LOADLIBRARY_FAILED);
    assert(exits==1&&!registers&&!lookups&&!registry_writes);
    reset();fixtures[0].bad_arch=1;assert(RUN(L"regsvr32",L"one.dll")==LOADLIBRARY_FAILED);
    assert(reexecs==1&&reexec_machine==0x8664&&exits==1&&loads==2&&!registers);
    reset();fixtures[1].bad_arch=1;assert(RUN(L"regsvr32",L"one.dll",L"two.dll")==LOADLIBRARY_FAILED);
    assert(!reexecs&&registers==1&&loads==2); /* Wrong-machine retry only for the first DLL. */
    reset();registry_value=1;assert(UnregisterDll(L"one.dll",TRUE)==0&&unregisters==1&&!registry_value&&frees==1);
    reset();registry_value=1;fixtures[0].unreg_hr=(HRESULT)0x80070005u;
    assert(UnregisterDll(L"one.dll",TRUE)==DLLSERVER_FAILED&&unregisters==1&&registry_value==1&&!registry_writes);
    reset();fixtures[0].no_unregister=1;assert(UnregisterDll(L"one.dll",TRUE)==GETPROCADDRESS_FAILED&&!unregisters);
    reset();assert(InstallDll(TRUE,L"one.dll",L"argument",TRUE)==0&&installs==1&&installed_flag&&!wcscmp(installed_argument,L"argument"));
    reset();fixtures[0].no_install=1;assert(InstallDll(TRUE,L"one.dll",L"",TRUE)==GETPROCADDRESS_FAILED&&!installs);
    reset();fixtures[0].install_hr=(HRESULT)0x80004005u;
    assert(InstallDll(FALSE,L"one.dll",L"",TRUE)==DLLSERVER_FAILED&&installs==1&&!installed_flag&&!registry_writes);
    reset();assert(RUN(L"regsvr32",L"one.dll",L"/s")==0);
    assert(registers==1&&registry_value&&console_messages==1&&!dialogs&&Silent&&locale==0x777&&ole_start==1&&ole_stop==1);
    reset();assert(RUN(L"regsvr32",L"/S",L"one.dll")==0&&console_messages==1&&!dialogs);
    reset();assert(RUN(L"regsvr32",L"-s",L"one.dll")==0&&console_messages==1&&!dialogs);
    reset();assert(RUN(L"regsvr32",L"one.dll")==0&&dialogs==1&&!console_messages);
    reset();fixtures[0].reg_hr=(HRESULT)0x80004005u;
    assert(RUN(L"regsvr32",L"one.dll",L"/s",L"two.dll")==DLLSERVER_FAILED);
    assert(registers==2&&fixtures[0].registrations==1&&fixtures[1].registrations==1&&registry_writes==1&&console_messages==2&&!dialogs);
    reset();fixtures[0].no_register=1;
    assert(RUN(L"regsvr32",L"/s",L"one.dll",L"two.dll")==GETPROCADDRESS_FAILED&&registers==1&&registry_writes==1);
    reset();fixtures[0].reg_hr=(HRESULT)0x80004005u;fixtures[1].no_register=1;
    assert(RUN(L"regsvr32",L"/s",L"one.dll",L"two.dll")==GETPROCADDRESS_FAILED); /* Most recent failure, never later success. */
    reset();assert(RUN(L"regsvr32",L"/s",L"/u",L"one.dll")==0&&unregisters==1&&!registers&&!strcmp(order,"U"));
    reset();assert(RUN(L"regsvr32",L"/s",L"/u",L"/i:remove",L"one.dll")==0&&!strcmp(order,"DU")&&!wcscmp(installed_argument,L"remove"));
    reset();fixtures[0].install_hr=(HRESULT)0x80004005u;
    assert(RUN(L"regsvr32",L"/s",L"/u",L"/i:remove",L"one.dll")==DLLSERVER_FAILED&&installs==1&&!unregisters&&!registry_writes);
    reset();assert(RUN(L"regsvr32",L"/s",L"/n",L"/i:\"hello world\"",L"one.dll")==0);
    assert(!registers&&installs==1&&installed_flag&&!wcscmp(installed_argument,L"hello world"));
    reset();assert(RUN(L"regsvr32",L"/s",L"/n",L"/i",L"one.dll")==0&&installs==1&&!registers&&!installed_argument[0]);
    reset();fixtures[0].install_hr=(HRESULT)0x80004005u;
    assert(RUN(L"regsvr32",L"/s",L"/i:argument",L"one.dll")==DLLSERVER_FAILED&&!strcmp(order,"RI")&&registry_writes==1);
    reset();assert(RUN(L"regsvr32",L"/n",L"one.dll")==INVALID_ARG&&!loads&&!registry_writes);
    reset();assert(RUN(L"regsvr32",L"/z",L"one.dll")==INVALID_ARG&&!loads&&!registry_writes);
    reset();assert(RUN(L"regsvr32",L"/")==INVALID_ARG&&!loads&&!registry_writes);
    reset();assert(RUN(L"regsvr32",L"/s")==INVALID_ARG&&!loads&&!registry_writes&&!dialogs);
    reset();fixtures[0].name=L"/absolute/owned.dll";
    assert(RUN(L"regsvr32",L"/absolute/owned.dll",L"/s")==0&&registers==1);
    puts("PASS stock Wine regsvr32 production source: genuine fixture export required for success; HRESULT/load/export errors, multiple-DLL error retention, /s output, /u and /i ordering, no installer-state fabrication");
    puts("Host Win32 loader/resource/re-exec plumbing is explicit fixture code; actual iOS/Wine/DirectX completion is not asserted");
    return 0;
}
'''.replace('TYPEDEFS', typedefs).replace('FUNCTIONS', functions)


def run_host():
    with tempfile.TemporaryDirectory(prefix='madeira-registration-program-') as directory:
        folder = Path(directory)
        source, executable = folder / 'registration.c', folder / 'registration'
        source.write_text(code)
        subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-I' + str(PRODUCTION.parent), str(source), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, timeout=30)


def run_wine(wine, compiler):
    """Optional genuine host-Wine program test; never selects the user's prefix."""
    if not shutil.which(wine) or not shutil.which(compiler[0]):
        raise SystemExit('--wine requires installed stock Wine and a Windows C cross-compiler')
    identity = uuid.uuid4().hex
    key = 'Software\\Madeira\\RegistrationFixture\\' + identity
    source = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ole2.h>
static const WCHAR key[] = L"FIXTURE_KEY_PATH";
static HRESULT write_value(const WCHAR *value) {
    HKEY handle; LONG result=RegCreateKeyExW(HKEY_CURRENT_USER,key,0,NULL,0,KEY_SET_VALUE,NULL,&handle,NULL);
    if(result)return HRESULT_FROM_WIN32(result);
    result=RegSetValueExW(handle,value,0,REG_SZ,(const BYTE *)L"genuine-export",sizeof(L"genuine-export"));
    RegCloseKey(handle);return result?HRESULT_FROM_WIN32(result):S_OK;
}
__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    WCHAR value[2];
    if(GetEnvironmentVariableW(L"MADEIRA_FIXTURE_REGISTER_FAIL",value,2))return E_ACCESSDENIED;
    return write_value(L"registered");
}
__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void) {
    LONG result=RegDeleteTreeW(HKEY_CURRENT_USER,key);
    return result&&result!=ERROR_FILE_NOT_FOUND?HRESULT_FROM_WIN32(result):S_OK;
}
__declspec(dllexport) void CALLBACK FixtureRunDll(HWND window,HINSTANCE instance,LPSTR args,int show) {
    (void)window;(void)instance;(void)args;(void)show;write_value(L"rundll");
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reason;(void)reserved;return TRUE;
}
'''.replace('FIXTURE_KEY_PATH', key.replace('\\', '\\\\'))
    with tempfile.TemporaryDirectory(prefix='madeira-registration-wine-') as directory:
        folder = Path(directory)
        cfile, dll = folder / 'owned.c', folder / 'owned.dll'
        cfile.write_text(source)
        subprocess.run(compiler + ['-shared', str(cfile), '-o', str(dll), '-ladvapi32'], check=True)
        environment = dict(os.environ, WINEPREFIX=str(folder / 'prefix'), WINEARCH='win64', WINEDEBUG='-all',
                           WINEDLLOVERRIDES='mscoree,mshtml=')
        for key_name in list(environment):
            if any(word in key_name.upper() for word in ('TOKEN','PASSWORD','SECRET','CREDENTIAL')):
                environment.pop(key_name)
        environment.pop('MADEIRA_FIXTURE_REGISTER_FAIL', None)
        win_dll = 'Z:' + str(dll).replace('/', '\\')
        win_key = 'HKEY_CURRENT_USER\\' + key

        def invoke(*arguments, expected=0):
            result = subprocess.run([wine, *arguments], env=environment, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            assert result.returncode == expected, (arguments, result.returncode, result.stdout[-3000:])
            return result.stdout

        try:
            invoke('regsvr32.exe', '/s', win_dll)
            assert 'genuine-export' in invoke('reg.exe', 'query', win_key, '/v', 'registered')
            invoke('regsvr32.exe', '/s', '/u', win_dll)
            invoke('reg.exe', 'query', win_key, expected=1)
            environment['MADEIRA_FIXTURE_REGISTER_FAIL'] = '1'
            invoke('regsvr32.exe', '/s', win_dll, expected=5)
            invoke('reg.exe', 'query', win_key, expected=1)
            environment.pop('MADEIRA_FIXTURE_REGISTER_FAIL')
            invoke('rundll32.exe', win_dll + ',FixtureRunDll')
            assert 'genuine-export' in invoke('reg.exe', 'query', win_key, '/v', 'rundll')
            invoke('regsvr32.exe', '/s', '/u', win_dll)
            invoke('reg.exe', 'query', win_key, expected=1)
        finally:
            if shutil.which('wineserver'):
                subprocess.run(['wineserver', '-k'], env=environment, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30, check=False)
                subprocess.run(['wineserver', '-w'], env=environment, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30, check=False)
    print('PASS actual installed stock Wine regsvr32/rundll32: owned DLL exports, genuine registry effects, failure status and unregistration; temporary test prefix only')
    print('Host-Wine integration does not establish iOS execution or official DXSETUP completion')


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--wine', nargs='?', const='wine', help='also run installed stock Wine commands')
parser.add_argument('--mingw-cc', default=os.environ.get('MADEIRA_REGISTRATION_MINGW_CC',
                                                      'x86_64-w64-mingw32-gcc'))
arguments = parser.parse_args()
run_host()
if arguments.wine:
    run_wine(arguments.wine, shlex.split(arguments.mingw_cc))
else:
    print('SKIP optional real-Wine integration (use --wine with an installed Windows cross-compiler)')
