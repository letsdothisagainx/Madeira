#!/usr/bin/env python3
"""Execute stock kernelbase image search plus its bounded failure-only overlay.

Windows allocation/file/path/log APIs are explicit host plumbing. The actual
find_exe_file/get_file_name and early return body are compiled unchanged.
"""
from pathlib import Path
import importlib.util
import os
import re
import shlex
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def function(text,signature):
    start=text.index(signature);brace=text.index('{',start);depth=0
    pattern=r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]'
    for token in re.finditer(pattern,text[brace:],re.S):
        depth+=(token[0]=='{')-(token[0]=='}')
        if token[0]=='}' and not depth:return text[start:brace+token.end()]
    raise AssertionError(signature)


with tempfile.TemporaryDirectory(prefix='madeira-process-lookup-') as directory:
    temp=Path(directory);stage=load('process_lookup_stage',ROOT/'tools/build/stage-process-lookup.py')
    original=(ROOT/'wine/dlls/kernelbase/process.c').read_text()
    stage.stage(temp/'stage',ROOT/'wine');changed=(temp/'stage'/stage.SOURCE).read_text()
    # Exercise nesting with the exact maintained IOSB/architecture stage.
    iosb=load('process_lookup_iosb',ROOT/'tools/build/stage-io-status-abi.py')
    iosb.stage(temp/'iosb',ROOT/'wine');before=(temp/'iosb'/stage.SOURCE).read_bytes()
    stage.apply(temp/'state',temp/'iosb')
    assert b'[steam-arch-v1]' in (temp/'iosb'/stage.SOURCE).read_bytes()
    stage.restore(temp/'state');assert (temp/'iosb'/stage.SOURCE).read_bytes()==before
    assert not (temp/'iosb'/stage.HEADER).exists()
    stage.apply(temp/'changed-state',temp/'iosb')
    altered=(temp/'iosb'/stage.SOURCE).read_bytes()+b'\n/* owned test edit made during build */\n'
    (temp/'iosb'/stage.SOURCE).write_bytes(altered)
    try:stage.restore(temp/'changed-state')
    except AssertionError:pass
    else:raise AssertionError('restoration discarded a concurrent source edit')
    assert (temp/'iosb'/stage.SOURCE).read_bytes()==altered
    fresh=temp/'symlink-source';(fresh/stage.SOURCE).parent.mkdir(parents=True)
    (fresh/stage.SOURCE).write_text(original)
    outside=temp/'unowned-header-target';(fresh/stage.HEADER).symlink_to(outside)
    try:stage.apply(temp/'symlink-state',fresh)
    except AssertionError:pass
    else:raise AssertionError('lookup stage followed an unowned dangling header link')
    assert not outside.exists() and (fresh/stage.HEADER).is_symlink() and (fresh/stage.SOURCE).read_text()==original
    source=r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <wchar.h>
#ifndef __APPLE__
/* Mirror Apple's short-wchar SDK guard in the portable regression too. */
#pragma GCC poison wcschr swprintf
#endif
typedef wchar_t WCHAR;typedef unsigned long DWORD;typedef int BOOL;typedef void *HANDLE;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define GENERIC_READ 1
#define FILE_SHARE_READ 1
#define FILE_SHARE_DELETE 4
#define OPEN_EXISTING 3
#define ERROR_FILE_NOT_FOUND 2
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define TRACE(...) ((void)0)
static _Thread_local DWORD last_error;
static DWORD GetLastError(void){return last_error;}
static void SetLastError(DWORD error){last_error=error;}
static unsigned notes;static char last_note[512];static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static void note(const char *format,...){va_list args;va_start(args,format);pthread_mutex_lock(&lock);vsnprintf(last_note,sizeof(last_note),format,args);notes++;pthread_mutex_unlock(&lock);va_end(args);SetLastError(777);}
#define ERR(...) note(__VA_ARGS__)
static HANDLE GetProcessHeap(void){return (HANDLE)1;}
static void *RtlAllocateHeap(HANDLE heap,unsigned flags,size_t size){(void)heap;(void)flags;return malloc(size);}
static void RtlFreeHeap(HANDLE heap,unsigned flags,void *p){(void)heap;(void)flags;free(p);}
#define HeapAlloc RtlAllocateHeap
static unsigned len(const WCHAR *value){unsigned n=0;while(value[n])n++;return n;}
#define lstrlenW len
static const WCHAR *fixture_wide_find(const WCHAR *value,WCHAR ch){while(*value&&*value!=ch)value++;return *value==ch?value:NULL;}
static int fixture_wide_format(WCHAR *out,size_t cap,const WCHAR *format,...){(void)format;va_list args;va_start(args,format);const WCHAR *a=va_arg(args,const WCHAR *),*b=va_arg(args,const WCHAR *);unsigned n=0;assert(cap>len(a)+len(b)+2);out[n++]='"';while(*a)out[n++]=*a++;out[n++]='"';while(*b)out[n++]=*b++;out[n]=0;va_end(args);return n;}
static int search_mode;
static int RtlGetExePath(const WCHAR *name,WCHAR **path){(void)name;*path=malloc(2*sizeof(WCHAR));(*path)[0]='.';(*path)[1]=0;return 0;}
static BOOL set_ntstatus(int status){return !status;}
static void RtlReleasePath(WCHAR *path){free(path);}
static unsigned SearchPathW(const WCHAR *path,const WCHAR *name,const WCHAR *ext,DWORD cap,WCHAR *out,WCHAR **part){(void)path;(void)ext;(void)part;if(search_mode){unsigned n=len(name);assert(n<cap);memcpy(out,name,(n+1)*sizeof(WCHAR));return n;}SetLastError(2);return 0;}
static HANDLE CreateFileW(const WCHAR *name,unsigned access,unsigned share,void *security,unsigned disp,unsigned flags,HANDLE other){(void)name;(void)access;(void)share;(void)security;(void)disp;(void)flags;(void)other;return (HANDLE)1;}
static void CloseHandle(HANDLE value){(void)value;}
'''
    source+=(ROOT/'build/wine-pe/process_lookup_trace.h').read_text()+'\n'
    production_search=function(original,'static BOOL find_exe_file(')+'\n'+function(original,'static WCHAR *get_file_name(')+'\n'
    # The algorithms stay verbatim; bind only their host OS adapters by name.
    # Defining aliases for libc wide identifiers is forbidden by Apple's SDK
    # when compiling Windows-width WCHAR with -fshort-wchar.
    for external,owned in [('wcschr','fixture_wide_find'),('swprintf','fixture_wide_format')]:
        assert len(re.findall(r'\b'+external+r'\b',production_search))==1
        production_search=re.sub(r'\b'+external+r'\b',owned,production_search)
    source+=production_search
    for label,text in [('old',original),('new',changed)]:
        start=text.index('        if (!(tidy_cmdline = get_file_name(')
        end=text.index('        app_name = name;',start)+len('        app_name = name;')
        source+='static BOOL '+label+'_lookup(WCHAR *cmd_line){WCHAR name[MAX_PATH],*tidy_cmdline=cmd_line;const WCHAR *app_name=NULL;\n'+text[start:end]+'\nassert(app_name==name);return TRUE;}\n'
    source+=r'''
static void *bounded_reader(void *unused){(void)unused;for(unsigned i=0;i<100;i++)madeira_process_image_lookup_failed(L"C:\\windows\\system32\\regsvr32.exe /s secret-token",2);assert(GetLastError()==2);return NULL;}
int main(void){
    WCHAR quoted[]=L"\"C:\\windows\\system32\\regsvr32.exe\" /s private-token";
    SetLastError(2);assert(!old_lookup(quoted)&&GetLastError()==2&&!notes);
    assert(!new_lookup(quoted)&&GetLastError()==2&&notes==1);
    assert(strstr(last_note,"error=2")&&strstr(last_note,"path=system32")&&strstr(last_note,"name=regsvr32.exe"));
    assert(!strstr(last_note,"private-token")&&!strstr(last_note,"C:")&&!strstr(last_note,"/s"));
    search_mode=1;assert(new_lookup(quoted)&&notes==1);search_mode=0;
    madeira_process_image_lookup_failed(L"C:\\users\\private-account\\rundll32.exe secret-password",3);
    assert(GetLastError()==3&&strstr(last_note,"path=other")&&strstr(last_note,"name=rundll32.exe")&&!strstr(last_note,"private-account")&&!strstr(last_note,"secret-password"));
    madeira_process_image_lookup_failed(L"C:\\windows\\syswow64\\rundll32.exe args",5);assert(GetLastError()==5&&strstr(last_note,"path=syswow64"));
    madeira_process_image_lookup_failed(L"C:\\windows\\sysnative\\regsvr32.exe args",2);assert(strstr(last_note,"path=sysnative"));
    madeira_process_image_lookup_failed(L"regsvr32.exe /s token",2);assert(strstr(last_note,"path=bare"));
    madeira_process_image_lookup_failed(L"\"C:\\private\\bad\x263a.exe\" secret",2);assert(strstr(last_note,"name=unavailable")&&!strstr(last_note,"secret"));
    madeira_process_image_lookup_failed(L"\"unterminated private-command",2);assert(strstr(last_note,"name=unavailable"));
    madeira_process_image_lookup_failed(NULL,8);assert(GetLastError()==8);
    madeira_process_image_lookup_failed(L"0123456789abcdefSensitiveToken private-argument",2);assert(strstr(last_note,"name=unavailable")&&!strstr(last_note,"SensitiveToken"));
    unsigned before=notes;for(unsigned i=0;i<100;i++)madeira_process_image_lookup_failed(L"regsvr32.exe token",2);assert(notes-before==7);
    pthread_t a,b;before=notes;assert(!pthread_create(&a,NULL,bounded_reader,NULL));assert(!pthread_create(&b,NULL,bounded_reader,NULL));assert(!pthread_join(a,NULL)&&!pthread_join(b,NULL));assert(notes-before==32);
    puts("PASS actual stock image-search negative control and failure-only early return: missing-image result unchanged, last error preserved, success untouched, bounded per-thread safe metadata and no command/private-path leakage");
}
'''
    path=temp/'check.c';path.write_text(source);exe=temp/'check'
    subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fshort-wchar','-pthread',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(path),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=30)
    print('PASS lookup staging nests inside actual IOSB/architecture overlay and restores byte-identical inputs')
