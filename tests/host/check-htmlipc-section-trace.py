#!/usr/bin/env python3
"""Compile production snapshots/results, invalid inputs, privacy and staging."""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('stage',ROOT/'tools/build/stage-htmlipc-section-trace.py')
stager=importlib.util.module_from_spec(spec);spec.loader.exec_module(stager)
original=(ROOT/'wine/dlls/ntdll/unix/sync.c').read_text()
header=ROOT/'build/ntdll-unix/htmlipc_section_trace.h'
staged=stager.stage(original,header)
assert staged.count('ios_htmlipc_section_note("create",&ios_trace,ret,handle,protect,sec_flags);')==1
assert staged.count('ios_htmlipc_section_note("open",&ios_trace,ret,handle,0,0);')==1
for function in ['NtCreateSection','NtOpenSection']:
    start=staged.index('NTSTATUS WINAPI '+function+'(');end=staged.index('\n}',start);body=staged[start:end]
    assert body.index('ios_htmlipc_section_capture(')<body.index('SERVER_START_REQ(')
    assert body.index('SERVER_END_REQ;')<body.index('ios_htmlipc_section_note(')<body.rindex('return ret;')
    assert '*handle' not in body[body.index('ios_htmlipc_section_note('):]
# No original request, early return, status assignment or output write changes.
restored=staged.replace('#include "'+str(header)+'"\n\n','')
restored='\n'.join(line for line in restored.split('\n') if not any(mark in line for mark in [
    'struct ios_htmlipc_section_snapshot ios_trace;','ios_htmlipc_section_capture(','ios_htmlipc_section_note(']))
assert restored==original
assert 'stage-htmlipc-section-trace.py' in (ROOT/'build/ntdll-unix/build.sh').read_text()
wow64=(ROOT/'wine/dlls/wow64/sync.c').read_text()
for name,native in [('wow64_NtCreateSection','NtCreateSection('),('wow64_NtOpenSection','NtOpenSection(')]:
    begin=wow64.index('NTSTATUS WINAPI '+name+'(');end=wow64.index('\n}',begin)
    assert native in wow64[begin:end] and 'objattr_32to64' in wow64[begin:end]
code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
typedef uint16_t WCHAR;typedef uintptr_t ULONG_PTR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;
typedef int32_t NTSTATUS;typedef void *HANDLE;
typedef struct {ULONGLONG QuadPart;} LARGE_INTEGER;
typedef struct {uint16_t Length,MaximumLength;WCHAR *Buffer;} UNICODE_STRING;
typedef struct {HANDLE RootDirectory;UNICODE_STRING *ObjectName;} OBJECT_ATTRIBUTES;
typedef struct {struct {HANDLE UniqueProcess,UniqueThread;} ClientId;} TEB;
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034)
static _Thread_local TEB teb={.ClientId={(void*)92,(void*)96}};static _Thread_local int wow;
static TEB *NtCurrentTeb(void){return &teb;}static int in_wow64_call(void){return wow;}
#ifndef __APPLE__
static int memory_fd;
#endif
static unsigned reads,lines;static char output[65536];static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static int safe_read(const void *source,void *target,size_t size){
    int saved=errno;
    __atomic_fetch_add(&reads,1,__ATOMIC_RELAXED);
    #ifdef __APPLE__
    mach_vm_size_t copied=0;int ok=mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)source,size,(mach_vm_address_t)target,&copied)==KERN_SUCCESS&&copied==size;
#else
    int ok=pread(memory_fd,target,size,(off_t)(uintptr_t)source)==(ssize_t)size;
#endif
    errno=saved;return ok;
}
#define IOS_HTMLIPC_TRACE_READ safe_read
static int note(int fd,const char *format,...){
    va_list ap;assert(fd==2);pthread_mutex_lock(&mutex);va_start(ap,format);
    size_t used=strlen(output);int n=vsnprintf(output+used,sizeof(output)-used,format,ap);
    assert(n>0&&(size_t)n<sizeof(output)-used);va_end(ap);++lines;pthread_mutex_unlock(&mutex);errno=EIO;return n;
}
#define dprintf note
#include "htmlipc_section_trace.h"
static UNICODE_STRING string(WCHAR *buffer,const char *text){
    unsigned n=(unsigned)strlen(text);for(unsigned i=0;i<n;++i)buffer[i]=(unsigned char)text[i];
    UNICODE_STRING result={(uint16_t)(n*2),(uint16_t)(n*2),buffer};return result;
}
static void *worker(void *unused){
    WCHAR buffer[160];UNICODE_STRING name=string(buffer,"SteamChrome_ClientStream_92_25_client_mem-IPCWrapper");
    OBJECT_ATTRIBUTES attr={(void*)123,&name};struct ios_htmlipc_section_snapshot snapshot;HANDLE handle=(void*)234;
    LARGE_INTEGER size={0x1900010};(void)unused;wow=1;
    ios_htmlipc_section_capture(&snapshot,&attr,&size);assert(snapshot.active);
    for(unsigned i=0;i<1000;++i)ios_htmlipc_section_note("create",&snapshot,0,&handle,4,0x8000000);
    return NULL;
}
int main(void){
#ifndef __APPLE__
    memory_fd=open("/proc/self/mem",O_RDONLY);assert(memory_fd>=0);
#endif
    WCHAR buffer[180];UNICODE_STRING name=string(buffer,"SteamChrome_MasterStream_spid92_mem-IPCWrapper");
    OBJECT_ATTRIBUTES attr={(void*)123,&name};struct ios_htmlipc_section_snapshot snapshot;LARGE_INTEGER size={0x2010};HANDLE handle=(void*)456;
    ios_htmlipc_section_capture(&snapshot,&attr,&size);assert(snapshot.active);unsigned before=reads;errno=EDOM;
    ios_htmlipc_section_note("open",&snapshot,STATUS_OBJECT_NAME_NOT_FOUND,(const HANDLE*)1,0,0);
    assert(lines==1&&reads==before&&errno==EDOM&&strstr(output,"abi=native64")&&strstr(output,"namespace=unresolved"));
    assert(strchr(output,'\n')&&strchr(output,'\n')[1]==0);
    wow=1;ios_htmlipc_section_capture(&snapshot,&attr,&size);assert(snapshot.active);
    ios_htmlipc_section_note("create",&snapshot,0,&handle,4,0x8000000);
    assert(lines==2&&strstr(output,"abi=i386")&&strstr(output,"bytes=2010 bytes-valid=1 protect=4 flags=8000000"));
    /* No output read on failure, and success with a missing/invalid output
     * pointer can only make metadata unavailable, never fault the observer. */
    before=reads;ios_htmlipc_section_note("open",&snapshot,(NTSTATUS)0xc000000d,(const HANDLE*)1,0,0);assert(reads==before);
    ios_htmlipc_section_note("open",&snapshot,0,NULL,0,0);assert(reads==before);
    ios_htmlipc_section_note("open",&snapshot,0,(const HANDLE*)1,0,0);assert(reads==before+1);
    char absent[80];snprintf(absent,sizeof(absent),"handle=%p handle-read=0",(void*)NULL);
    assert(strstr(output,absent));
    unsigned previous=lines;
    ios_htmlipc_section_capture(&snapshot,NULL,NULL);assert(!snapshot.active);
    ios_htmlipc_section_capture(&snapshot,(const OBJECT_ATTRIBUTES*)1,NULL);assert(!snapshot.active);
    ios_htmlipc_section_note("open",&snapshot,0,&handle,0,0);assert(lines==previous);
    size_t page=(size_t)sysconf(_SC_PAGESIZE);void *dead=mmap(NULL,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(dead!=MAP_FAILED);assert(!munmap(dead,page));
    ios_htmlipc_section_capture(&snapshot,dead,NULL);assert(!snapshot.active);
    attr.ObjectName=dead;ios_htmlipc_section_capture(&snapshot,&attr,NULL);assert(!snapshot.active);attr.ObjectName=&name;
    WCHAR *saved=name.Buffer;name.Buffer=dead;ios_htmlipc_section_capture(&snapshot,&attr,NULL);assert(!snapshot.active);name.Buffer=saved;
    ios_htmlipc_section_capture(&snapshot,&attr,dead);assert(snapshot.active&&!snapshot.size_valid&&snapshot.size==0);
    /* Destroy caller inputs after the snapshot: completion uses native-owned
     * data only and must not reread attr, UNICODE_STRING, buffer or size. */
    ios_htmlipc_section_capture(&snapshot,&attr,&size);assert(snapshot.active);
    attr.ObjectName=dead;name.Buffer=dead;before=reads;
    ios_htmlipc_section_note("open",&snapshot,STATUS_OBJECT_NAME_NOT_FOUND,(const HANDLE*)dead,0,0);
    assert(reads==before&&strstr(output,"SteamChrome_MasterStream_spid92_mem-IPCWrapper"));
    attr.ObjectName=&name;name.Buffer=saved;
    name=string(buffer,"unrelated-private");ios_htmlipc_section_capture(&snapshot,&attr,NULL);assert(!snapshot.active);
    name=string(buffer,"SteamChrome_AccountCredential123");ios_htmlipc_section_capture(&snapshot,&attr,NULL);assert(!snapshot.active);
    name=string(buffer,"SteamChrome_/private");ios_htmlipc_section_capture(&snapshot,&attr,NULL);assert(!snapshot.active);
    name=string(buffer,"SteamChrome_MasterStream_spid92_mem-IPCWrapper");ios_htmlipc_section_capture(&snapshot,&attr,NULL);assert(snapshot.active);
    for(unsigned i=0;i<10000;++i)ios_htmlipc_section_note("open",&snapshot,STATUS_OBJECT_NAME_NOT_FOUND,NULL,0,0);
    assert(lines<32);before=lines;
    pthread_t threads[8];for(unsigned i=0;i<8;++i)assert(!pthread_create(&threads[i],0,worker,0));
    for(unsigned i=0;i<8;++i)pthread_join(threads[i],0);
    assert(lines==128&&before<lines&&!strstr(output,"Credential"));
    puts("PASS common section observer: no protocol/status changes, fault-safe input snapshots, no failed-output dereference, unmap/null/error paths, privacy/errno preservation and concurrent128-event bound");
}
'''
with tempfile.TemporaryDirectory(prefix='htmlipc-section-') as folder:
    source=Path(folder)/'test.c';source.write_text(code);binary=Path(folder)/'test'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-pthread','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(ROOT/'build/ntdll-unix'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=20)
