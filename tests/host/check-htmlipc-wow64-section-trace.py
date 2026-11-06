#!/usr/bin/env python3
"""Execute actual Wine I386 section thunks/converters into production observer.

Uses a real nonidentity mapped guest window and the unchanged production C
conversion functions. The final NT operation is an explicit result fixture;
this proves diagnostic coverage, not a running CEF/Steam connection.
"""
from pathlib import Path
import os
import argparse
import importlib.util
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
private=(ROOT/'wine/dlls/wow64/wow64_private.h').read_text()
sync=(ROOT/'wine/dlls/wow64/sync.c').read_text()
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--stage',type=Path,default=ROOT/'tools/build/stage-htmlipc-section-trace.py',help='Explicit staging implementation for a before/after negative control')
args=parser.parse_args()
spec=importlib.util.spec_from_file_location('stage',args.stage)
stager=importlib.util.module_from_spec(spec);spec.loader.exec_module(stager)
native=(ROOT/'wine/dlls/ntdll/unix/sync.c').read_text()
staged=stager.stage(native,ROOT/'build/ntdll-unix/htmlipc_section_trace.h')

def function(source,signature):
    begin=source.index(signature);brace=source.index('{',begin);depth=1;end=brace+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[begin:end]
functions='\n'.join(function(private,name) for name in [
    'static inline void *guest_ptr32(', 'static inline ULONG get_ulong(',
    'static inline HANDLE get_handle(', 'static inline void *get_ptr(',
    'static inline UNICODE_STRING *unicode_str_32to64(',
    'static inline SECURITY_DESCRIPTOR *secdesc_32to64(',
    'static inline OBJECT_ATTRIBUTES *objattr_32to64(',
    'static inline void put_handle('])
thunks='\n'.join(function(sync,name) for name in [
    'NTSTATUS WINAPI wow64_NtCreateSection(', 'NTSTATUS WINAPI wow64_NtOpenSection('])
validation='\n'.join(function(native,name) for name in ['unsigned int alloc_object_attributes(', 'static unsigned int validate_open_object_attributes('])
# Extract the actual staged functions (including the original guard bodies),
# rather than implementing their status returns in an independent model.
sections=[]
for name in ['NtCreateSection','NtOpenSection']:
    signature='static NTSTATUS WINAPI ios_htmlipc_impl_'+name+'('
    if signature in staged:sections.append(function(staged,signature))
    sections.append(function(staged,'NTSTATUS WINAPI '+name+'('))
native_sections='\n'.join(sections)

code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stddef.h>
#define WINAPI
#define SE_SELF_RELATIVE 0x8000
#define SE_SACL_PRESENT 0x10
#define SE_DACL_PRESENT 4
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034)
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_UNKNOWN_REVISION ((NTSTATUS)0xc0000058)
#define STATUS_DATATYPE_MISALIGNMENT ((NTSTATUS)0x80000002)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xc0000033)
#define STATUS_NO_MEMORY ((NTSTATUS)0xc0000017)
#define STATUS_INVALID_PAGE_PROTECTION ((NTSTATUS)0xc0000045)
#define SECURITY_DESCRIPTOR_REVISION 1
#define PAGE_NOACCESS 1
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_WRITECOPY 8
#define PAGE_EXECUTE 16
#define PAGE_EXECUTE_READ 32
#define PAGE_EXECUTE_READWRITE 64
#define PAGE_EXECUTE_WRITECOPY 128
#define FILE_READ_DATA 1
#define FILE_WRITE_DATA 2
#define SEC_IMAGE 0x1000000
typedef unsigned char BYTE;typedef uint16_t WCHAR;typedef uint32_t ULONG,UINT,ACCESS_MASK;
typedef uintptr_t ULONG_PTR;typedef uint64_t ULONGLONG;typedef int32_t NTSTATUS;typedef void *HANDLE,*PSID;
typedef struct {ULONGLONG QuadPart;} LARGE_INTEGER;
typedef struct {uint16_t Length,MaximumLength;WCHAR *Buffer;} UNICODE_STRING;
typedef struct {uint16_t Length,MaximumLength;ULONG Buffer;} UNICODE_STRING32;
typedef struct {BYTE Revision,Sbz1;uint16_t Control;void *Owner,*Group,*Sacl,*Dacl;} SECURITY_DESCRIPTOR;
typedef struct {BYTE Revision,Sbz1;uint16_t Control;ULONG Owner,Group,Sacl,Dacl;} SECURITY_DESCRIPTOR_RELATIVE;
typedef struct {ULONG Length;HANDLE RootDirectory;UNICODE_STRING *ObjectName;ULONG Attributes;void *SecurityDescriptor,*SecurityQualityOfService;} OBJECT_ATTRIBUTES;
typedef struct {ULONG Length,RootDirectory,ObjectName,Attributes,SecurityDescriptor,SecurityQualityOfService;} OBJECT_ATTRIBUTES32;
typedef ULONG data_size_t;
typedef struct {BYTE Revision,SubAuthorityCount,Authority[6];ULONG SubAuthority[1];} SID;
typedef struct {BYTE Revision,Sbz1;uint16_t AclSize,AceCount,Sbz2;} ACL;
struct object_attributes {ULONG rootdir,attributes,sd_len,name_len;};
struct security_descriptor {ULONG control,owner_len,group_len,sacl_len,dacl_len;};
struct object_attr64 {OBJECT_ATTRIBUTES attr;UNICODE_STRING str;SECURITY_DESCRIPTOR sd;};
static ULONG_PTR wow_guest_base;
#define LongToHandle(x) ((HANDLE)(intptr_t)(int32_t)(x))
#define HandleToULong(x) ((ULONG)(uintptr_t)(x))
typedef struct {struct {HANDLE UniqueProcess,UniqueThread;} ClientId;} TEB;
static TEB teb={.ClientId={(void*)0x90,(void*)0x94}};
static TEB *NtCurrentTeb(void){return &teb;}static int in_wow64_call(void){return 1;}
static int safe_read(const void *source,void *target,size_t size){memcpy(target,source,size);return 1;}
#define IOS_HTMLIPC_TRACE_READ safe_read
static char output[4096];static unsigned lines;
static int note(int fd,const char *format,...){
    va_list ap;assert(fd==2);va_start(ap,format);size_t used=strlen(output);
    int n=vsnprintf(output+used,sizeof(output)-used,format,ap);va_end(ap);assert(n>0&&(size_t)n<sizeof(output)-used);++lines;return n;
}
#define dprintf note
#include "htmlipc_section_trace.h"
/*production-converters*/
static NTSTATUS outcome;static unsigned native_calls;
struct fake_request {const char *op;ULONG access,flags,file_handle,file_access,attributes,rootdir;ULONGLONG size;};
struct fake_reply {ULONG handle;};static struct fake_reply *current_reply;
#define wine_server_obj_handle(x) ((ULONG)(uintptr_t)(x))
#define wine_server_ptr_handle(x) LongToHandle(x)
static void wine_server_add_data(struct fake_request *req,const void *data,size_t size){
    const WCHAR *characters=(const void*)(wow_guest_base+0x300);
    size_t length=((const UNICODE_STRING32*)(wow_guest_base+0x200))->Length;
    if(!strcmp(req->op,"create_mapping")){
        const struct object_attributes *attr=data;assert(attr&&attr->rootdir==0x6c&&attr->name_len==length&&size>=sizeof(*attr)+length);
        assert(!memcmp((const unsigned char*)(attr+1)+attr->sd_len,characters,length));
    }else{assert(!strcmp(req->op,"open_mapping")&&data==characters&&size==length);}
}
static unsigned wine_server_call(struct fake_request *req){
    ++native_calls;assert(req->access==0xf001f);
    if(!strcmp(req->op,"create_mapping"))assert(req->flags==0x8000000&&req->file_handle==0&&req->file_access==3&&req->size==0x2010);
    else assert(!strcmp(req->op,"open_mapping")&&req->rootdir==0x6c);
    current_reply->handle=outcome?0:(!strcmp(req->op,"create_mapping")?0x204:0x208);return outcome;
}
#define SERVER_START_REQ(operation) do {struct fake_request request_storage={0};struct fake_reply reply_storage={0};struct fake_request *req=&request_storage;struct fake_reply *reply=&reply_storage;req->op=#operation;current_reply=reply;
#define SERVER_END_REQ }while(0)
/*production-validation*/
/*production-native-sections*/
/*production-thunks*/
int main(void){
    size_t bytes=0x10000;void *window=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(window!=MAP_FAILED);
    wow_guest_base=(ULONG_PTR)window;assert(wow_guest_base>UINT32_MAX);
    OBJECT_ATTRIBUTES32 *attr=(void*)(wow_guest_base+0x100);UNICODE_STRING32 *name=(void*)(wow_guest_base+0x200);
    WCHAR *characters=(void*)(wow_guest_base+0x300);LARGE_INTEGER *size=(void*)(wow_guest_base+0x500);ULONG *output_handle=(void*)(wow_guest_base+0x600);
    const char *text="SteamChrome_MasterStream_spid92_mem-IPCWrapper";size_t n=strlen(text);
    for(size_t i=0;i<n;++i)characters[i]=(unsigned char)text[i];
    *name=(UNICODE_STRING32){(uint16_t)(n*2),(uint16_t)(n*2),0x300};
    *attr=(OBJECT_ATTRIBUTES32){sizeof(*attr),0x6c,0x200,0x80,0,0};size->QuadPart=0x2010;
    UINT create[]={0x600,0xf001f,0x100,0x500,4,0x8000000,0};
    outcome=0;assert(wow64_NtCreateSection(create)==0&&*output_handle==0x204&&native_calls==1);
    assert(lines==1&&strstr(output,"op=create pid=0090 tid=0094 abi=i386")&&strstr(output,"name=SteamChrome_MasterStream_spid92_mem-IPCWrapper"));
    outcome=(NTSTATUS)0xc0000017;assert(wow64_NtCreateSection(create)==outcome&&*output_handle==0&&native_calls==2);
    assert(lines==2&&strstr(output,"status=c0000017"));
    UINT open[]={0x600,0xf001f,0x100};outcome=STATUS_OBJECT_NAME_NOT_FOUND;
    assert(wow64_NtOpenSection(open)==outcome&&*output_handle==0&&native_calls==3);
    assert(lines==3&&strstr(output,"op=open pid=0090 tid=0094 abi=i386"));
    outcome=0;assert(wow64_NtOpenSection(open)==0&&*output_handle==0x208&&native_calls==4&&lines==4);
    /* Real native early rejection before SERVER_START_REQ must be visible.
     * The old post-alloc observer misses this exact malformed-SD result. */
    SECURITY_DESCRIPTOR_RELATIVE *sd=(void*)(wow_guest_base+0x700);sd->Revision=0;attr->SecurityDescriptor=0x700;
    assert(wow64_NtCreateSection(create)==STATUS_UNKNOWN_REVISION&&*output_handle==0&&native_calls==4);
    if(lines!=5){fprintf(stderr,"missing early STATUS_UNKNOWN_REVISION observation\n");return 7;}
    assert(strstr(output,"status=c0000058"));attr->SecurityDescriptor=0;
    create[4]=3;assert(wow64_NtCreateSection(create)==STATUS_INVALID_PAGE_PROTECTION&&*output_handle==0&&native_calls==4&&lines==6);
    create[4]=4;
    struct object_attr64 converted;OBJECT_ATTRIBUTES *attributes=objattr_32to64(&converted,attr);attributes->Length=0;HANDLE native_handle=(void*)-1;
    assert(NtCreateSection(&native_handle,0xf001f,attributes,size,4,0x8000000,NULL)==STATUS_INVALID_PARAMETER&&native_handle==0&&native_calls==4&&lines==7);
    assert(NtOpenSection(&native_handle,0xf001f,attributes)==STATUS_INVALID_PARAMETER&&native_handle==0&&native_calls==4&&lines==8);
    assert(strstr(output,"status=c000000d"));
    assert(!munmap(window,bytes));
    puts("PASS actual Wine I386 thunks + native section guards reach production observer: nonidentity pointers, raw handles, real validation/unknown-SD-revision/invalid-protection/NT result statuses, no changed protocol");
}
'''.replace('/*production-converters*/',functions).replace('/*production-thunks*/',thunks).replace('/*production-validation*/',validation).replace('/*production-native-sections*/',native_sections)
with tempfile.TemporaryDirectory(prefix='htmlipc-wow64-section-') as folder:
    source=Path(folder)/'test.c';source.write_text(code);binary=Path(folder)/'test'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(ROOT/'build/ntdll-unix'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=20)
