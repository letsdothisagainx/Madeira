/* SPDX-License-Identifier: MIT. Exact PE preloader header, normal attach mocked. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t WCHAR;typedef int32_t NTSTATUS;typedef void *HMODULE;
typedef struct {uint16_t Length,MaximumLength;WCHAR *Buffer;} UNICODE_STRING;
typedef struct {UNICODE_STRING ImagePathName;} PARAMETERS;
typedef struct {PARAMETERS *ProcessParameters;} PEB;
typedef struct {PEB *Peb;} TEB;
#define STATUS_SUCCESS 0
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_VARIABLE_NOT_FOUND ((NTSTATUS)0xc0000100)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define ERR(...) ((void)0)
static TEB teb;static PEB peb;static PARAMETERS parameters;
static WCHAR helper[1024],cache[1024];static int helper_set,cache_set,fail_load,recursive_load;
static unsigned loads;
static TEB *NtCurrentTeb(void){return &teb;}
static size_t wlen(const WCHAR *p){size_t n=0;while(p[n])n++;return n;}
static void RtlInitUnicodeString(UNICODE_STRING *s,const WCHAR *v){s->Buffer=(WCHAR *)v;s->Length=wlen(v)*2;s->MaximumLength=s->Length+2;}
static int weq(const WCHAR *a,const char *b){size_t i;for(i=0;b[i];i++)if(a[i]!=(unsigned char)b[i])return 0;return !a[i];}
static NTSTATUS RtlQueryEnvironmentVariable_U(void *env,UNICODE_STRING *name,UNICODE_STRING *out){
    WCHAR *value;int set;(void)env;
    if(weq(name->Buffer,"MADEIRA_HTMLIPC_HELPER")){value=helper;set=helper_set;}else{assert(weq(name->Buffer,"MADEIRA_HTMLIPC_CACHE_DIR"));value=cache;set=cache_set;}
    if(!set)return STATUS_VARIABLE_NOT_FOUND;
    out->Length=wlen(value)*2;if(out->Length>out->MaximumLength)return STATUS_BUFFER_TOO_SMALL;
    memcpy(out->Buffer,value,out->Length);return STATUS_SUCCESS;
}
static NTSTATUS LdrLoadDll(const WCHAR *,void *,const UNICODE_STRING *,HMODULE *);
#include "htmlipc_pe_loader.h"
static NTSTATUS LdrLoadDll(const WCHAR *path,void *flags,const UNICODE_STRING *name,HMODULE *out){
    UNICODE_STRING core;(void)path;(void)flags;loads++;
    assert(weq(name->Buffer,"C:\\windows\\system32\\madeira-htmlipc-bridge.dll"));
    if(recursive_load){RtlInitUnicodeString(&core,(const WCHAR *)L"chromehtml.dll");assert(madeira_htmlipc_before_chromehtml(&core)==STATUS_NOT_SUPPORTED);}
    *out=fail_load?NULL:(void *)(uintptr_t)0x71000000;
    return fail_load?STATUS_NOT_SUPPORTED:STATUS_SUCCESS;
}
static void wide(WCHAR *out,const char *s){size_t i;for(i=0;s[i];i++)out[i]=(unsigned char)s[i];out[i]=0;}
int main(void){
    UNICODE_STRING request;WCHAR image[128];
    teb.Peb=&peb;peb.ProcessParameters=&parameters;wide(image,"C:\\Steam\\Steam.exe");RtlInitUnicodeString(&parameters.ImagePathName,image);
    wide(cache,"C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7");wide(helper,"C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7\\steamwebhelper.exe");
    RtlInitUnicodeString(&request,(const WCHAR *)L"chromehtml.dll");
    assert(madeira_htmlipc_before_chromehtml(&request)==0&&!loads);
    helper_set=1;assert(madeira_htmlipc_before_chromehtml(&request)==STATUS_NOT_SUPPORTED&&!loads);
    cache_set=1;recursive_load=1;assert(madeira_htmlipc_before_chromehtml(&request)==0&&loads==1);
    assert(madeira_htmlipc_before_chromehtml(&request)==0&&loads==1);
    madeira_htmlipc_source_state.state=0;fail_load=1;assert(madeira_htmlipc_before_chromehtml(&request)==STATUS_NOT_SUPPORTED&&loads==2);
    fail_load=0;assert(madeira_htmlipc_before_chromehtml(&request)==STATUS_NOT_SUPPORTED&&loads==2);
    madeira_htmlipc_source_state.state=0;recursive_load=0;
    RtlInitUnicodeString(&request,(const WCHAR *)L"chromehtml");assert(madeira_htmlipc_before_chromehtml(&request)==0&&loads==3);
    madeira_htmlipc_source_state.state=0;
    RtlInitUnicodeString(&request,(const WCHAR *)L"libcef.dll");assert(madeira_htmlipc_before_chromehtml(&request)==0&&loads==3);
    wide(image,"C:\\Games\\game.exe");RtlInitUnicodeString(&parameters.ImagePathName,image);
    RtlInitUnicodeString(&request,(const WCHAR *)L"chromehtml.dll");assert(madeira_htmlipc_before_chromehtml(&request)==0&&loads==3);
    wide(image,"C:\\Steam\\steam.exe");RtlInitUnicodeString(&parameters.ImagePathName,image);helper[0]='D';
    assert(madeira_htmlipc_before_chromehtml(&request)==STATUS_NOT_SUPPORTED&&loads==3);
    puts("PE loader: exact Steam/chromehtml scope, normal source load, recursive dependency, cached success, failure and unrelated pass-through passed");
    return 0;
}
