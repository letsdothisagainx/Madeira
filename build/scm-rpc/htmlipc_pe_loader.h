/* SPDX-License-Identifier: MIT. Maintained PE loader overlay, ARM64EC only. */
#ifndef MADEIRA_HTMLIPC_PE_LOADER_H
#define MADEIRA_HTMLIPC_PE_LOADER_H
#include "htmlipc_policy.h"
/* LdrLoadDll holds loader_section across this state and recursive attach.
 * It is process-private ntdll data, never a global AppInit/proxy DLL switch. */
static struct madeira_htmlipc_preload_state madeira_htmlipc_source_state;
struct madeira_htmlipc_load_context { NTSTATUS status; };
static int madeira_htmlipc_load_source(void *opaque)
{
    struct madeira_htmlipc_load_context *context=opaque;
    UNICODE_STRING name;HMODULE module=NULL;
    RtlInitUnicodeString(&name,L"C:\\windows\\system32\\madeira-htmlipc-bridge.dll");
    /* Normal PE attach invokes AMD64 DllMain through Wine ARM64EC dispatch.
     * The provider configures itself; no factory/GetStatus/config export calls
     * are made under the loader lock or from native Unix code. */
    context->status=LdrLoadDll(NULL,0,&name,&module);
    return !context->status&&module;
}
static NTSTATUS madeira_htmlipc_before_chromehtml(const UNICODE_STRING *requested)
{
    UNICODE_STRING helper_name,cache_name,helper,cache,*image;
    WCHAR helper_buffer[32768],cache_buffer[32768];
    struct madeira_htmlipc_load_context context={STATUS_SUCCESS};
    NTSTATUS hs,cs;int result;
    if(!requested||!requested->Buffer||(requested->Length&1)||
       (!madeira_htmlipc_basename(requested->Buffer,requested->Length/sizeof(WCHAR),"chromehtml.dll")&&
        !madeira_htmlipc_basename(requested->Buffer,requested->Length/sizeof(WCHAR),"chromehtml"))||
       !NtCurrentTeb()->Peb->ProcessParameters)return STATUS_SUCCESS;
    image=&NtCurrentTeb()->Peb->ProcessParameters->ImagePathName;
    if((image->Length&1)||!madeira_htmlipc_basename(image->Buffer,image->Length/sizeof(WCHAR),"steam.exe"))return STATUS_SUCCESS;
    RtlInitUnicodeString(&helper_name,L"MADEIRA_HTMLIPC_HELPER");
    RtlInitUnicodeString(&cache_name,L"MADEIRA_HTMLIPC_CACHE_DIR");
    helper.Buffer=helper_buffer;helper.Length=0;helper.MaximumLength=sizeof(helper_buffer)-sizeof(WCHAR);
    cache.Buffer=cache_buffer;cache.Length=0;cache.MaximumLength=sizeof(cache_buffer)-sizeof(WCHAR);
    hs=RtlQueryEnvironmentVariable_U(NULL,&helper_name,&helper);
    cs=RtlQueryEnvironmentVariable_U(NULL,&cache_name,&cache);
    if(hs==STATUS_VARIABLE_NOT_FOUND&&cs==STATUS_VARIABLE_NOT_FOUND)return STATUS_SUCCESS;
    if(hs||cs||(helper.Length&1)||(cache.Length&1)||
       !madeira_htmlipc_cache_target(helper.Buffer,helper.Length/sizeof(WCHAR),cache.Buffer,cache.Length/sizeof(WCHAR)))
        return STATUS_NOT_SUPPORTED;
    result=madeira_htmlipc_preload(&madeira_htmlipc_source_state,1,madeira_htmlipc_load_source,&context);
    if(result<0){
        static unsigned reports;
        if(reports++<4)ERR("[htmlipc-native-v1] preload failed; chromehtml refused status=%08x\n",(unsigned)context.status);
        return context.status?context.status:STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}
#endif
