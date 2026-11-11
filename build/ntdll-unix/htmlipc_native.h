/* SPDX-License-Identifier: MIT. Included by native process_ios.c, WINE_IOS only.
 * Read AMD64 DATA only. Never call a guest PE export from the native Unix host. */
#ifndef MADEIRA_HTMLIPC_NATIVE_H
#define MADEIRA_HTMLIPC_NATIVE_H
#include "../scm-rpc/htmlipc_policy.h"
#include "../scm-rpc/htmlipc_ready_reader.h"
#include "htmlipc_log_path.h"
extern void *ios_jit_current_peb(void);
extern unsigned long long ios_thread_process_snapshot(void *,unsigned *,int *,int *);

static uint64_t ios_htmlipc_live_lease(void *owner)
{
    unsigned threads=0;int exiting=0,reclaimed=0;
    uint64_t lease=ios_thread_process_snapshot(owner,&threads,&exiting,&reclaimed);
    return lease&&threads&&!exiting&&!reclaimed?lease:0;
}
static int ios_htmlipc_read(void *context,uint64_t address,void *out,size_t size)
{
    mach_vm_size_t got=0;(void)context;
    if(!address||address<0x10000||!size||address>UINTPTR_MAX-size)return 0;
    return mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)address,size,
        (mach_vm_address_t)out,&got)==KERN_SUCCESS&&got==size;
}
static int ios_htmlipc_current_steam(void *owner,WCHAR *name,size_t capacity,size_t *length)
{
    RTL_USER_PROCESS_PARAMETERS *parameters=NULL;UNICODE_STRING image;
    if(!owner||!ios_htmlipc_read(NULL,(uintptr_t)owner+offsetof(PEB,ProcessParameters),&parameters,sizeof(parameters))||
       !parameters||!ios_htmlipc_read(NULL,(uintptr_t)parameters+offsetof(RTL_USER_PROCESS_PARAMETERS,ImagePathName),&image,sizeof(image))||
       !image.Buffer||!image.Length||(image.Length&1)||image.Length/sizeof(WCHAR)>=capacity||
       !ios_htmlipc_read(NULL,(uintptr_t)image.Buffer,name,image.Length))return 0;
    *length=image.Length/sizeof(WCHAR);name[*length]=0;
    return madeira_htmlipc_basename(name,*length,"steam.exe");
}
/* Every spawn starts at the current PEB, not a global module list. Native64
 * LDR pointers are already real addresses: no blanket guest-base addition.
 * Check both directions, complete the bounded walk, and reject concurrent list
 * changes. No positive pointer/readiness result survives this invocation. */
/* Failure evidence is copied only from two identical, current-owner DATA
 * snapshots. It never authorizes a redirect or outlives this invocation. */
struct ios_htmlipc_ready_evidence {
    int coherent;
    uint32_t flags,provider_error,installer_error;
};
static int ios_htmlipc_source_ready(void *owner,uint64_t lease,uint32_t pid,
                                   struct ios_htmlipc_ready_evidence *evidence)
{
    PEB_LDR_DATA *ldr=NULL;LIST_ENTRY first,last,links;uintptr_t head,current,previous;
    uint64_t module=0,core_module=0,address=0;uint32_t image_size=0;unsigned seen=0,core_seen=0,count=0;
    struct madeira_htmlipc_ready a,b;
    if(evidence)memset(evidence,0,sizeof(*evidence));
    if(!lease||owner!=ios_jit_current_peb()||lease!=ios_htmlipc_live_lease(owner)||
       !ios_htmlipc_read(NULL,(uintptr_t)owner+offsetof(PEB,LdrData),&ldr,sizeof(ldr))||!ldr)return 0;
    head=(uintptr_t)ldr+offsetof(PEB_LDR_DATA,InLoadOrderModuleList);
    if(!ios_htmlipc_read(NULL,head,&first,sizeof(first)))return 0;
    current=(uintptr_t)first.Flink;previous=head;
    while(current!=head){
        uintptr_t entry;UNICODE_STRING name;WCHAR basename[64];
        if(!current||++count>256)return 0;
        entry=current-offsetof(LDR_DATA_TABLE_ENTRY,InLoadOrderLinks);
        if(!ios_htmlipc_read(NULL,current,&links,sizeof(links))||(uintptr_t)links.Blink!=previous||
           !ios_htmlipc_read(NULL,entry+offsetof(LDR_DATA_TABLE_ENTRY,BaseDllName),&name,sizeof(name)))return 0;
        if(name.Length&&!(name.Length&1)&&name.Length<sizeof(basename)&&name.Buffer&&
           ios_htmlipc_read(NULL,(uintptr_t)name.Buffer,basename,name.Length)){
            int source=madeira_htmlipc_basename(basename,name.Length/sizeof(WCHAR),"madeira-htmlipc-bridge.dll");
            int core=madeira_htmlipc_basename(basename,name.Length/sizeof(WCHAR),"chromehtml.dll");
            if(source||core){
                void *base=NULL;ULONG size=0;
                if(!ios_htmlipc_read(NULL,entry+offsetof(LDR_DATA_TABLE_ENTRY,DllBase),&base,sizeof(base))||
                   !ios_htmlipc_read(NULL,entry+offsetof(LDR_DATA_TABLE_ENTRY,SizeOfImage),&size,sizeof(size))||
                   !base||size<0x1000)return 0;
                if(source){if(++seen!=1||size>(32u<<20))return 0;module=(uintptr_t)base;image_size=size;}
                else{if(++core_seen!=1)return 0;core_module=(uintptr_t)base;}
            }
        }
        previous=current;current=(uintptr_t)links.Flink;
    }
    if((uintptr_t)first.Blink!=previous||!ios_htmlipc_read(NULL,head,&last,sizeof(last))||
       memcmp(&first,&last,sizeof(first))||seen!=1||core_seen!=1||
       !madeira_htmlipc_find_ready_export(ios_htmlipc_read,NULL,module,image_size,&address)||
       !ios_htmlipc_read(NULL,address,&a,sizeof(a))||!ios_htmlipc_read(NULL,address,&b,sizeof(b))||
       owner!=ios_jit_current_peb()||lease!=ios_htmlipc_live_lease(owner)||
       pid!=HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess))return 0;
    if(evidence&&!memcmp(&a,&b,sizeof(a))&&a.magic==MADEIRA_HTMLIPC_READY_MAGIC&&
       a.size==sizeof(a)&&a.version==MADEIRA_HTMLIPC_READY_VERSION&&a.sequence&&!(a.sequence&1)&&
       a.pid==pid&&a.owner_peb==(uintptr_t)owner&&a.owner_lease==lease&&a.self_module==module&&
       !a.reserved&&a.generation){
        evidence->coherent=1;evidence->flags=a.flags;
        evidence->provider_error=a.provider_error;evidence->installer_error=a.installer_error;
    }
    return a.installed_module==core_module&&madeira_htmlipc_ready_valid(&a,&b,(uintptr_t)owner,lease,pid,module);
}
/* At most 32 rejection records per private native image. No command line,
 * environment value, pointer or private path enters this failure trail. */
static unsigned ios_htmlipc_rejection_count;
static NTSTATUS ios_htmlipc_reject(const char *stage,NTSTATUS status,uint32_t pid,
                                  USHORT requested_machine,const struct ios_htmlipc_ready_evidence *evidence)
{
    unsigned count=__atomic_load_n(&ios_htmlipc_rejection_count,__ATOMIC_RELAXED);
    while(count<32&&!__atomic_compare_exchange_n(&ios_htmlipc_rejection_count,&count,count+1,0,
                                                __ATOMIC_RELAXED,__ATOMIC_RELAXED)){}
    if(count<32){
        if(evidence&&evidence->coherent)
            dprintf(2,"[htmlipc-native-v1] result=refused stage=%s status=%08x pid=%04x requested-machine=%04x ready-data=coherent flags=%08x provider-error=%08x installer-error=%08x\n",
                stage,(unsigned)status,(unsigned)pid,(unsigned)requested_machine,
                (unsigned)evidence->flags,(unsigned)evidence->provider_error,(unsigned)evidence->installer_error);
        else
            dprintf(2,"[htmlipc-native-v1] result=refused stage=%s status=%08x pid=%04x requested-machine=%04x ready-data=unavailable\n",
                stage,(unsigned)status,(unsigned)pid,(unsigned)requested_machine);
    }
    return status;
}
/* The host-owned compatibility cache uses an ASCII Windows C path, outside
 * Steam's installation. Reject non-ASCII/embedded controls without a lossy
 * host-codepage conversion that could select a different file. */
static int ios_htmlipc_env_path(const char *value,WCHAR *out,size_t capacity,size_t *length)
{
    size_t n;
    if(!value||(n=strlen(value))==0||n>32760||n>=capacity)return 0;
    for(size_t i=0;i<n;i++){unsigned char c=value[i];if(c<32||c>126)return 0;out[i]=c;}
    out[n]=0;*length=n;return 1;
}
/* Returns success unchanged for all unrelated applications. Activation comes
 * only from the host-selected helper/cache pair. No environment value alone
 * authorizes a 32-bit child: source Installed DATA + live lease are mandatory. */
static NTSTATUS ios_htmlipc_redirect(UNICODE_STRING *path,RTL_USER_PROCESS_PARAMETERS *params,
    USHORT requested_machine,HANDLE parent,WCHAR **allocated_path,WCHAR **allocated_command,BOOL *redirected)
{
    const char *helper_env=getenv("MADEIRA_HTMLIPC_HELPER"),*cache_env=getenv("MADEIRA_HTMLIPC_CACHE_DIR");
    WCHAR helper[32768],cache[32768],steam[32768],*new_path=NULL,*new_command=NULL;size_t hn,cn,sn,command_n;
    enum madeira_htmlipc_log_route log_route;
    struct ios_htmlipc_ready_evidence evidence;
    void *owner=ios_jit_current_peb();uint64_t lease;uint32_t pid;
    *redirected=FALSE;*allocated_path=NULL;*allocated_command=NULL;
    if(!madeira_htmlipc_basename(params->ImagePathName.Buffer,params->ImagePathName.Length/sizeof(WCHAR),"steamwebhelper.exe")||
       !ios_htmlipc_current_steam(owner,steam,ARRAY_SIZE(steam),&sn)||(!helper_env&&!cache_env))return STATUS_SUCCESS;
    pid=HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess);
    if(parent&&parent!=GetCurrentProcess())
        return ios_htmlipc_reject("parent",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(!helper_env||!cache_env)
        return ios_htmlipc_reject("env-pair",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(!path->Buffer||(path->Length&1)||(params->ImagePathName.Length&1)||(params->CommandLine.Length&1)||
       !madeira_htmlipc_basename(path->Buffer,path->Length/sizeof(WCHAR),"steamwebhelper.exe"))
        return ios_htmlipc_reject("path",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(!madeira_htmlipc_steam_tags(params->CommandLine.Buffer,params->CommandLine.Length/sizeof(WCHAR),pid))
        return ios_htmlipc_reject("steam-tags",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(!ios_htmlipc_env_path(helper_env,helper,ARRAY_SIZE(helper),&hn)||
       !ios_htmlipc_env_path(cache_env,cache,ARRAY_SIZE(cache),&cn)||
       !madeira_htmlipc_cache_target(helper,hn,cache,cn))
        return ios_htmlipc_reject("cache-paths",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(requested_machine&&requested_machine!=IMAGE_FILE_MACHINE_I386)
        return ios_htmlipc_reject("requested-machine",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(!(lease=ios_htmlipc_live_lease(owner)))
        return ios_htmlipc_reject("owner-lease",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    if(!ios_htmlipc_source_ready(owner,lease,pid,&evidence))
        return ios_htmlipc_reject("bridge-ready",STATUS_NOT_SUPPORTED,pid,requested_machine,&evidence);
    /* Get_pe_file_info determines the real target machine after this rewrite.
     * No machine or image metadata is fabricated or forced to I386. */
    if(!(new_path=malloc((hn+5)*sizeof(WCHAR)))||
       !(new_command=malloc(32768*sizeof(WCHAR)))){
        free(new_path);return ios_htmlipc_reject("allocation",STATUS_NO_MEMORY,pid,requested_machine,NULL);
    }
    if(!madeira_htmlipc_replace_argv0(params->CommandLine.Buffer,params->CommandLine.Length/sizeof(WCHAR),
                                    helper,hn,new_command,32768,&command_n)){
        free(new_path);free(new_command);return ios_htmlipc_reject("argv0",STATUS_NOT_SUPPORTED,pid,requested_machine,NULL);
    }
    log_route=madeira_htmlipc_route_log(new_command,command_n,32768,steam,sn,&command_n);
    /* Logging is best effort; failed parsing/allocation/capacity leaves the
     * successfully redirected command byte-identical and cannot deny launch. */
    new_path[0]='\\';new_path[1]='?';new_path[2]='?';new_path[3]='\\';
    memcpy(new_path+4,helper,(hn+1)*sizeof(WCHAR));
    path->Buffer=new_path;path->Length=(hn+4)*sizeof(WCHAR);path->MaximumLength=(hn+5)*sizeof(WCHAR);
    params->ImagePathName.Buffer=new_path+4;params->ImagePathName.Length=hn*sizeof(WCHAR);
    params->ImagePathName.MaximumLength=(hn+1)*sizeof(WCHAR);
    params->CommandLine.Buffer=new_command;params->CommandLine.Length=command_n*sizeof(WCHAR);
    params->CommandLine.MaximumLength=(command_n+1)*sizeof(WCHAR);
    *allocated_path=new_path;*allocated_command=new_command;*redirected=TRUE;
    dprintf(2,"[htmlipc-native-v1] helper=cache readiness=installed owner-lease=verified\n");
    dprintf(2,"[htmlipc-log-v1] destination=%s cache-default=%s\n",
        log_route==MADEIRA_HTMLIPC_LOG_ERROR?"unchanged":log_route==MADEIRA_HTMLIPC_LOG_EXPLICIT?"explicit":
        log_route==MADEIRA_HTMLIPC_LOG_STEAM?"steam-logs":"stderr",
        log_route==MADEIRA_HTMLIPC_LOG_STEAM||log_route==MADEIRA_HTMLIPC_LOG_STDERR?"avoided":
        log_route==MADEIRA_HTMLIPC_LOG_EXPLICIT?"not-assessed":"possible");
    return STATUS_SUCCESS;
}
#endif
