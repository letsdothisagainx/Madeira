/* SPDX-License-Identifier: MIT
 * Common Unix syscall boundary: unlike the ARM64EC-only PE wrapper, this sees
 * both genuine I386 helper creators and AMD64 Steam openers. Observation only;
 * no object, handle, namespace, mapping, return status or readiness is changed. */
#ifndef MADEIRA_HTMLIPC_SECTION_TRACE_H
#define MADEIRA_HTMLIPC_SECTION_TRACE_H
#ifndef IOS_HTMLIPC_TRACE_READ
static int ios_htmlipc_section_read(const void *source,void *target,size_t size)
{
    mach_vm_size_t copied=0;uintptr_t address=(uintptr_t)source;
    if(!address||address<0x10000||!size||address>UINTPTR_MAX-size)return 0;
    return mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)address,size,
        (mach_vm_address_t)target,&copied)==KERN_SUCCESS&&copied==size;
}
#define IOS_HTMLIPC_TRACE_READ ios_htmlipc_section_read
#endif
/* Bootstrap/connected names contain public process IDs and random numeric
 * suffixes. Do not expose arbitrary SteamChrome_-prefixed payload or tokens. */
static int ios_htmlipc_section_public_name(const char *name)
{
    const char *p;unsigned fields;
    if(!strncmp(name,"SteamChrome_MasterStream_spid",29)){p=name+29;fields=1;}
    else if(!strncmp(name,"SteamChrome_MasterStream_",25)){p=name+25;fields=2;}
    else if(!strncmp(name,"SteamChrome_ClientStream_",25)){p=name+25;fields=2;}
    else return 0;
    for(unsigned i=0;i<fields;++i){
        unsigned digits=0;
        while(*p>='0'&&*p<='9'){if(++digits>10)return 0;++p;}
        if(!digits)return 0;
        if(i+1<fields&&*p++!='_')return 0;
    }
    return !strcmp(p,"_mem-IPCWrapper")||!strcmp(p,"_client_mem-IPCWrapper")||!strcmp(p,"_server_mem-IPCWrapper");
}
struct ios_htmlipc_section_snapshot {
    char name[160];HANDLE root;ULONGLONG size;
    unsigned active,size_valid,pid,tid,wow;
};
/* All caller input is copied before the real server protocol. A concurrent
 * unmap/retirement can make a diagnostic unavailable; it must not introduce a
 * fault, retain a guest pointer, or reinterpret data after its lifetime ends. */
static void ios_htmlipc_section_capture(struct ios_htmlipc_section_snapshot *out,
    const OBJECT_ATTRIBUTES *attributes,const LARGE_INTEGER *size)
{
    static const char prefix[]="SteamChrome_";
    OBJECT_ATTRIBUTES attr;UNICODE_STRING name;WCHAR characters[160];unsigned n,i;
    memset(out,0,sizeof(*out));
    if(!attributes||!IOS_HTMLIPC_TRACE_READ(attributes,&attr,sizeof(attr))||!attr.ObjectName||
       !IOS_HTMLIPC_TRACE_READ(attr.ObjectName,&name,sizeof(name))||!name.Buffer||!name.Length||(name.Length&1))return;
    n=name.Length/sizeof(WCHAR);
    if(n<sizeof(prefix)-1||n>=160||!IOS_HTMLIPC_TRACE_READ(name.Buffer,characters,name.Length))return;
    for(i=0;i<n;++i){unsigned c=characters[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return;
        out->name[i]=(char)c;
    }
    out->name[n]=0;
    if(memcmp(out->name,prefix,sizeof(prefix)-1)||!ios_htmlipc_section_public_name(out->name))return;
    out->root=attr.RootDirectory;
    out->size_valid=!size||IOS_HTMLIPC_TRACE_READ(size,&out->size,sizeof(out->size));
    if(!out->size_valid)out->size=0;
    out->pid=(unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
    out->tid=(unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    out->wow=in_wow64_call();out->active=1;
}
static void ios_htmlipc_section_note(const char *operation,const struct ios_htmlipc_section_snapshot *input,
    NTSTATUS status,const HANDLE *output,ULONG protect,ULONG flags)
{
    static unsigned reports,missing;
    unsigned attempt=0,handle_read=0;HANDLE handle=NULL;int saved_errno=errno;
    if(!input||!input->active)return;
    if(status==STATUS_OBJECT_NAME_NOT_FOUND){
        attempt=__atomic_add_fetch(&missing,1,__ATOMIC_RELAXED);
        /* First attempts and exponential milestones; no hot-loop log stream. */
        if(attempt>8&&(attempt&(attempt-1)))return;
    }
    if(__atomic_fetch_add(&reports,1,__ATOMIC_RELAXED)>=128)return;
    /* Failed operations have no meaningful output handle. Even on success the
     * observer performs only a fault-safe read; the original return is retained.
     * Root handles are recorded as handles, not queried through an extra RPC or
     * mistaken for a cross-process namespace identity. */
    if(status>=0&&output)handle_read=IOS_HTMLIPC_TRACE_READ(output,&handle,sizeof(handle));
    if(!handle_read)handle=NULL;
    dprintf(2,"[htmlipc-section-v1] op=%s pid=%04x tid=%04x abi=%s name=%s root-handle=%p namespace=unresolved status=%08x handle=%p handle-read=%u bytes=%llx bytes-valid=%u protect=%x flags=%x missing-attempt=%u\n",
        operation,input->pid,input->tid,input->wow?"i386":"native64",input->name,input->root,
        (unsigned)status,handle,handle_read,(unsigned long long)input->size,input->size_valid,
        (unsigned)protect,(unsigned)flags,attempt);
    errno=saved_errno;
}
#endif
