/* SPDX-License-Identifier: MIT.
 * Compile the exact native header against bounded Wine/Mach test doubles.
 * Synthetic images and process memory only; this proves no real Steam UI. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint16_t WCHAR, USHORT;
typedef uint32_t ULONG, NTSTATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct list_entry { struct list_entry *Flink,*Blink; } LIST_ENTRY;
typedef struct { LIST_ENTRY InLoadOrderModuleList; } PEB_LDR_DATA;
typedef struct { UNICODE_STRING ImagePathName,CommandLine; unsigned other; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; PEB_LDR_DATA *Ldr; } PEB;
typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    UNICODE_STRING BaseDllName;
    void *DllBase;
    ULONG SizeOfImage;
} LDR_DATA_TABLE_ENTRY;
typedef struct { struct { void *UniqueProcess; } ClientId; } TEB;
typedef uint64_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define TRUE 1
#define FALSE 0
#define KERN_SUCCESS 0
#define IMAGE_FILE_MACHINE_I386 0x014c
#define STATUS_SUCCESS UINT32_C(0)
#define STATUS_NOT_SUPPORTED UINT32_C(0xc00000bb)
#define STATUS_NO_MEMORY UINT32_C(0xc0000017)
#define HandleToULong(h) ((uint32_t)(uintptr_t)(h))
#define GetCurrentProcess() ((HANDLE)(intptr_t)-1)
static TEB test_teb;
#define NtCurrentTeb() (&test_teb)
static unsigned mock_reads,mock_snapshots,mock_fail_read,mock_expire_snapshot;
static uint64_t mock_lease;
static unsigned mock_threads;
static int mock_exiting,mock_reclaimed;
static void *mock_owner;
static HANDLE mock_parent;
static unsigned char *mock_flip_data;
static struct { uintptr_t start; size_t size; } ranges[8];
static unsigned nranges;
static void readable(void *start,size_t size)
{
    assert(nranges<ARRAY_SIZE(ranges));
    ranges[nranges].start=(uintptr_t)start;ranges[nranges++].size=size;
}
static int mach_task_self(void) { return 0; }
static int mach_vm_read_overwrite(int task,mach_vm_address_t address,size_t size,
                                 mach_vm_address_t output,mach_vm_size_t *got)
{
    unsigned i;(void)task;*got=0;++mock_reads;
    if(mock_fail_read&&mock_reads==mock_fail_read)return 1;
    for(i=0;i<nranges;i++)if(address>=ranges[i].start&&address-ranges[i].start<=ranges[i].size&&
        size<=ranges[i].size-(size_t)(address-ranges[i].start)){
        memcpy((void *)(uintptr_t)output,(const void *)(uintptr_t)address,size);*got=size;
        if(mock_flip_data&&address==(uintptr_t)mock_flip_data){mock_flip_data[28]=1;mock_flip_data=NULL;}
        return KERN_SUCCESS;
    }
    return 1;
}
void *ios_jit_current_peb(void) { return mock_owner; }
unsigned long long ios_thread_process_snapshot(void *owner,unsigned *threads,int *exiting,int *reclaimed)
{
    ++mock_snapshots;*threads=mock_threads;*exiting=mock_exiting;*reclaimed=mock_reclaimed;
    if(owner!=mock_owner)return 0;
    return mock_expire_snapshot&&mock_snapshots>=mock_expire_snapshot?mock_lease+1:mock_lease;
}
#include "htmlipc_native.h"

#define IMAGE_SIZE 0x4000u
static const char helper[]="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7\\steamwebhelper.exe";
static const char cache[]="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7";
static const char original_image[]="C:\\Program Files (x86)\\Steam\\bin\\cef\\cef.win64\\steamwebhelper.exe";
static const char tail[]="\t -nocrashdialog \"-steampid=32\" \"-buildid=1234567890\" \"-steamid=76561199999999999\""
    " \"-cachedir=C:\\users\\mobile\\AppData\\Local\\Steam\\htmlcache\" --js-flags=\"--jitless --max_old_space_size=128\"";
struct fixture {
    PEB peb;PEB_LDR_DATA ldr;LDR_DATA_TABLE_ENTRY module,core;
    RTL_USER_PROCESS_PARAMETERS parent,child;
    UNICODE_STRING path;
    WCHAR parent_name[128],module_name[128],core_name[128],image_name[256],nt_name[256],command[1024];
    _Alignas(8) unsigned char image[IMAGE_SIZE];
};
static struct fixture f;
static void u16(unsigned char *p,unsigned v) { p[0]=v;p[1]=v>>8; }
static void u32(unsigned char *p,uint32_t v) { p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24; }
static size_t widen(WCHAR *out,const char *in)
{
    size_t n=strlen(in);for(size_t i=0;i<=n;i++)out[i]=(unsigned char)in[i];return n;
}
static void string(UNICODE_STRING *s,WCHAR *buffer,const char *value)
{
    size_t n=widen(buffer,value);assert(n<32767);
    s->Buffer=buffer;s->Length=n*sizeof(WCHAR);s->MaximumLength=(n+1)*sizeof(WCHAR);
}
static int equals(const UNICODE_STRING *s,const char *value)
{
    size_t n=strlen(value);
    if(s->Length!=n*sizeof(WCHAR))return 0;
    for(size_t i=0;i<n;i++)if(s->Buffer[i]!=(unsigned char)value[i])return 0;
    return !s->Buffer[n];
}
static struct madeira_htmlipc_ready *ready(void)
{ return (struct madeira_htmlipc_ready *)(void *)(f.image+0x2080); }
static void build(void)
{
    unsigned char *p;LIST_ENTRY *head;char cmd[2048],nt[512];
    memset(&f,0,sizeof(f));mock_reads=mock_snapshots=mock_fail_read=mock_expire_snapshot=0;
    mock_lease=UINT64_C(0x123456789);mock_threads=3;mock_exiting=mock_reclaimed=0;
    mock_owner=&f.peb;mock_parent=NULL;mock_flip_data=NULL;test_teb.ClientId.UniqueProcess=(void *)(uintptr_t)32;
    nranges=0;readable(&f,sizeof(f));
    assert(!setenv("MADEIRA_HTMLIPC_HELPER",helper,1));assert(!setenv("MADEIRA_HTMLIPC_CACHE_DIR",cache,1));
    f.peb.ProcessParameters=&f.parent;f.peb.Ldr=&f.ldr;
    string(&f.parent.ImagePathName,f.parent_name,"C:\\Program Files (x86)\\Steam\\Steam.exe");
    string(&f.module.BaseDllName,f.module_name,"madeira-htmlipc-bridge.dll");
    string(&f.core.BaseDllName,f.core_name,"chromehtml.dll");
    head=&f.ldr.InLoadOrderModuleList;head->Flink=&f.module.InLoadOrderLinks;head->Blink=&f.core.InLoadOrderLinks;
    f.module.InLoadOrderLinks.Blink=head;f.module.InLoadOrderLinks.Flink=&f.core.InLoadOrderLinks;
    f.core.InLoadOrderLinks.Blink=&f.module.InLoadOrderLinks;f.core.InLoadOrderLinks.Flink=head;
    f.core.DllBase=(void *)(uintptr_t)UINT64_C(0x7110000000);f.core.SizeOfImage=0x1000;
    f.module.DllBase=f.image;f.module.SizeOfImage=sizeof(f.image);
    string(&f.child.ImagePathName,f.image_name,original_image);
    assert(snprintf(nt,sizeof(nt),"\\??\\%s",original_image)>0);string(&f.path,f.nt_name,nt);
    assert(snprintf(cmd,sizeof(cmd),"\"%s\"%s",original_image,tail)>0);string(&f.child.CommandLine,f.command,cmd);
    f.child.other=UINT32_C(0xdecafbad);
    p=f.image;u16(p,0x5a4d);u32(p+60,0x80);
    p+=0x80;u32(p,0x4550);u16(p+4,0x8664);u16(p+6,2);u16(p+20,240);
    p+=24;u16(p,0x20b);u32(p+56,IMAGE_SIZE);u32(p+60,0x400);
    u32(p+108,16);u32(p+112,0x1000);u32(p+116,0x200);
    p=f.image+0x188;memcpy(p,".rdata",6);u32(p+8,0x1000);u32(p+12,0x1000);u32(p+36,0x40000040);
    p+=40;memcpy(p,".data",5);u32(p+8,0x1000);u32(p+12,0x2000);u32(p+36,0xc0000040);
    p=f.image+0x1000;u32(p+20,1);u32(p+24,1);u32(p+28,0x1100);u32(p+32,0x1110);u32(p+36,0x1120);
    u32(f.image+0x1100,0x2080);u32(f.image+0x1110,0x1140);u16(f.image+0x1120,0);
    memcpy(f.image+0x1140,"MadeiraRuntimeReady",sizeof("MadeiraRuntimeReady"));
    *ready()=(struct madeira_htmlipc_ready){
        .magic=MADEIRA_HTMLIPC_READY_MAGIC,.size=sizeof(*ready()),.version=1,.sequence=2,
        .flags=MADEIRA_HTMLIPC_READY_FLAGS,.pid=32,.owner_peb=(uintptr_t)&f.peb,
        .owner_lease=mock_lease,.self_module=(uintptr_t)f.image,.installed_module=UINT64_C(0x7110000000),.generation=1};
}
static NTSTATUS run(USHORT requested,BOOL *redirected,WCHAR **path,WCHAR **command)
{ return ios_htmlipc_redirect(&f.path,&f.child,requested,mock_parent,path,command,redirected); }
static void rejected(USHORT requested)
{
    UNICODE_STRING old_path=f.path,old_image=f.child.ImagePathName,old_command=f.child.CommandLine;
    WCHAR *path=(void *)(uintptr_t)1,*command=(void *)(uintptr_t)1;BOOL redirected=TRUE;
    assert(run(requested,&redirected,&path,&command)==STATUS_NOT_SUPPORTED);
    assert(!redirected&&!path&&!command);
    assert(!memcmp(&f.path,&old_path,sizeof(old_path))&&!memcmp(&f.child.ImagePathName,&old_image,sizeof(old_image))&&
           !memcmp(&f.child.CommandLine,&old_command,sizeof(old_command)));
}
static void unchanged(void)
{
    UNICODE_STRING old_path=f.path,old_image=f.child.ImagePathName,old_command=f.child.CommandLine;
    WCHAR *path=(void *)(uintptr_t)1,*command=(void *)(uintptr_t)1;BOOL redirected=TRUE;
    assert(run(0,&redirected,&path,&command)==STATUS_SUCCESS);
    assert(!redirected&&!path&&!command);
    assert(!memcmp(&f.path,&old_path,sizeof(old_path))&&!memcmp(&f.child.ImagePathName,&old_image,sizeof(old_image))&&
           !memcmp(&f.child.CommandLine,&old_command,sizeof(old_command)));
}
static void success(USHORT requested)
{
    WCHAR *path,*command;BOOL redirected;char expected[2048];size_t old_end,tail_size;
    WCHAR preserved[1024];
    old_end=madeira_htmlipc_argv0_end(f.command,f.child.CommandLine.Length/sizeof(WCHAR));
    tail_size=f.child.CommandLine.Length/sizeof(WCHAR)-old_end;
    memcpy(preserved,f.command+old_end,tail_size*sizeof(WCHAR));
    assert(run(requested,&redirected,&path,&command)==STATUS_SUCCESS&&redirected);
    assert(path==f.path.Buffer&&f.child.ImagePathName.Buffer==path+4&&command==f.child.CommandLine.Buffer);
    assert(snprintf(expected,sizeof(expected),"\\??\\%s",helper)>0);assert(equals(&f.path,expected));
    assert(equals(&f.child.ImagePathName,helper));
    assert(snprintf(expected,sizeof(expected),"\"%s\"%s",helper,tail)>0);assert(equals(&f.child.CommandLine,expected));
    assert(!memcmp(command+strlen(helper)+2,preserved,tail_size*sizeof(WCHAR)));
    assert(f.path.MaximumLength==f.path.Length+sizeof(WCHAR));
    assert(f.child.ImagePathName.MaximumLength==f.child.ImagePathName.Length+sizeof(WCHAR));
    assert(f.child.CommandLine.MaximumLength==f.child.CommandLine.Length+sizeof(WCHAR));
    assert(f.child.other==UINT32_C(0xdecafbad));free(path);free(command);
}
int main(void)
{
    unsigned reads;char unquoted[2048];
    build();success(0);reads=mock_reads;
    build();success(IMAGE_FILE_MACHINE_I386);
    build();mock_parent=GetCurrentProcess();success(0);
    build();assert(snprintf(unquoted,sizeof(unquoted),"steamwebhelper.exe%s",tail)>0);
    string(&f.child.CommandLine,f.command,unquoted);success(0);
    /* Process/owner selection must leave every unrelated request untouched. */
    build();string(&f.parent.ImagePathName,f.parent_name,"C:\\games\\Game.exe");unchanged();
    build();string(&f.child.ImagePathName,f.image_name,"C:\\games\\Game.exe");unchanged();
    build();mock_owner=NULL;unchanged();
    build();assert(!unsetenv("MADEIRA_HTMLIPC_HELPER"));assert(!unsetenv("MADEIRA_HTMLIPC_CACHE_DIR"));unchanged();
    /* Active, properly tagged requests fail closed whenever either host input
     * or the actual source Installed/current-lease proof is unavailable. */
    build();assert(!unsetenv("MADEIRA_HTMLIPC_HELPER"));rejected(0);
    build();assert(!unsetenv("MADEIRA_HTMLIPC_CACHE_DIR"));rejected(0);
    build();assert(!setenv("MADEIRA_HTMLIPC_HELPER","C:\\other\\steamwebhelper.exe",1));rejected(0);
    build();assert(!setenv("MADEIRA_HTMLIPC_CACHE_DIR","C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7\\.. ",1));rejected(0);
    build();rejected(0x8664);
    build();mock_parent=(HANDLE)(uintptr_t)0x100;rejected(0); /* foreign PS parent handle */
    build();ready()->pid=33;rejected(0);
    build();ready()->owner_lease--;rejected(0);
    build();ready()->owner_peb++;rejected(0);
    build();ready()->self_module++;rejected(0);
    build();ready()->installed_module=0;rejected(0);
    build();ready()->installed_module++;rejected(0); /* readiness names a different core */
    build();ready()->flags&=~MADEIRA_HTMLIPC_READY_INSTALLED;rejected(0);
    build();ready()->flags&=~MADEIRA_HTMLIPC_READY_CACHE_VERIFIED;rejected(0);
    build();ready()->sequence=3;rejected(0);
    build();ready()->sequence=0;rejected(0);
    build();ready()->provider_error=1;rejected(0);
    build();ready()->installer_error=1;rejected(0);
    build();ready()->generation=0;rejected(0);
    build();ready()->magic=0;rejected(0);
    build();ready()->size--;rejected(0);
    build();ready()->version++;rejected(0);
    build();ready()->reserved=1;rejected(0);
    build();mock_flip_data=f.image+0x2080;rejected(0); /* snapshots differ */
    build();mock_lease=0;rejected(0);
    build();mock_threads=0;rejected(0);
    build();mock_exiting=1;rejected(0);
    build();mock_reclaimed=1;rejected(0);
    build();mock_expire_snapshot=3;rejected(0); /* generation changed during native read */
    build();f.peb.Ldr=NULL;rejected(0);
    build();f.peb.Ldr=(void *)(uintptr_t)0x12345670000;rejected(0);
    build();f.ldr.InLoadOrderModuleList.Flink=f.ldr.InLoadOrderModuleList.Blink=&f.ldr.InLoadOrderModuleList;rejected(0);
    build();f.ldr.InLoadOrderModuleList.Flink=NULL;rejected(0);
    build();f.ldr.InLoadOrderModuleList.Blink=&f.ldr.InLoadOrderModuleList;rejected(0);
    build();f.module.InLoadOrderLinks.Blink=&f.module.InLoadOrderLinks;rejected(0);
    build();f.module.InLoadOrderLinks.Flink=&f.module.InLoadOrderLinks;rejected(0);
    build();string(&f.module.BaseDllName,f.module_name,"other.dll");rejected(0);
    build();f.module.BaseDllName.Buffer=(void *)(uintptr_t)0x12345670000;rejected(0);
    build();f.module.SizeOfImage=1;rejected(0);
    build();string(&f.core.BaseDllName,f.core_name,"other.dll");rejected(0);
    build();f.core.DllBase=(void *)(uintptr_t)UINT64_C(0x7220000000);rejected(0);
    build();f.core.BaseDllName=f.module.BaseDllName;f.core.DllBase=f.module.DllBase;
    f.core.SizeOfImage=f.module.SizeOfImage;rejected(0); /* duplicate bridge in current list */
    {
        LDR_DATA_TABLE_ENTRY many[257];LIST_ENTRY *head;WCHAR unknown[16];UNICODE_STRING other_name;
        build();memset(many,0,sizeof(many));readable(many,sizeof(many));readable(unknown,sizeof(unknown));
        string(&other_name,unknown,"other.dll");head=&f.ldr.InLoadOrderModuleList;
        head->Flink=&many[0].InLoadOrderLinks;head->Blink=&many[256].InLoadOrderLinks;
        many[0]=f.module;many[1]=f.core;
        for(unsigned i=0;i<ARRAY_SIZE(many);i++){
            if(i>1)many[i].BaseDllName=other_name;
            many[i].InLoadOrderLinks.Blink=i?&many[i-1].InLoadOrderLinks:head;
            many[i].InLoadOrderLinks.Flink=i+1<ARRAY_SIZE(many)?&many[i+1].InLoadOrderLinks:head;
        }
        rejected(0);assert(mock_reads<800); /* valid proof beyond explicit 256-entry read budget */
    }
    build();u32(f.image+0x1100,0x1180);rejected(0); /* forwarded export */
    build();u32(f.image+0x1b0+36,0xe0000040);rejected(0); /* executable object */
    build();string(&f.path,f.nt_name,"\\??\\C:\\other.exe");rejected(0);
    build();string(&f.child.CommandLine,f.command,"helper.exe -steampid=33 -buildid=123");rejected(0);
    build();string(&f.child.CommandLine,f.command,"helper.exe --foo=\" -steampid=32 -buildid=123 a\"--bar");rejected(0);
    /* Every native DATA read failure must close the gate or leave the request
     * unrelated, without changing its path or parameters. */
    for(unsigned i=1;i<=reads;i++){
        WCHAR *path,*command;BOOL redirected;NTSTATUS status;
        build();mock_fail_read=i;status=run(0,&redirected,&path,&command);
        assert(status==STATUS_NOT_SUPPORTED||status==STATUS_SUCCESS);
        assert(!redirected&&!path&&!command);
        assert(equals(&f.child.ImagePathName,original_image));
    }
    assert(!unsetenv("MADEIRA_HTMLIPC_HELPER"));assert(!unsetenv("MADEIRA_HTMLIPC_CACHE_DIR"));
    puts("native header: coherent redirect, untouched tail, passthrough, current-PID/lease readiness and malformed DATA/LDR gates passed");
    return 0;
}
