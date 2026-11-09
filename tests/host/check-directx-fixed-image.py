#!/usr/bin/env python3
"""Run Madeira's actual fixed-image contract and Wine relocation check.

The synthetic PE header matches the captured infinst architecture, fixed 4GiB
base, stripped/absent relocations and 64KiB image. It is not Valve/Microsoft
code and does not establish that the official DirectX installer completes.
Only OS/protection/callback plumbing is supplied by the host harness; Native
eligibility, owned registry, capability snapshot, startup guard, VM translation,
entry translation and Wine's relocation rejection execute production bodies.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
v=(ROOT/'build/ntdll-unix/virtual_ios.c').read_text()
s=(ROOT/'build/ntdll-unix/signal_arm64_ios.c').read_text()
f=(ROOT/'build/ntdll-unix/fex_view_ownership.h').read_text()
w=(ROOT/'wine/dlls/ntdll/loader.c').read_text()
# Literal production snapshot of the installed 9d441546 source guard. Keep the
# negative control self-contained: Actions uses shallow checkouts and must not
# depend on a local history rewrite/hash being present in the runner.
old_header=r'''
    else if (!image_info->map_addr && image_info->base && image_info->base < 0x100000000ull &&
             (ULONG_PTR)ptr != image_info->base &&
             (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
             nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && !ios_wow_in_window( ptr ))
    {
        ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase = (ULONG_PTR)ptr;
        fprintf( stderr, "ml1195: sub-floor image RELOCS_STRIPPED without a dynamic base, mapped at "
                 "%p (preferred %#llx): ImageBase rewritten, nothing relocated\n",
                 ptr, (unsigned long long)image_info->base );
    }
'''
def body(text,start):
    brace=text.index('{',start); depth=1; end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}'); end+=1
    return text[start:end]
def function(text,name):
    start=text.index(name)
    while text.index(';',start)<text.index('{',start): start=text.index(name,start+len(name))
    # Start at return type, not a preceding explanatory comment.
    start=text.rfind('\n',0,start)+1
    return body(text,start)+'\n'
def header_block(text):
    a=text.index('    else if (!image_info->map_addr')
    return text[a:text.index('\n#endif\n\n#ifdef WINE_IOS\n    /* ml938:',a)]
reg=s[s.index('#define IOS_SUBFLOOR_MAX '):s.index('/* Read `size` bytes at `a`',s.index('#define IOS_SUBFLOOR_MAX '))]
# Compile the guard verbatim, and assert it runs before callback publication/drain.
a=v.index('NTSTATUS unixcall_ios_push_jit_aliases(')
g=v.index('    {\n        extern int ios_subfloor_extended_owner',a)
guard=body(v,g)
assert g < v.index('ios_jit_alias_pushback_peb = self;',a) < v.index('/* ml951:',a)
prefix=r'''
#define _GNU_SOURCE
#define _WIN64 1
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include "windef.h"
#include "winnt.h"
#include "ntstatus.h"
typedef LONG NTSTATUS;
static const unsigned page_size=0x1000;
struct fake_peb {void *ImageBaseAddress;};
static struct fake_peb pebs[2];
static _Thread_local struct {struct fake_peb *Peb;} teb;
#define NtCurrentTeb() (&teb)
#define NtCurrentProcess() ((HANDLE)(uintptr_t)-1)
#define GetProcessHeap() ((HANDLE)1)
#define WARN(...) ((void)0)
#define TRACE(...) ((void)0)
#define get_rva(base,offset) ((void *)((char *)(base)+(offset)))
static void *RtlAllocateHeap(HANDLE h,ULONG flags,SIZE_T bytes) {(void)h;(void)flags;return malloc(bytes);}
static void RtlFreeHeap(HANDLE h,ULONG flags,void *p) {(void)h;(void)flags;free(p);}
static NTSTATUS NtProtectVirtualMemory(HANDLE h,void **p,SIZE_T *size,ULONG prot,ULONG *old) {
    (void)h;(void)p;(void)size;(void)prot;*old=PAGE_READONLY;return STATUS_SUCCESS;
}
static IMAGE_BASE_RELOCATION *LdrProcessRelocationBlock(void *p,UINT count,USHORT *rel,INT_PTR delta) {
    (void)p;(void)count;(void)rel;(void)delta;assert(!"stripped fixture must not relocate bytes");return NULL;
}
static unsigned long long leases[2]={23,29};
static unsigned quiescent[2];
static unsigned long long ios_thread_process_lease(void *owner,int create) {
    (void)create;for(unsigned i=0;i<2;i++)if(owner==&pebs[i])return leases[i];return 0;
}
static unsigned long long ios_thread_process_quiescent_lease(void *owner) {
    for(unsigned i=0;i<2;i++)if(owner==&pebs[i]&&quiescent[i])return leases[i];return 0;
}
static void *ios_jit_current_peb(void) {return teb.Peb;}
static uint64_t mock_floor=UINT64_C(0x1044f8000);
static char *ios_query_map_floor(void) {return (char *)(uintptr_t)mock_floor;}
static int wow;
static _Thread_local const void *ios_subfloor_main_image_info;
static int ios_wow_in_window(const void *p) {(void)p;return wow;}
static void diagnostic(int fd,const char *format,...) {(void)format;assert(fd==2);}
#define dprintf diagnostic
static struct {void *peb;void (*cb)(unsigned long long,unsigned long long,unsigned long long);} callbacks[2];
typedef void (*ios_alias_cb_t)(unsigned long long,unsigned long long,unsigned long long);
static int ios_alias_per_process_enabled(void) {return 1;}
static ios_alias_cb_t ios_alias_cb_for(void *owner) {
    for(unsigned i=0;i<2;i++)if(callbacks[i].peb==owner)return callbacks[i].cb;return NULL;
}
static ios_alias_cb_t ios_jit_alias_pushback_cb;
static void *ios_jit_alias_pushback_peb;
static int ios_subfloor_callback_capable(void *,ios_alias_cb_t);
static unsigned messages,controls,windows;
static uint64_t last_low,last_real,last_size;
static void callback(unsigned long long low,unsigned long long real,unsigned long long size) {
    messages++;
    if(!low&&!real) {assert(size==mock_floor);controls++;}
    else {assert(size);last_low=low;last_real=real;last_size=size;windows++;}
}
struct ios_jit_mapping {
    unsigned long long generation; void *pe_base,*jit_base;size_t size;
    void *owner_peb,*map_peb;unsigned unmapped,is_fex;
};
static struct ios_jit_mapping ios_jit_mappings[2];
static int ios_jit_mapping_count;
static ULONG_PTR ios_fex_arena_base_unix=0xb50000000ull,ios_fex_arena_end_unix=0xd50000000ull;
static const char *backend_name="libarm64ecfex.dll";
static const char *ios_pe_module_name(const void *base,size_t size) {(void)base;(void)size;return backend_name;}
'''
prefix+=function(v,'unsigned long long ios_subfloor_map_floor(')
prefix+=reg
prefix+=function(v,'void ios_push_subfloor_window(')
prefix+=f[f.index('#define IOS_FEX_OWNERS'):f.index('extern unsigned long long ios_thread_process_lease')]
for name in ('static int ios_fex_range_ok(', 'static ULONG_PTR *ios_fex_private_export(', 'static NTSTATUS ios_fex_prepare_image(', 'static int ios_fex_subfloor_image_capable('):prefix+=function(f,name)
prefix+=function(v,'static int ios_subfloor_callback_capable( void *owner, ios_alias_cb_t callback )')
prefix+=function(v,'static int ios_subfloor_fixed_main_eligible(')
prefix+=function(v,'static int ios_subfloor_image_translate(')
prefix+=function(v,'void *ios_subfloor_low_entry(')
prefix+=function(w,'static NTSTATUS perform_relocations(')
prefix+='\n'+next(line for line in v.splitlines() if line.startswith('#define VPROT_ARM64EC'))+'\n'
prefix+=r'''
static jmp_buf terminated;
static unsigned termination_status;
static void abort_process(int status) {termination_status=(unsigned)status;longjmp(terminated,1);}
struct ios_push_jit_aliases_args {ios_alias_cb_t callback;};
static NTSTATUS startup_guard(void *args) {
    struct ios_push_jit_aliases_args *params=args;
    void *self=ios_jit_current_peb();
    if(!params||!params->callback)return STATUS_INVALID_PARAMETER;
'''+guard+r'''
    return STATUS_SUCCESS;
}
struct image_mapping {uint64_t map_addr,base;unsigned is_hybrid;};
static NTSTATUS previous_map_header(struct image_mapping *image_info,char *ptr,size_t total_size,IMAGE_NT_HEADERS *nt) {
    NTSTATUS status=STATUS_SUCCESS;(void)total_size;
    if(image_info->map_addr) {}
'''+old_header+r'''
    return status;
}
static NTSTATUS actual_map_header(struct image_mapping *image_info,char *ptr,size_t total_size,IMAGE_NT_HEADERS *nt) {
    NTSTATUS status=STATUS_SUCCESS;
    struct {unsigned protect;} storage={0},*view=&storage;
    if(image_info->map_addr) {}
'''+header_block(v)+r'''
done:return status;
}
'''
main=r'''
static char *image,*backend;
static const size_t image_size=0x10000;
static IMAGE_NT_HEADERS64 *header(char *p) {return (void *)(p+0x80);}
static void header_init(char *p) {
    memset(p,0,image_size);IMAGE_DOS_HEADER *dos=(void *)p;IMAGE_NT_HEADERS64 *nt=header(p);
    dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=0x80;
    nt->Signature=IMAGE_NT_SIGNATURE;nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.Characteristics=0x23;nt->FileHeader.NumberOfSections=1;
    nt->FileHeader.SizeOfOptionalHeader=sizeof(nt->OptionalHeader);
    nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.ImageBase=0x100000000ull;nt->OptionalHeader.SectionAlignment=page_size;
    nt->OptionalHeader.SizeOfImage=image_size;nt->OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
}
static void backend_init(int version) {
    header_init(backend);IMAGE_NT_HEADERS64 *nt=header(backend);
    IMAGE_SECTION_HEADER *sections=IMAGE_FIRST_SECTION(nt);
    sections->VirtualAddress=0x1000;sections->Misc.VirtualSize=0x1000;
    sections->Characteristics=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]=(IMAGE_DATA_DIRECTORY){0x2000,0x400};
    IMAGE_EXPORT_DIRECTORY *dir=(void *)(backend+0x2000);
    dir->NumberOfNames=dir->NumberOfFunctions=3;
    dir->AddressOfNames=0x2040;dir->AddressOfFunctions=0x2050;dir->AddressOfNameOrdinals=0x2060;
    DWORD *names=(void *)(backend+0x2040),*functions=(void *)(backend+0x2050);
    WORD *ord=(void *)(backend+0x2060);
    const char *symbols[]={"ios_fex_band_base","ios_fex_band_end","IosSubfloorProtocolV1"};
    size_t off=0x2100;
    for(unsigned i=0;i<3;i++) {names[i]=off;strcpy(backend+off,symbols[i]);off+=strlen(symbols[i])+1;functions[i]=0x1000+i*8;ord[i]=i;}
    *(uint64_t *)(backend+0x1010)=version?0x4d53460100000001ull:0;
    assert(ios_fex_prepare_image(backend,image_size,nt,sections,1)==STATUS_SUCCESS);
    ios_jit_mapping_count=1;
    ios_jit_mappings[0]=(struct ios_jit_mapping){1,backend,(void *)((uintptr_t)&callback&~0xfffull),0x10000,teb.Peb,teb.Peb,0,1};
    callbacks[0].peb=teb.Peb;callbacks[0].cb=callback;
}
static void reset_window(void) {
    memset(ios_subfloor,0,sizeof(ios_subfloor));ios_subfloor_count=0;
    memset(ios_fex_owners,0,sizeof(ios_fex_owners));
    memset(callbacks,0,sizeof(callbacks));ios_jit_mapping_count=0;
    messages=controls=windows=termination_status=0;quiescent[0]=quiescent[1]=0;
    teb.Peb=&pebs[0];leases[0]=23;leases[1]=29;wow=0;
    pebs[0].ImageBaseAddress=image;header_init(image);
}
struct reader_args {void *owner;uintptr_t real;_Atomic(unsigned) *done;};
static void *mapping_reader(void *opaque) {
    struct reader_args *args=opaque;teb.Peb=args->owner;
    while(!*args->done) {
        uintptr_t single=ios_subfloor_translate(0x100008000ull,args->owner);
        uintptr_t span=ios_subfloor_translate_span(0x100008000ull,8,args->owner);
        assert(!single||single==args->real+0x8000);
        assert(!span||span==args->real+0x8000);
        assert(!ios_subfloor_translate(0x100008000ull,NULL));
    }
    return NULL;
}
static void concurrent_owner_reuse(void) {
    reset_window();_Atomic(unsigned) done=0;pthread_t readers[4];
    struct reader_args args[4]={
        {&pebs[0],(uintptr_t)image,&done},{&pebs[1],(uintptr_t)backend,&done},
        {&pebs[0],(uintptr_t)image,&done},{&pebs[1],(uintptr_t)backend,&done}};
    for(unsigned i=0;i<4;i++)assert(!pthread_create(&readers[i],NULL,mapping_reader,&args[i]));
    for(unsigned i=0;i<5000;i++) {
        assert(ios_register_fixed_subfloor_image(0x100000000ull,image_size,(uintptr_t)image,&pebs[0]));
        ios_subfloor_release_mapping((uintptr_t)image,image_size);
        assert(ios_register_fixed_subfloor_image(0x100000000ull,image_size,(uintptr_t)backend,&pebs[1]));
        ios_subfloor_release_mapping((uintptr_t)backend,image_size);
    }
    done=1;
    for(unsigned i=0;i<4;i++)assert(!pthread_join(readers[i],NULL));
    assert(!ios_subfloor_translate(0x100008000ull,&pebs[0]));
    assert(!ios_subfloor_translate(0x100008000ull,&pebs[1]));
    puts("PASS concurrent native publication/retirement: 10000 slot generations, four owner-specific lock-free readers, no mixed or foreign translation");
}
int main(int argc,char **argv) {
    assert(argc==2);teb.Peb=&pebs[0];
    if(!strcmp(argv[1],"floor-off")) {assert(ios_subfloor_map_floor()==0x100000000ull);return 0;}
    if(!strcmp(argv[1],"floor-invalid")) {mock_floor=0x800000000ull;assert(ios_subfloor_map_floor()==0x100000000ull);return 0;}
    if(!strcmp(argv[1],"floor-unaligned")) {mock_floor++;assert(ios_subfloor_map_floor()==0x100000000ull);return 0;}
    assert(ios_subfloor_map_floor()==mock_floor);
    image=mmap((void *)0x13d700000ull,image_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    backend=mmap((void *)0x240000000ull,image_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(image!=MAP_FAILED&&backend!=MAP_FAILED&&(uintptr_t)image>=mock_floor&&(uintptr_t)backend>=mock_floor);
    reset_window();
    struct image_mapping info={0,0x100000000ull,0};
    assert(previous_map_header(&info,image,image_size,(void *)header(image))==STATUS_SUCCESS);
    assert(header(image)->OptionalHeader.ImageBase==0x100000000ull);
    assert(perform_relocations(image,(void *)header(image),image_size)==STATUS_CONFLICTING_ADDRESSES);
    assert(!ios_subfloor_count);
    puts("PASS previous production main-map guard reproduces exact4GiB RELOCS_STRIPPED Wine C0000018 before guest entry");
    assert(actual_map_header(&info,image,image_size,(void *)header(image))==STATUS_CONFLICTING_ADDRESSES);
    assert(!ios_subfloor_count&&header(image)->OptionalHeader.ImageBase==0x100000000ull);
    /* Only the exact initial-main mapping token can enter this protocol. */
    ios_subfloor_main_image_info=&info;
    char *many=mmap(NULL,IOS_SUBFLOOR_MAX*image_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(many!=MAP_FAILED&&(uintptr_t)many>=mock_floor);
    for(unsigned i=0;i<IOS_SUBFLOOR_MAX;i++)
        ios_register_subfloor_image(0x10000000ull+i*0x20000ull,image_size,(uintptr_t)many+i*image_size,teb.Peb);
    assert(ios_subfloor_count==IOS_SUBFLOOR_MAX);
    assert(actual_map_header(&info,image,image_size,(void *)header(image))==STATUS_CONFLICTING_ADDRESSES);
    assert(header(image)->OptionalHeader.ImageBase==0x100000000ull);
    ios_subfloor_release_owner(teb.Peb);assert(!munmap(many,IOS_SUBFLOOR_MAX*image_size));
    assert(actual_map_header(&info,image,image_size,(void *)header(image))==STATUS_SUCCESS);
    assert(header(image)->OptionalHeader.ImageBase==(uintptr_t)image&&ios_subfloor[0].size==image_size);
    assert(perform_relocations(image,(void *)header(image),image_size)==STATUS_SUCCESS);
    assert(ios_subfloor_extended_owner(teb.Peb,23)==1);
    assert(ios_subfloor_low_entry(image+0x3710,0x23)==(void *)0x100003710ull);
    assert(!messages); /* backend unknown: never probe a callback */
    struct ios_push_jit_aliases_args args={callback};
    if(!setjmp(terminated)) {startup_guard(&args);assert(!"old backend must stop");}
    assert(termination_status==(unsigned)STATUS_NOT_SUPPORTED&&!messages);
    backend_init(0);
    if(!setjmp(terminated)) {startup_guard(&args);assert(!"missing capability must stop");}
    assert(!messages);
    backend_init(1);
    assert(!mprotect(backend,0x1000,PROT_NONE));
    assert(startup_guard(&args)==STATUS_SUCCESS); /* cached proof never rereads protected headers */
    assert(!mprotect(backend,0x1000,PROT_READ|PROT_WRITE));
    ios_push_subfloor_window(0x100000000ull,(uintptr_t)image,image_size,teb.Peb);
    assert(messages==2&&controls==1&&windows==1&&last_low==0x100000000ull&&last_real==(uintptr_t)image&&last_size==image_size);
    uint64_t expected=0x7162534435261708ull,out=0;
    memcpy(image+0x8000,&expected,8);
    /* Captured domain includes bit32; never narrow this absolute address to0. */
    unsigned long long real=ios_subfloor_translate_span(0x100008000ull,8,teb.Peb);
    assert(real==(uintptr_t)image+0x8000);memcpy(&out,(void *)(uintptr_t)real,8);assert(out==expected);
    *(uint64_t *)(uintptr_t)real=expected+1;memcpy(&out,image+0x8000,8);assert(out==expected+1);
    assert(ios_subfloor_image_translate(0x100008000ull,8,&real)&&real==(uintptr_t)image+0x8000);
    assert(!ios_subfloor_translate_span(0x10000fffcull,8,teb.Peb));
    assert(!ios_subfloor_image_translate(0x10000fffcull,8,&real));
    assert(!ios_subfloor_image_translate(UINT64_MAX-1,8,&real));
    assert(!ios_subfloor_translate(0,teb.Peb)&&!ios_subfloor_translate(4,teb.Peb));
    assert(!ios_subfloor_translate(0x100008000ull,&pebs[1])&&!ios_subfloor_translate(0x100008000ull,NULL));
    uint64_t saved=ios_subfloor[0].real_base;
    assert(!ios_register_fixed_subfloor_image(0x100000000ull,image_size,(uintptr_t)image+0x20000,teb.Peb));
    assert(ios_subfloor[0].real_base==saved);
    assert(!ios_register_fixed_subfloor_image(mock_floor-0x1000,0x2000,(uintptr_t)image,teb.Peb));
    assert(!ios_register_fixed_subfloor_image(0x100000000ull,image_size,UINT64_MAX-8,teb.Peb));
    /* Replacing a CPU image with an old/malformed export table cannot inherit
     * the previously cached protocol, even at the same address and lease. */
    IMAGE_NT_HEADERS64 *backend_header=header(backend);
    DWORD *exports=(void *)(backend+0x2050);
    DWORD saved_export=exports[2];exports[2]=0x2000; /* forwarder is not DATA */
    assert(ios_fex_prepare_image(backend,image_size,backend_header,IMAGE_FIRST_SECTION(backend_header),1)==STATUS_SUCCESS);
    assert(!ios_subfloor_callback_capable(teb.Peb,callback));
    exports[2]=saved_export;
    assert(ios_fex_prepare_image(backend,image_size,backend_header,IMAGE_FIRST_SECTION(backend_header),1)==STATUS_SUCCESS);
    assert(ios_subfloor_callback_capable(teb.Peb,callback));
    DWORD saved_names=((IMAGE_EXPORT_DIRECTORY *)(backend+0x2000))->AddressOfNames;
    ((IMAGE_EXPORT_DIRECTORY *)(backend+0x2000))->AddressOfNames=image_size+1;
    assert(ios_fex_prepare_image(backend,image_size,backend_header,IMAGE_FIRST_SECTION(backend_header),1)==STATUS_SUCCESS);
    assert(!ios_subfloor_callback_capable(teb.Peb,callback));
    ((IMAGE_EXPORT_DIRECTORY *)(backend+0x2000))->AddressOfNames=saved_names;
    assert(ios_fex_prepare_image(backend,image_size,backend_header,IMAGE_FIRST_SECTION(backend_header),1)==STATUS_SUCCESS);
    /* A differently named non-CPU view at identical PE/owner/lease and a new
     * live JIT generation cannot inherit pre-CRT proof from the old CPU. */
    backend_name="unrelated.dll";ios_jit_mappings[0].generation++;
    assert(ios_fex_prepare_image(backend,image_size,backend_header,IMAGE_FIRST_SECTION(backend_header),1)==STATUS_SUCCESS);
    assert(!ios_fex_subfloor_image_capable(teb.Peb,backend,23));
    assert(!ios_subfloor_callback_capable(teb.Peb,callback));
    backend_name="libarm64ecfex.dll";ios_jit_mappings[0].generation++;
    assert(ios_fex_prepare_image(backend,image_size,backend_header,IMAGE_FIRST_SECTION(backend_header),1)==STATUS_SUCCESS);
    /* Live image/callback identity and process generation are independent proof. */
    ios_jit_mappings[0].is_fex=0;assert(!ios_subfloor_callback_capable(teb.Peb,callback));ios_jit_mappings[0].is_fex=1;
    ios_jit_mappings[0].unmapped=1;assert(!ios_subfloor_callback_capable(teb.Peb,callback));ios_jit_mappings[0].unmapped=0;
    ios_jit_mappings[0].generation=0;assert(!ios_subfloor_callback_capable(teb.Peb,callback));ios_jit_mappings[0].generation=1;
    assert(!ios_subfloor_callback_capable(&pebs[1],callback));
    leases[0]++;assert(ios_subfloor_extended_owner(teb.Peb,leases[0])==-1);
    assert(!ios_subfloor_callback_capable(teb.Peb,callback));
    ios_subfloor_release_owner(teb.Peb);assert(!ios_subfloor_translate(0x100008000ull,teb.Peb));
    assert(ios_register_fixed_subfloor_image(0x100000000ull,image_size,(uintptr_t)image,teb.Peb));
    assert(ios_subfloor[0].owner_lease==24&&ios_subfloor_extended_owner(teb.Peb,24)==1);
    ios_subfloor_release_mapping((uintptr_t)image,image_size);
    assert(!ios_subfloor_translate(0x100008000ull,teb.Peb));
    assert(ios_register_fixed_subfloor_image(0x100000000ull,image_size,(uintptr_t)image,teb.Peb));
    assert(ios_subfloor_translate(0x100008000ull,teb.Peb)==(uintptr_t)image+0x8000);
    reset_window();
    /* Neither generic relocation rules nor this owner can opt a native/WoW or
     * relocatable/DLL/cross-floor/unbacked image into the new protocol. */
    IMAGE_NT_HEADERS64 *nt=header(image);
    nt->FileHeader.Characteristics|=IMAGE_FILE_DLL;assert(!ios_subfloor_fixed_main_eligible(info.base,image_size,image,(void *)nt,0));
    nt->FileHeader.Characteristics&=~IMAGE_FILE_DLL;
    nt->OptionalHeader.DllCharacteristics|=IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;assert(!ios_subfloor_fixed_main_eligible(info.base,image_size,image,(void *)nt,0));
    nt->OptionalHeader.DllCharacteristics=0;
    assert(!ios_subfloor_fixed_main_eligible(info.base,image_size,image,(void *)nt,1));
    nt->FileHeader.Characteristics&=~IMAGE_FILE_RELOCS_STRIPPED;assert(!ios_subfloor_fixed_main_eligible(info.base,image_size,image,(void *)nt,0));
    nt->FileHeader.Characteristics|=IMAGE_FILE_RELOCS_STRIPPED;wow=1;assert(!ios_subfloor_fixed_main_eligible(info.base,image_size,image,(void *)nt,0));wow=0;
    assert(!ios_subfloor_fixed_main_eligible(info.base+1,image_size,image,(void *)nt,0));
    assert(!ios_subfloor_fixed_main_eligible(info.base,image_size-1,image,(void *)nt,0));
    assert(!ios_subfloor_fixed_main_eligible(mock_floor-0x1000,0x2000,image,(void *)nt,0));
    assert(!ios_subfloor_fixed_main_eligible(info.base,image_size,(void *)(mock_floor-0x1000),(void *)nt,0));
    /* Preserved legacy logical image and shared KUSER separation. */
    ios_register_subfloor_image(0x400000,image_size,(uintptr_t)image,teb.Peb);
    ios_register_subfloor_image(0x7ffe0000,0x1000,(uintptr_t)backend,NULL);
    assert(ios_subfloor_translate(0x408000,teb.Peb)==(uintptr_t)image+0x8000);
    assert(ios_subfloor_translate(0x7ffe0004,&pebs[1])==(uintptr_t)backend+4);
    assert(!ios_subfloor_image_translate(0x7ffe0004,4,&real));
    concurrent_owner_reuse();
    assert(!munmap(image,image_size)&&!munmap(backend,image_size));
    puts("PASS production actual-floor contract: fixedmain eligibility/publication/entry/VM spans; pre-CRT DATA version + live callback owner/lease/generation; old-backend abort before guest; absolute64-bit data reads/writes, no null alias, overflow/collision/stale retirement refusal, unchanged legacy windows");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-directx-fixed-') as temp:
    path=Path(temp);src=path/'check.c';exe=path/'check'
    src.write_text(prefix+main)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-Wno-sign-compare','-Wno-unused-function','-Wno-unused-variable','-Wno-misleading-indentation',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread','-I'+str(ROOT/'wine/include'),
                    str(src),'-o',str(exe)],check=True)
    for mode, env in [('normal',{}),('floor-off',{'MADEIRA_SUBFLOOR_ACTUAL_FLOOR':'0'}),
                      ('floor-off',{'MADEIRA_SUBFLOOR_LOWENTRY':'0'}),('floor-off',{'MADEIRA_SUBFLOOR_VM':'0'}),
                      ('floor-off',{'MADEIRA_ALIAS_PER_PROCESS':'0'}),('floor-off',{'MADEIRA_NO_SUBFLOOR_XQUERY':'1'}),
                      ('floor-invalid',{}),('floor-unaligned',{})]:
        subprocess.run([str(exe),mode],env=dict(os.environ,**env),check=True,timeout=30)
