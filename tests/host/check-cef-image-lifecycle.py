#!/usr/bin/env python3
"""Run the private CEF-image owner/reaper against real host mappings."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
virtual = (root/'build/ntdll-unix/virtual_ios.c').read_text()
server = (root/'build/ntdll-unix/server_ios.c').read_text()
assert 'view->ios_cef_owner = NULL;' in virtual and 'view->ios_cef_lease = 0;' in virtual
assert '#include "cef_image_ownership.h"' in virtual
assert 'if (!is_builtin && !offset && !image_info->is_hybrid && !ios_map_resource_view)\n            ios_cef_tag_private_image( view, nt_name );' in virtual
finish = server[server.index('static void ios_finish_process_memory('):server.index('\nvoid process_exit_wrapper(',server.index('static void ios_finish_process_memory('))]
assert finish.index('ios_jit_reclaim_process(dead_peb);') < finish.index('ios_fex_reclaim_process_views(dead_peb);') < finish.index('ios_cef_reclaim_process_images(dead_peb);')
assert finish.index('ios_cef_reclaim_process_images(dead_peb);') < finish.index('ios_thread_process_finalize_native(dead_peb, lease)')

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef uint16_t WCHAR;
typedef int32_t LONG;
typedef struct { uint16_t Length,MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; } PEB;
typedef struct { uint16_t e_magic; unsigned char pad[58]; LONG e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { uint16_t Machine,NumberOfSections; uint32_t TimeDateStamp,PointerToSymbolTable,NumberOfSymbols; uint16_t SizeOfOptionalHeader,Characteristics; } IMAGE_FILE_HEADER;
typedef struct { uint16_t Magic; unsigned char pad[54]; uint32_t SizeOfImage; unsigned char rest[180]; } IMAGE_OPTIONAL_HEADER64;
typedef struct { uint32_t Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64;
typedef struct { unsigned char pad[36]; uint32_t Characteristics; } IMAGE_SECTION_HEADER;
#define IMAGE_DOS_SIGNATURE 0x5a4d
#define IMAGE_NT_SIGNATURE 0x4550
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define SEC_IMAGE 0x1000000
#define VPROT_SYSTEM 0x200
#define VPROT_ARM64EC 0x100
#define IOS_VIEW_QUARANTINED 4
struct file_view { void *base; size_t size; unsigned protect,ios_flags; void *ios_cef_owner; unsigned long long ios_cef_lease; int active; };
static struct file_view views[64];
static unsigned view_count;
static struct { int root; } views_tree;
#define WINE_RB_FOR_EACH_ENTRY(v,t,k,e) for (unsigned loop_i=0; loop_i<view_count && (((v)=&views[loop_i]),1); ++loop_i)
static pthread_mutex_t virtual_mutex=PTHREAD_MUTEX_INITIALIZER,ios_pool_lock=PTHREAD_MUTEX_INITIALIZER;
static struct { void *pe_base; size_t size; int unmapped; } ios_jit_mappings[64];
static int ios_jit_mapping_count;
static void *current;
static unsigned long long generation=1,quiescent,replace_on_lock;
static unsigned deleted,lock_depth;
static int wow;
static unsigned char *arena;
static size_t arena_bytes=128u<<20;
static const size_t host_page_mask=0x3fff;
static uintptr_t alias_base,alias_end;
static int ios_jit_anon_alias_overlaps(void *base,size_t bytes,uintptr_t *first,uintptr_t *end) {
    if(alias_base && alias_base<(uintptr_t)base+bytes && (uintptr_t)base<alias_end) {
        *first=alias_base;*end=alias_end;return 1;
    }
    return 0;
}
static void *ios_jit_current_peb(void) { return current; }
static uintptr_t ios_wow_base(void) { return wow ? 0x400000000ull : 0; }
static unsigned long long ios_thread_process_lease(void *owner,int create) { assert(!create); return owner==current?generation:0; }
static unsigned long long ios_thread_process_quiescent_lease(void *owner) { return owner==current?quiescent:0; }
#ifndef __APPLE__
static sigjmp_buf reader_context;
static void read_fault(int signal_number) { (void)signal_number;siglongjmp(reader_context,1); }
#endif
static int ios_io_trace_read(const void *source,void *out,size_t bytes) {
    if(!source || bytes>UINTPTR_MAX-(uintptr_t)source)return 0;
#ifdef __APPLE__
    mach_vm_size_t got=0;
    return mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)source,bytes,(mach_vm_address_t)out,&got)==KERN_SUCCESS && got==bytes;
#else
    /* Some Linux CI sandboxes disable process_vm_readv. This isolated,
     * single-threaded fixture uses a guarded copy for the same failure contract. */
    struct sigaction action={0},old_segv,old_bus;
    action.sa_handler=read_fault;sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGSEGV,&action,&old_segv));assert(!sigaction(SIGBUS,&action,&old_bus));
    volatile int ok=0;
    if(!sigsetjmp(reader_context,1)) { memcpy(out,source,bytes);ok=1; }
    assert(!sigaction(SIGSEGV,&old_segv,NULL));assert(!sigaction(SIGBUS,&old_bus,NULL));
    return ok;
#endif
}
static void server_enter_uninterrupted_section(pthread_mutex_t *mutex,sigset_t *set) {
    (void)set;assert(!pthread_mutex_lock(mutex));assert(!lock_depth++);
    if(replace_on_lock) { generation=replace_on_lock;quiescent=replace_on_lock;replace_on_lock=0; }
}
static void server_leave_uninterrupted_section(pthread_mutex_t *mutex,sigset_t *set) {
    (void)set;assert(lock_depth--==1);assert(!pthread_mutex_unlock(mutex));
}
static void note(int fd,const char *format,...) { assert(fd==2 && strstr(format,"[cef-image-owner-v1]")); }
#define dprintf note
static void delete_view(struct file_view *view) {
    assert(lock_depth && view->active);
    assert((unsigned char *)view->base>=arena && (unsigned char *)view->base+view->size<=arena+arena_bytes);
    /* Real reserved-area semantics: discard backing without exposing a hole. */
    size_t span=(view->size+host_page_mask)&~host_page_mask;
    void *p=mmap(view->base,span,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    assert(p==view->base);deleted++;memset(view,0,sizeof(*view));
}
#include "cef_image_ownership.h"
static UNICODE_STRING text(WCHAR *out,const char *input) {
    size_t n=strlen(input);for(size_t i=0;i<=n;i++)out[i]=(unsigned char)input[i];
    return (UNICODE_STRING){n*2,n*2+2,out};
}
static struct file_view *image(unsigned slot,size_t bytes) {
    unsigned index;
    for(index=0;index<view_count && views[index].active;index++){}
    assert(index<ARRAY_SIZE(views));if(index==view_count)view_count++;
    void *base=arena+slot*(2u<<20);assert((unsigned char *)base+bytes<=arena+arena_bytes);
    assert(mmap(base,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==base);
    memset(base,0x7a,bytes);
    IMAGE_DOS_HEADER *dos=base;memset(dos,0,sizeof(*dos));dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=0x100;
    IMAGE_NT_HEADERS64 *nt=(void *)((char *)base+0x100);memset(nt,0,sizeof(*nt));
    nt->Signature=IMAGE_NT_SIGNATURE;nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;nt->FileHeader.NumberOfSections=1;
    nt->FileHeader.SizeOfOptionalHeader=sizeof(nt->OptionalHeader);nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;nt->OptionalHeader.SizeOfImage=bytes;
    IMAGE_SECTION_HEADER *section=(void *)(nt+1);memset(section,0,sizeof(*section));
    views[index]=(struct file_view){.base=base,.size=bytes,.protect=SEC_IMAGE,.active=1};
    return &views[index];
}
static IMAGE_NT_HEADERS64 *nt(struct file_view *view) { return (void *)((char *)view->base+0x100); }
static void empty_backing(void *base,size_t bytes) {
    unsigned char resident[512];size_t pages=bytes/(size_t)sysconf(_SC_PAGESIZE);
    assert(pages<=sizeof(resident));assert(!mincore(base,bytes,(void *)resident));
    for(size_t i=0;i<pages;i++)assert(!(resident[i]&1));
    assert(!mprotect(base,bytes,PROT_READ));assert(*(volatile unsigned char *)base==0);
    assert(!mprotect(base,bytes,PROT_NONE));
}
int main(void) {
    (void)views_tree;
    assert(sizeof(IMAGE_DOS_HEADER)==64 && sizeof(IMAGE_OPTIONAL_HEADER64)==240 && sizeof(IMAGE_NT_HEADERS64)==264);
    void *reservation=mmap(NULL,arena_bytes+0x4000,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(reservation!=MAP_FAILED);arena=(void *)(((uintptr_t)reservation+0x3fff)&~(uintptr_t)0x3fff);
    WCHAR executable[128],dll[128],other[128];
    RTL_USER_PROCESS_PARAMETERS params={text(executable,"C:\\Steam\\bin\\cef\\cef.win64\\SteamWebHelper.EXE")};
    PEB owner={&params},survivor={&params};current=&owner;
    UNICODE_STRING libcef=text(dll,"C:\\Steam\\bin\\cef\\cef.win64\\libcef.dll"),wrong=text(other,"C:\\notlibcef.dll");
    struct file_view *live=image(1,1u<<20);live->ios_cef_owner=&survivor;live->ios_cef_lease=17;
    unsigned char *canary=(unsigned char *)live->base+0x5000;*canary=0xa9;
    for(unsigned cycle=0;cycle<160;cycle++) {
        generation=cycle+1;quiescent=0;
        struct file_view *view=image(0,1u<<20);void *base=view->base;
        assert(ios_cef_name_is(&libcef,"libcef.dll"));assert(ios_cef_native_browser(&owner));
        ios_cef_tag_private_image(view,&libcef);assert(view->ios_cef_owner==&owner && view->ios_cef_lease==generation);
        unsigned before=deleted;ios_cef_reclaim_process_images(&owner);assert(deleted==before && view->active);
        quiescent=generation;ios_cef_reclaim_process_images(&owner);assert(deleted==before+1 && !view->active);
        empty_backing(base,1u<<20);assert(*canary==0xa9 && live->active);
    }
    /* A recycled PEB with a different generation cannot retire newer views. */
    struct file_view *view=image(0,1u<<20);generation=400;quiescent=0;
    ios_cef_tag_private_image(view,&libcef);quiescent=399;
    unsigned before=deleted;ios_cef_reclaim_process_images(&owner);assert(deleted==before && view->active);
    quiescent=400;replace_on_lock=401;ios_cef_reclaim_process_images(&owner);assert(deleted==before && view->active);
    generation=400;quiescent=400;ios_cef_reclaim_process_images(&owner);assert(!view->active);
    /* Any surviving JIT reference, even unattributed/unmapped, retains backing. */
    view=image(0,1u<<20);generation=500;quiescent=0;ios_cef_tag_private_image(view,&libcef);
    ios_jit_mapping_count=1;ios_jit_mappings[0].pe_base=(char *)view->base+0x1000;ios_jit_mappings[0].size=0x2000;ios_jit_mappings[0].unmapped=1;
    quiescent=500;before=deleted;ios_cef_reclaim_process_images(&owner);assert(deleted==before && view->active);
    ios_jit_mappings[0].pe_base=NULL;ios_cef_reclaim_process_images(&owner);assert(!view->active);
    /* Decline mismatched process/module, WoW, shared/partial/system/EC images. */
    view=image(0,1u<<20);quiescent=0;generation=600;
    ios_cef_tag_private_image(view,&wrong);assert(!view->ios_cef_owner);
    params.ImagePathName=text(executable,"C:\\Steam\\steam.exe");ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);
    params.ImagePathName=text(executable,"steamwebhelper.exe");wow=1;ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);wow=0;
    IMAGE_SECTION_HEADER *section=(void *)(nt(view)+1);section->Characteristics=IMAGE_SCN_MEM_SHARED;
    ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);section->Characteristics=0;
    view->protect|=VPROT_SYSTEM;ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);view->protect=SEC_IMAGE|VPROT_ARM64EC;
    ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);view->protect=SEC_IMAGE;
    nt(view)->OptionalHeader.SizeOfImage-=0x1000;ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);nt(view)->OptionalHeader.SizeOfImage+=0x1000;
    nt(view)->FileHeader.Machine=0x14c;ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);nt(view)->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
    assert(!mprotect(view->base,view->size,PROT_NONE));ios_cef_tag_private_image(view,&libcef);assert(!view->ios_cef_owner);
    assert(!mprotect(view->base,view->size,PROT_READ|PROT_WRITE));
    ios_cef_tag_private_image(view,&libcef);assert(view->ios_cef_owner==&owner);
    quiescent=600;ios_cef_reclaim_process_images(&owner);assert(!view->active && *canary==0xa9);
    /* A 4 KiB logical image tail shares one 16 KiB host page with a live
     * foreign view or unknown anonymous alias. Neither may be erased. */
    generation=650;quiescent=0;view=image(0,0x11000);ios_cef_tag_private_image(view,&libcef);
    assert(view->ios_cef_owner==&owner && !mprotect(view->base,0x14000,PROT_READ|PROT_WRITE));
    assert(view_count<ARRAY_SIZE(views));struct file_view *tail=&views[view_count++];
    *tail=(struct file_view){.base=(char *)view->base+0x11000,.size=0x1000,.active=1,.ios_cef_owner=&survivor,.ios_cef_lease=77};
    unsigned char *tail_canary=(unsigned char *)view->base+0x11088;*tail_canary=0xd7;
    before=deleted;quiescent=650;ios_cef_reclaim_process_images(&owner);
    assert(deleted==before && view->active && tail->active && *tail_canary==0xd7);
    memset(tail,0,sizeof(*tail));alias_base=(uintptr_t)view->base+0x12000;alias_end=alias_base+0x1000;
    unsigned char *alias_canary=(void *)(alias_base+0x88);*alias_canary=0xb6;
    ios_cef_reclaim_process_images(&owner);assert(deleted==before && view->active && *alias_canary==0xb6);
    alias_base=alias_end=0;void *tail_base=view->base;ios_cef_reclaim_process_images(&owner);
    assert(!view->active && deleted==before+1 && *canary==0xa9);empty_backing(tail_base,0x14000);
    /* More than one reaper batch retains stable views while deleting others. */
    generation=700;quiescent=0;
    for(unsigned i=0;i<40;i++) { view=image(i+2,0x10000);ios_cef_tag_private_image(view,&libcef);assert(view->ios_cef_owner==&owner); }
    quiescent=700;before=deleted;ios_cef_reclaim_process_images(&owner);assert(deleted==before+40 && live->active && *canary==0xa9);
    assert(!munmap(reservation,arena_bytes+0x4000));
    puts("PASS private CEF image lifetime: 160 real dirty-map retire/reuse cycles return backing; live foreign owner survives; generation races, active/JIT references, shared/builtin boundaries and invalid PE reads decline; 4 KiB tail/16 KiB host neighbours and unknown aliases retain backing; batched retirement and teardown ordering verified");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-cef-images-') as temporary:
    directory=Path(temporary); source=directory/'images.c';binary=directory/'images'
    source.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread',
                    '-I'+str(root/'build/ntdll-unix'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
