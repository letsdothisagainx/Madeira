#!/usr/bin/env python3
"""Execute the real private-ntdll loader in both architecture directions."""
from pathlib import Path
import os, subprocess, tempfile

root=Path(__file__).resolve().parents[2]
source=(root/'build/ntdll-unix/loader_ios.c').read_text()
def function(signature):
    start=source.index(signature); end=source.index('{',start)+1; depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]
select=function('static int ios_child_ntdll_can_clone(')
loader=function('static int ios_load_child_ntdll(')
boot=source[source.index('void wine_ios_child_main('):] if 'void wine_ios_child_main(' in source else source[source.index('        /* A hybrid session ntdll') :]
assert '!ios_child_ntdll_can_clone( ios_session_ntdll_machine, ios_cur_image_info()->Machine )' in boot
assert 'ios_session_ntdll_machine = ((const IMAGE_NT_HEADERS *)' in source
trap=(root/'build/ntdll-unix/signal_arm64_ios.c').read_text()
assert '[guest-trap-context-v1]' in trap and 'BackupRefPtr refcount assertion:' not in trap

code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t WCHAR,USHORT; typedef uintptr_t ULONG_PTR,UINT_PTR,unixlib_handle_t;
typedef size_t SIZE_T; typedef struct {void *EcCodeBitMap;} PEB;
typedef struct {USHORT Machine;} SECTION_IMAGE_INFORMATION;
typedef struct {int dummy;} OBJECT_ATTRIBUTES,UNICODE_STRING,IMAGE_EXPORT_DIRECTORY,IMAGE_ARM64EC_METADATA;
typedef struct {uintptr_t CHPEMetadataPointer;} IMAGE_LOAD_CONFIG_DIRECTORY;
typedef struct {uint64_t ntdll_handle,pLdrInitializeThunk,pRtlUserThreadStart;} SYSTEM_DLL_INIT_BLOCK;
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 1
#define STATUS_IMAGE_NOT_AT_BASE 0x40000003u
#define FALSE 0
struct ios_ntdll_funcs {void *LdrInitializeThunk,*RtlUserThreadStart,*KiUserExceptionDispatcher,*KiUserApcDispatcher,*KiUserCallbackDispatcher,*KiUserEmulationDispatcher,*KiRaiseUserExceptionDispatcher,*DbgUiRemoteBreakin;};
static struct model_image {void *slots[8]; unsigned tsd; ULONG_PTR arena[2];SYSTEM_DLL_INIT_BLOCK wow;unsigned char code[256];} images[72];
static struct model_image *mapped;static unsigned image_count=1;
#define image (*mapped)
static IMAGE_EXPORT_DIRECTORY exports;
static IMAGE_ARM64EC_METADATA metadata;
static IMAGE_LOAD_CONFIG_DIRECTORY cfg;
static SECTION_IMAGE_INFORMATION current;
static SYSTEM_DLL_INIT_BLOCK wow={0xfff40000,0xfff8ef90,0xfff90000};
static const char *build_dir,*ntdll_dir="bundle",*dll_dir="bundle",*missing;
static unsigned status_in,wrong_machine,published,redirects,patches,syncs,loads;
static USHORT ios_session_ntdll_machine,requested;
static PEB *published_owner;
static struct ios_ntdll_funcs published_funcs;
static unsigned char parent_data[256];
static void *unix_call_funcs=(void *)0x123456,*__wine_syscall_dispatcher=(void *)0x4444,*__wine_unix_call_dispatcher=(void *)0x5555;
int ios_teb_tls_slot_offset=0x148;
ULONG_PTR ios_fex_arena_base_unix=0xb40000000,ios_fex_arena_end_unix=0xd40000000;
static void init_unicode_string(UNICODE_STRING*s,const WCHAR*p){(void)s;(void)p;}
#define InitializeObjectAttributes(a,b,c,d,e) ((void)0)
static unsigned open_builtin_pe_file(const char *name,OBJECT_ATTRIBUTES*a,void **module,SIZE_T*size,SECTION_IMAGE_INFORMATION*info,int l,int h,USHORT machine,int prefer,int offset){
 (void)a;(void)l;(void)h;(void)prefer;(void)offset;requested=machine;loads++;
 assert(strstr(name,machine==IMAGE_FILE_MACHINE_AMD64?"/arm64ec-windows/ntdll.dll":"/aarch64-windows/ntdll.dll"));
 if(status_in)return status_in;
 assert(image_count<72);mapped=&images[image_count++];memset(&image,0,sizeof(image));image.slots[2]=(void *)0x6666;
 *module=&image;*size=sizeof(image);info->Machine=wrong_machine?0x14c:machine;return 0;
}
static unsigned virtual_relocate_module(void*m){(void)m;return 0;}
static const void *get_module_data_dir(void*m,int directory,void*n){(void)n;assert(m==&image);return directory==IMAGE_DIRECTORY_ENTRY_EXPORT?(void *)&exports:(requested==IMAGE_FILE_MACHINE_AMD64?(void *)&cfg:NULL);}
static uintptr_t find_named_export(void*m,const IMAGE_EXPORT_DIRECTORY*e,const char*name){
 (void)e;assert(m==&image);if(missing&&!strcmp(name,missing))return 0;
 static const char*names[]={"__wine_syscall_dispatcher","__wine_unix_call_dispatcher","__wine_unix_call_dispatcher_arm64ec","__wine_unixlib_handle","p_ios_jit_translate_addr","p_ios_jit_reverse_translate_addr"};
 for(unsigned i=0;i<sizeof(names)/sizeof(*names);i++)if(!strcmp(name,names[i]))return(uintptr_t)&image.slots[i];
 if(!strcmp(name,"ios_teb_tsd_offset"))return(uintptr_t)&image.tsd;
 if(!strcmp(name,"ios_fex_arena_base"))return(uintptr_t)&image.arena[0];
 if(!strcmp(name,"ios_fex_arena_end"))return(uintptr_t)&image.arena[1];
 if(!strcmp(name,"LdrSystemDllInitBlock"))return(uintptr_t)&image.wow;
 if(!strcmp(name,"LdrInitializeThunk"))return(uintptr_t)&image.code[0];
 return(uintptr_t)&image.code[32];
}
void ios_jit_sync_write(void *p,size_t s){assert((uintptr_t)p>=(uintptr_t)&image&&(uintptr_t)p+s<=(uintptr_t)(&image+1));syncs++;}
void *ios_jit_translate_addr(void*p){return p;}
void *ios_jit_reverse_translate_addr(const void*p){return(void *)p;}
void *ios_arm64ec_bitmap_base(void){return(void *)0xace0;}
int ios_patch_rtl_pc_to_file_header(void*m,const void*p){assert(m==&image&&p);patches++;return 0;}
int ios_patch_execreq_leave(void*m){assert(m==&image);patches++;return 0;}
static uintptr_t redirect_arm64ec_rva(void*m,uintptr_t r,const void*p){assert(m==&image&&p==&metadata);redirects++;return r+16;}
static void *get_rva(void*m,uintptr_t r){return(char *)m+r;}
static SECTION_IMAGE_INFORMATION *ios_cur_image_info(void){return &current;}
static int is_machine_64bit(USHORT m){return m==IMAGE_FILE_MACHINE_AMD64||m==IMAGE_FILE_MACHINE_ARM64;}
static const SYSTEM_DLL_INIT_BLOCK *ios_wow64_init_block_for_peb(void*p){assert(p);return &wow;}
static void ios_set_proc_ntdll(PEB*p,void*m,const struct ios_ntdll_funcs*f){assert(p&&m==&image);published++;published_owner=p;published_funcs=*f;}
'''+select+'\n'+loader+r'''
int main(void){
 cfg.CHPEMetadataPointer=(uintptr_t)&metadata;
 memset(&images[0],0x5a,sizeof(images[0]));struct model_image saved=images[0],first_child={0};
 assert(!ios_child_ntdll_can_clone(0x8664,0x14c)); /* observed broken reverse path */
 assert(!ios_child_ntdll_can_clone(0x8664,0xaa64));
 assert(!ios_child_ntdll_can_clone(0xaa64,0x8664));
 assert(ios_child_ntdll_can_clone(0xaa64,0x14c)&&ios_child_ntdll_can_clone(0xaa64,0xaa64));
 assert(ios_child_ntdll_can_clone(0x8664,0x8664));
 for(unsigned round=0;round<64;round++){
  PEB child={0};current.Machine=0x14c;ios_session_ntdll_machine=0x8664;
  unsigned before=published;assert(!ios_load_child_ntdll(&child,0xaa64));
  assert(published==before+1&&published_owner==&child&&requested==0xaa64);
  assert(published_funcs.LdrInitializeThunk==image.code&&published_funcs.KiUserEmulationDispatcher==NULL);
  assert(image.slots[0]==__wine_syscall_dispatcher&&image.slots[1]==__wine_unix_call_dispatcher);
  assert(!memcmp(&image.wow,&wow,sizeof(wow))&&!child.EcCodeBitMap);
  assert(image.tsd==0x148&&image.arena[0]==ios_fex_arena_base_unix);
  assert(!redirects&&!patches); /* native callbacks never use EC metadata */
  if(!round)first_child=images[1];else assert(!memcmp(&images[1],&first_child,sizeof(first_child)));
 }
 PEB child={0};current.Machine=0xaa64;assert(!ios_load_child_ntdll(&child,0xaa64));
 assert(!image.wow.ntdll_handle); /* native child gets no guest32 startup block */
 current.Machine=0x8664;ios_session_ntdll_machine=0xaa64;
 assert(!ios_load_child_ntdll(&child,0x8664));assert(requested==0x8664&&child.EcCodeBitMap==(void *)0xace0);
 assert(published_funcs.LdrInitializeThunk==image.code+16&&redirects==8&&patches==2);
 assert(image.slots[1]==(void *)0x6666&&image.slots[2]==__wine_unix_call_dispatcher);
 unsigned before=published;
 missing="KiUserExceptionDispatcher";assert(ios_load_child_ntdll(&child,0x8664)<0&&published==before);missing=NULL;
 cfg.CHPEMetadataPointer=0;assert(ios_load_child_ntdll(&child,0x8664)<0&&published==before);cfg.CHPEMetadataPointer=(uintptr_t)&metadata;
 wrong_machine=1;assert(ios_load_child_ntdll(&child,0xaa64)<0&&published==before);wrong_machine=0;
 status_in=0xc0000017;assert(ios_load_child_ntdll(&child,0xaa64)<0&&published==before);
 assert(!memcmp(&images[0],&saved,sizeof(saved))&&syncs>0&&loads>64);
 puts("PASS production child ntdll loader:hybrid-to-WoW64/native and native-to-hybrid,64 isolated WoW64 blocks,dispatchers/EC redirects,failed allocation/export/machine rejected before publication;parent unchanged");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-native-child-') as t:
    p=Path(t);(p/'test.c').write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-variable','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
    result=subprocess.run([str(p/'test')],capture_output=True,text=True)
    if result.returncode: print(result.stdout+result.stderr);raise SystemExit(result.returncode)
    print(result.stdout,end='')
