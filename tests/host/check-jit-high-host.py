#!/usr/bin/env python3
"""Compile actual Wine high-host publication, adoption and fixed-map guards.

Only Mach region/task answers, Unix mmap and environment/allocation failure
boundaries are supplied. No game, real debugger or iPhone execution is implied.
"""
from pathlib import Path
import os
import ast
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
source=(ROOT/'build/ntdll-unix/virtual_ios.c').read_text()

def function(signature):
    start=source.index(signature)
    while source.index(';',start)<source.index('{',start):
        start=source.index(signature,start+len(signature))
    return source[start:source.index('\n}',start)+2]+'\n'

helpers=''.join(function(name) for name in (
    'static int ios_native_jit_number(',
    'static int ios_native_jit_span_has_protection(',
    'static int ios_native_fex_receipt_word(',
    'static int ios_native_fex_hold_description(',
    'static int ios_native_fex_receipts_equal(',
    'static int ios_native_fex_receipt_matches(',
    'static void ios_publish_native_high_jit_pool(',
    'static int ios_native_high_jit_intersects(',
))
receipt_types=source[source.index('/* BEGIN NATIVE FEX RECEIPT V2 */'):source.index('/* END NATIVE FEX RECEIPT V2 */')]
registration=function('static int mmap_add_fex_reserved_area(')
adoption=function('static NTSTATUS ios_adopt_early_fex_arena(')
fixed=function('void *anon_mmap_fixed(')
cover=function('static int ios_native_high_fex_legacy_request(')+function('static int fex_arena_covers(')
placement=function('static void *map_reserved_area_inner(')
route=function('NTSTATUS ios_reserve_fex_arena(void)')
route=route[route.index('    if (done) return result;'):route.index('    /* ml757:')]
loader=(ROOT/'build/ntdll-unix/loader_ios.c').read_text()
assert 'extern NTSTATUS ios_reserve_fex_arena(void);' in loader
startup=loader[loader.index('WINE_IOS_LOG("ios_reserve_fex_arena...");'):]
startup=startup[:startup.index('/* ml997:')]
assert 'NTSTATUS arena_status = ios_reserve_fex_arena();' in startup
assert 'if (arena_status)' in startup and 'fatal_error(' in startup
assert startup.index('if (arena_status)')<startup.index('fatal_error(')

harness=r'''
#define _GNU_SOURCE 1
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
#define PAGE ((size_t)0x4000)
#define GB ((uintptr_t)1<<30)
#define FULL ((size_t)0x48000000)
#define HIGH ((uintptr_t)0x7c00000000)
#define RX HIGH
#define RW (HIGH+FULL)
#define FEX (HIGH+2*FULL)
#define FEX_SIZE ((size_t)8<<30)
#define VM_PROT_NONE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_ALL 7
#define VM_REGION_SUBMAP_INFO_COUNT_64 8
#define KERN_SUCCESS 0
#define KERN_INVALID_ADDRESS 1
#define TASK_VM_INFO 22
#define TASK_VM_INFO_COUNT 8
#define STATUS_SUCCESS 0
#define STATUS_INVALID_ADDRESS ((NTSTATUS)0xc0000141)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_NO_MEMORY ((NTSTATUS)0xc0000017)
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define ERR(...) ((void)0)
#define dprintf(...) ((void)0)
#define ROUND_SIZE(a,b,m) (((uintptr_t)(a)+(uintptr_t)(b)+(m))&~(uintptr_t)(m))
#define ROUND_ADDR(a,m) ((void*)((uintptr_t)(a)&~(uintptr_t)(m)))
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif
typedef uint32_t NTSTATUS;
typedef uintptr_t UINT_PTR,ULONG_PTR;
typedef size_t SIZE_T;
typedef uint64_t mach_vm_address_t,mach_vm_size_t;
typedef unsigned natural_t,mach_msg_type_number_t;
typedef int kern_return_t,vm_prot_t;
typedef int *vm_region_recurse_info_t,*task_info_t;
typedef struct {uint64_t min_address,max_address;} task_vm_info_data_t;
typedef struct {unsigned is_submap,user_tag;int protection,max_protection;uint64_t object_id,offset;} vm_region_submap_info_data_64_t;
static void* ios_jit_rx_base_global;
static void* ios_jit_rw_base_global;
static size_t ios_jit_pool_size_global;
static int ios_native_high_jit_pool;
static NTSTATUS ios_native_required_pool_status;
static uintptr_t ios_native_fex_hold_base;
static size_t ios_native_fex_hold_size;
@RECEIPT_TYPES@
static struct ios_native_fex_receipt ios_native_fex_hold_receipt;
static int ios_native_fex_hold_pending;
static uintptr_t ios_fex_arena_base_unix,ios_fex_arena_end_unix;
static uintptr_t ios_layerkit_lo,ios_layerkit_hi;
static size_t host_page_mask=0x3fff,granularity_mask=0xffff;
static long long config_cap;
static unsigned map_calls,malloc_calls,find_calls;
static int malloc_failure,fail_env_at,env_calls,task_failure,region_failure,submap_loop,real_submap,fex_second_object;
static uint64_t fex_kernel_object=1;
struct region {uintptr_t base;size_t size;unsigned tag;int prot,max;uint64_t object,offset;};
static struct region regions[300];static unsigned region_count;
static int mach_task_self(void){return 1;}
static int task_info(int task,int kind,task_info_t out,mach_msg_type_number_t* count){
 CHECK(task==1&&kind==TASK_VM_INFO&&*count==TASK_VM_INFO_COUNT);
 if(task_failure)return 5;
 *(task_vm_info_data_t*)out=(task_vm_info_data_t){0x100ab8000ULL,0x8000000000ULL};return 0;
}
static int mach_vm_region_recurse(int task,mach_vm_address_t* address,mach_vm_size_t* size,
 natural_t* depth,vm_region_recurse_info_t out,mach_msg_type_number_t* count){
 CHECK(task==1&&*count==VM_REGION_SUBMAP_INFO_COUNT_64);
 if(region_failure)return 5;
 vm_region_submap_info_data_64_t* info=(void*)out;
 if(submap_loop){*size=16*GB;*info=(vm_region_submap_info_data_64_t){1,0,0,0,0};return 0;}
 if(real_submap&&!*depth){*address=HIGH;*size=16*GB;*info=(vm_region_submap_info_data_64_t){1,0,0,0,0};return 0;}
 int selected=-1;
 for(unsigned i=0;i<region_count;i++)if(regions[i].base+regions[i].size>*address&&
    (selected<0||regions[i].base<regions[selected].base))selected=(int)i;
 if(selected<0)return KERN_INVALID_ADDRESS;
 struct region r=regions[selected];*address=r.base;*size=r.size;
 *info=(vm_region_submap_info_data_64_t){0,r.tag,r.prot,r.max,
  r.object?r.object:(r.base>=FEX&&r.base<FEX+FEX_SIZE?(fex_second_object&&r.base>FEX?2:fex_kernel_object):1),r.offset};(void)depth;return 0;
}
static long long madeira_cfg_int(const char* key,int fallback){CHECK(!strcmp(key,"arena-mb")&&!fallback);return config_cap;}
static uintptr_t wow_base;
static uintptr_t ios_wow_base(void){return wow_base;}
static int tracked_setenv(const char* key,const char* value,int overwrite){
 if(fail_env_at&&++env_calls==fail_env_at){errno=ENOMEM;return -1;}
 return setenv(key,value,overwrite);
}
static void* tracked_malloc(size_t bytes){malloc_calls++;return malloc_failure?NULL:malloc(bytes);}
static void* kernel_mmap(void* base,size_t size,int prot,int flags,int fd,off_t offset){
 CHECK(base&&size&&fd==-1&&!offset&&(flags&MAP_FIXED));(void)prot;map_calls++;return base;
}
static void ios_pool_va_warn(const char* op,const void* base,size_t size){CHECK(op&&base&&size);}
static void ios_jit_range_tripwire(const char* op,const void* base,size_t size,int prot,void* pc){CHECK(op&&base&&size&&pc);(void)prot;}
struct list {struct list* next,*prev;};
#define LIST_INIT(name) {&(name),&(name)}
#define LIST_ENTRY(ptr,type,field) ((type*)((char*)(ptr)-offsetof(type,field)))
#define LIST_FOR_EACH(pos,head) for(pos=(head)->next;pos!=(head);pos=pos->next)
#define LIST_FOR_EACH_ENTRY(pos,head,type,field) for(struct list* _p=(head)->next;_p!=(head)&&((pos=LIST_ENTRY(_p,type,field)),1);_p=_p->next)
#define LIST_FOR_EACH_ENTRY_REV(pos,head,type,field) for(struct list* _p=(head)->prev;_p!=(head)&&((pos=LIST_ENTRY(_p,type,field)),1);_p=_p->prev)
static void list_add_before(struct list* at,struct list* node){node->prev=at->prev;node->next=at;at->prev->next=node;at->prev=node;}
struct reserved_area {struct list entry;void* base;size_t size;unsigned fex_only,thin_only;};
static struct list reserved_areas=LIST_INIT(reserved_areas);
static unsigned area_count(void){unsigned n=0;struct list* p;LIST_FOR_EACH(p,&reserved_areas)n++;return n;}
static void add_area(uintptr_t base,size_t size){struct reserved_area* r=calloc(1,sizeof(*r));CHECK(r);r->base=(void*)base;r->size=size;struct list* p;LIST_FOR_EACH(p,&reserved_areas)if((uintptr_t)LIST_ENTRY(p,struct reserved_area,entry)->base>base)break;list_add_before(p,&r->entry);}
static void* find_reserved_free_area_outside_preloader(void* start,void* end,size_t size,int top,size_t alignment){
 find_calls++;uintptr_t low=(uintptr_t)start,high=(uintptr_t)end;
 if(high<low||size>high-low)return NULL;
 uintptr_t result=top?(high-size)&~alignment:(low+alignment)&~alignment;
 if(result<low||result>high-size)return NULL;return(void*)result;
}
@HELPERS@
#define malloc tracked_malloc
@REGISTRATION@
#undef malloc
#define setenv tracked_setenv
@ADOPTION@
#undef setenv
#define mmap kernel_mmap
@FIXED@
#undef mmap
@COVER@
@PLACEMENT@
static NTSTATUS reserve_route(void){static int done;static NTSTATUS result;
@ROUTE@
 return 0x12345678;
}
static void setup(int high){
 const char* keys[]={"WINE_IOS_JIT_PAIR_V1","WINE_IOS_JIT_RX","WINE_IOS_JIT_RW","WINE_IOS_JIT_SIZE","WINE_IOS_FEX_EARLY_V1","WINE_IOS_FEX_EARLY_V2",
 "WINE_IOS_FEX_ARENA_BASE","WINE_IOS_FEX_ARENA_SIZE","WINE_IOS_FEX_ARENA_END","WINE_IOS_FEX_ARENA_VERSION","MADEIRA_FEX_ARENA"};
 for(unsigned i=0;i<sizeof(keys)/sizeof(*keys);i++)unsetenv(keys[i]);
 setenv("WINE_IOS_JIT_PAIR_V1","1",1);setenv("WINE_IOS_JIT_SIZE","48000000",1);
 if(high){setenv("WINE_IOS_JIT_RX","7c00000000",1);setenv("WINE_IOS_JIT_RW","7c48000000",1);setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:1:0:7",1);
  regions[0]=(struct region){RX,FULL,251,5,7};regions[1]=(struct region){RW,FULL,252,3,7};regions[2]=(struct region){FEX,FEX_SIZE,253,0,7};region_count=3;
 }else{setenv("WINE_IOS_JIT_RX","300000000",1);setenv("WINE_IOS_JIT_RW","348000000",1);
  regions[0]=(struct region){0x300000000ULL,FULL,251,5,7};regions[1]=(struct region){0x348000000ULL,FULL,252,3,7};region_count=2;
 }
}
static void success_case(int limited){
 setup(1);if(limited){regions[2].max=3;setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:1:0:3",1);}ios_publish_native_high_jit_pool();CHECK(!ios_native_required_pool_status&&ios_native_high_jit_pool&&ios_native_fex_hold_pending);
 CHECK(ios_jit_rx_base_global==(void*)RX&&ios_jit_rw_base_global==(void*)RW&&ios_jit_pool_size_global==FULL);
 errno=0;CHECK(anon_mmap_fixed((void*)RX,PAGE,3,0)==MAP_FAILED&&errno==EEXIST&&!map_calls);
 CHECK(anon_mmap_fixed((void*)(RW+PAGE),PAGE,3,0)==MAP_FAILED&&!map_calls);
 CHECK(anon_mmap_fixed((void*)FEX,PAGE,3,0)==MAP_FAILED&&!map_calls);
 CHECK(!ios_native_high_jit_intersects((void*)(RX-PAGE),PAGE));CHECK(!ios_native_high_jit_intersects((void*)(FEX+FEX_SIZE),PAGE));
 CHECK(ios_native_high_jit_intersects((void*)(UINTPTR_MAX-PAGE),2*PAGE));
 CHECK(reserve_route()==STATUS_SUCCESS&&area_count()==1&&!ios_native_fex_hold_pending);
 CHECK(ios_fex_arena_base_unix==FEX&&ios_fex_arena_end_unix==FEX+FEX_SIZE);
 CHECK(getenv("WINE_IOS_FEX_ARENA_BASE")&&!strcmp(getenv("WINE_IOS_FEX_ARENA_VERSION"),"1"));
 struct reserved_area* r=LIST_ENTRY(reserved_areas.next,struct reserved_area,entry);CHECK(r->fex_only&&!r->thin_only&&r->base==(void*)FEX&&r->size==FEX_SIZE);
 CHECK(!map_calls);CHECK(reserve_route()==0&&area_count()==1); /* Exactly once. */
 CHECK(anon_mmap_fixed((void*)RX,PAGE,3,0)==MAP_FAILED&&!map_calls);
 CHECK(anon_mmap_fixed((void*)FEX,PAGE,3,0)==(void*)FEX&&map_calls==1);
 CHECK(!map_reserved_area_inner((void*)0,(void*)UINTPTR_MAX,PAGE,0,3,0xffff,0));
 CHECK(fex_arena_covers((void*)FEX,(void*)(FEX+FEX_SIZE)));
 CHECK(map_reserved_area_inner((void*)FEX,(void*)(FEX+FEX_SIZE),PAGE,0,3,0xffff,1)==(void*)FEX&&map_calls==2);
 setenv("WINE_IOS_JIT_RX","7000000000",1);ios_publish_native_high_jit_pool();CHECK(ios_jit_rx_base_global==(void*)RX);
}
static void invalid_pair(int mode){
 setup(1);
 switch(mode){
 case 0:unsetenv("WINE_IOS_JIT_RW");break;
 case 1:setenv("WINE_IOS_JIT_RX","7000000000",1);break;
 case 2:setenv("WINE_IOS_JIT_SIZE","27000000",1);break;
 case 3:setenv("WINE_IOS_JIT_RW","7c00004000",1);break;
 case 4:regions[0].prot=7;break;
 case 5:regions[1].prot=7;break;
 case 6:task_failure=1;break;
 case 7:region_failure=1;break;
 case 8:submap_loop=1;break;
 case 9:regions[0].size=FULL/2;regions[3]=(struct region){RX+FULL/2+PAGE,FULL/2-PAGE,251,5,7};region_count=4;break;
 case 10:regions[0].size=FULL/2;regions[3]=(struct region){RX+FULL/2,FULL/2,251,1,7};region_count=4;break;
 }
 ios_publish_native_high_jit_pool();CHECK(ios_native_required_pool_status==STATUS_INVALID_ADDRESS&&!ios_native_high_jit_pool&&!ios_jit_rx_base_global);
 CHECK(reserve_route()==STATUS_INVALID_ADDRESS&&!area_count()&&!map_calls);
}
static void invalid_adoption(int mode){
 setup(1);ios_publish_native_high_jit_pool();CHECK(ios_native_fex_hold_pending);
 switch(mode){
 case 0:unsetenv("WINE_IOS_FEX_EARLY_V2");break;
 case 1:setenv("WINE_IOS_FEX_EARLY_V2","2:7ca0000000:200000000:1:0:200000000:1:0:7",1);break;
 case 2:regions[2].tag=252;break;
 case 3:regions[2].prot=1;break;
 case 4:regions[2].max=1;break;
 case 5:ios_layerkit_lo=FEX+PAGE;ios_layerkit_hi=FEX+2*PAGE;break;
 case 6:malloc_failure=1;break;
 case 7:add_area(FEX+PAGE,PAGE);break;
 case 8:add_area(FEX-PAGE,2*PAGE);break;
 case 9:config_cap=4096;break;
 case 10:setenv("MADEIRA_FEX_ARENA","0",1);break;
 case 11:fex_kernel_object=2;break; /* same tag/protection, different kernel object */
 case 12:setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:2:0:7",1);break;
 case 13:regions[2].size=FEX_SIZE/2;regions[3]=(struct region){FEX+FEX_SIZE/2,FEX_SIZE/2,253,0,7};region_count=4;fex_second_object=1;break;
 case 14:fex_kernel_object=2;setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:2:0:7",1);break;
 }
 NTSTATUS result=reserve_route();CHECK(result&&ios_native_fex_hold_pending&&!ios_fex_arena_base_unix&&!map_calls);
 CHECK(!getenv("WINE_IOS_FEX_ARENA_BASE"));
 CHECK(ios_native_high_jit_intersects((void*)FEX,PAGE));
}
static void publication_failure(int at){
 setup(1);ios_publish_native_high_jit_pool();fail_env_at=at;
 CHECK(reserve_route()==STATUS_NO_MEMORY&&area_count()==1&&ios_native_fex_hold_pending&&!ios_fex_arena_base_unix&&!map_calls);
 CHECK(!getenv("WINE_IOS_FEX_ARENA_BASE")&&!getenv("WINE_IOS_FEX_ARENA_SIZE")&&!getenv("WINE_IOS_FEX_ARENA_END")&&!getenv("WINE_IOS_FEX_ARENA_VERSION"));
 CHECK(reserve_route()==STATUS_NO_MEMORY&&area_count()==1);
}
static void no_hold(int mode){
 setup(1);
 if(mode==0)unsetenv("WINE_IOS_FEX_EARLY_V2");if(mode==1)regions[2].tag=0;if(mode==2)regions[2].prot=3;
 if(mode==3)setenv("WINE_IOS_FEX_EARLY_V2","2:7c00000000:200000000:1:0:200000000:1:0:7",1);
 if(mode==4)setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:0:0:7",1);
 if(mode==5)setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:100000000:0:7",1);
 if(mode==6)setenv("WINE_IOS_FEX_EARLY_V2","2:7c90000000:200000000:1:0:200000000:1:0:7:2",1);
 if(mode==7){unsetenv("WINE_IOS_FEX_EARLY_V2");setenv("WINE_IOS_FEX_EARLY_V1","7c90000000:200000000:1",1);}
 ios_publish_native_high_jit_pool();CHECK(ios_native_high_jit_pool&&!ios_native_fex_hold_pending);
 CHECK(reserve_route()==STATUS_INVALID_ADDRESS&&!area_count()&&!map_calls);
}
static void baseline(int mode){
 setup(0);if(mode==1)unsetenv("WINE_IOS_JIT_PAIR_V1");if(mode==2)setenv("WINE_IOS_JIT_PAIR_V1","0",1);
 ios_publish_native_high_jit_pool();CHECK(!ios_native_high_jit_pool&&!ios_native_required_pool_status&&!ios_jit_pool_size_global);
 CHECK(reserve_route()==0x12345678&&!area_count()&&!map_calls);
}
static void parsers(void){
 uintptr_t value=123;struct ios_native_fex_receipt receipt;
 const char* invalid[]={"","0","-1","+1","fffffffffffffffff","7c00000000z"};
 for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++){setenv("TEST_NUMBER",invalid[i],1);CHECK(!ios_native_jit_number("TEST_NUMBER",&value));}
 unsetenv("TEST_NUMBER");CHECK(!ios_native_jit_number("TEST_NUMBER",&value));setenv("TEST_NUMBER","7c00000000",1);CHECK(ios_native_jit_number("TEST_NUMBER",&value)&&value==HIGH);
 const char* bad[]={"", "-1:200000000", "7c90000000:-1", "7c90000001:200000000", "7c90000000:100000000", "7fff000000:200000000", "7c90000000:200000000junk", "7c90000000200000000"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++){setenv("WINE_IOS_FEX_EARLY_V2",bad[i],1);CHECK(!ios_native_fex_hold_description(&receipt));}
}
static void register_boundaries(void){
 add_area(FEX-PAGE,PAGE);add_area(FEX+FEX_SIZE,PAGE);
 CHECK(mmap_add_fex_reserved_area((void*)FEX,FEX_SIZE)&&area_count()==3);
 CHECK(!mmap_add_fex_reserved_area((void*)FEX,FEX_SIZE)&&area_count()==3);
 CHECK(!mmap_add_fex_reserved_area((void*)FEX,0)&&area_count()==3);
 CHECK(!mmap_add_fex_reserved_area((void*)(UINTPTR_MAX-PAGE),2*PAGE)&&area_count()==3);
}

static void wow_hardware(int disabled){
 setup(1);ios_publish_native_high_jit_pool();CHECK(!reserve_route());wow_base=0x400000000ULL;
 if(disabled){setenv("MADEIRA_WOW_FEX_BAND","0",1);CHECK(!fex_arena_covers((void*)HIGH,(void*)0x8000000000ULL));return;}
 CHECK(fex_arena_covers((void*)HIGH,(void*)0x7fffffffffULL));CHECK(fex_arena_covers((void*)HIGH,(void*)0x8000000000ULL));
 CHECK(!fex_arena_covers((void*)(HIGH-PAGE),(void*)0x8000000000ULL));
 CHECK(!fex_arena_covers((void*)HIGH,(void*)0x8000004000ULL));
 CHECK(!fex_arena_covers((void*)(HIGH+PAGE),(void*)0x8000000000ULL));
 wow_base=0;CHECK(!fex_arena_covers((void*)HIGH,(void*)0x8000000000ULL));wow_base=0x400000000ULL;
 ios_native_high_jit_pool=0;CHECK(!fex_arena_covers((void*)HIGH,(void*)0x8000000000ULL));ios_native_high_jit_pool=1;
 CHECK(!map_reserved_area_inner((void*)HIGH,(void*)0x8000000000ULL,16<<20,0,3,0xffff,0));
 void* result=map_reserved_area_inner((void*)HIGH,(void*)0x8000000000ULL,16<<20,0,3,0xffff,
  fex_arena_covers((void*)HIGH,(void*)0x8000000000ULL));
 CHECK((uintptr_t)result>=FEX&&(uintptr_t)result+(16<<20)<=FEX+FEX_SIZE&&map_calls==1);
 CHECK(!ios_native_high_jit_intersects(result,16<<20));
}

/* These are real XNU anonymous-map leaf sizes, not one fictitious object for
 * an entire 8 GiB reservation. Only the Mach answers are modelled; parsing,
 * caching, leaf traversal, adoption and all rejection policy remain literal
 * production functions above. */
static void write_receipt(const struct ios_native_fex_receipt* receipt){
 char text[IOS_NATIVE_FEX_RECEIPT_BYTES+1];
 int n=snprintf(text,sizeof(text),"2:%llx:%llx:%x",
  (unsigned long long)receipt->base,(unsigned long long)receipt->size,receipt->count);
 CHECK(n>0&&(size_t)n<sizeof(text));size_t used=(size_t)n;
 for(unsigned i=0;i<receipt->count;i++){
  const struct ios_native_fex_segment* s=&receipt->segments[i];
  n=snprintf(text+used,sizeof(text)-used,":%llx:%llx:%llx:%llx:%x",
   (unsigned long long)s->offset,(unsigned long long)s->length,
   (unsigned long long)s->object,(unsigned long long)s->backing_offset,s->maximum);
  CHECK(n>0&&(size_t)n<sizeof(text)-used);used+=(size_t)n;
 }
 CHECK(!setenv("WINE_IOS_FEX_EARLY_V2",text,1));
}
static void chunked_setup(unsigned count,int limited){
 CHECK(count&&count<=IOS_NATIVE_FEX_RECEIPT_MAX);setup(1);
 struct ios_native_fex_receipt receipt={.base=FEX,.size=FEX_SIZE,.count=count};
 uint64_t length=FEX_SIZE/count;CHECK(!(length&(PAGE-1)));
 for(unsigned i=0;i<count;i++){
  uint64_t offset=(uint64_t)i*length,object=100+i;
  receipt.segments[i]=(struct ios_native_fex_segment){offset,length,object,0,limited?3:7};
  regions[2+i]=(struct region){FEX+offset,length,253,0,limited?3:7,object,0};
 }
 region_count=2+count;write_receipt(&receipt);
}
static void chunks_success(int mode){
 unsigned count=mode==1?256:64;chunked_setup(count,mode==4);
 struct ios_native_fex_receipt parsed;CHECK(ios_native_fex_hold_description(&parsed));
 CHECK(parsed.count==count&&parsed.base==FEX&&parsed.size==FEX_SIZE);
 if(mode==2){
  /* VM entry splits retain the same object and correct backing offsets. */
  for(int i=(int)count-1;i>=0;i--){
   struct region r=regions[2+i];r.size/=2;regions[2+2*i]=r;
   r.base+=r.size;r.offset+=r.size;regions[3+2*i]=r;
  }
  region_count=2+2*count;
 }
 if(mode==3){
  /* Conversely, one kernel entry may cover adjacent receipt leaves. */
  parsed.count=2;parsed.segments[0]=(struct ios_native_fex_segment){0,FEX_SIZE/2,1,0,7};
  parsed.segments[1]=(struct ios_native_fex_segment){FEX_SIZE/2,FEX_SIZE/2,1,FEX_SIZE/2,7};
  write_receipt(&parsed);regions[2]=(struct region){FEX,FEX_SIZE,253,0,7,1,0};region_count=3;
 }
 if(mode==5)real_submap=1; /* Recurse from cursor, not returned parent base. */
 CHECK(ios_native_fex_receipt_matches(&parsed));
 ios_publish_native_high_jit_pool();CHECK(ios_native_fex_hold_pending&&!ios_native_required_pool_status);
 struct ios_native_fex_receipt original=ios_native_fex_hold_receipt;
 CHECK(reserve_route()==STATUS_SUCCESS&&area_count()==1&&!map_calls);
 CHECK(ios_native_fex_receipts_equal(&original,&ios_native_fex_hold_receipt));
 CHECK(!ios_native_fex_hold_pending&&ios_fex_arena_base_unix==FEX&&ios_fex_arena_end_unix==FEX+FEX_SIZE);
}
static void chunks_changed(int mode){
 chunked_setup(64,0);ios_publish_native_high_jit_pool();CHECK(ios_native_fex_hold_pending);
 struct ios_native_fex_receipt original=ios_native_fex_hold_receipt,changed=original;
 switch(mode){
 case 0:regions[65].object++;break;
 case 1:regions[33].prot=1;break;
 case 2:regions[33].max=3;break;
 case 3:regions[33].tag=252;break;
 case 4:regions[33].offset=PAGE;break;
 case 5:regions[33].base+=PAGE;regions[33].size-=PAGE;break;
 case 6:regions[33].object=0;fex_kernel_object=0;break;
 case 7:changed.segments[31].object++;regions[33].object++;write_receipt(&changed);break;
 case 8:changed.segments[31].maximum=3;regions[33].max=3;write_receipt(&changed);break;
 case 9:changed.segments[31].backing_offset=PAGE;regions[33].offset=PAGE;write_receipt(&changed);break;
 }
 CHECK(reserve_route()==STATUS_INVALID_ADDRESS&&ios_native_fex_hold_pending&&!area_count()&&!map_calls);
 CHECK(!ios_fex_arena_base_unix&&!getenv("WINE_IOS_FEX_ARENA_BASE"));
 CHECK(!memcmp(&original,&ios_native_fex_hold_receipt,sizeof(original)));
 CHECK(ios_native_high_jit_intersects((void*)FEX,PAGE));
}
static void receipt_invalid(int mode){
 chunked_setup(64,0);struct ios_native_fex_receipt receipt;
 CHECK(ios_native_fex_hold_description(&receipt));
 switch(mode){
 case 0:receipt.base+=PAGE;break;
 case 1:receipt.base=HIGH;break; /* syntactically valid, but overlaps RX */
 case 2:receipt.size-=PAGE;break;
 case 3:receipt.segments[30].offset+=PAGE;break;
 case 4:receipt.segments[30].offset-=PAGE;break;
 case 5:receipt.segments[30].length=0;break;
 case 6:receipt.segments[30].length++;break;
 case 7:receipt.segments[30].object=0;break;
 case 8:receipt.segments[30].object=0x100000000ULL;break;
 case 9:receipt.segments[30].backing_offset=1;break;
 case 10:receipt.segments[30].backing_offset=UINT64_MAX-PAGE+1;break;
 case 11:receipt.segments[30].maximum=1;break;
 case 12:receipt.count--;break;
 }
 write_receipt(&receipt);
 if(mode==1){
  ios_publish_native_high_jit_pool();CHECK(ios_native_high_jit_pool&&!ios_native_fex_hold_pending);
  CHECK(reserve_route()==STATUS_INVALID_ADDRESS&&!map_calls&&!area_count());return;
 }
 struct ios_native_fex_receipt parsed;CHECK(!ios_native_fex_hold_description(&parsed));
 CHECK(!ios_native_fex_receipt_matches(&receipt));
}
static void receipt_text_invalid(void){
 static const char* bad[]={
  "7c90000000:200000000:1", /* v1 never upgrades to ownership */
  "1:7c90000000:200000000:1:0:200000000:1:0:7",
  "2:7c90000000:200000000:0:0:200000000:1:0:7",
  "2:7c90000000:200000000:101:0:200000000:1:0:7",
  "2:7c90000000:200000000:1:0:200000000:1:0:100000007",
  "2:7c90000000:200000000:1:0:200000000:1:0:7:",
  "2:7c90000000:200000000:1:0:200000000:1:0:7:dead",
  "2:7c90000000:200000000:1:0:200000000:+1:0:7",
  "2:7c90000000:200000000:1:0:200000000:fffffffffffffffff:0:7",
  "2:7c90000000:200000000:1:0:200000000:1:0:",
 };
 struct ios_native_fex_receipt receipt;
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++){
  setenv("WINE_IOS_FEX_EARLY_V2",bad[i],1);CHECK(!ios_native_fex_hold_description(&receipt));
 }
 char oversized[IOS_NATIVE_FEX_RECEIPT_BYTES+2];memset(oversized,'0',sizeof(oversized)-1);oversized[sizeof(oversized)-1]=0;
 setenv("WINE_IOS_FEX_EARLY_V2",oversized,1);CHECK(!ios_native_fex_hold_description(&receipt));
 /* Each field, including the zero offset, participates in cached identity. */
 chunked_setup(64,0);CHECK(ios_native_fex_hold_description(&receipt));
 struct ios_native_fex_receipt changed=receipt;
 CHECK(ios_native_fex_receipts_equal(&receipt,&changed));
 changed.segments[1].offset++;CHECK(!ios_native_fex_receipts_equal(&receipt,&changed));changed=receipt;
 changed.segments[1].length--;CHECK(!ios_native_fex_receipts_equal(&receipt,&changed));changed=receipt;
 changed.segments[1].object++;CHECK(!ios_native_fex_receipts_equal(&receipt,&changed));changed=receipt;
 changed.segments[1].backing_offset+=PAGE;CHECK(!ios_native_fex_receipts_equal(&receipt,&changed));changed=receipt;
 changed.segments[1].maximum=3;CHECK(!ios_native_fex_receipts_equal(&receipt,&changed));
}

static void execute_case(int category,int value){
 pid_t child=fork();CHECK(child>=0);
 if(!child){if(category==0)success_case(value);if(category==1)invalid_pair(value);if(category==2)invalid_adoption(value);
 if(category==3)publication_failure(value);if(category==4)no_hold(value);if(category==5)baseline(value);if(category==6)parsers();if(category==7)register_boundaries();if(category==8)wow_hardware(value);
 if(category==9)chunks_success(value);if(category==10)chunks_changed(value);if(category==11)receipt_invalid(value);if(category==12)receipt_text_invalid();_exit(0);}
 int status;CHECK(waitpid(child,&status,0)==child);if(!WIFEXITED(status)||WEXITSTATUS(status)){fprintf(stderr,"failed category=%d value=%d status=%d\n",category,value,status);exit(1);}
}
int main(void){
 execute_case(0,0);execute_case(0,1);
 for(int i=0;i<11;i++)execute_case(1,i);
 for(int i=0;i<15;i++)execute_case(2,i);
 for(int i=1;i<=4;i++)execute_case(3,i);
 for(int i=0;i<8;i++)execute_case(4,i);
 for(int i=0;i<3;i++)execute_case(5,i);
 execute_case(6,0);execute_case(7,0);execute_case(8,0);execute_case(8,1);
 for(int i=0;i<6;i++)execute_case(9,i);
 for(int i=0;i<10;i++)execute_case(10,i);
 for(int i=0;i<13;i++)execute_case(11,i);
 execute_case(12,0);
 puts("PASS actual Wine high-host pair publication, whole-span rights/limits/one-shot status, native RX/RW fixed-map exclusion, pending FEX hold guard and no-release adoption");
 puts("PASS actual FEX-only registration, both-neighbor overlap refusal/adjacency, generic exclusion and contained/legacy-WoW exact-band clipping inside the owned8GiB; opt-out/non-WoW/wider bounds rejected");
 puts("PASS actual failed metadata/region/tag/permissions/registration/config/publication handling propagates honest status and retains pending ownership; low/legacy routing unchanged");
 puts("PASS V2 full 8GiB receipts: 64 real-size 128MiB leaves and 256 bounded leaves; split/merged kernel regions preserve exact object/backing offsets; altered cached fields remain rejected without unmapping");
 return 0;
}
'''
for token,value in {'RECEIPT_TYPES':receipt_types,'HELPERS':helpers,'REGISTRATION':registration,'ADOPTION':adoption,'FIXED':fixed,'COVER':cover,'PLACEMENT':placement,'ROUTE':route}.items():
    harness=harness.replace('@'+token+'@',value)
with tempfile.TemporaryDirectory(prefix='madeira-jit-high-host-') as tmp:
    cfile=Path(tmp)/'actual.c';binary=Path(tmp)/'actual'
    cfile.write_text(harness)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Wno-missing-field-initializers',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',str(cfile),'-o',str(binary)],check=True,timeout=120)
    subprocess.run([str(binary)],check=True,timeout=30)
print('PASS loader tests retain genuine NTSTATUS failure and stop the affected Wine startup instead of starting FEX without its required arena')


# Execute the complete production map_view entry against allocator boundaries
# that honestly report a full owned arena and free space outside it. The
# baseline control removes only the new entry clipping block from the actual
# function; it must demonstrate the otherwise-successful escape.
floor_tree=ast.parse((ROOT/'tests/host/check-ios-host-va-floor.py').read_text())
prefix=next(ast.literal_eval(node.value) for node in floor_tree.body
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='prefix' for t in node.targets))
old_stub='static int ios_native_high_fex_legacy_request(ULONG_PTR lo, ULONG_PTR hi) { return 0; }'
assert prefix.count(old_stub)==1
prefix=prefix.replace(old_stub,'static int ios_native_high_jit_pool;\n'+function('static int ios_native_high_fex_legacy_request('))
functions_node=next(node.value for node in floor_tree.body
                   if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='functions' for t in node.targets))
common=[]
for item in functions_node.elts:
    signature=ast.literal_eval(item.args[0])
    if signature.startswith('static void *map_free_area(') or signature.startswith('static void *map_free_area_inner(') or signature.startswith('static NTSTATUS map_view('):
        continue
    common.append(function(signature))
view=function('static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size,')
clip_start=view.index('    if (ios_native_high_fex_legacy_request( limit_low, limit_high ))')
clip_end=view.index('\n    }',clip_start)+6
before_view=view[:clip_start]+view[clip_end:]
map_boundary=r'''
static unsigned free_calls;
static uintptr_t free_low,free_high;
static void* map_free_area(void* lo,void* hi,size_t size,int top,int prot,size_t mask){
 (void)top;(void)prot;(void)mask;
 free_calls++;free_low=(uintptr_t)lo;free_high=(uintptr_t)hi;
 uintptr_t available=ios_fex_arena_end_unix+0x10000000;
 if(available>=(uintptr_t)lo&&available+size<=(uintptr_t)hi)return(void*)available;
 errno=ENOMEM;return NULL;
}
'''
map_main=r'''
int main(void){
 const uintptr_t host=0x7c00000000ULL,fex=host+0x90000000ULL,end=fex+0x200000000ULL;
 address_space_start=(void*)0x119000000ULL;
 address_space_limit=host_addr_space_limit=user_space_limit=working_set_limit=(void*)0x8000000000ULL;
 kernel_floor=0x119000000ULL;ios_furniture_ceiling=ios_usable_va_floor=0;
 ios_native_high_jit_pool=1;fake_wow_base=0x400000000ULL;
 ios_fex_arena_base_unix=fex;ios_fex_arena_end_unix=end;
 unsetenv("MADEIRA_WOW_FEX_BAND");
 for(unsigned i=0;i<2;i++){
  struct file_view* result=NULL;free_calls=map_calls_placeholder=0;
  NTSTATUS status=map_view(&result,NULL,0x4000,0x3000,0x23,host,i?0x7fffffffffULL:0x8000000000ULL,0);
#ifdef TEST_BEFORE_CLIP
  assert(!status&&result&&(uintptr_t)result->base>=end);
  assert(free_low==host&&free_high> end);
  puts("BEFORE actual map_view without entry clip escapes a full FEX arena into free host furniture");
  return 23;
#else
  assert(status==STATUS_NO_MEMORY&&!result&&free_calls);
  assert(free_low==fex&&free_high==end+1&&!anon_calls&&!fixed_calls);
#endif
 }
 struct file_view* result=NULL;
 NTSTATUS status=map_view(&result,(void*)(end+0x4000),0x4000,0x3000,0x23,host,0x8000000000ULL,0);
 assert(status==STATUS_CONFLICTING_ADDRESSES&&!result&&!fixed_calls);
 fake_wow_base=0;
 status=map_view(&result,NULL,0x4000,0x3000,0x23,host,0x8000000000ULL,0);
 assert(!status&&result&&(uintptr_t)result->base>end);
 puts("PASS actual complete map_view: full owned FEX returns honest failure without outside fallback; fixed escape rejected; unrelated non-WoW host allocation remains valid");
 return 0;
}
'''.replace('free_calls=map_calls_placeholder=0','free_calls=0')
# The prefix's callbacks are explicit boundaries; the entire map_view policy,
# WoW bound exclusion helpers and real high-band predicate remain literal.
for before_control in (False,True):
    with tempfile.TemporaryDirectory(prefix='madeira-jit-fex-map-view-') as tmp:
        cfile=Path(tmp)/'actual-map-view.c';binary=Path(tmp)/'actual-map-view'
        cfile.write_text(prefix+'\n'.join(common)+map_boundary+(before_view if before_control else view)+map_main)
        flags=['-DTEST_BEFORE_CLIP'] if before_control else []
        subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Werror=implicit-function-declaration',
                        '-fsanitize=address,undefined','-fno-sanitize-recover=all',*flags,str(cfile),'-o',str(binary)],check=True,timeout=120)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        print(result.stdout,end='')
        if result.returncode!=(23 if before_control else 0):
            print(result.stderr,end='');raise RuntimeError('Actual map_view escape control/production result was incorrect')
