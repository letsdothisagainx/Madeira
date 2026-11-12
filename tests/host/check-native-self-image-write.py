#!/usr/bin/env python3
"""Run production native PE self-write code against real private file mappings.

Linux supplies the Mach-region/read adapter; target selection, immutable ISA
cache, VM/owner/ledger/protection checks and NtWrite dispatch are production C.
This establishes a host contract, not an on-device Steam or VAC result.
"""
from pathlib import Path
import os
import hashlib
import platform
import subprocess
import tempfile

if platform.system() != 'Linux':
    print('SKIP native PE self-write mapped-memory host test: Linux Mach adapter required; portable shipped-PE parser runs separately')
    raise SystemExit(0)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()


def function(text, marker):
    at = text.index(marker)
    return text[at:text.index('\n}', at) + 2]


PRELUDE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include "pe_x64_write_span.h"
typedef void* HANDLE;typedef uintptr_t ULONG_PTR;typedef size_t SIZE_T;typedef unsigned NTSTATUS;typedef unsigned char BYTE;
typedef int BOOL;
#define FALSE 0
#define TRUE 1
typedef uintptr_t mach_vm_address_t;typedef size_t mach_vm_size_t;typedef unsigned natural_t,mach_msg_type_number_t;
typedef int kern_return_t,vm_prot_t;typedef void* vm_region_recurse_info_t;
typedef struct {int is_submap,protection,max_protection;unsigned user_tag;uint64_t object_id;} vm_region_submap_info_data_64_t;
#define VM_REGION_SUBMAP_INFO_COUNT_64 1
#define KERN_SUCCESS 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define WINAPI
#define WINE_IOS 1
#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY 0xc0000017u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define STATUS_ACCESS_VIOLATION 0xc0000005u
#define STATUS_PARTIAL_COPY 0x8000000du
#define STATUS_INVALID_USER_BUFFER 0xc00000e8u
#define PROCESS_VM_WRITE 0x20
#define DUPLICATE_SAME_ACCESS 2
#define VPROT_WRITE 2
#define VPROT_WRITECOPY 8
#define VPROT_COMMITTED 0x20
#define VPROT_GUARD 0x10
#define VPROT_WRITEWATCH 0x40
#define VPROT_SYSTEM 0x200
#define VPROT_PLACEHOLDER 0x400
#define SEC_IMAGE 0x1000000
#define ObjectBasicInformation 0
#define ProcessBasicInformation 0
#define NtCurrentProcess() ((void*)(intptr_t)-1)
#define IOS_JIT_MAX_MAPPINGS 512
#define IOS_JIT_MAX_CODE_RANGES 96
#define IOS_JIT_MAX_X64_WRITE_RANGES 32
#define IOS_NATIVE_IMAGE_WRITE_MAX 0x10000
#define min(a,b) ((a)<(b)?(a):(b))
static int mach_task_self(void){return 1;}
static kern_return_t mach_vm_read_overwrite(int task,mach_vm_address_t address,mach_vm_size_t bytes,mach_vm_address_t output,mach_vm_size_t* copied){
 (void)task;*copied=0;FILE* maps=fopen("/proc/self/maps","r");assert(maps);char line[512],perms[8];unsigned long lo,hi;uintptr_t cursor=address,end=address+bytes;
 while(cursor<end&&fgets(line,sizeof(line),maps))if(sscanf(line,"%lx-%lx %7s",&lo,&hi,perms)==3&&hi>cursor){if(lo>cursor||perms[0]!='r')break;cursor=hi<end?hi:end;}
 fclose(maps);if(cursor!=end)return 1;
 int fd=open("/proc/self/mem",O_RDONLY);assert(fd>=0);ssize_t n=pread(fd,(void*)output,bytes,(off_t)address);close(fd);*copied=n>0?(size_t)n:0;return n==(ssize_t)bytes?0:1;
}
/* Query real mappings; never infer W/X from the guest request or test state. */
static kern_return_t mach_vm_region_recurse(int task,mach_vm_address_t* address,mach_vm_size_t* bytes,natural_t* depth,vm_region_recurse_info_t out,mach_msg_type_number_t* count){
 (void)task;(void)depth;(void)count;FILE* f=fopen("/proc/self/maps","r");assert(f);char line[512],perms[8];unsigned long lo,hi;int result=1;
 while(fgets(line,sizeof(line),f)) {
  if(sscanf(line,"%lx-%lx %7s",&lo,&hi,perms)==3&&hi>*address){
   vm_region_submap_info_data_64_t* info=out;memset(info,0,sizeof(*info));info->protection=(perms[0]=='r'?1:0)|(perms[1]=='w'?2:0)|(perms[2]=='x'?4:0);
   info->max_protection=info->protection;*address=lo;*bytes=hi-lo;result=0;break;
  }
 }
 fclose(f);return result;
}
typedef struct {struct {void* UniqueProcess;} ClientId;} TEB;static TEB teb;
static TEB* NtCurrentTeb(void){return &teb;}
typedef struct {unsigned GrantedAccess;} OBJECT_BASIC_INFORMATION;
typedef struct {uintptr_t UniqueProcessId;} PROCESS_BASIC_INFORMATION;
static unsigned rights=PROCESS_VM_WRITE;static uintptr_t handle_pid=100;static int queryfail,server_calls;
static unsigned pinned_rights;static uintptr_t pinned_pid;static int pin_open,pin_closes,reuse_after_pin;
static void *current_owner=(void*)0x123450000ULL,*pLdrInitializeThunk=(void*)0x77770000;
static uintptr_t wow;
static void *ios_jit_rx_base_global,*ios_jit_rw_base_global;static size_t ios_jit_pool_size_global;
static unsigned char *image;static size_t image_size=0x10000;static BYTE prot[16];
static const size_t page_size=4096,page_mask=4095;
static pthread_mutex_t virtual_mutex=PTHREAD_MUTEX_INITIALIZER,ios_pool_lock=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int vm_depth;static int watch_notes;static void (*unprotect_callback)(void);
static unsigned long long current_lease=42;static unsigned current_threads=1;static int owner_exiting,owner_reclaimed;
static const char* module_name="ordinary-test.dll";
static uintptr_t ios_wow_base(void){return wow;}
static void* ios_jit_current_peb(void){return current_owner;}
static NTSTATUS NtDuplicateObject(HANDLE from,HANDLE h,HANDLE to,HANDLE* out,unsigned access,unsigned attributes,unsigned flags){assert(from==NtCurrentProcess()&&to==NtCurrentProcess()&&h==(void*)8&&!access&&!attributes&&flags==DUPLICATE_SAME_ACCESS&&!pin_open);pinned_rights=rights;pinned_pid=handle_pid;pin_open=1;*out=(void*)16;if(reuse_after_pin){rights=0;handle_pid=100;}return 0;}
static NTSTATUS NtClose(HANDLE h){assert(h==(void*)16&&pin_open);pin_open=0;pin_closes++;return 0;}
static NTSTATUS NtQueryObject(HANDLE h,int c,OBJECT_BASIC_INFORMATION* o,size_t n,void* r){assert(h==(void*)16&&pin_open);(void)c;(void)n;(void)r;o->GrantedAccess=pinned_rights;return queryfail?STATUS_ACCESS_DENIED:0;}
static NTSTATUS NtQueryInformationProcess(HANDLE h,int c,PROCESS_BASIC_INFORMATION* o,size_t n,void* r){assert(h==(void*)16&&pin_open);(void)c;(void)n;(void)r;o->UniqueProcessId=pinned_pid;return queryfail?STATUS_ACCESS_DENIED:0;}
static unsigned long long ios_thread_process_snapshot(void* owner,unsigned* threads,int* exiting,int* reclaimed){assert(!vm_depth);*threads=current_threads;*exiting=owner_exiting;*reclaimed=owner_reclaimed;return owner==current_owner?current_lease:0;}
static unsigned long long ios_thread_process_query_lease(void* owner,unsigned pid){return owner==current_owner&&pid==100&&!owner_exiting&&!owner_reclaimed?current_lease:0;}
static int virtual_check_buffer_for_read(const void* b,size_t n){return !n || (uintptr_t)b>=0x10000;}
static void server_enter_uninterrupted_section(pthread_mutex_t* m,sigset_t* set){(void)set;assert(!pthread_mutex_lock(m));vm_depth++;}
static void server_leave_uninterrupted_section(pthread_mutex_t* m,sigset_t* set){(void)set;vm_depth--;assert(!pthread_mutex_unlock(m));}
static BYTE get_page_vprot(const void* a){uintptr_t p=(uintptr_t)a;return p>=(uintptr_t)image&&p-(uintptr_t)image<image_size?prot[(p-(uintptr_t)image)/4096]:0;}
static BYTE get_host_page_vprot(const void* a){return get_page_vprot(a);}
static int get_unix_prot(BYTE p){return (p&VPROT_COMMITTED)?PROT_READ|((p&(VPROT_WRITE|VPROT_WRITECOPY))?PROT_WRITE:0):PROT_NONE;}
#define ROUND_ADDR(a,mask) ((void*)((uintptr_t)(a)&~(uintptr_t)(mask)))
#define ROUND_SIZE(a,n,mask) ((((uintptr_t)(a)+(n)+(mask))&~(uintptr_t)(mask))-((uintptr_t)(a)&~(uintptr_t)(mask)))
static const size_t host_page_size=4096,host_page_mask=4095;
static int mprotect_range(void* a,size_t n,BYTE set,BYTE clear){(void)set;assert(vm_depth);assert(clear==VPROT_WRITEWATCH);assert(!pthread_mutex_trylock(&ios_pool_lock));pthread_mutex_unlock(&ios_pool_lock);if(unprotect_callback)unprotect_callback();return mprotect(a,n,PROT_READ|PROT_WRITE);}
static void update_write_watches(void* a,size_t n,size_t written){assert(vm_depth);assert(!pthread_mutex_trylock(&ios_pool_lock));pthread_mutex_unlock(&ios_pool_lock);assert(written==0||written==n);watch_notes++;if(written)for(size_t i=(uintptr_t)a-(uintptr_t)image;i<(uintptr_t)a-(uintptr_t)image+n;i=(i+4096)&~(size_t)4095)prot[i/4096]&=~VPROT_WRITEWATCH;else assert(!mprotect(ROUND_ADDR(a,4095),ROUND_SIZE(a,n,4095),PROT_READ));}
struct file_view {void* base;size_t size;unsigned protect;};static struct file_view fixture_view;
static struct file_view* find_view(const void* a,size_t n){uintptr_t p=(uintptr_t)a,b=(uintptr_t)fixture_view.base;return fixture_view.base&&p>=b&&p-b<=fixture_view.size&&n<=fixture_view.size-(p-b)?&fixture_view:NULL;}
static const char* ios_pe_module_name(const void* a,size_t n){(void)a;(void)n;return module_name;}
static int ios_kw_has_rw_alias(uintptr_t lo,uintptr_t hi){uintptr_t rx=(uintptr_t)ios_jit_rx_base_global;return rx&&lo<rx+ios_jit_pool_size_global&&rx<hi;}
static void ios_trace_wow_write_begin(HANDLE p,void* a,const void* b,size_t n){(void)p;(void)a;(void)b;(void)n;}
static void ios_trace_wow_write(NTSTATUS s,size_t n,const char* route){(void)s;(void)n;(void)route;}
static int ios_wow_self_write_target(HANDLE p,const void* a,size_t n){(void)p;(void)a;(void)n;return 0;}
static NTSTATUS ios_wow_write_self(void* a,const void* b,size_t n){(void)a;(void)b;(void)n;abort();}
struct request {HANDLE handle;uintptr_t addr;} request;
struct reply {size_t written;} response;
#define SERVER_START_REQ(x) do { struct request* req=&request;struct reply* reply=&response;
#define SERVER_END_REQ } while(0)
static HANDLE wine_server_obj_handle(HANDLE h){return h;}
static uintptr_t wine_server_client_ptr(void* p){return (uintptr_t)p;}
static void wine_server_add_data(struct request* r,const void* b,size_t n){(void)r;(void)b;(void)n;}
static NTSTATUS wine_server_call(struct request* r){(void)r;server_calls++;response.written=0;return STATUS_ACCESS_DENIED;}
'''

structure_at = SOURCE.index('struct ios_jit_mapping {')
structure = SOURCE[structure_at:SOURCE.index('\n};', structure_at) + 3]
reader_at = SOURCE.index('struct ios_pe_span_reader {')
reader = SOURCE[reader_at:SOURCE.index('\n', reader_at)]
COMMON = PRELUDE + structure + r'''
static struct ios_jit_mapping ios_jit_mappings[IOS_JIT_MAX_MAPPINGS];static int ios_jit_mapping_count;
static struct {size_t off,size;void* peb;} ios_pool_ledger[4];static int ios_pool_ledger_count;
''' + reader + '\n' + '\n'.join(function(SOURCE, marker) for marker in [
    'static int ios_pe_span_read(',
    'static void ios_jit_cache_x64_write_spans(',
    'static int ios_native_jit_span_has_protection(',
    'static NTSTATUS check_write_access(',
    'static struct ios_jit_mapping *ios_native_self_image_mapping(',
    'static int ios_native_self_image_write(',
])

MAIN = r'''
static void u16(size_t at,uint16_t v){memcpy(image+at,&v,2);}static void u32(size_t at,uint32_t v){memcpy(image+at,&v,4);}static void u64(size_t at,uint64_t v){memcpy(image+at,&v,8);}
static void reset_metadata(void){
 memset(image,0,image_size);u16(0,0x5a4d);u32(60,0x80);memcpy(image+0x80,"PE\0\0",4);u16(0x84,0x8664);u16(0x86,2);u16(0x94,0xf0);
 u16(0x98,0x20b);u64(0x98+24,0x140000000ULL);u32(0x98+56,image_size);u32(0x98+108,16);u32(0x98+0x70+80,0x800);u32(0x98+0x70+84,208);
 u32(0x188+8,0x1000);u32(0x188+12,0x2000);u32(0x188+36,0x60000020);u32(0x1b0+8,0x4000);u32(0x1b0+12,0x4000);u32(0x1b0+36,0x60000020);
 u64(0x800+0xc8,0x140000a00ULL);u32(0xa04,0xb00);u32(0xa08,2);u32(0xb00,0x2001);u32(0xb04,0x1000);u32(0xb08,0x4002);u32(0xb0c,0x4000);
}
static void setup_mapping(void){
 memset(ios_jit_mappings,0,sizeof(ios_jit_mappings));struct ios_jit_mapping* m=&ios_jit_mappings[0];
 m->pe_base=image;m->jit_base=ios_jit_rx_base_global;m->size=image_size;m->map_peb=current_owner;m->generation=77;
 ios_jit_mapping_count=1;ios_pool_ledger_count=1;ios_pool_ledger[0].off=0;ios_pool_ledger[0].size=image_size;ios_pool_ledger[0].peb=current_owner;
 fixture_view=(struct file_view){image,image_size,SEC_IMAGE};memset(prot,VPROT_COMMITTED|VPROT_WRITECOPY,sizeof(prot));
 ios_jit_cache_x64_write_spans(m,image);assert(m->x64_write_range_count==1&&m->x64_write_ranges[0].offset==0x4000);
}
static void denied(void* dst,const void* src,size_t bytes){size_t written=999;assert(NtWriteVirtualMemory(NtCurrentProcess(),dst,src,bytes,&written)!=0&&written==0);}
static void change_epoch(void){ios_jit_mappings[0].generation++;}
static void* writer(void* value){size_t slot=(uintptr_t)value;unsigned char payload[5]={6,7,8,9,10};for(unsigned i=0;i<25;i++){size_t n=0;assert(!NtWriteVirtualMemory(NtCurrentProcess(),image+0x6000+32*slot,payload,5,&n)&&n==5);}return NULL;}
int main(void){
 char filename[]="/tmp/madeira-owned-pe-XXXXXX";int fd=mkstemp(filename);assert(fd>=0);unlink(filename);assert(!ftruncate(fd,image_size));
 image=mmap(NULL,image_size,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);assert(image!=MAP_FAILED);reset_metadata();assert(pwrite(fd,image,image_size,0)==(ssize_t)image_size);
 assert(!munmap(image,image_size));image=mmap(NULL,image_size,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);assert(image!=MAP_FAILED);
 int poolfd=memfd_create("native-copy-control",0);assert(poolfd>=0);assert(!ftruncate(poolfd,image_size));
 ios_jit_pool_size_global=image_size;ios_jit_rw_base_global=mmap(NULL,image_size,PROT_READ|PROT_WRITE,MAP_SHARED,poolfd,0);ios_jit_rx_base_global=mmap(NULL,image_size,PROT_READ|PROT_EXEC,MAP_SHARED,poolfd,0);
 assert(ios_jit_rw_base_global!=MAP_FAILED&&ios_jit_rx_base_global!=MAP_FAILED);memcpy(ios_jit_rw_base_global,image,image_size);
 teb.ClientId.UniqueProcess=(void*)100;setup_mapping();
 const unsigned char data[5]={1,2,3,4,5};size_t written=99;
#ifdef BASELINE
 assert(NtWriteVirtualMemory(NtCurrentProcess(),image+0x4ffe,data,5,&written)==STATUS_ACCESS_DENIED&&written==0);
 assert(!memcmp(image+0x4ffe,"\0\0\0\0\0",5));puts("PASS before: unchanged production native64 dispatch reproduces ACCESS_DENIED for an owned RW/NX x64 image page");
#else
 assert(!NtWriteVirtualMemory(NtCurrentProcess(),image+0x4ffe,data,5,&written)&&written==5);assert(!memcmp(image+0x4ffe,data,5));assert(!server_calls);
 unsigned char disk[5];assert(pread(fd,disk,5,0x4ffe)==5&&!memcmp(disk,"\0\0\0\0\0",5));assert(!memcmp((char*)ios_jit_rx_base_global+0x4ffe,"\0\0\0\0\0",5));
 assert(!NtWriteVirtualMemory((void*)8,image+0x4100,data,5,&written)&&written==5);
 memcpy(image+0x4200,"123456789",9);assert(!NtWriteVirtualMemory(NtCurrentProcess(),image+0x4202,image+0x4200,5,&written));assert(!memcmp(image+0x4200,"121234589",9));
 size_t n=1;rights=0;assert(NtWriteVirtualMemory((void*)8,image+0x4100,data,5,&n)==STATUS_ACCESS_DENIED&&n==0);rights=PROCESS_VM_WRITE;handle_pid=200;n=1;assert(NtWriteVirtualMemory((void*)8,image+0x4100,data,5,&n)==STATUS_ACCESS_DENIED&&n==0);handle_pid=100;
 queryfail=1;n=1;assert(NtWriteVirtualMemory((void*)8,image+0x4100,data,5,&n)==STATUS_ACCESS_DENIED&&n==0);queryfail=0;
 handle_pid=200;reuse_after_pin=1;n=1;assert(NtWriteVirtualMemory((void*)8,image+0x4100,data,5,&n)==STATUS_ACCESS_DENIED&&n==0);reuse_after_pin=0;handle_pid=100;rights=PROCESS_VM_WRITE;assert(!pin_open&&pin_closes==5);
 /* A 4 KB logical sibling cannot authorize a denied target, even in the
  * same 16 KB real host-page grouping. All rejection writes remain atomic. */
 unsigned char unchanged[5];memcpy(unchanged,image+0x4ffe,5);prot[5]=VPROT_COMMITTED;denied(image+0x4ffe,data,5);assert(!memcmp(unchanged,image+0x4ffe,5));
 prot[5]=VPROT_COMMITTED|VPROT_WRITECOPY|VPROT_GUARD;denied(image+0x4ffe,data,5);prot[5]=VPROT_WRITECOPY;denied(image+0x4ffe,data,5);
 prot[5]=VPROT_COMMITTED|VPROT_WRITECOPY|VPROT_WRITEWATCH;assert(!mprotect(image+0x5000,4096,PROT_READ));assert(!NtWriteVirtualMemory(NtCurrentProcess(),image+0x4ffe,data,5,&written)&&written==5);assert(watch_notes==1&&!(prot[5]&VPROT_WRITEWATCH));prot[5]=VPROT_COMMITTED|VPROT_WRITECOPY;
 prot[4]=VPROT_COMMITTED|VPROT_WRITECOPY|VPROT_WRITEWATCH;assert(!mprotect(image+0x4000,4096,PROT_READ));unprotect_callback=change_epoch;denied(image+0x4300,data,5);assert(!memcmp(image+0x4300,"\0\0\0\0\0",5));unprotect_callback=NULL;prot[4]=VPROT_COMMITTED|VPROT_WRITECOPY;assert(!mprotect(image+0x4000,4096,PROT_READ|PROT_WRITE));
 assert(!mprotect(image+0x4000,0x4000,PROT_READ));denied(image+0x4100,data,5);assert(!mprotect(image+0x4000,0x4000,PROT_READ|PROT_WRITE|PROT_EXEC));denied(image+0x4100,data,5);assert(!mprotect(image+0x4000,0x4000,PROT_READ|PROT_WRITE));
 struct ios_jit_mapping* m=&ios_jit_mappings[0];m->generation=0;denied(image+0x4100,data,5);m->generation=77;m->unmapped=1;denied(image+0x4100,data,5);m->unmapped=0;
 m->map_peb=(void*)0x77770000;denied(image+0x4100,data,5);m->map_peb=current_owner;m->owner_peb=(void*)0x77770000;denied(image+0x4100,data,5);m->owner_peb=NULL;
 ios_jit_mappings[1]=*m;ios_jit_mappings[1].map_peb=(void*)0x77770000;ios_jit_mapping_count=2;denied(image+0x4100,data,5);ios_jit_mappings[1].map_peb=NULL;denied(image+0x4100,data,5);ios_jit_mapping_count=1;
 ios_pool_ledger[0].peb=NULL;denied(image+0x4100,data,5);ios_pool_ledger[0].peb=current_owner;owner_exiting=1;denied(image+0x4100,data,5);owner_exiting=0;current_threads=0;denied(image+0x4100,data,5);current_threads=1;owner_reclaimed=1;denied(image+0x4100,data,5);owner_reclaimed=0;
 denied(image+0x2100,data,5);denied(ios_jit_rx_base_global,data,5);denied(ios_jit_rw_base_global,data,5);denied((void*)(uintptr_t)-2,data,5);
 fixture_view.protect=0;denied(image+0x4100,data,5);fixture_view.protect=SEC_IMAGE|VPROT_SYSTEM;denied(image+0x4100,data,5);fixture_view.protect=SEC_IMAGE;
 wow=0x400000000ULL;denied(image+0x4100,data,5);wow=0;
 /* Caller cannot rewrite mutable original CodeMap to authorize native code. */
 u32(0xb00,0x2002);denied(image+0x2100,data,5);u32(0xb00,0x2001);
 module_name="ntdll.dll";ios_jit_cache_x64_write_spans(m,image);assert(m->x64_write_range_count==1);assert(!NtWriteVirtualMemory(NtCurrentProcess(),image+0x4100,data,5,&written));module_name="ordinary-test.dll";
 pLdrInitializeThunk=NULL;denied(image+0x4100,data,5);pLdrInitializeThunk=image+0x2100;denied(image+0x4100,data,5);
 pLdrInitializeThunk=(char*)ios_jit_rx_base_global+0x2100;denied(image+0x4100,data,5);pLdrInitializeThunk=(void*)0x77770000;
 u32(0x1b0+36,0x70000020);ios_jit_cache_x64_write_spans(m,image);assert(!m->x64_write_range_count);denied(image+0x4100,data,5);u32(0x1b0+36,0x60000020);ios_jit_cache_x64_write_spans(m,image);
 /* Invalid complete-map metadata must not publish partial x64 evidence. */
 u32(0xb08,0x2002);ios_jit_cache_x64_write_spans(m,image);assert(!m->x64_write_range_count);u32(0xb08,0x4003);ios_jit_cache_x64_write_spans(m,image);assert(!m->x64_write_range_count);u32(0xb08,0x4002);
 u32(0xa08,0xffffffffu);ios_jit_cache_x64_write_spans(m,image);assert(!m->x64_write_range_count);u32(0xa08,2);ios_jit_cache_x64_write_spans(m,image);assert(m->x64_write_range_count==1);
 void* inaccessible=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(inaccessible!=MAP_FAILED);written=99;assert(NtWriteVirtualMemory(NtCurrentProcess(),image+0x4100,inaccessible,5,&written)==STATUS_PARTIAL_COPY&&!written);assert(!munmap(inaccessible,4096));
 assert(ios_native_jit_span_has_protection((uintptr_t)ios_jit_rx_base_global,image_size,VM_PROT_READ|VM_PROT_EXECUTE,VM_PROT_WRITE,0,0));
 assert(ios_native_jit_span_has_protection((uintptr_t)ios_jit_rw_base_global,image_size,VM_PROT_READ|VM_PROT_WRITE,VM_PROT_EXECUTE,0,0));
 assert(!pthread_mutex_trylock(&virtual_mutex));pthread_mutex_unlock(&virtual_mutex);assert(!pthread_mutex_trylock(&ios_pool_lock));pthread_mutex_unlock(&ios_pool_lock);
 assert(pread(fd,disk,5,0x4ffe)==5&&!memcmp(disk,"\0\0\0\0\0",5));
 pthread_t writers[4];for(uintptr_t i=0;i<4;i++)assert(!pthread_create(&writers[i],NULL,writer,(void*)i));for(unsigned i=0;i<4;i++)assert(!pthread_join(writers[i],NULL));
 puts("PASS after: production native self-image dispatch writes only owned immutable-CodeMap x64 backing; private COW/file identity, overlap, guards, 4KB guest rights, actual W^X, lease/owner/generation/foreign claims, S1 exclusion and honest failures verified");
#endif
 assert(!munmap(image,image_size));assert(!munmap(ios_jit_rx_base_global,image_size));assert(!munmap(ios_jit_rw_base_global,image_size));close(fd);close(poolfd);
}
'''

baseline = (ROOT / 'tests/host/fixtures/native-self-write-dispatch-before.c').read_text()
baseline_function = function(baseline, 'NTSTATUS WINAPI NtWriteVirtualMemory(')
assert hashlib.sha256(baseline_function.encode()).hexdigest() in baseline.split('*/', 1)[0]
with tempfile.TemporaryDirectory(prefix='madeira-native-self-write-') as directory:
    for name, dispatch in [('before', baseline_function),
                           ('after', function(SOURCE, 'NTSTATUS WINAPI NtWriteVirtualMemory('))]:
        source = Path(directory) / (name + '.c')
        binary = Path(directory) / name
        source.write_text(COMMON + '\n' + dispatch + '\n' + MAIN)
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-variable', '-fsanitize=undefined',
                   '-fno-sanitize-recover=all', '-pthread', '-I' + str(ROOT / 'build/ntdll-unix'),
                   str(source), '-o', str(binary)]
        if name == 'before':
            command.insert(1, '-DBASELINE')
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)

flush = (ROOT / 'wine/dlls/ntdll/signal_arm64ec.c').read_text()
assert 'pBTCpu64FlushInstructionCache( addr, size )' in function(flush, 'NTSTATUS SYSCALL_API NtFlushInstructionCache(')
frontend = (ROOT / 'FEX/FEXCore/Source/Interface/Core/Core.cpp').read_text()
assert 'const uint64_t PeRIP = IosJitReverseTranslate(GuestRIP);' in frontend
assert 'GuestCode = reinterpret_cast<const uint8_t*>(GetGuestBase() + GuestRIP);' in frontend
print('PASS FEX byte-source/cache contract: native64 x64 decoding reads original PE after reverse translation; existing PE flush notifies FEX')
