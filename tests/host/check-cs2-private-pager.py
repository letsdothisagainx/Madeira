#!/usr/bin/env python3
"""Actual policy/identity functions; ordinary RW file mapping and metadata only."""
from pathlib import Path
import tempfile,subprocess,os
root=Path(__file__).resolve().parents[2]
def body(s,sig):
 b=s.index(sig);e=s.index('{',b)+1;depth=1
 while depth:depth+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[b:e]
thread=(root/'build/ntdll-unix/thread_ios.c').read_text();server=(root/'build/ntdll-unix/server_ios.c').read_text();vm=(root/'build/ntdll-unix/virtual_ios.c').read_text()
identity=body(thread,'int ios_native_current_process_identity(')
owner=body(server,'int ios_cs2_current_private_owner(')
policy=body(vm,'static void ios_swap_private_pager_advice(')
with tempfile.TemporaryDirectory() as d:
 p=Path(d)
 (p/'test.c').write_text(r'''
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#include "native_thread_lifetime.h"
#include "cs2_stall_watch.h"
#define CHECK(c) do{if(!(c)){fprintf(stderr,"ordinary pager fixture line %d: %s errno=%d\n",__LINE__,#c,errno);return 1;}}while(0)
typedef struct {void *Peb;struct{void *UniqueProcess,*UniqueThread;}ClientId;} TEB;
static TEB teb;static TEB *current=&teb;
#define NtCurrentTeb() current
#define ULONG_PTR uintptr_t
static struct madeira_native_thread ios_native_current;static int ios_native_finishing;
struct file_view{void *base;size_t size;unsigned protect;uintptr_t ios_evidence_owner;uint64_t ios_evidence_id;};
static struct file_view view;
static struct file_view *find_view(void *base){return (uintptr_t)base>=(uintptr_t)view.base && (uintptr_t)base-(uintptr_t)view.base<view.size ? &view:NULL;}
static int fixture_private_view=1;
static int is_view_valloc(struct file_view *v){(void)v;return fixture_private_view;}
enum{SEC_FILE=1<<8,SEC_IMAGE=1<<9,SEC_RESERVE=1<<10,VPROT_SYSTEM=1<<11,VPROT_ARM64EC=1<<12,VPROT_WRITEWATCH=1<<13,VPROT_EXEC=4,VPROT_GUARD=1<<14,VPROT_WRITECOPY=1<<15,VPROT_PLACEHOLDER=1<<16,VPROT_FREE_PLACEHOLDER=1<<17};
static uint64_t ios_swap_random_attempts,ios_swap_random_success,ios_swap_random_failures,ios_swap_random_bytes,ios_ev_vm_generation;
static int ios_swap_random_last_error;
static uint64_t ios_runtime_begin(unsigned k,uint64_t op){(void)k;(void)op;return 1;}
static void ios_runtime_end(unsigned k,uint64_t start){(void)k;(void)start;}
static uint64_t ios_evidence_begin(unsigned o,uintptr_t a,uint64_t b,uint64_t g,unsigned l){(void)o;(void)a;(void)b;(void)g;(void)l;return 1;}
static void ios_evidence_end(uint64_t t,int r,int e){(void)t;(void)r;(void)e;}
'''+identity+'\n'+owner+'\n'+policy+r'''
int main(void){
 size_t bytes=8u<<20;char name[]="/tmp/madeira-pager-normal-XXXXXX";int fd=mkstemp(name);CHECK(fd>=0);unlink(name);CHECK(!ftruncate(fd,(off_t)bytes));
 uint64_t *data=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);CHECK(data!=MAP_FAILED);
 teb.Peb=(void*)0x100000;teb.ClientId.UniqueProcess=(void*)17;teb.ClientId.UniqueThread=(void*)18;
 ios_native_current=(struct madeira_native_thread){.owner=teb.Peb,.teb=&teb,.lease=34,.pid=17,.tid=18};
 ios_cs2_stall_register_main((uintptr_t)teb.Peb,17,34,18,(uintptr_t)&teb,99);
 view=(struct file_view){data,bytes,3,(uintptr_t)teb.Peb,1};
 for(size_t i=0;i<bytes/8;i++)data[i]=(uint64_t)i*UINT64_C(0x9e3779b97f4a7c15);
 errno=EDOM;ios_swap_private_pager_advice(data,bytes);CHECK(errno==EDOM && ios_swap_random_success==1 && ios_swap_random_attempts==1 && ios_swap_random_bytes==bytes && !ios_swap_random_failures);
 for(size_t i=0;i<bytes/8;i++)CHECK(data[i]==(uint64_t)i*UINT64_C(0x9e3779b97f4a7c15));
 /* Ordinary aligned writes to a small owned, fully initialized RW allocation.
  * No eviction, discard, protection change or intentional fault is induced. */
 for(size_t i=0;i<20000;i++){size_t at=(i*7919)%(bytes/8);data[at]^=UINT64_C(0x12345678);data[at]^=UINT64_C(0x12345678);}
#ifdef __APPLE__
 mach_vm_address_t at=(uintptr_t)data;mach_vm_size_t span=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t n=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t object=0;
 CHECK(mach_vm_region(mach_task_self(),&at,&span,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&n,&object)==KERN_SUCCESS);
 CHECK(info.behavior==VM_BEHAVIOR_RANDOM && info.protection==(VM_PROT_READ|VM_PROT_WRITE));if(object)mach_port_deallocate(mach_task_self(),object);
 puts("Darwin actual VM region confirms RANDOM behavior and unchanged RW protection");
#else
 puts("Darwin behavior query unavailable on Linux; no phone paging/FPS result inferred");
#endif
 fixture_private_view=0;ios_swap_private_pager_advice(data,bytes);fixture_private_view=1;
 unsigned excluded[]={SEC_FILE,SEC_IMAGE,SEC_RESERVE,VPROT_SYSTEM,VPROT_ARM64EC,VPROT_WRITEWATCH,VPROT_EXEC,VPROT_GUARD,VPROT_WRITECOPY,VPROT_PLACEHOLDER,VPROT_FREE_PLACEHOLDER};
 for(unsigned i=0;i<sizeof(excluded)/sizeof(*excluded);i++){view.protect=3|excluded[i];ios_swap_private_pager_advice(data,bytes);}view.protect=3;
 view.ios_evidence_owner++;ios_swap_private_pager_advice(data,bytes);view.ios_evidence_owner--;
 void *saved_owner=teb.Peb;teb.Peb=(void*)0x200000;ios_native_current.owner=teb.Peb;view.ios_evidence_owner=(uintptr_t)teb.Peb;
 ios_swap_private_pager_advice(data,bytes);teb.Peb=saved_owner;ios_native_current.owner=saved_owner;view.ios_evidence_owner=(uintptr_t)saved_owner;
 ios_native_current.lease=35;ios_swap_private_pager_advice(data,bytes);ios_native_current.lease=34;
 ios_native_current.cancelled=1;ios_swap_private_pager_advice(data,bytes);ios_native_current.cancelled=0;
 teb.ClientId.UniqueProcess=(void*)19;ios_swap_private_pager_advice(data,bytes);teb.ClientId.UniqueProcess=(void*)17;
 ios_native_finishing=1;ios_swap_private_pager_advice(data,bytes);ios_native_finishing=0;
 ios_swap_private_pager_advice((char*)data+8,bytes);CHECK(ios_swap_random_attempts==1);
 /* A real worker registration in the same live owner/lease is eligible. */
 teb.ClientId.UniqueThread=(void*)20;ios_native_current.tid=20;ios_swap_private_pager_advice(data,bytes);CHECK(ios_swap_random_success==2 && errno==EDOM);
 for(size_t i=0;i<bytes/8;i++)CHECK(data[i]==(uint64_t)i*UINT64_C(0x9e3779b97f4a7c15));
 CHECK(!munmap(data,bytes));CHECK(!close(fd));
 puts("actual CS2 private pager policy: real MADV_RANDOM, preserved every byte, Main/worker identity+lease, Steam/foreign/stale/executable/image/view exclusions, errno and bounded range PASS");return 0;
}
''')
 subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-pthread','-I'+str(root/'build/ntdll-unix'),str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
# Advice must accompany actual fresh maps, never a sampler or an image map.
assert 'ios_swap_private_pager_advice(hs,len);' in body(vm,'static int ios_swap_map(')
assert 'ios_swap_private_pager_advice(lo,len);' in body(vm,'static int ios_swap_punch_resv(')
assert 'ios_swap_private_pager_advice(' not in body(vm,'static int ios_swap_image_map(')
assert 'mprotect' not in policy and 'memcpy' not in policy and 'pthread_' not in policy
assert 'return;' not in owner and 'ios_thread_process_' not in owner
print('fresh/private-only placement; no new migration, payload/protection operations, registry lock or allocation failure fabricated PASS')
