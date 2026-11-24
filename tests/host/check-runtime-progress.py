#!/usr/bin/env python3
"""Execute only ordinary counter and synthetic JIT *metadata* fixtures, never instructions."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'build/ntdll-unix/signal_arm64_ios.c').read_text()
b=s.index('struct ios_vlpair {');e=s.index('static const char *ios_wait_api_name(',b)
actual=s[b:e]
with tempfile.TemporaryDirectory() as d:
 p=Path(d)
 (p/'actual.h').write_text(actual)
 (p/'test.c').write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#define KERN_SUCCESS 0
static unsigned calls;static uint8_t metadata[8192];
typedef uint64_t mach_vm_size_t;typedef uint64_t mach_vm_address_t;
static int mach_task_self(void){return 0;}
static int mach_vm_read_overwrite(int task,mach_vm_address_t a,mach_vm_size_t n,mach_vm_address_t out,mach_vm_size_t *got){
 (void)task;calls++;if(a<(uintptr_t)metadata || a-(uintptr_t)metadata>sizeof(metadata) || n>sizeof(metadata)-(a-(uintptr_t)metadata)){*got=0;return 1;}
 memcpy((void*)(uintptr_t)out,(void*)(uintptr_t)a,n);*got=n;return 0;
}
#include "actual.h"
int main(void){
 const uint64_t base=(uintptr_t)metadata;uint32_t off=4096;
 struct {uint64_t size,rip,guest_size;uint32_t entries,off_entries;} tail={2048,0x71000000,1024,257,32};
 memcpy(metadata,&off,4);memcpy(metadata+off,&tail,sizeof(tail));
 memset(metadata+off+32,0,257); /* vl8 metadata: host+4, guest+1; not machine code */
 assert(ios_native_rip_from_hostpc_budget(base,base+6)==0x71000001);
 assert(ios_native_rip_from_hostpc_budget(base,base+1025)==0);
 assert(ios_native_rip_from_hostpc(base,base+1025,NULL)==0x71000100);
 assert(ios_native_rip_from_hostpc_budget(base,base+2048)==0);
 assert(ios_native_rip_from_hostpc_budget(0,base)==0);
 tail.entries=65537;memcpy(metadata+off,&tail,sizeof(tail));assert(!ios_native_rip_from_hostpc_budget(base,base+4));
 puts("actual resolver: metadata decoding, existing full lookup, bounded 256-entry exhaustion, missing/out-of-block rejection PASS; no instructions executed");
}
''')
 subprocess.run([os.getenv('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+d,str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
# Preserve original call/control behavior: observations outside held sampler scope.
n=(root/'build/ntdll-unix/cs2_stall_watch_native.h').read_text()
held=n[n.index('suspend_result = thread_suspend(port);'):n.index('ios_stuck_clock_us(&held_end);')]
assert 'ios_runtime_' not in held and 'ios_native_rip_' not in held
assert 'if(!rip && generatedPC && ios_ts_read(st.__x[28]' in n
assert n.index('thread_resume(port)')<n.index('ios_runtime_snapshot(')<n.index('ios_native_rip_from_hostpc_budget(block,pc)')
server=(root/'build/ntdll-unix/server_ios.c').read_text()
assert 'mutex_lock( mutex );\n    ios_runtime_end(1,runtime);' in server
assert 'ret = server_select( select_op, size, flags, abs_timeout, NULL, &apc );\n        ios_runtime_end(2,runtime);' in server
assert 'if(ios_cs2_stall_find((uintptr_t)owner,pid,lease))\n        ios_runtime_register' in server
print('passive placement: known initial thread only, original wait/lock statuses, no added suspension/loader walk/payload reads PASS')
# Execute the actual try-only cache wrapper on ordinary metadata. The retained
# view must survive a different observer publishing another map.
def function(text,signature):
 b=text.index(signature);e=text.index('{',b)+1;depth=1
 while depth:depth+=(text[e]=='{')-(text[e]=='}');e+=1
 return text[b:e]
wrapper=function(server,'static struct ios_ts_map *ios_ts_map_for_teb(uint64_t teb)')
with tempfile.TemporaryDirectory() as d:
 p=Path(d)
 (p/'cache.c').write_text(r'''
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
struct ios_ts_mod {uint64_t base,size;char name[40];};
struct ios_ts_map {uint64_t peb,lease,observed_ns;int n;struct ios_ts_mod m[160];};
static struct ios_ts_map backing,ios_ts_borrows[4];
static uintptr_t ios_ts_borrow_owner[4];static unsigned ios_ts_map_lock;
static struct ios_ts_map *ios_ts_map_for_teb_impl(uint64_t teb){backing.peb=teb;backing.n=1;backing.m[0].base=teb;return &backing;}
'''+wrapper+r'''
static void *other(void *unused){(void)unused;struct ios_ts_map *p=ios_ts_map_for_teb(2);assert(p && p->peb==2);return NULL;}
int main(void){
 struct ios_ts_map *one=ios_ts_map_for_teb(1);assert(one && one!=&backing && one->peb==1);
 pthread_t t;assert(!pthread_create(&t,NULL,other,NULL));pthread_join(t,NULL);
 assert(backing.peb==2 && one->peb==1 && one->m[0].base==1);
 ios_ts_map_lock=1;assert(!ios_ts_map_for_teb(3));ios_ts_map_lock=0;
 assert(one->peb==1);_Static_assert(sizeof(ios_ts_borrows)<36*1024,"fixed cache budget");
 puts("actual module cache wrapper: retained observer view survives concurrent publication; busy returns unavailable; four fixed copies below 36KiB PASS");
}
''')
 subprocess.run([os.getenv('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-O2','-pthread',str(p/'cache.c'),'-o',str(p/'cache')],check=True)
 subprocess.run([str(p/'cache')],check=True)
assert server.index('ios_ts_nmaps=0; /* reset before acquiring task_threads rights */') < server.index('if (task_threads(mach_task_self(), &tlist, &tcount) != KERN_SUCCESS) return;',server.index('static void ios_thread_sampler_pass('))
assert n.index('memcpy(resolved.w+20,module,n);')<n.index('__atomic_store_n(&ios_ts_map_lock,0,__ATOMIC_RELEASE);')
