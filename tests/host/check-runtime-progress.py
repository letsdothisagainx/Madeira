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
assert n.index('thread_resume(port)')<n.index('ios_runtime_snapshot(')<n.index('ios_native_rip_from_hostpc_budget(block,pc)')
server=(root/'build/ntdll-unix/server_ios.c').read_text()
assert 'mutex_lock( mutex );\n    ios_runtime_end(1,runtime);' in server
assert 'ret = server_select( select_op, size, flags, abs_timeout, NULL, &apc );\n        ios_runtime_end(2,runtime);' in server
assert 'if(ios_cs2_stall_find((uintptr_t)owner,pid,lease))\n        ios_runtime_register' in server
print('passive placement: known initial thread only, original wait/lock statuses, no added suspension/loader walk/payload reads PASS')
