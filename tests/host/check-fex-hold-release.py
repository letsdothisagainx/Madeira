#!/usr/bin/env python3
"""Validate the native hold-release ABI and observation-only Mach delivery boundary."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()

def body(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[brace:], re.S):
        if token.group() == '{': depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth: return source[start:brace + token.end()]
    raise AssertionError(signature)

observer = body(signal, 'static void ios_note_fex_hold_delivery(')
reap_policy = body(signal, 'static int ios_dead_fex_hold_policy(')
delivery = body(signal, 'static int ios_mach_deliver_guest_exception_inner(')
assert delivery.index('ios_note_fex_hold_delivery(') > delivery.index('mach_vm_write(')
assert 'ios_hold_release_lookup' not in delivery and 'unlock' not in observer
assert 'this delivery leaks the read hold' not in signal
census = body(signal, 'static void ios_lock_census(void)')
assert census.index('if (!already && !live && handled_n < 16)') < census.index('ios_dead_fex_hold_policy(')
assert 'handled_tebs[handled_n++] = (uint64_t)cteb;' in census
assert 'if (policy)' in census and 'action=own-thread-cleanup-only' in census

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "fex_hold_release_abi.h"
typedef size_t mach_vm_size_t;
typedef uintptr_t mach_vm_address_t;
#define KERN_SUCCESS 0
#define mach_task_self() 1
typedef struct {
    char pad[0x40];
    struct {void *UniqueProcess,*UniqueThread;} ClientId;
    char reserved[0x10];
    void *Peb;
} TEB;
static unsigned char teb[0x1800];
static unsigned logs, reads;
static int readable=1;
static char last_line[600];
static int ios_g32_read(uint64_t address,void *out,size_t size) {
    reads++;errno=EIO;
    uintptr_t base=(uintptr_t)teb;
    if(!readable||address<base||address-base>sizeof(teb)||size>sizeof(teb)-(address-base))return 0;
    memcpy(out,(void*)(uintptr_t)address,size);return 1;
}
static int mach_vm_read_overwrite(int task,uint64_t address,size_t size,uintptr_t out,size_t *got) {
    assert(task==1);int ok=ios_g32_read(address,(void*)out,size);*got=ok?size:0;return ok?0:5;
}
static int registry_policy;
int ios_hold_release_wow_owner(void *owner,unsigned long long *lease) {
    assert(owner==(void*)(uintptr_t)0x500310000);*lease=registry_policy==1?77:0;return registry_policy;
}
static int diagnostic(int fd,const char *format,...) {
    assert(fd==2);logs++;
    va_list args;va_start(args,format);vsnprintf(last_line,sizeof(last_line),format,args);va_end(args);
    errno=ERANGE;return 0;
}
#define dprintf diagnostic
''' + observer + '\n' + reap_policy + r'''
int main(void) {
    _Static_assert(MADEIRA_FEX_HOLD_REGISTER_CLASS==1011,"private registration operation");
    _Static_assert(MADEIRA_FEX_HOLD_REGISTER_VERSION==1,"registration version");
    _Static_assert(MADEIRA_FEX_JIT_POOL_ADDRESS_CLASS==1005,"native ARM64 RX alias query");
    _Static_assert(MADEIRA_FEX_HOLD_RELEASE_SELFTEST==16,"existing callback self-test result");
    errno=EDOM;ios_note_fex_hold_delivery(0,0xc000001d,0x300c96d5c,0xd4400020);
    assert(errno==EDOM&&!reads&&!logs);
    ios_note_fex_hold_delivery(UINTPTR_MAX-0x1000,0xc000001d,0,0);
    assert(errno==EDOM&&!reads&&!logs);
    readable=0;ios_note_fex_hold_delivery((uintptr_t)teb,0xc000001d,0,0);
    assert(errno==EDOM&&reads==1&&!logs);
    readable=1;ios_note_fex_hold_delivery((uintptr_t)teb,0xc000001d,0,0);
    assert(errno==EDOM&&!logs); /* no diagnostic stamp */
    uint64_t stamp=0xb620e0118,owner=0x500310000;uint32_t depth=2,tid=0x1e8;
    memcpy(teb+0x16f8,&stamp,8);memcpy(teb+0x16f0,&depth,4);
    memcpy(teb+offsetof(TEB,Peb),&owner,8);memcpy(teb+offsetof(TEB,ClientId.UniqueThread),&tid,4);
    unsigned depth_out;uint64_t srw;void *owner_out;unsigned long long lease;
    registry_policy=1;
    assert(ios_dead_fex_hold_policy((uintptr_t)teb,stamp,&depth_out,&srw,&owner_out,&lease)==1&&lease==77);
    registry_policy=-1;
    assert(ios_dead_fex_hold_policy((uintptr_t)teb,stamp,&depth_out,&srw,&owner_out,&lease)==-1);
    registry_policy=0;
    assert(!ios_dead_fex_hold_policy((uintptr_t)teb,stamp,&depth_out,&srw,&owner_out,&lease)&&depth_out==2);
    /* A Mach sample taken before own-thread cleanup cannot release the now
     * cleared hold a second time, even after callback registration is dropped. */
    uint64_t zero=0;memcpy(teb+0x16f8,&zero,8);memcpy(teb+0x16f0,&zero,8);
    assert(ios_dead_fex_hold_policy((uintptr_t)teb,stamp,&depth_out,&srw,&owner_out,&lease)==-2);
    memcpy(teb+0x16f8,&stamp,8);memcpy(teb+0x16f0,&depth,4);
    errno=EDOM;
    unsigned char before[sizeof(teb)];memcpy(before,teb,sizeof(teb));
    for(unsigned i=0;i<10000;i++){
        ios_note_fex_hold_delivery((uintptr_t)teb,0xc000001d,0x300c96d5c,0xd4400020);
        assert(errno==EDOM&&!memcmp(before,teb,sizeof(teb)));
    }
    assert(logs==16&&strstr(last_line,"phase=frame-prepared")&&strstr(last_line,"recorded-depth=2"));
    assert(strstr(last_line,"release-authority=current-thread-terminal-boundary"));
    puts("PASS: shared 24-byte native registration ABI; Mach hold observations are bounded/fault-safe, preserve errno and never alter another thread's lock metadata");
    puts("PASS: actual dead-hold policy refuses registered WoW, busy registry and stale post-cleanup samples; fresh legacy EC policy remains available");
}
'''
with tempfile.TemporaryDirectory() as temp:
    src=Path(temp)/'check.c';src.write_text(code)
    exe=Path(temp)/'check'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-I'+str(root/'build/ntdll-unix'),str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))

virtual = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
process = (root / 'build/ntdll-unix/process_ios.c').read_text()
registry_start = virtual.index('#define IOS_HOLD_RELEASE_MAX ')
registry_end = virtual.index('unsigned int (*ios_hold_release_lookup(', registry_start)
registry = virtual[registry_start:registry_end]
registry += body(virtual,'struct ios_register_hold_release_args') + ';\n'
registry += '\n'.join(body(virtual, s) for s in (
    'unsigned int (*ios_hold_release_lookup(', 'static void ios_hold_release_drop(',
    'static NTSTATUS ios_register_hold_release_kind(', 'NTSTATUS unixcall_ios_register_hold_release(',
    'int ios_hold_release_wow_owner(', 'static NTSTATUS ios_register_wow_thread_retire(',
    'unsigned int (*ios_wow_thread_retire_lookup('))
wrapper = '\n'.join(body(virtual,x) for x in ('static NTSTATUS ios_fex_register_wow_callback(', 'NTSTATUS ios_fex_register_wow_hold_release(', 'NTSTATUS ios_fex_register_wow_thread_retire('))
operation = body(process,'case (PROCESSINFOCLASS)MADEIRA_FEX_HOLD_REGISTER_CLASS:')
native_code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <signal.h>
#include "fex_hold_release_abi.h"
typedef uint32_t NTSTATUS;typedef size_t SIZE_T;typedef void *HANDLE;typedef unsigned PROCESSINFOCLASS;
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_INVALID_HANDLE 0xc0000008u
#define STATUS_ACCESS_VIOLATION 0xc0000005u
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004u
#define STATUS_INSUFFICIENT_RESOURCES 0xc000009au
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define VM_PROT_READ 1
#define VM_PROT_EXECUTE 4
#define IOS_FEX_OWNERS 4
static int diagnostic(int fd,const char *format,...){assert(fd==2&&format);return 0;}
#define dprintf diagnostic
''' + registry + r'''
static unsigned char image[0x3000];
static void *current_owner=(void*)(uintptr_t)0x500310000;
static struct {void *owner,*image;unsigned long long lease;} ios_fex_owners[IOS_FEX_OWNERS];
static struct {void *pe_base,*jit_base,*owner_peb,*map_peb;size_t size;unsigned unmapped,machine;} ios_jit_mappings[4];
static int ios_jit_mapping_count,readable=1,export_exists=1,executable=1,physical_ok=1;
static unsigned protections=5;
static uintptr_t export_rva=0x100;
static const char *module_name="libwow64fex.dll";
static unsigned long long live_lease=77,quiet_lease;
static struct madeira_fex_hold_registration input;
static void *ios_jit_rx_base_global=(void*)(uintptr_t)0x300000000;
static size_t ios_jit_pool_size_global=0x40000000;
static pthread_mutex_t virtual_mutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned vm_depth;
static void *ios_jit_current_peb(void){return current_owner;}
static int ios_safe_read(uintptr_t p,void *out,size_t n){
 if(!readable||p!=(uintptr_t)&input||n!=sizeof(input))return 0;memcpy(out,&input,n);return 1;
}
static void server_enter_uninterrupted_section(pthread_mutex_t *m,sigset_t *s){(void)s;assert(!vm_depth);pthread_mutex_lock(m);vm_depth++;}
static void server_leave_uninterrupted_section(pthread_mutex_t *m,sigset_t *s){(void)s;assert(vm_depth==1);vm_depth--;pthread_mutex_unlock(m);}
static unsigned long long ios_thread_process_lease(void *p,int create){assert(p==current_owner&&!create);return live_lease;}
static unsigned long long ios_thread_process_quiescent_lease(void *p){assert(p==current_owner);return quiet_lease;}
static unsigned ios_jit_mapping_machine(int i){return ios_jit_mappings[i].machine;}
static const char *ios_pe_module_name(void *p,size_t n){assert(p==image&&n);return module_name;}
static void *ios_pe_find_export(void *p,const char *name){assert(p==image&&(!strcmp(name,"MadeiraBTCpuIosReleaseThreadHolds")||!strcmp(name,"MadeiraBTCpuIosRetireThread")));return export_exists?(void*)((uintptr_t)p+export_rva):0;}
static int ios_img_off_is_exec(void *p,size_t n,uintptr_t rva){assert(p==image&&n&&rva==export_rva);return executable;}
static int ios_pool_range_execable(uintptr_t off,size_t n,unsigned *current,unsigned *maximum){assert(off<ios_jit_pool_size_global&&n==4);*current=protections;*maximum=7;return physical_ok;}
''' + wrapper + r'''
static HANDLE NtCurrentProcess(void){return (void*)(intptr_t)-1;}
static NTSTATUS native_operation(HANDLE handle,void *info,SIZE_T size){switch(MADEIRA_FEX_HOLD_REGISTER_CLASS){
''' + operation + r'''
}return STATUS_INVALID_PARAMETER;}
static NTSTATUS retire_operation(HANDLE handle,void *info,SIZE_T size){
 if(handle!=NtCurrentProcess())return STATUS_INVALID_HANDLE;return ios_fex_register_wow_thread_retire(info,size);
}
static void reset(void){
 memset(ios_hold_release,0,sizeof(ios_hold_release));ios_hold_release_n=0;
 memset(ios_fex_owners,0,sizeof(ios_fex_owners));memset(ios_jit_mappings,0,sizeof(ios_jit_mappings));
 ios_fex_owners[0].owner=current_owner;ios_fex_owners[0].image=image;ios_fex_owners[0].lease=77;
 ios_jit_mappings[0].pe_base=image;ios_jit_mappings[0].jit_base=(void*)(uintptr_t)0x300010000;
 ios_jit_mappings[0].owner_peb=current_owner;ios_jit_mappings[0].map_peb=current_owner;
 ios_jit_mappings[0].size=sizeof(image);ios_jit_mappings[0].machine=IMAGE_FILE_MACHINE_ARM64;ios_jit_mapping_count=1;
 readable=export_exists=executable=physical_ok=1;protections=5;module_name="libwow64fex.dll";export_rva=0x100;
 live_lease=77;quiet_lease=0;
 input=(struct madeira_fex_hold_registration){sizeof(input),1,current_owner,(void*)(uintptr_t)0x300010100};
}
static NTSTATUS submit(void){NTSTATUS s=native_operation(NtCurrentProcess(),&input,sizeof(input));assert(!vm_depth);return s;}
static void rejected(void){assert(submit()!=STATUS_SUCCESS);assert(!ios_hold_release_lookup(current_owner));unsigned long long lease=99;assert(ios_hold_release_wow_owner(current_owner,&lease)==-1&&lease==0);}
int main(void){unsigned long long lease;
 reset();assert(retire_operation(NtCurrentProcess(),&input,sizeof(input))==STATUS_INVALID_PARAMETER);
 assert(!native_operation(NtCurrentProcess(),&input,sizeof(input)));
 assert(!retire_operation(NtCurrentProcess(),&input,sizeof(input)));
 assert(ios_wow_thread_retire_lookup(current_owner,77)==(void*)input.callback);
 assert(!ios_wow_thread_retire_lookup(current_owner,78));
 ios_hold_release_drop(current_owner);assert(!ios_wow_thread_retire_lookup(current_owner,77));
 reset();assert(native_operation((void*)1,&input,sizeof(input))==STATUS_INVALID_HANDLE);
 assert(native_operation(NtCurrentProcess(),&input,23)==STATUS_INFO_LENGTH_MISMATCH);
 assert(native_operation(NtCurrentProcess(),(void*)1,sizeof(input))==STATUS_ACCESS_VIOLATION);
 readable=0;rejected();reset();input.size--;rejected();reset();input.version++;rejected();
 reset();input.peb=(void*)2;rejected();reset();input.callback=0;rejected();
 reset();live_lease=0;rejected();reset();quiet_lease=77;rejected();reset();ios_fex_owners[0].lease=76;rejected();
 reset();ios_jit_mappings[0].unmapped=1;rejected();reset();ios_jit_mappings[0].size=0;rejected();
 reset();ios_jit_mappings[0].owner_peb=(void*)2;rejected();reset();ios_jit_mappings[0].owner_peb=0;ios_jit_mappings[0].map_peb=(void*)2;rejected();
 reset();ios_jit_mappings[0].machine=0xa641;rejected();reset();module_name=0;rejected();reset();module_name="ntdll.dll";rejected();
 reset();export_exists=0;rejected();reset();export_rva=0x101;rejected();reset();export_rva=sizeof(image);rejected();
 reset();executable=0;rejected();reset();physical_ok=0;rejected();reset();protections=7;rejected();reset();protections=1;rejected();
 reset();input.callback=image+0x100;rejected();reset();input.callback=(void*)(uintptr_t)0x340010100;rejected();
 reset();assert(!submit());assert((void*)ios_hold_release_lookup(current_owner)==input.callback);
 assert(ios_hold_release_wow_owner(current_owner,&lease)==1&&lease==77);
 pthread_mutex_lock(&ios_hold_release_lock);assert(ios_hold_release_wow_owner(current_owner,&lease)==-1);pthread_mutex_unlock(&ios_hold_release_lock);
 ios_hold_release_drop(current_owner);assert(ios_hold_release_wow_owner(current_owner,&lease)==-1&&lease==0);
 assert(ios_hold_release_wow_owner(0,&lease)==-1); /* dropped before first Mach sample is unknown */
 struct ios_register_hold_release_args ec={sizeof(ec),1,current_owner,(void*)(uintptr_t)0x300010100};
 assert(!unixcall_ios_register_hold_release(&ec));assert(!ios_hold_release_wow_owner(current_owner,&lease)&&lease==0);
 ios_hold_release_drop(current_owner);assert(ios_hold_release_wow_owner(current_owner,&lease)==-1);
 reset();ios_jit_mappings[0].owner_peb=0;assert(!submit()); /* current mapper's known default */
 reset();ios_jit_mappings[1]=ios_jit_mappings[0];ios_jit_mappings[1].jit_base=(void*)(uintptr_t)0x300020000;
 ios_jit_mappings[0].owner_peb=0;ios_jit_mapping_count=2;rejected(); /* own copy wins; no default fallthrough */
 input.callback=(void*)(uintptr_t)0x300020100;assert(!submit());
 puts("PASS: actual native registration rejects invalid ABI, foreign handles/owners, stale leases, EC/raw/foreign aliases and non-RX code; exact own ARM64 export registers without executing it");
 puts("PASS: actual nonblocking registry distinguishes known EC/WoW from busy, failed-registration and dropped-before-first-sample owners; missing ownership never enables foreign reaping");
}
'''
with tempfile.TemporaryDirectory() as temp:
    src=Path(temp)/'native.c';src.write_text(native_code)
    exe=Path(temp)/'native'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g','-pthread',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-I'+str(root/'build/ntdll-unix'),str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))
