#!/usr/bin/env python3
"""Exercise the actual signal/Mach FEX-trap discriminator and stop-state
construction. Real production helpers, fake kernel calls; no guest execution.
"""
import os
import re
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
src = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
header = root / 'build/ntdll-unix/fault_replay.h'
helpers = src[src.index('#include "fault_replay.h"'):src.index('static int ios_mach_deliver_guest_exception_inner(', src.index('#include "fault_replay.h"'))]
helpers = helpers.replace('#include "fault_replay.h"', '#include "'+str(header)+'"')
harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define DECLSPEC_NORETURN __attribute__((noreturn))
#define STATUS_ACCESS_VIOLATION 0xc0000005u
#define KERN_SUCCESS 0
#define MACH_PORT_NULL 0
#define VM_REGION_BASIC_INFO_64 9
#define VM_REGION_BASIC_INFO_COUNT_64 9
#define VM_PROT_WRITE 2
#define REGn_sig(n, ctx) ((ctx)->uc_mcontext->__ss.__x[n])
#define PC_sig(ctx) ((ctx)->uc_mcontext->__ss.__pc)
#define SP_sig(ctx) ((ctx)->uc_mcontext->__ss.__sp)
#define FP_sig(ctx) ((ctx)->uc_mcontext->__ss.__x[29])
#define LR_sig(ctx) ((ctx)->uc_mcontext->__ss.__x[30])
#define arm_thread_state64_get_sp(state) ((state).__sp)
#define __darwin_arm_thread_state64_set_sp(state, value) ((state).__sp=(value))
#define __darwin_arm_thread_state64_set_pc_fptr(state, value) ((state).__pc=(uintptr_t)(value))
typedef uintptr_t mach_vm_size_t, mach_vm_address_t, mach_port_t;
typedef int kern_return_t;
typedef unsigned mach_msg_type_number_t;
typedef void *vm_region_info_t;
typedef struct { int protection; } vm_region_basic_info_data_64_t;
typedef struct { uint64_t __x[31], __sp, __pc; } arm_thread_state64_t;
typedef struct { arm_thread_state64_t __ss; } fake_mcontext;
typedef struct { fake_mcontext *uc_mcontext; } test_context;
#define ucontext_t test_context
typedef struct { struct { void *Self; } Tib; void *Peb; void *TlsSlots[16]; } TEB;
static TEB *current_teb;
static TEB *NtCurrentTeb(void) { return current_teb; }
static void *GetCurrentProcess(void) { return (void*)-1; }
static void NtTerminateProcess(void *p,unsigned s) { assert(0); }
static DECLSPEC_NORETURN void abort_process(unsigned s) { assert(0); __builtin_trap(); }
static DECLSPEC_NORETURN void abort_thread(unsigned s) { assert(0); __builtin_trap(); }
static int ios_peb_is_dead(const void *p) { return 0; }
static struct { uintptr_t base, size; } readable[8];
static unsigned readable_count, original_logs, terminal_logs;
static int writable_stack=1, correct_code_owner=1;
static int ios_fex_code_owner_matches(uintptr_t pc,void *owner) {
    return correct_code_owner && current_teb && current_teb->Peb==owner;
}
static uint64_t now_ms=1000;
static mach_port_t mach_task_self(void) { return 0; }
static int mach_vm_read_overwrite(mach_port_t task,mach_vm_address_t a,size_t n,mach_vm_address_t dest,mach_vm_size_t *got) {
    for (unsigned i=0;i<readable_count;i++)
        if (a>=readable[i].base && a-readable[i].base<=readable[i].size &&
            n<=readable[i].size-(a-readable[i].base)) {
            memcpy((void*)dest,(void*)a,n); *got=n; return 0;
        }
    return 1;
}
static int mach_vm_region(mach_port_t t,mach_vm_address_t *base,mach_vm_size_t *size,int flavor,
                           vm_region_info_t ptr,mach_msg_type_number_t *count,mach_port_t *obj) {
    *size=0x10000; ((vm_region_basic_info_data_64_t*)ptr)->protection=writable_stack ? 3 : 1;
    *obj=0; return 0;
}
static void mach_port_deallocate(mach_port_t t,mach_port_t o) { assert(0); }
static int fake_clock_gettime(int id,struct timespec *out) {
    out->tv_sec=now_ms/1000; out->tv_nsec=now_ms%1000*1000000; return 0;
}
#define clock_gettime fake_clock_gettime
static ssize_t fake_write(int fd,const void *data,size_t size) {
    assert(size<1400); assert(fd==STDERR_FILENO);
    if (memmem(data,size,"original guest AV",17)) ++original_logs;
    if (memmem(data,size,"ending owner only",17)) ++terminal_logs;
    return size;
}
#define write fake_write
'''
main = r'''
static void add_readable(void *p,size_t size) { readable[readable_count].base=(uintptr_t)p; readable[readable_count++].size=size; }
int main(void) {
    struct ios_fault_replay replay={0};
    unsigned char state[0x140+160]={0};
    TEB teb={0}; uint32_t insns[2]={0x52800001,0xf9400021};
    fake_mcontext mc={0}; test_context context={&mc};
    uint64_t *frame=(void*)(state+0x140);
    *(uintptr_t*)state=(uintptr_t)frame;
    teb.Tib.Self=&teb; teb.Peb=(void*)0x600310000; teb.TlsSlots[14]=state; current_teb=&teb;
    frame[0x18/8]=0xffe7ef90; frame[0x20/8+4]=0x410fd10;
    mc.__ss.__x[28]=(uintptr_t)frame; mc.__ss.__pc=(uintptr_t)&insns[1]; mc.__ss.__sp=0x1369cf350;
    add_readable(&teb,sizeof(teb)); add_readable(state,sizeof(state)); add_readable(insns,sizeof(insns));
    arm_thread_state64_t original=mc.__ss;
    /* x1 is intentionally zero. First genuine exception retains ALL registers. */
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    assert(!memcmp(&original,&mc.__ss,sizeof(original)) && original_logs==1);
    for(unsigned i=1;i<255;i++) {
        ++now_ms;
        assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
        assert(!memcmp(&original,&mc.__ss,sizeof(original)));
    }
    assert(ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    assert(mc.__ss.__pc==(uintptr_t)ios_stop_faulting_process);
    assert(mc.__ss.__pc!=original.__pc+4);
    assert(mc.__ss.__x[0]==STATUS_ACCESS_VIOLATION && !(mc.__ss.__sp&15));
    assert(terminal_logs==1);
    mc.__ss=original;
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    assert(terminal_logs==1); /* no repeated diagnostic after stop */
    /* Ordinary null reads, x18 loads, foreign frames and invalid TEBs are not
       this trap and must keep their normal exception path. */
    memset(&replay,0,sizeof(replay));
    insns[0]=0xd2800000;
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    insns[0]=0x52800001; insns[1]=0xb9980e48;
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    insns[1]=0xf9400021; mc.__ss.__x[28]+=8;
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    mc.__ss=original;
    correct_code_owner=0;
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    correct_code_owner=1;
    assert(!ios_bound_fex_guest_fault(&context,0x180c,0,&replay));
    assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0x10004,&replay));
    assert(!memcmp(&mc.__ss,&original,sizeof(original)));
    /* Sparse recurring guest AVs cannot accumulate across frames. */
    for(unsigned i=0;i<1000;i++) {
        now_ms+=501;
        assert(!ios_bound_fex_guest_fault(&context,(uintptr_t)&teb,0,&replay));
    }
    assert(replay.logs==1000 && original_logs==9 && terminal_logs==1);
    /* Isolated threads/processes retain independent failure budgets. */
    struct ios_fault_replay many[300]={0};
    struct ios_fault_signature key={1,2,3,0,0xffe7ef90,0x410fd10,0x1369cf350};
    for(unsigned n=0;n<255;n++) for(unsigned i=0;i<300;i++) {
        key.owner=i+1; key.teb=i+1000;
        assert(ios_fault_replay_note(&many[i],&key,n)<2);
    }
    for(unsigned i=0;i<300;i++) {
        key.owner=i+1; key.teb=i+1000;
        assert(ios_fault_replay_note(&many[i],&key,255)==2);
    }
    /* Exception-dispatch recursion changing only SP is still the same failed
       guest entry, not evidence of executable guest progress. */
    memset(&replay,0,sizeof(replay)); key.rip=0xffe7e4a8;
    for(unsigned i=0;i<255;i++) {
        --key.sp; --key.rsp; assert(ios_fault_replay_note(&replay,&key,i)<2);
    }
    assert(ios_fault_replay_note(&replay,&key,255)==2);
    /* A new guest instruction/owner starts its own run, and an unwritable
       native stack is never replaced with a fabricated guest stack. */
    memset(&replay,0,sizeof(replay));
    for(unsigned i=0;i<1000;i++) { key.rip++; assert(ios_fault_replay_note(&replay,&key,i)<2); }
    mc.__ss=original; writable_stack=0;
    assert(!ios_redirect_process_failure(&mc.__ss,STATUS_ACCESS_VIOLATION));
    assert(!memcmp(&mc.__ss,&original,sizeof(original)));
    puts("PASS: actual trap matching, first state, 256-fault bound, 300 interleaved owners, progress, stack and log bounds");
    return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    c = Path(temp)/'fault.c'; exe=Path(temp)/'fault'
    c.write_text(harness+helpers+main)
    subprocess.run([os.environ.get('CC','cc'), '-D_GNU_SOURCE', '-std=gnu11', '-g', '-O1', '-Wall',
                    '-Werror=implicit-function-declaration', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=undefined', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=30, env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))
code=re.sub(r'/\*.*?\*/|//[^\n]*', '', src, flags=re.S)
assert '0xDEAD0001' not in code and 'SEGV LOOP FATAL' not in code
assert 'task_terminate( mach_task_self() )' not in src
inner=src[src.index('static int ios_mach_deliver_guest_exception_inner(',src.index('#include "fault_replay.h"')):]
inner=inner[:inner.index('\n}\n')]
assert 'BEST-EFFORT delivery on guest stack' not in inner
assert 'ios_thread_registry[i].mach_thread == thread && ios_thread_registry[i].teb == thread_teb' in inner
assert 'ios_redirect_process_failure(&state, STATUS_ACCESS_VIOLATION)' in src
assert '0x1788' not in helpers and 'ChpeV2CpuAreaInfo' not in helpers, 'i386 must use its own FEX TLS state'
assert 'dprintf(' not in helpers and 'malloc(' not in helpers
print('PASS: no skipped fault/fabricated return, task kill, guessed guest frame or signal-unsafe logging in new guard')
