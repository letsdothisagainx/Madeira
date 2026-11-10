#!/usr/bin/env python3
"""Execute the actual original/staged CompileBlock history and private binder.

Protected canonical writes must fault until the production loader binds the
explicit writer. Exact source statements, slot collisions and the full payload
are compared; this fixture does not execute the FEX compiler or predict FPS.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fex_diagnostic_producers', ROOT / 'tests/host/check-fex-native-diagnostics-performance.py')
producers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producers)

HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "production-fex-diagnostics-fixture.h"
extern void madeira_diag_image(void *,void *);
extern uintptr_t madeira_diag_history_frame(unsigned),madeira_diag_history_address(void);
extern void madeira_diag_history_old(unsigned,uint64_t,uint64_t),madeira_diag_history_bound(unsigned,uint64_t,uint64_t);
enum { HISTORY_BYTES=192 };
static const uintptr_t alias_distance=0x48000000;
struct aliases {unsigned char *reservation,*rx,*rw;size_t bytes;};
static struct aliases mapping(void) {
  struct aliases m={0};m.bytes=alias_distance+FEX_DIAG_IMAGE_SIZE;
  m.reservation=mmap(NULL,m.bytes,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(m.reservation!=MAP_FAILED);
  char path[]="/tmp/madeira-fex-history-XXXXXX";int fd=mkstemp(path);
  assert(fd>=0&&!unlink(path)&&!ftruncate(fd,FEX_DIAG_IMAGE_SIZE));
  m.rx=mmap(m.reservation,FEX_DIAG_IMAGE_SIZE,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
  m.rw=mmap(m.reservation+alias_distance,FEX_DIAG_IMAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
  assert(m.rx==m.reservation&&m.rw==m.reservation+alias_distance&&!close(fd));return m;
}
static void protected_canonical_fails(struct aliases *m,unsigned staged) {
  unsigned char before[HISTORY_BYTES];memcpy(before,m->rx+FEX_DIAG_HISTORY,HISTORY_BYTES);
  assert(madeira_diag_history_address()==(uintptr_t)m->rx+FEX_DIAG_HISTORY);
  pid_t child=fork();assert(child>=0);
  if(!child){
    struct rlimit limit={0,0};assert(!setrlimit(RLIMIT_CORE,&limit));
    if(staged)madeira_diag_history_bound(0,0x2000,0x140000000);
    else madeira_diag_history_old(0,0x2000,0x140000000);
    _exit(0);
  }
  int status;assert(waitpid(child,&status,0)==child);
  assert(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS));
  assert(!memcmp(before,m->rx+FEX_DIAG_HISTORY,HISTORY_BYTES));
}
static void record(unsigned bound,unsigned index,uint64_t crsp,uint64_t rip) {
  if(bound)madeira_diag_history_bound(index,crsp,rip);else madeira_diag_history_old(index,crsp,rip);
}
static void sequence(unsigned bound,unsigned char *image) {
  const uint64_t *h=(const void *)(image+FEX_DIAG_HISTORY);
  for(unsigned step=0;step<7;step++)for(unsigned index=0;index<4;index++){
    unsigned slot=(madeira_diag_history_frame(index)>>6)&3;
    assert(((madeira_diag_history_frame(index+4)>>6)&3)==slot);
    uint64_t crsp=step?0x2000+index*0x100+(step%3)*0x10:0;
    record(bound,index,crsp,UINT64_C(0x140000000)+index*0x1000+step*4);
    if(!step)assert(h[4+slot]==UINT64_MAX&&h[8+slot]==0&&h[12+slot]==0);
    unsigned char before[HISTORY_BYTES];memcpy(before,h,HISTORY_BYTES);
    record(bound,index+4,0xdeadbeef,UINT64_C(0xbadbadbad));
    assert(!memcmp(before,h,HISTORY_BYTES));
  }
  for(unsigned index=0;index<4;index++){
    unsigned slot=(madeira_diag_history_frame(index)>>6)&3;
    assert(h[slot]==madeira_diag_history_frame(index));
    assert(h[4+slot]==0x2000+index*0x100&&h[8+slot]==0x2020+index*0x100);
    assert(h[12+slot]==0x2000+index*0x100&&h[16+slot]==7);
    assert(h[20+slot]==UINT64_C(0x140000000)+index*0x1000+24);
  }
}
static void protection(const void *pointer,const char *required,const char *forbidden) {
#ifdef __linux__
  FILE *maps=fopen("/proc/self/maps","r");assert(maps);char line[1024],perms[5];unsigned long lo,hi;int found=0;
  while(fgets(line,sizeof(line),maps))if(sscanf(line,"%lx-%lx %4s",&lo,&hi,perms)==3&&lo<=(uintptr_t)pointer&&(uintptr_t)pointer<hi){
    for(const char *p=required;*p;p++)assert(strchr(perms,*p));
    for(const char *p=forbidden;*p;p++)assert(!strchr(perms,*p));
    found=1;break;
  }
  assert(found&&!fclose(maps));
#else
  (void)pointer;(void)required;(void)forbidden; /* Mach fixture queries actual VM protections. */
#endif
}
int main(void) {
  (void)ios_native_atomic_image_lower;(void)ios_native_counter_alias_bind;
  unsigned char *reference=calloc(1,FEX_DIAG_IMAGE_SIZE);assert(reference);
  diagnostic_pe_fixture(reference);madeira_diag_image(reference,reference);sequence(0,reference);
  unsigned char expected[HISTORY_BYTES];memcpy(expected,reference+FEX_DIAG_HISTORY,HISTORY_BYTES);free(reference);
  struct aliases m=mapping();diagnostic_pe_fixture(m.rw);madeira_diag_image(m.rx,m.rw);
  protected_canonical_fails(&m,0);protected_canonical_fails(&m,1);
  assert(ios_native_fex_diagnostics_bind(m.rw,FEX_DIAG_IMAGE_SIZE,UINT64_C(0x500000000),(uintptr_t)m.rx,(intptr_t)alias_distance,1));
  assert(madeira_diag_history_address()==(uintptr_t)m.rw+FEX_DIAG_HISTORY);
  unsigned char before[FEX_DIAG_IMAGE_SIZE];memcpy(before,m.rx,sizeof(before));
  sequence(1,m.rx);assert(!memcmp(expected,m.rx+FEX_DIAG_HISTORY,HISTORY_BYTES));
  for(size_t at=0;at<FEX_DIAG_IMAGE_SIZE;at++)if(at<FEX_DIAG_HISTORY||at>=FEX_DIAG_HISTORY+HISTORY_BYTES)assert(m.rx[at]==before[at]);
  protection(m.rx,"rx","w");protection(m.rw,"rw","x");assert(!munmap(m.reservation,m.bytes));
  puts("PASS actual staged CompileBlock history: old/unbound protected stores fault; production-bound alias preserves all192bytes, slot collisions, zero-SP, min/max, count, RIP, neighbors and RX/RW protections");
}
'''

EMULATION_HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
typedef struct {uint64_t __x[29],__fp,__lr,__sp;} arm_thread_state64_t;
enum { FEX_DIAG_HISTORY=0x6600,HISTORY_BYTES=192 };
static struct {unsigned char *rx;} active={(unsigned char *)UINT64_C(0x100000)};
static _Alignas(8) unsigned char storage[HISTORY_BYTES+16];
static int inside(uintptr_t p,size_t bytes,uintptr_t base,size_t span) {
  return p>=base&&p-base<=span&&bytes<=span-(p-base);
}
static uintptr_t history_rx(void) {return (uintptr_t)active.rx+FEX_DIAG_HISTORY;}
static uintptr_t ios_write_alias(uintptr_t address) {
  return inside(address,1,history_rx(),HISTORY_BYTES)?(uintptr_t)(storage+8)+address-history_rx():0;
}
static int ios_alias_write_is_trapped(uintptr_t address) {return !ios_write_alias(address);}
/* These history data aliases contain no private CodeBuffer guard ranges. */
int ios_jit_code_guard_contains(uintptr_t address,size_t length) {(void)address;(void)length;return 0;}
static int ios_fault_read_insn(uint64_t pc,uint32_t *out) {(void)pc;(void)out;return 0;}
static int quiet_dprintf(int fd,const char *text,...) {(void)fd;(void)text;return 0;}
#define dprintf quiet_dprintf
#include "production-atomic-emulation.h"
/* The old fixture's actual scalar branch is retained as the negative control. */
@SCALAR_CONTROL@
/* Extracted verbatim from the Mach fixture being exercised in Apple CI. */
@TARGET_HELPERS@
#undef dprintf
static uint32_t indexed(unsigned rn,unsigned rm,unsigned option,unsigned scale,unsigned rt) {
  return UINT32_C(0xf8200800)|(rm<<16)|(option<<13)|(scale<<12)|(rn<<5)|rt;
}
static void preserves_store(uint32_t op,arm_thread_state64_t *state,uintptr_t target) {
  arm_thread_state64_t before=*state;
  unsigned char neighbors[sizeof(storage)];memset(storage,0xa5,sizeof(storage));memcpy(neighbors,storage,sizeof(storage));
  assert(diag_history_store_target(target,op,state));
  assert(baseline_emulate(op,UINT64_C(0x700000),target,ios_write_alias(target),state));
  assert(!memcmp(&before,state,sizeof(before)));
  uint64_t expected=(op&31)==31?0:diag_history_register(state,op&31),actual=0;
  memcpy(&actual,storage+8+target-history_rx(),8);assert(actual==expected);
  for(size_t at=0;at<sizeof(storage);at++)
    if(at<8+target-history_rx()||at>=16+target-history_rx())assert(storage[at]==neighbors[at]);
}
static void rejects(uint32_t op,arm_thread_state64_t *state,uintptr_t target) {
  arm_thread_state64_t before=*state;unsigned char neighbors[sizeof(storage)];
  memset(storage,0xa5,sizeof(storage));memcpy(neighbors,storage,sizeof(storage));
  assert(!diag_history_store_target(target,op,state));
  assert(!memcmp(&before,state,sizeof(before))&&!memcmp(storage,neighbors,sizeof(storage)));
}
int main(void) {
  arm_thread_state64_t state={0};
  for(unsigned r=0;r<29;r++)state.__x[r]=UINT64_C(0xabc0000000000000)+r;
  state.__fp=UINT64_C(0xaaaabbbbccccdddd);state.__lr=UINT64_C(0x123456789abcdef0);state.__sp=history_rx();
  state.__x[11]=history_rx()+16;state.__x[12]=24;state.__x[10]=UINT64_C(0x0123456789abcdef);
  const uint32_t captured=UINT32_C(0xf82c696a);uintptr_t target=history_rx()+40;
  assert(captured==indexed(11,12,3,0,10));
  unsigned char before_storage[sizeof(storage)];memset(storage,0xa5,sizeof(storage));memcpy(before_storage,storage,sizeof(storage));
  arm_thread_state64_t before=state;
  assert(!scalar_only_emulate(captured,UINT64_C(0x700000),target,ios_write_alias(target),&state));
  assert(!memcmp(&before,&state,sizeof(state))&&!memcmp(before_storage,storage,sizeof(storage)));
  preserves_store(captured,&state,target);
  /* UXTW ignores high32 bits; SXTW sign-extends low32. UXTX/SXTX retain64. */
  for(unsigned option=2;option<8;option++)if(option&2)for(unsigned scale=0;scale<2;scale++){
    state.__x[11]=history_rx()+64;
    state.__x[12]=option==2?UINT64_C(0x1234567800000008):option==6?UINT64_C(0xabcdef01fffffff8):option==7?UINT64_MAX-7:8;
    uint64_t offset=(option>=6?UINT64_MAX-7:8);if(scale)offset<<=3;
    preserves_store(indexed(11,12,option,scale,10),&state,state.__x[11]+offset);
  }
  state.__sp=history_rx()+32;state.__x[12]=8;
  preserves_store(indexed(31,12,3,0,10),&state,history_rx()+40);
  state.__x[11]=history_rx()+56;
  preserves_store(indexed(11,31,3,1,10),&state,history_rx()+56); /* Rm31=ZR, never SP. */
  state.__fp=history_rx()+32;state.__lr=8;
  preserves_store(indexed(29,30,3,0,10),&state,history_rx()+40);
  state.__lr=history_rx()+48;state.__fp=8;
  preserves_store(indexed(30,29,3,0,10),&state,history_rx()+56);
  state.__x[11]=history_rx()+56;
  preserves_store(indexed(11,31,3,0,31),&state,history_rx()+56); /* Rt31 stores zero. */
  state.__x[11]=UINT64_MAX-7;state.__x[12]=history_rx()+16;
  preserves_store(indexed(11,12,3,0,10),&state,history_rx()+8); /* A64 modulo64 addition. */
  state.__x[11]=history_rx()+64;state.__x[12]=8;
  for(unsigned option=0;option<8;option++)if(!(option&2))rejects(indexed(11,12,option,0,10),&state,history_rx()+72);
  rejects(captured,&state,history_rx()+80); /* Wrong supplied fault target. */
  rejects(captured,&state,history_rx()+73); /* Unaligned target. */
  state.__x[11]=history_rx()-16;rejects(captured,&state,history_rx()-8);
  state.__x[11]=history_rx()+HISTORY_BYTES-8;rejects(captured,&state,history_rx()+HISTORY_BYTES);
  state.__x[11]=history_rx()+HISTORY_BYTES-12;rejects(captured,&state,history_rx()+HISTORY_BYTES-4);
  state.__x[11]=history_rx()+8;state.__x[12]=UINT64_MAX-15;
  rejects(indexed(11,12,7,0,10),&state,history_rx()-8);
  state.__x[11]=history_rx()+64;state.__x[12]=8;
  rejects(captured^UINT32_C(0x40000000),&state,history_rx()+72); /*32-bit store. */
  rejects(captured|UINT32_C(0x00400000),&state,history_rx()+72); /* Load encoding. */
  uint32_t immediate=UINT32_C(0xf9000000)|(3<<10)|(11<<5)|10;
  preserves_store(immediate,&state,history_rx()+88);
  assert(scalar_only_emulate(immediate,UINT64_C(0x700000),history_rx()+88,ios_write_alias(history_rx()+88),&state));
  rejects(immediate,&state,history_rx()+96);
  puts("PASS captured f82c696a production recovery: scalar-only control rejects; exact64bit value/registers/neighbors preserved; actual Mach target validator covers extensions/scaling/signed indices/SP/ZR/wrap and rejects reserved/foreign targets");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-fex-native-history-') as folder:
    work = Path(folder)
    producers.prepare(work)
    harness = work / 'history.c'
    harness.write_text(HARNESS)
    flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-I', str(work), '-I', str(ROOT / 'build/ntdll-unix'), '-I', str(ROOT / 'build/fex-compat')]
    cc, cxx = os.environ.get('CC', 'cc'), os.environ.get('CXX', 'c++')
    cobj, cppobj = work / 'harness.o', work / 'producer.o'
    subprocess.run([cc, '-std=c11', *flags, '-c', str(harness), '-o', str(cobj)], check=True)
    subprocess.run([cxx, '-std=c++17', *flags, '-c', str(ROOT / 'tests/host/native-fex-native-diagnostics-performance.cpp'), '-o', str(cppobj)], check=True)
    binary = work / 'history'
    subprocess.run([cxx, str(cobj), str(cppobj), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
    producers.emulation_header(work)
    signal_source = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
    start = signal_source.index('                    else if ((insn & 0xffe00c00) == 0xf8200800)')
    end = signal_source.index('                    /* STLR (Store-Release Register, 64-bit):', start)
    indexed = signal_source[start:end]
    emulation = (work / 'production-atomic-emulation.h').read_text()
    scalar_control = producers.function(emulation, 'static int baseline_emulate(')
    assert indexed in scalar_control
    scalar_control = scalar_control.replace(indexed, '').replace('baseline_emulate(', 'scalar_only_emulate(', 1)
    fixture_source = (ROOT / 'tests/host/native-fex-native-diagnostics-performance.c').read_text()
    helpers = '\n'.join(producers.function(fixture_source, signature) for signature in
                        ('static uint64_t diag_history_register(', 'static int diag_history_store_target('))
    emulation_harness = work / 'emulation.c'
    emulation_harness.write_text(EMULATION_HARNESS.replace('@SCALAR_CONTROL@', scalar_control).replace('@TARGET_HELPERS@', helpers))
    emulation_binary = work / 'emulation'
    subprocess.run([cc, '-std=c11', *flags, '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(emulation_harness), '-o', str(emulation_binary)], check=True)
    subprocess.run([str(emulation_binary)], check=True, timeout=30)
