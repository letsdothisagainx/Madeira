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
