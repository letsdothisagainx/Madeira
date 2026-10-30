#!/usr/bin/env python3
"""Exercise real staged OpenGL attach code with Wine TEB layouts and VM holes."""
from pathlib import Path
import hashlib,importlib.util,os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('stage_gl',root/'tools/build/stage-opengl-wow64.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
def fn(s,signature):
 a=s.index(signature);b=s.index('{',a);n=1;i=b+1
 while n:
  n+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[a:i]
with tempfile.TemporaryDirectory() as d:
 t=Path(d)
 originals={n:(root/'wine/dlls/opengl32'/n).read_bytes() for n in stage.FILES}
 staged=stage.stage(root/'wine',t)
 assert all((root/'wine/dlls/opengl32'/n).read_bytes()==v for n,v in originals.items())
 header=(staged/'unix_private.h').read_text();wgl=(staged/'unix_wgl.c').read_text()
 original=originals['unix_private.h'].decode()
 helpers=(root/'wine/include/wine/unixlib.h').read_text()
 functions='\n'.join([
  fn(helpers,'static inline ULONG_PTR ios_wow_host_base('),
  fn(helpers,'static inline void *ios_wow_host_ptr('),
  fn(original,'static inline TEB *get_teb64(').replace('get_teb64(','broken_get_teb64('),
  fn(header,'static inline TEB *get_teb64_from('),
  fn(wgl,'NTSTATUS thread_attach('),
  fn(wgl,'NTSTATUS wow64_thread_attach('),
 ])
 code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#define NtCurrentTeb wine_unused_NtCurrentTeb
#include "windef.h"
#include "winternl.h"
#include "ntstatus.h"
#undef NtCurrentTeb
#define WINE_IOS 1
_Static_assert(offsetof(TEB32,WowTebOffset)==0xfdc,"real Wine TEB32");
_Static_assert(offsetof(TEB,glTable)==0x1238,"real Wine native TEB");
static ULONG_PTR current_base;
static TEB *current_teb;
static TEB *NtCurrentTeb(void) { return current_teb; }
ULONG_PTR ios_wow_base(void) __attribute__((weak));
ULONG_PTR ios_wow_base(void) { return current_base; }
static int null_opengl_funcs=123;
unsigned int madeira_gl_wow64_calls;
static void madeira_gl_count_call(const char *name) { (void)name; }
static void ios_wow_gl_attach_trace(void *a,void *b,NTSTATUS s) {(void)a;(void)b;(void)s;}
#define get_teb64(x) get_teb64_from((x),__func__)
FUNCTIONS
static void expect_fault(int broken,void *arg) {
 pid_t child=fork();assert(child>=0);
 if(!child) {
  struct rlimit core={0,0};assert(!setrlimit(RLIMIT_CORE,&core));
  if(broken) thread_attach(broken_get_teb64((ULONG_PTR)arg));
  else wow64_thread_attach(arg);
  _exit(99);
 }
 int status;assert(waitpid(child,&status,0)==child);
 assert(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS));
}
int main(void) {
 const ULONG_PTR window=(ULONG_PTR)1<<32;
 const ULONG guest32=0x7ffc2000;
 long page=sysconf(_SC_PAGESIZE);assert(page>0 && page<=0x4000);
 void *reserve=mmap(NULL,3*window,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(reserve!=MAP_FAILED);
 ULONG_PTR bases[2]={((ULONG_PTR)reserve+window-1)&~(window-1),0};bases[1]=bases[0]+window;
 for(unsigned i=0;i<2;i++) {
  assert(bases[i]+window<=(ULONG_PTR)reserve+3*window);
  current_base=bases[i];current_teb=(TEB*)(current_base+guest32-0x2000);
  assert(!mprotect(current_teb,0x4000,PROT_READ|PROT_WRITE));
  TEB32 *peer=(TEB32*)(current_base+guest32);peer->WowTebOffset=-0x2000;
  current_teb->WowTebOffset=0x2000;current_teb->glTable=NULL;
  expect_fault(1,peer); /* the old code loses B and faults at guest32+0xfdc */
  assert(wow64_thread_attach(peer)==STATUS_SUCCESS);
  assert(current_teb->glTable==&null_opengl_funcs);
  assert(peer->WowTebOffset==-0x2000);
  current_teb->glTable=NULL;
  peer->WowTebOffset=0;
  assert(wow64_thread_attach(peer)==STATUS_INVALID_PARAMETER && !current_teb->glTable);
  peer->WowTebOffset=-0x2000;
  expect_fault(0,(void*)(current_base+0x11110000)); /* within window, unmapped: real fault */
  assert(wow64_thread_attach(NULL)==STATUS_INVALID_PARAMETER);
 }
 current_base=bases[0];current_teb=(TEB*)(current_base+guest32-0x2000);current_teb->glTable=NULL;
 assert(wow64_thread_attach((void*)(bases[1]+guest32))==STATUS_INVALID_PARAMETER);
 assert(!current_teb->glTable);
 current_base=0;assert(wow64_thread_attach((void*)(bases[0]+guest32))==STATUS_INVALID_PARAMETER);
 assert(!munmap(reserve,3*window));
 puts("PASS real OpenGL attach: lost-base reproduction, paired TEB initialization, two owners, bad offsets, unmapped regions retain faults");
}
'''.replace('FUNCTIONS',functions)
 c=t/'attach.c';exe=t/'attach';c.write_text(code)
 subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-address','-I'+str(root/'wine/include'),'-D__WINESRC__',str(c),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
 # Generated pointer conversions must match the same staged header, while
 # buffer offsets and handles retain their intended non-pointer semantics.
 thunks=(staged/'unix_thunks.c').read_text()
 assert 'ios_wow_host_ptr(params->' in thunks and 'wow64_buffer_ptr(' in thunks
 assert 'ULongToPtr(params->hdc)' in thunks or 'ULongToPtr(params->hDc)' in thunks
 print('PASS stage applies generated pointer thunks without editing the pinned Wine source')
 with tempfile.TemporaryDirectory() as warm:
  again=stage.stage(t,Path(warm))
  assert (again/'unix_private.h').read_bytes()==(staged/'unix_private.h').read_bytes()
 print('PASS a fully applied developer overlay stages without double-patching')
