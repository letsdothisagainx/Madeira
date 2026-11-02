#!/usr/bin/env python3
"""Reproduce the partial-alias RX spill with real mappings and concurrent writers."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'build/ntdll-unix/virtual_ios.c').read_text()
def function(marker):
 a=s.index(marker); b=s.index('{',a); depth=1; end=b+1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]
cover=function('int ios_jit_anon_alias_find_cover(')
host_prot=function('static BYTE get_host_page_vprot(')
alias_run=function('static int ios_protect_alias_run(')
mixed_tail=function('static struct file_view *ios_alias_mixed_image_tail(')
assert 'PHYSICAL forced R%s' not in function('static NTSTATUS set_protection(')
raw=function('static int mprotect_range_raw(')
assert raw.count('ios_protect_host_range(')==2
assert 'mprotect_exec(' not in raw
code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "alias_protection.h"
#define PAGE 0x4000u
#ifdef __APPLE__
// An unsigned macOS host fixture cannot reproduce Madeira's signed JIT
// entitlement. Exercise real removal of WRITE with R here; Linux exercises
// the exact RX syscall. The production helper must request RX on both.
#define HOST_EXEC 0
#else
#define HOST_EXEC PROT_EXEC
#endif
static struct {uintptr_t user_va,user_va_end,jit_rw_alias,jit_rx_alias;} ios_jit_anon_aliases[2];
static int ios_jit_anon_alias_count;
''' +cover+r'''
#define _WIN64 1
typedef unsigned char BYTE;
static size_t host_page_mask=PAGE-1,host_page_size=PAGE,page_shift=12,page_size=4096,pages_vprot_shift=8,pages_vprot_mask=255,pages_vprot_size=1;
static BYTE logical[256],*pages_vprot[1]={logical};
#define ROUND_ADDR(a,m) ((void*)((uintptr_t)(a)&~(uintptr_t)(m)))
''' +host_prot+r'''
#undef _WIN64
static int diagnostic(int fd,const char *format,...){assert(fd==2);(void)format;errno=ERANGE;return 0;}
static int mprotect_exec(void *base,size_t size,int prot){return mprotect(base,size,prot);}
#define SEC_IMAGE 0x1000000u
struct file_view {void *base;size_t size;unsigned protect;};
static struct file_view *find_view(const void *base,size_t size){(void)base;(void)size;return NULL;}
#define dprintf diagnostic
''' +mixed_tail+'\n'+alias_run+r'''
#undef dprintf

static pthread_mutex_t vm=PTHREAD_MUTEX_INITIALIZER;
static unsigned applies,alias_calls;static int reject;static uintptr_t window;
static int owned(uintptr_t page,size_t size,void *context){
 (void)context;void *rw=NULL,*rx=NULL;return ios_jit_anon_alias_find_cover((void*)page,size,&rw,&rx);
}
static int apply(uintptr_t page,size_t size,int prot,int alias,void *context){
 (void)context;assert(!(page&(PAGE-1))&&!(size&(PAGE-1))&&size);applies++;
 if(alias){assert(prot==(PROT_READ|PROT_EXEC));alias_calls++;}
 assert((prot&(PROT_WRITE|PROT_EXEC))!=(PROT_WRITE|PROT_EXEC));
 if(reject){errno=EACCES;return -1;}
 return mprotect((void*)page,size,(prot&~PROT_EXEC)|((prot&PROT_EXEC)?HOST_EXEC:0));
}
static void protect(int prot,size_t size){
 pthread_mutex_lock(&vm);
 assert(!madeira_protect_alias_writes(window,size,PAGE,prot,owned,apply,NULL));
 pthread_mutex_unlock(&vm);
}
static _Atomic(int) stop;
static void* write_neighbors(void *unused){
 (void)unused;unsigned value=0;
 while(!atomic_load(&stop)){
  atomic_store((_Atomic(unsigned)*)(window+4),++value);
  atomic_store((_Atomic(unsigned)*)(window+PAGE+4),value);
 }
 return NULL;
}
int main(void){
 errno=0;assert(ios_protect_alias_run(1,PAGE,PROT_READ,1,NULL)==-1&&errno==EINVAL);
 memset(logical,0x23,sizeof(logical));logical[0x11]=0x21;
 BYTE before_metadata[256];memcpy(before_metadata,logical,sizeof(logical));
 assert((get_host_page_vprot((void*)0x10000)&3)==3);
 assert((get_host_page_vprot((void*)0x14000)&3)==3);
 assert((get_host_page_vprot((void*)0x18000)&3)==3);
 void *space=mmap(NULL,6*PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(space!=MAP_FAILED);window=((uintptr_t)space+PAGE-1)&~(uintptr_t)(PAGE-1);
 int fd=memfd_create("madeira-alias-test",0);assert(fd>=0&&!ftruncate(fd,PAGE));
 void *rw=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);assert(rw!=MAP_FAILED);
 void *rx=mmap((void*)(window+2*PAGE),PAGE,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);assert(rx==(void*)(window+2*PAGE));
 ios_jit_anon_alias_count=1;
 ios_jit_anon_aliases[0]=(typeof(ios_jit_anon_aliases[0])){window+2*PAGE,window+3*PAGE,(uintptr_t)rw,(uintptr_t)rx};
 // Captured request: 0x9000 bytes; only its last4KiB overlaps a16KiB alias.
 // Old whole-request mprotect rounds to3host pages and kills the first store.
 pid_t child=fork();assert(child>=0);
 if(!child){signal(SIGSEGV,SIG_DFL);signal(SIGBUS,SIG_DFL);if(mprotect((void*)window,0x9000,PROT_READ|HOST_EXEC)){perror("negative-control protection");_exit(2);}*(volatile unsigned*)window=0;_exit(0);}
 int status;assert(waitpid(child,&status,0)==child&&WIFSIGNALED(status));
 assert(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS);
 protect(PROT_READ|PROT_WRITE,0x9000);assert(applies==2&&alias_calls==1);
 *(volatile unsigned*)window=0;*(volatile unsigned*)(window+PAGE+4)=0;
 pthread_t writers[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&writers[i],NULL,write_neighbors,NULL));
 for(unsigned round=0;round<3000;round++){
  protect(PROT_READ|PROT_WRITE,0x9000);
  // Emulated guest code stores use the existing writable sibling, never RWX.
  atomic_store((_Atomic(unsigned)*)rw,round+1);
  assert(atomic_load((_Atomic(unsigned)*)rx)==round+1);
 }
 atomic_store(&stop,1);for(unsigned i=0;i<4;i++)pthread_join(writers[i],NULL);
 // Normal SMC-style read trap and disarm keep the logical4KiB table separate.
 protect(PROT_READ,0x9000);protect(PROT_READ|PROT_WRITE,0x9000);
 assert(*(unsigned*)rx==3000);
 protect(PROT_NONE,0x9000);protect(PROT_READ|PROT_WRITE,0x9000);
 assert(*(unsigned*)rx==3000);
 // Retired guest window: alias tombstone is removed under the same VM lock;
 // a new reservation at exactly that address must not inherit its RX policy.
 pthread_mutex_lock(&vm);ios_jit_anon_aliases[0].user_va_end=0;ios_jit_anon_aliases[0].user_va=0;
 assert(mmap((void*)(window+2*PAGE),PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==(void*)(window+2*PAGE));
 assert(!madeira_protect_alias_writes(window,0x9000,PAGE,PROT_READ|PROT_WRITE,owned,apply,NULL));
 pthread_mutex_unlock(&vm);*(volatile unsigned*)(window+2*PAGE)=0x12345678;assert(*(unsigned*)rw==3000);
 unsigned before=applies;reject=1;errno=0;
 assert(madeira_protect_alias_writes(window,0x9000,PAGE,PROT_READ|PROT_WRITE,owned,apply,NULL)==-1&&errno==EACCES&&applies==before+1);
 assert(madeira_protect_alias_writes(window+1,0x9000,PAGE,3,owned,apply,NULL)==-1&&errno==EINVAL);
 assert(madeira_protect_alias_writes(UINTPTR_MAX-PAGE+1,2*PAGE,PAGE,3,owned,apply,NULL)==-1);
 assert(!memcmp(before_metadata,logical,sizeof(logical)));
 munmap(rw,PAGE);munmap(space,6*PAGE);close(fd);
 puts("PASS write-protection spill reproduced; real alias coherence, four concurrent neighbor writers,3000 transitions,SMC/noaccess cycles,guest-window reuse and protection failure propagation; no writable/executable mapping");
#ifdef __APPLE__
 puts("NOTE Darwin fixture uses physical R for the write fault; requested alias policy is verified RX. Signed iOS RX reprotection requires the device acceptance run.");
#endif
}
'''
with tempfile.TemporaryDirectory() as t:
 p=Path(t)/'check.c';p.write_text(code);exe=Path(t)/'check'
 # Linux memfd models Darwin's existing RX/RW shared backing. Darwin uses shm_open.
 if os.uname().sysname=='Darwin':
  code=code.replace('int fd=memfd_create("madeira-alias-test",0);','char name[64];snprintf(name,sizeof(name),"/madeira-%d",getpid());int fd=shm_open(name,O_CREAT|O_EXCL|O_RDWR,0600);shm_unlink(name);')
  code=code.replace('#include <unistd.h>','#include <unistd.h>\n#include <fcntl.h>').replace('typeof(', '__typeof__(')
  p.write_text(code)
 subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-pthread','-Wall','-Wextra','-Werror','-I'+str(root/'build/ntdll-unix'),str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
