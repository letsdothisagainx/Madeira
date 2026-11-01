#!/usr/bin/env python3
"""Execute the production sync backend against real RW/read-only shared views."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'build/ntdll-unix/virtual_ios.c').read_text()
def function(signature):
    a=s.index(signature)
    return s[a:s.index('\n}',a)+2]
backend=function('void ios_jit_sync_write(void *addr, size_t size)')
call=function('NTSTATUS unixcall_ios_sync_pe_write(void *args)')
code=r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint32_t ULONG,NTSTATUS;
typedef uintptr_t ULONG_PTR;
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER 1
#define STATUS_UNSUCCESSFUL 2
struct ios_sync_pe_write_params { void *address; ULONG size,synced; };
static struct { void *pe_base,*owner_peb,*jit_base; size_t size; } ios_jit_mappings[2];
static int ios_jit_mapping_count=2, absent, wrong_copy;
static void *owner=(void*)2,*ios_jit_rx_base_global,*ios_jit_rw_base_global;
static void *ios_jit_current_peb(void) { return owner; }
static void *ios_jit_translate_addr(void *p) {
 if(absent) return p;
 int n=(owner && !wrong_copy)?1:0;
 return (char*)ios_jit_mappings[n].jit_base+((char*)p-(char*)ios_jit_mappings[n].pe_base);
}
BACKEND
CALL
int main(void) {
 long page=sysconf(_SC_PAGESIZE); assert(page>0);
 FILE *f=tmpfile();assert(f);int fd=fileno(f);assert(!ftruncate(fd,2*page));
 unsigned char *rw=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 unsigned char *rx=mmap(NULL,2*page,PROT_READ,MAP_SHARED,fd,0);
 assert(rw!=MAP_FAILED && rx!=MAP_FAILED);memset(rw,0xa5,2*page);
 unsigned char image[4096]={0};
 ios_jit_rx_base_global=rx;ios_jit_rw_base_global=rw;
 for(int i=0;i<2;i++) {
  ios_jit_mappings[i].pe_base=image;ios_jit_mappings[i].size=sizeof(image);
  ios_jit_mappings[i].owner_peb=i?(void*)2:NULL;
  ios_jit_mappings[i].jit_base=rx+i*page;
 }
 uint64_t target=0x123456789abcdef0ULL;memcpy(image+128,&target,8);
 struct ios_sync_pe_write_params p={image+128,8,99};
 assert(!unixcall_ios_sync_pe_write(&p) && p.synced==1);
 assert(!memcmp(rx+page+128,&target,8));
 for(int i=0;i<8;i++)assert(rx[128+i]==0xa5);
 assert(rx[page+127]==0xa5 && rx[page+136]==0xa5);
 owner=NULL;target=0xfedcba9876543210ULL;memcpy(image+128,&target,8);
 assert(!unixcall_ios_sync_pe_write(&p) && p.synced==1);
 assert(!memcmp(rx+128,&target,8));
 assert(memcmp(rx+page+128,&target,8));
 owner=(void*)2;wrong_copy=1;target++;memcpy(image+128,&target,8);
 assert(unixcall_ios_sync_pe_write(&p)==STATUS_UNSUCCESSFUL && !p.synced);
 wrong_copy=0;absent=1;
 assert(!unixcall_ios_sync_pe_write(&p) && !p.synced);
 assert(unixcall_ios_sync_pe_write(NULL)==STATUS_INVALID_PARAMETER);
 p.size=16;assert(unixcall_ios_sync_pe_write(&p)==STATUS_INVALID_PARAMETER);
 p.size=3;assert(unixcall_ios_sync_pe_write(&p)==STATUS_INVALID_PARAMETER);
 p.size=8;p.address=NULL;assert(unixcall_ios_sync_pe_write(&p)==STATUS_INVALID_PARAMETER);
 assert(!munmap(rw,2*page));assert(!munmap(rx,2*page));fclose(f);
 puts("PASS SCM pointer sync: real read-only view, writable alias, all 8 bytes, owner isolation, canaries and failure reporting");
}
'''.replace('BACKEND',backend).replace('CALL',call)
with tempfile.TemporaryDirectory() as d:
    c,exe=Path(d)/'sync.c',Path(d)/'sync';c.write_text(code)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
patch=(root/'build/scm-rpc/loader.patch').read_text()
assert 'WINE_UNIX_CALL( unix_ios_sync_pe_write, &params )' in patch
assert 'params.size = sizeof(*aux)' in patch
assert '*(volatile ULONG_PTR *)pool' not in patch
