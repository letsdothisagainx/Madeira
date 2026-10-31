#!/usr/bin/env python3
"""Compile the production page policy and breakpoint classifier with sanitizers."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parents[2]
virtual=(root/'build/ntdll-unix/virtual_ios.c').read_text()
a=virtual.index('static void ios_pool_protect_image_data(');b=virtual.index('\n}\n',a)+3
protect=virtual[a:b]
code=r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "pool_section_policy.h"
#include "stik_breakpoint.h"
#include "steam_helper_identity.h"
#include <errno.h>
typedef uintptr_t mach_vm_address_t;typedef size_t mach_vm_size_t;typedef unsigned natural_t,mach_msg_type_number_t;typedef int kern_return_t;
typedef struct { unsigned protection,max_protection; } vm_region_submap_short_info_data_64_t;
typedef void *vm_region_recurse_info_t;
#define VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 1
#define PROT_READ 1
#define PROT_WRITE 2
static uintptr_t transitions[32];static unsigned calls;
static int mprotect(void *p,size_t n,int prot) {assert(n==0x4000 && prot==3 && calls<32);transitions[calls++]=(uintptr_t)p;return 0;}
static unsigned mach_task_self(void) {return 1;}
static void *ios_jit_current_peb(void) {return (void*)0x1234;}
static int mach_vm_region_recurse(unsigned task,uintptr_t *a,size_t *n,unsigned *d,void *i,unsigned *c) {(void)a;(void)n;(void)d;(void)c;assert(task==1);vm_region_submap_short_info_data_64_t *q=i;q->protection=5;q->max_protection=7;return 0;}
static int capture(int fd,const char *fmt,...) {(void)fd;(void)fmt;errno=EINTR;return 0;}
#define dprintf capture
''' + protect + r'''
static unsigned char pe[0x20000];
static void u32(size_t p,uint32_t v) {memcpy(pe+p,&v,4);}
static void section(unsigned n,unsigned rva,unsigned size,unsigned flags) {
 size_t p=0x100+24+40*n;u32(p+8,size);u32(p+12,rva);u32(p+36,flags);
}
static void init(unsigned count) {memset(pe,0,sizeof(pe));pe[0x106]=count;}
static unsigned policy(uintptr_t rx,uintptr_t page) {return ios_pool_page_policy(pe,sizeof(pe),0x100,rx,page,0x4000);}
static const char *helper(const char *s) {unsigned short wide[160];size_t n=strlen(s);assert(n<160);for(size_t i=0;i<n;i++)wide[i]=(unsigned char)s[i];return ios_steam_helper_name(wide,n);}
int main(void) {
 uintptr_t rx=0x305270000ull;
 // .text and .data share a 16 KB page. It must retain execute permission.
 init(2);section(0,0x1000,0x4500,0x60000020);section(1,0x6000,0xb000,0xc0000040);
 assert(policy(rx,rx+0x4000)==(IOS_POOL_PAGE_CODE|IOS_POOL_PAGE_DATA));
 assert(policy(rx,rx+0x8000)==IOS_POOL_PAGE_DATA);
 assert(policy(rx,rx+0x10000)==IOS_POOL_PAGE_DATA);
 errno=EAGAIN;ios_pool_protect_image_data((void*)rx,pe,sizeof(pe),0x100,0x4000,"test");assert(errno==EAGAIN);
 assert(calls==3 && transitions[0]==rx+0x8000 && transitions[1]==rx+0xc000 && transitions[2]==rx+0x10000);
 // A later executable section, and a writable+executable section, are protected too.
 init(3);section(0,0x1000,0x1000,0x60000020);section(1,0x5000,0xa000,0xc0000040);section(2,0xe000,0x1000,0x60000020);
 assert(policy(rx,rx+0xc000)==3);section(1,0x5000,0xa000,0xe0000020);assert(policy(rx,rx+0x8000)==3);
 // Misaligned image copies cannot downgrade allocator padding or their neighbour.
 init(1);section(0,0,0x20000,0xc0000040);
 assert(!(policy(rx+0x1000,rx)&IOS_POOL_PAGE_DATA));
 assert(!(policy(rx+0x1000,rx+0x20000)&IOS_POOL_PAGE_DATA));
 // Invalid/truncated/overflowing metadata fails closed, with no out-of-bounds read.
 section(0,0x1f000,0x2000,0xc0000040);assert(policy(rx,rx)==IOS_POOL_PAGE_CODE);
 assert(ios_pool_page_policy(pe,10,0x100,rx,rx,0x4000)==IOS_POOL_PAGE_CODE);
 assert(ios_pool_page_policy(pe,sizeof(pe),SIZE_MAX,rx,rx,0x4000)==IOS_POOL_PAGE_CODE);
 assert(ios_pool_page_policy(pe,sizeof(pe),0x100,UINTPTR_MAX-0x1000,rx,0x4000)==IOS_POOL_PAGE_CODE);
 // Cross every PE subpage alignment, independent of the first writable section.
 for(unsigned shift=0;shift<0x4000;shift+=0x1000) for(unsigned end=0x1000;end<0x10000;end+=0x1000) {
  init(2);section(0,0,end,0x60000020);section(1,end,0x20000-end,0xc0000040);
  for(uintptr_t p=rx;p<rx+0x24000;p+=0x4000) {
   unsigned f=policy(rx+shift,p);
   if(p<rx+shift+end && p+0x4000>rx+shift) assert(f&IOS_POOL_PAGE_CODE);
  }
 }
 assert(ios_expected_stik_breakpoint(0xd43e01a0,0,"jit26_detach"));
 assert(ios_expected_stik_breakpoint(0xd43e01a0,1,"jit26_prepare_region"));
 assert(!ios_expected_stik_breakpoint(0xd43e01a0,1,"jit26_detach"));
 assert(!ios_expected_stik_breakpoint(0xd43e01a0,0,"foreign_function"));
 assert(!ios_expected_stik_breakpoint(0xd4395fc0,0,"jit26_detach"));
 assert(!ios_expected_stik_breakpoint(0xd4200020,0,"jit26_detach"));
 assert(!ios_expected_stik_breakpoint(0xd43e01a0,0,NULL));
 assert(helper("C:\\Steam\\BIN\\GLDriverQuery64.EXE"));
 assert(helper("C:/Steam/bin/vulkandriverquery.exe"));
 assert(!helper("C:/Steam/bin/vulkandriverquery.exe.bak"));
 assert(!helper("C:/Steam/steam.exe"));
 puts("PASS production policy preserves mixed/late executable sections, rejects malformed layouts; exact JIT protocol and helper identities");
}
'''
virtual=(root/'build/ntdll-unix/virtual_ios.c').read_text()
signal=(root/'build/ntdll-unix/signal_arm64_ios.c').read_text()
assert virtual.count('ios_pool_protect_image_data( ')==3
assert 'if (!pe || !jb || !live_size || !t_sz' in virtual
assert 'ios_jit_mappings[mi].pe_base != pe' in virtual
assert signal.index('goto send_exception_reply;')<signal.index('[mach_exc] UNHANDLED')
assert signal.index('send_exception_reply:;')<signal.index('reply.ret_code = handled ? KERN_SUCCESS : KERN_FAILURE;')
assert 'req->exception == EXC_BREAKPOINT' in signal[signal.index('thread_t thread = req->thread.name;'):signal.index('goto send_exception_reply;')]
with tempfile.TemporaryDirectory() as tmp:
 src=Path(tmp)/'main.c';binary=Path(tmp)/'check';src.write_text(code)
 subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(root/'build/ntdll-unix'),str(src),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
