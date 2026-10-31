#!/usr/bin/env python3
"""Exercise the production LL/SC alias path required by mixed RX/data pages."""
from pathlib import Path
import subprocess,os,tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'build/ntdll-unix/signal_arm64_ios.c').read_text();a=s.index('                    else if ((insn & 0x3fe07c00) == 0x08007c00)');b=s.index('                    /* iOS-Madeira ml626: SWP',a);case=s[a:b]
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static uint32_t instructions[4];
static int ios_fault_read_insn(uint64_t p,uint32_t *out) {if(p<(uintptr_t)instructions || p+4>(uintptr_t)(instructions+4))return 0;memcpy(out,(void*)(uintptr_t)p,4);return 1;}
static int capture(int fd,const char *fmt,...) {(void)fd;(void)fmt;return 0;}
#define dprintf capture
#define IOS_STORE_SRC(r) ((r)==31 ? 0ull : state.__x[r])
struct state {uint64_t __x[32],__sp;};
static int route(uint32_t insn,void *rw_addr,struct state *st) {struct state state=*st;uint64_t fault_pc=(uintptr_t)(instructions+2),fault_addr=state.__x[8];int emulated=0;if(0){}
''' + case + r'''
 *st=state;return emulated;}
int main(void) {
 for(unsigned size=2;size<=3;size++) {
  uint64_t value=40;struct state st={0};st.__x[8]=(uintptr_t)&value;st.__x[9]=40;st.__x[10]=41;
  instructions[0]=0x085ffc00u | (size<<30) | (8<<5) | 9;
  instructions[1]=0x1100052au | ((size==3)?0x80000000u:0);
  uint32_t store=0x0800fc00u | (size<<30) | (11<<16) | (8<<5) | 10;
  assert(route(store,&value,&st) && value==41 && st.__x[11]==0);
  value=42;st.__x[9]=40;st.__x[10]=41;
  assert(route(store,&value,&st) && value==42 && st.__x[11]==1);
  // In-place SUBS recovers the expected loaded value for CAS.
  value=40;st.__x[9]=39;st.__x[10]=0;
  instructions[1]=0x71000529u | ((size==3)?0x80000000u:0);
  store=0x0800fc00u | (size<<30) | (10<<16) | (8<<5) | 9;
  assert(route(store,&value,&st) && value==39 && st.__x[10]==0);
  // A clobbered expected register must decline, not write lost data.
  instructions[1]=0x52800009u;value=40;st.__x[9]=0;
  assert(!route(store,&value,&st) && value==40);
 }
 puts("PASS existing production STXR/STLXR alias branch: 32/64-bit, success/retry, in-place subtraction, unknown clobber rejection");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-exclusive-') as tmp:
    src=Path(tmp)/'check.c';binary=Path(tmp)/'check';src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(src),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
