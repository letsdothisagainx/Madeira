#!/usr/bin/env python3
"""Execute the narrow mixed-tail control and the captured SWPAL continuation."""
import os, re, subprocess, tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[2]
vm=(root/'build/ntdll-unix/virtual_ios.c').read_text()
signal=(root/'build/ntdll-unix/signal_arm64_ios.c').read_text()
def body(source,marker):
    start=source.index(marker);brace=source.index('{',start);depth=0
    for t in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]',source[brace:],re.S):
        if t[0]=='{':depth+=1
        elif t[0]=='}':
            depth-=1
            if not depth:return source[start:brace+t.end()]
    raise AssertionError(marker)
def run(name,code,cxx=False):
    with tempfile.TemporaryDirectory() as folder:
        p=Path(folder)/('check.cpp' if cxx else 'check.c');p.write_text(code);exe=p.with_suffix('')
        command=[os.environ.get('CXX' if cxx else 'CC','c++' if cxx else 'cc'),
                 '-std=c++20' if cxx else '-std=gnu11','-O1','-g','-pthread',
                 '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                 '-I'+str(root/'build/ntdll-unix'),str(p),'-o',str(exe)]
        subprocess.run(command,check=True)
        subprocess.run([str(exe)],check=True,timeout=45)
    print('PASS '+name)

cover=body(vm,'int ios_jit_anon_alias_find_cover(')
mixed=body(vm,'static struct file_view *ios_alias_mixed_image_tail(')
apply=body(vm,'static int ios_protect_alias_run(')
route=body(vm,'static int ios_protect_host_range(')
page=body(vm,'static int ios_protect_page_is_alias(')
overlap=body(vm,'int ios_jit_anon_alias_overlaps(')
legacy_start=vm.index('/* iOS-Madeira ml640: AN OWNED ANON-JIT RANGE IS SETTLED')
legacy=body(vm[legacy_start:],'if (unix_prot != PROT_NONE)')
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include "alias_protection.h"
#define SEC_IMAGE 0x1000000u
static size_t host_page_size=0x4000;
struct file_view{void* base;size_t size;unsigned protect;};
static struct file_view image;
static struct {uintptr_t user_va,user_va_end,jit_rw_alias,jit_rx_alias;} ios_jit_anon_aliases[2];
static int ios_jit_anon_alias_count=1;
static unsigned kernel_calls,legacy_calls,queried_size,requested;
static int fail_kernel;
static struct file_view* find_view(const void* p,size_t n){
 uintptr_t a=(uintptr_t)p,b=(uintptr_t)image.base;queried_size=(unsigned)n;
 return image.size&&a>=b&&a-b<image.size&&n<=image.size-(a-b)?&image:NULL;
}
static int diagnostic(int fd,const char* fmt,...){(void)fd;(void)fmt;errno=ERANGE;return 0;}
#define dprintf diagnostic
static int kernel_protect(void* b,size_t n,int p){
 (void)b;(void)n;kernel_calls++;assert((p&6)!=6);
 if(fail_kernel){errno=EACCES;return -1;}return 0;
}
''' +cover+'\n'+overlap+r'''
static int mprotect_exec(void* base,size_t size,int unix_prot){
 legacy_calls++;requested=unix_prot;
 if(unix_prot&PROT_EXEC){
''' +legacy+r'''
 }
 return kernel_protect(base,size,unix_prot&~PROT_EXEC);
}
#define mprotect kernel_protect
''' +page+'\n'+mixed+'\n'+apply+'\n'+route+r'''
int main(void){
 uintptr_t b=0x47a490000ull,tail=b+0xc000;int want=7;
 image=(struct file_view){(void*)b,0xf000,SEC_IMAGE};
 ios_jit_anon_aliases[0]=(typeof(ios_jit_anon_aliases[0])){tail,tail+0x4000,0x3409d8000,0x3009d8000};
 struct file_view before=image;
 assert(ios_alias_mixed_image_tail(tail,0x4000)==&image&&queried_size==1);
 // The installed v2 raw RX call fails on the captured replacement mapping.
 fail_kernel=1;assert(kernel_protect((void*)tail,0x4000,5)==-1&&errno==EACCES);
 kernel_calls=legacy_calls=0;
 assert(!ios_protect_host_range((void*)tail,0x4000,want));
 assert(legacy_calls==1&&!kernel_calls&&requested==7&&!memcmp(&image,&before,sizeof(image)));
 // Errors in a real legacy operation still propagate, including errno.
 want=3;errno=0;assert(ios_protect_host_range((void*)tail,0x4000,want)==-1&&errno==EACCES);
 // Full image pages, anonymous pages and larger runs keep v2 behaviour.
 image.size=0x10000;assert(!ios_alias_mixed_image_tail(tail,0x4000));
 errno=0;assert(ios_protect_host_range((void*)tail,0x4000,7)==-1&&errno==EACCES);
 image.size=0xf000;image.protect=0;assert(!ios_alias_mixed_image_tail(tail,0x4000));
 image.protect=SEC_IMAGE;assert(!ios_alias_mixed_image_tail(tail,0x8000));
 assert(!ios_alias_mixed_image_tail(tail+1,0x4000));
 // Protection-only and no-access requests take the original route.
 unsigned was=legacy_calls;fail_kernel=0;
 assert(!ios_protect_host_range((void*)tail,0x4000,PROT_NONE)&&legacy_calls==was+1);
 // Removing the actual view cannot turn a nearby header into ownership.
 image.size=0;assert(!ios_alias_mixed_image_tail(tail,0x4000));
 // Current section unmap leaves an anonymous record. Detect that mismatch;
 // this controlled variant does NOT claim to repair that independent lifetime.
 void *rw=NULL,*rx=NULL;assert(ios_jit_anon_alias_find_cover((void*)tail,0x4000,&rw,&rx));
 assert(!find_view((void*)tail,1));
 ios_jit_anon_aliases[0].user_va=0; // normal alias tombstone/reuse
 assert(!ios_jit_anon_alias_find_cover((void*)tail,0x4000,&rw,&rx));
 assert(!memcmp(&image.base,&before.base,sizeof(void*)));
 // Real shared backing, then a legitimate image replacement at the same VA.
 // The unchanged registry lookup can still select the old, detached backing.
 FILE* file=tmpfile();assert(file&&!ftruncate(fileno(file),0x4000));
 uint32_t* backing=mmap(NULL,0x4000,PROT_READ|PROT_WRITE,MAP_SHARED,fileno(file),0);
 uint32_t* guest=mmap(NULL,0x4000,PROT_READ,MAP_SHARED,fileno(file),0);
 assert(backing!=MAP_FAILED&&guest!=MAP_FAILED);
 ios_jit_anon_aliases[0]=(typeof(ios_jit_anon_aliases[0])){(uintptr_t)guest,(uintptr_t)guest+0x4000,(uintptr_t)backing,(uintptr_t)guest};
 assert(!__atomic_exchange_n(backing,0xfff95f20,__ATOMIC_SEQ_CST)&&*guest==0xfff95f20);
 assert(mmap(guest,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==guest);
 assert(!*guest&&ios_jit_anon_alias_find_cover(guest,0x4000,&rw,&rx)&&rw==backing);
 assert(__atomic_exchange_n((uint32_t*)rw,0xfff95f20,__ATOMIC_SEQ_CST)==0xfff95f20&&!*guest);
 // A tombstone stops that stale selection. Do not fabricate a new mapping.
 ios_jit_anon_aliases[0].user_va=0;assert(!ios_jit_anon_alias_find_cover(guest,0x4000,&rw,&rx));
 munmap(backing,0x4000);munmap(guest,0x4000);fclose(file);
 puts("NOTE section-unmap/stale-alias mismatch remains observable; mapping lifetime is not declared repaired");
}
'''
run('actual mixed-tail selector and host router: captured failure/control, exact original flags, no syscall for owned RWX, failed errors preserved, other page classes unchanged',code)

swap=body(signal,'else if ((insn & 0x3F20FC00) == 0x38208000)')
advance=signal[signal.index('/* Advance PC past the emulated instruction */'):]
advance=advance[:advance.index('handled = 1;')+len('handled = 1;')]
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
struct state{uint64_t __x[29],__fp,__lr,__sp,__pc;unsigned __cpsr;};
struct frame{uint64_t header,unused[2],rip,gregs[16];};
static struct frame cpu;
static unsigned observations;
static int diagnostic(int fd,const char* fmt,...){(void)fd;(void)fmt;return 0;}
#define dprintf diagnostic
#define __darwin_arm_thread_state64_set_pc_fptr(s,p) ((s).__pc=(uintptr_t)(p))
static void ios_mono_bridge_capture(uint64_t t,uint64_t f,uint64_t p,uint64_t a){(void)t;(void)f;(void)p;(void)a;}
static void ios_trace_alias_swap(uintptr_t t,const struct state* s,uint64_t a,uint64_t w,unsigned n){(void)t;(void)s;(void)a;(void)w;(void)n;observations++;}
static int emulate(uint32_t insn,uintptr_t rw_addr,struct state* out){
 struct state state=*out;uintptr_t fault_addr=rw_addr,thread_teb=0x401e00000ull;uint64_t fault_pc=state.__pc;
 int emulated=0,handled=0;if(0){}
''' +swap+r'''
 if(emulated){
''' +advance+r'''
 }
 *out=state;return handled;
}
static uint32_t word;
static void* worker(void* arg){
 uint32_t token=(uint32_t)(uintptr_t)arg;struct state s={0};s.__pc=0x33f123000;
 for(unsigned i=0;i<10000;i++){s.__x[7]=token;assert(emulate(0xb8e78307,(uintptr_t)&word,&s));assert(s.__x[7]>=1&&s.__x[7]<=8);}
 return NULL;
}
int main(void){
 memset(&cpu,0x5a,sizeof(cpu));cpu.rip=0x7a494321;struct frame before=cpu;
 struct state s;memset(&s,0xa5,sizeof(s));s.__pc=0x33f001000;s.__x[28]=(uintptr_t)&cpu;
 s.__x[7]=0x12345678fff95f20ull;struct state expected=s;expected.__x[7]=0;expected.__pc+=4;
 word=0;assert(emulate(0xb8e78307,(uintptr_t)&word,&s));
 assert(word==0xfff95f20&&!memcmp(&s,&expected,sizeof(s))&&!memcmp(&cpu,&before,sizeof(cpu)));
 s.__x[7]=0xfff95f20;expected=s;expected.__x[7]=0xfff95f20;expected.__pc+=4;
 assert(emulate(0xb8e78307,(uintptr_t)&word,&s)&&!memcmp(&s,&expected,sizeof(s)));
 assert(!memcmp(&cpu,&before,sizeof(cpu))&&cpu.rip);
 // All scalar widths and discarded/zero operand forms, with zero-extension.
 for(unsigned width=0;width<4;width++)for(unsigned rs=0;rs<=31;rs+=31)for(unsigned rt=0;rt<=31;rt+=31){
  uint64_t memory=0xfedcba9876543210ull;memset(&s,0xa5,sizeof(s));s.__pc=0x33f001000;s.__x[0]=0xf00d1234;
  expected=s;uint64_t mask=UINT64_MAX>>(64-(8u<<width));
  uint64_t value=rs==31?0:s.__x[rs];if(rt!=31)expected.__x[rt]=memory&mask;expected.__pc+=4;
  uint32_t op=0x38e08000u|(width<<30)|(rs<<16)|rt;
  assert(emulate(op,(uintptr_t)&memory,&s)&&!memcmp(&s,&expected,sizeof(s)));
  assert(memory==((0xfedcba9876543210ull&~mask)|(value&mask)));
 }
 expected=s;assert(!emulate(0xb8e78307,(uintptr_t)&word+1,&s)&&!memcmp(&s,&expected,sizeof(s)));
 pthread_t threads[8];word=1;
 for(unsigned i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,worker,(void*)(uintptr_t)(i+1)));
 for(unsigned i=0;i<8;i++)pthread_join(threads[i],NULL);
 assert(word>=1&&word<=8&&!memcmp(&cpu,&before,sizeof(cpu))&&observations==8);
}
'''
run('production SWPAL X7/X7 case and actual PC+4 continuation: captured old values, register/FP/LR/SP/frame/RIP preservation, widths, zero operands, alignment refusal and 80000 concurrent swaps',code)

observer=body(signal,'static void ios_trace_alias_swap(')
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
typedef struct {void* Peb;void* TlsSlots[64];} TEB;
typedef struct {uint64_t __x[29],__fp,__lr,__sp,__pc;} arm_thread_state64_t;
#define arm_thread_state64_get_pc(s) ((s).__pc)
static TEB teb;static uint64_t thread[2],frame[32],value=0xfff95f20;
static unsigned logs,decoded;static char line[1800];
struct ios_g32_fault_block{uint64_t exact;};
static int ios_g32_read(uint64_t a,void* out,size_t n){
 const void* objects[]={&teb,thread,frame,&value};size_t sizes[]={sizeof(teb),sizeof(thread),sizeof(frame),sizeof(value)};
 errno=EIO;for(unsigned i=0;i<4;i++){uintptr_t b=(uintptr_t)objects[i];if(a>=b&&a-b<sizes[i]&&n<=sizes[i]-(a-b)){memcpy(out,(void*)(uintptr_t)a,n);return 1;}}return 0;
}
static uint64_t ios_wow_base_for_peb(void* p){return p==(void*)0x47ffd0000ull?0x400000000ull:0;}
static int ios_g32_fault_block(uint64_t f,uint64_t pc,uint64_t owner,struct ios_g32_fault_block* b){
 assert(f==(uintptr_t)frame&&pc==0x33f001000&&owner==0x47ffd0000ull);decoded++;b->exact=0x7a494319;return 1;
}
static int diagnostic(int fd,const char* fmt,...){assert(fd==2);va_list a;va_start(a,fmt);vsnprintf(line,sizeof(line),fmt,a);va_end(a);logs++;errno=ERANGE;return 0;}
#define dprintf diagnostic
''' +observer+r'''
int main(void){
 teb.Peb=(void*)0x47ffd0000ull;teb.TlsSlots[14]=thread;thread[0]=(uintptr_t)frame;frame[3]=0x7a494321;
 arm_thread_state64_t s={0};s.__pc=0x33f001000;s.__x[19]=0x400000000ull;s.__x[28]=(uintptr_t)frame;
 arm_thread_state64_t before=s;uint64_t frame_before[32];memcpy(frame_before,frame,sizeof(frame));TEB teb_before=teb;
 errno=EDOM;ios_trace_alias_swap((uintptr_t)&teb,&s,(uintptr_t)&value,0x3409d8100,4);
 assert(errno==EDOM&&logs==1&&decoded==1&&strstr(line,"frame-validated=1")&&strstr(line,"exact-valid=1"));
 assert(strstr(line,"saved-rip=0x7a494321")&&strstr(line,"exact-rip=0x7a494319")&&strstr(line,"continuation=0x33f001004"));
 assert(strstr(line,"guest=0xfff95f20")&&!memcmp(&s,&before,sizeof(s))&&!memcmp(frame,frame_before,sizeof(frame))&&!memcmp(&teb,&teb_before,sizeof(teb)));
 s.__x[28]++;before=s;ios_trace_alias_swap((uintptr_t)&teb,&s,(uintptr_t)&value,0x3409d8100,4);
 assert(errno==EDOM&&decoded==1&&strstr(line,"frame-validated=0")&&strstr(line,"exact-valid=0")&&!memcmp(&s,&before,sizeof(s)));
 for(unsigned i=0;i<1000;i++){ios_trace_alias_swap(1,&s,1,0x3409d8100,4);assert(errno==EDOM);}
 assert(logs==8&&decoded==1&&strstr(line,"guest-readable=0")&&!memcmp(frame,frame_before,sizeof(frame)));
}
'''
run('actual swap observer validates TLS14/frame/owner, distinguishes saved/exact RIP, survives unreadable addresses, preserves all state and errno and stops at eight records',code)

# Execute the existing producer's refusal. Returning null is NOT a valid
# translated entry. Do not claim the dispatcher can never branch to null:
# the submitted capture proves it currently can, after a bad guest target.
core=(root/'FEX/FEXCore/Source/Interface/Core/Core.cpp').read_text()
guard=body(core,'if (GuestRIP < 0x10000)')
run('actual invalid-RIP compile refusal leaves guest context intact; null result is not a valid JIT entry',r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
namespace LogMan::Msg{template<class... T>void IFmt(const char*,T...) {}}
static uintptr_t reject(uint64_t GuestRIP){
'''+guard+r'''
return 1;}
int main(){uint64_t frame[32],before[32];memset(frame,0x5a,sizeof(frame));memcpy(before,frame,sizeof(frame));
for(auto rip:{uint64_t(0),uint64_t(4),uint64_t(0xffff)}){assert(!reject(rip));assert(!memcmp(before,frame,sizeof(frame)));}
assert(reject(0x7a494321));}
''',True)
