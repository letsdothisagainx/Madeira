#!/usr/bin/env python3
"""Run the actual WoW32 observer against the pinned FEX metadata producer."""
from pathlib import Path
import os, re, subprocess, tempfile

root = Path(__file__).resolve().parents[2]
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
a = signal.index('static void ios_trace_wow32_fault(')
observer = signal[a:signal.index('\n}', a) + 2]
producer = (root / 'FEX/FEXCore/Source/Interface/Core/CPUBackend.h').read_text()
a = producer.index('    struct JITCodeHeader {')
b = producer.index('\n    /**', a)
layout = producer[a:b]
sra = (root / 'FEX/FEXCore/Source/Interface/Core/ArchHelpers/Arm64Emitter.cpp').read_text()
x32 = sra[sra.index('namespace x32 {'):]
x32 = x32[:x32.index('constexpr std::array<ARMEmitter::Register, 14> RA')]
actual_sra = re.findall(r'ARMEmitter::Reg::r(\d+)', x32)
assert actual_sra == ['4','7','5','6','8','9','10','11']
native_header = (root / 'build/ntdll-unix/guest32_fault.h').read_text()
assert re.search(r'sra\[8\] = \{([^}]+)', native_header).group(1).split(',') == actual_sra
state = (root / 'FEX/FEXCore/include/FEXCore/Core/CoreState.h').read_text()
a = state.index('template<typename T>')
counter = state[a:state.index('struct alignas(64) CPUState',a)]
a = state.index('  uint64_t InlineJITBlockHeader')
state_prefix = state[a:state.index('  uint64_t L1Pointer',a)]
assert 'state->__x[19]!=window' in observer and 'frame!=state->__x[28]' in observer
assert signal.index('ios_trace_wow32_fault(thread_teb,state,fault_addr)') < signal.index('dispatch:\n', signal.index('static int ios_mach_deliver_guest_exception_inner('))

code = r'''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cerrno>
#include <atomic>
#include <type_traits>
#include <vector>
#include "Utils/variable_length_integer.h"
namespace Producer {
''' + layout + counter + '\nstruct StatePrefix {\n' + state_prefix + '\n};\n' + r'''
}
static_assert(sizeof(Producer::JITCodeHeader)==4);
static_assert(sizeof(Producer::JITCodeTail)==40);
static_assert(offsetof(Producer::JITCodeTail,RIP)==8 && offsetof(Producer::JITCodeTail,GuestSize)==16);
static_assert(offsetof(Producer::JITCodeTail,NumberOfRIPEntries)==24 && offsetof(Producer::JITCodeTail,OffsetToRIPEntries)==28);
static_assert(offsetof(Producer::StatePrefix,InlineJITBlockHeader)==0);
static_assert(offsetof(Producer::StatePrefix,rip)==0x18 && offsetof(Producer::StatePrefix,gregs)==0x20);
static unsigned char guest[0x60000], frame_data[0x100], pool[0x20000];
static constexpr uint64_t window=0x500000000ull, pool_base=0x326400000ull;
static constexpr uint64_t frame=0xc2f001140ull, fex=0xc2f001000ull, owner=0x500310000ull;
static bool denied, foreign; static unsigned reads, reports, deallocations;
static uint64_t thread_frame=frame;
static int ios_g32_read(uint64_t a,void* out,size_t n) {
 reads++; if(denied)return 0;
 if(a==fex&&n==8){memcpy(out,&thread_frame,8);return 1;}
 if(a>=frame&&a-frame<=sizeof(frame_data)&&n<=sizeof(frame_data)-(a-frame)){memcpy(out,frame_data+(a-frame),n);return 1;}
 if(a>=pool_base&&a-pool_base<=sizeof(pool)&&n<=sizeof(pool)-(a-pool_base)){memcpy(out,pool+(a-pool_base),n);return 1;}
 if(a>=window&&a-window<=sizeof(guest)&&n<=sizeof(guest)-(a-window)){memcpy(out,guest+(a-window),n);return 1;}
 return 0;
}
static int ios_g32_fault_owned(uint64_t a,uint64_t o){return !foreign&&o==owner&&a>=pool_base&&a-pool_base<sizeof(pool);}
static char output[1048576]; static size_t used;
static int capture(int fd,const char* fmt,...){
 assert(fd==2);va_list ap;va_start(ap,fmt);int n=vsnprintf(output+used,sizeof(output)-used,fmt,ap);va_end(ap);
 assert(n>=0&&(size_t)n<sizeof(output)-used);used+=n;if(strstr(fmt,"[guest32-fault-event]"))reports++;errno=EIO;return n;
}
#define dprintf capture
#include "guest32_origin.h"
#include "guest32_fault.h"
struct TEB {uint64_t Peb;void* TlsSlots[64];struct{uint64_t UniqueProcess,UniqueThread;} ClientId;};
struct arm_thread_state64_t {uint64_t __x[29];uint64_t pc;};
static uint64_t arm_thread_state64_get_pc(const arm_thread_state64_t& s){return s.pc;}
static uint64_t ios_wow_base_for_peb(void* p){return (uint64_t)(uintptr_t)p==owner?window:0;}
using mach_vm_address_t=uint64_t;using mach_vm_size_t=uint64_t;using mach_msg_type_number_t=unsigned;using mach_port_t=unsigned;using kern_return_t=int;using vm_region_info_t=void*;
struct vm_region_basic_info_data_64_t {int protection,max_protection;};
#define VM_REGION_BASIC_INFO_COUNT_64 2
#define VM_REGION_BASIC_INFO_64 1
#define MACH_PORT_NULL 0
#define KERN_SUCCESS 0
static unsigned mach_task_self(){return 1;}
static int mach_vm_region(unsigned t,uint64_t* a,uint64_t* n,int kind,void* i,unsigned* count,unsigned* object){
 assert(t==1&&kind==1&&*count==2);*a=window;*n=0x110000;auto* info=(vm_region_basic_info_data_64_t*)i;
 info->protection=0;info->max_protection=7;*object=42;return 0;
}
static void mach_port_deallocate(unsigned t,unsigned object){assert(t==1&&object==42);deallocations++;}
''' + observer + r'''
static void u16(unsigned p,uint16_t v){assert(p+2<=sizeof(guest));memcpy(guest+p,&v,2);}
static void u32(unsigned p,uint32_t v){assert(p+4<=sizeof(guest));memcpy(guest+p,&v,4);}
static void reg(unsigned p,uint64_t v){assert(p+8<=sizeof(frame_data));memcpy(frame_data+p,&v,8);}
static void make_block(uint64_t entry,const std::vector<std::pair<int64_t,int64_t>>& offsets){
 memset(pool,0,sizeof(pool));uint32_t off=0x4f8;memcpy(pool+0x810,&off,4);
 Producer::JITCodeTail tail{};tail.RIP=entry;tail.GuestSize=0x200;tail.NumberOfRIPEntries=offsets.size();tail.OffsetToRIPEntries=sizeof(tail);
 size_t cursor=0x810+off+sizeof(tail);
 for(auto [h,g]:offsets)cursor+=FEXCore::Utils::vl64pair::Encode(pool+cursor,h,g);
 tail.Size=cursor-0x810;memcpy(pool+0x810+off,&tail,sizeof(tail));reg(0,pool_base+0x810);reg(0x18,0x24444);
}
static Producer::JITCodeTail tail_get(){Producer::JITCodeTail t;memcpy(&t,pool+0xd08,sizeof(t));return t;}
static void tail_set(Producer::JITCodeTail t){memcpy(pool+0xd08,&t,sizeof(t));}
int main(){
 // Guest loader metadata, executable bytes, and a four-byte object pointer.
 u32(0x1180c,0x2000);u32(0x12000,0xffffffff);u32(0x12004,0x19000);u32(0x12008,0x18000);u32(0x12030,0x13000);
 u32(0x1300c,0x14000);u32(0x1400c,0x15000);u32(0x15000,0x1400c);u32(0x15018,0x20000);u32(0x15020,0x20000);
 u16(0x1502c,20);u32(0x15030,0x16000);const char* dll="libcef.dll";for(unsigned i=0;i<10;i++)u16(0x16000+2*i,dll[i]);
 u16(0x20000,0x5a4d);u32(0x2003c,0x80);u32(0x20080,0x4550);u16(0x20086,1);u16(0x20094,0xe0);u16(0x20098,0x10b);
 u32(0x20180,0x5000);u32(0x20184,0x1000);u32(0x2019c,0x60000020);
 guest[0x21122]=0xcc;guest[0x21123]=0x8b;guest[0x21124]=0x40;guest[0x21125]=4; // exact opcode, no INT3 adjustment
 u32(0x18020,0x18030);u32(0x18024,0x21177);u32(0x18030,0);u32(0x18034,0x21188);
 strcpy((char*)guest+0x40008,"AUTHSECRET");u32(0x40004,0);
 make_block(0x21100,{{20,0},{0xd4,0x23}});
 struct ios_g32_fault_block b;assert(ios_g32_fault_block(frame,pool_base+0x8f8,owner,&b));
 assert(b.saved==0x24444&&b.exact==0x21123&&b.walked==2);
 make_block(0x21100,{{20,0},{0,1}});assert(ios_g32_fault_block(frame,pool_base+0x8f8,owner,&b)&&b.exact==0x21101);
 make_block(0x21100,{{20,0},{-4,1}});assert(!ios_g32_fault_block(frame,pool_base+0x8f8,owner,&b));
 // Actual FEX encoder supplies all four formats, including signed backward RIP deltas.
 make_block(0xf0000000,{{20,0},{4,1},{512,-7},{8,1000},{4,-0x90000000ll}});
 assert(ios_g32_fault_block(frame,pool_base+0x810+548,owner,&b));assert(b.exact==0x600003e2);
 uint32_t random=0x12345678;
 for(unsigned iteration=0;iteration<1000;iteration++){
  std::vector<std::pair<int64_t,int64_t>> entries;uint64_t guestpc=0x200000,hostpc=20;entries.push_back({20,0});
  unsigned stop=iteration%30;
  for(unsigned j=0;j<30;j++){
   random=random*1664525+1013904223;int64_t dh=4+4*(random%8),dg=(int)(random%10001)-5000;
   entries.push_back({dh,dg});if(j<stop){hostpc+=dh;guestpc+=dg;}
  }
  make_block(0x200000,entries);assert(ios_g32_fault_block(frame,pool_base+0x810+hostpc,owner,&b));assert(b.exact==guestpc);
 }
 make_block(0x21100,{{20,0},{0xd4,0x23}});auto good=tail_get();
 for(unsigned i=0;i<7;i++){
  auto bad=good;if(i==0)bad.Size=UINT64_MAX;if(i==1)bad.NumberOfRIPEntries=4097;if(i==2)bad.OffsetToRIPEntries=39;
  if(i==3)bad.OffsetToRIPEntries=0xffffffff;if(i==4)bad.RIP=0x100000000ull;if(i==5)bad.Size=0x4f8+39;
  if(i==6)bad.NumberOfRIPEntries=0;
  tail_set(bad);assert(!ios_g32_fault_block(frame,pool_base+0x8f8,owner,&b));
 }
 tail_set(good);foreign=true;unsigned before=reads;assert(!ios_g32_fault_block(frame,pool_base+0x8f8,owner,&b)&&reads==before);foreign=false;
 assert(!ios_g32_fault_block(frame,pool_base+0xd08,owner,&b)); // tail/data is never executable provenance
 denied=true;assert(!ios_g32_fault_block(frame,pool_base+0x8f8,owner,&b));denied=false;
 // Execute the actual Mach observer: real gate logic, immutable state, dedup/budget and errno.
 TEB teb{};teb.Peb=owner;teb.TlsSlots[14]=(void*)(uintptr_t)fex;teb.ClientId.UniqueProcess=0x64;teb.ClientId.UniqueThread=0x124;
 memcpy(guest+0x10000,&teb,sizeof(teb));
 reg(0x40,0x18888);reg(0x48,0x18890);
 arm_thread_state64_t native{};native.pc=pool_base+0x8f8;native.__x[19]=window;native.__x[24]=window+4;native.__x[28]=frame;
 native.__x[4]=0;native.__x[7]=0x40000;native.__x[8]=0x18000;native.__x[9]=0x18020;native.__x[10]=0x40000;native.__x[11]=0x6b0192e0;
 uint32_t instructions[7]={0x11001154,0x8b344278,0xb8bfc304,0xd503201f,0x11001094,0x8b344278,0xb8bfc304};
 memcpy(pool+0x8f8-24,instructions,sizeof(instructions));
 auto original=native;unsigned char original_frame[sizeof(frame_data)];memcpy(original_frame,frame_data,sizeof(frame_data));
 errno=EINTR;ios_trace_wow32_fault(window+0x10000,&native,window+4);
 assert(reports==1&&deallocations==1&&errno==EINTR&&!memcmp(&native,&original,sizeof(native))&&!memcmp(frame_data,original_frame,sizeof(frame_data)));
 assert(strstr(output,"pid=0064 tid=0124 stage=before-exception-dispatch"));
 assert(strstr(output,"saved-rip=0x24444 exact-rip=0x21123 table=valid"));
 assert(strstr(output,"live eax=00000000 ecx=00040000")&&strstr(output,"esp=00018000 ebp=00018020"));
 assert(strstr(output,"tag=first-av-exact libcef.dll+0x1123 bytes=8b 40 04"));
 assert(strstr(output,"ecx+4=0x40004 sampled=0"));assert(!strstr(output,"AUTHSECRET"));
 assert(strstr(output,"contains=1 base=0x500000000 size=0x110000 prot=0 max=7"));
 ios_trace_wow32_fault(window+0x10000,&native,window+4);assert(reports==1);
 foreign=true;native.pc+=4;ios_trace_wow32_fault(window+0x10000,&native,window+4);assert(reports==1);foreign=false;
 native.__x[28]=frame+8;ios_trace_wow32_fault(window+0x10000,&native,window+4);assert(reports==1);native.__x[28]=frame;
 native.__x[19]=0;ios_trace_wow32_fault(window+0x10000,&native,window+4);assert(reports==1);native.__x[19]=window;
 for(unsigned i=1;i<30;i++){native.pc=pool_base+0x8f8+4*i;ios_trace_wow32_fault(window+0x10000,&native,window+4);}
 assert(reports==8&&deallocations==8&&errno==EINTR);
 puts("PASS actual WoW32 fault observer: pinned producer layouts/SRA, all encoded widths and signed RIP deltas, 1000 producer tables, malformed/unreadable/foreign metadata, live versus saved registers, exact rebased opcode, pointer-only sampling, untouched execution state, owner gates, dedup and eight-event bound");
}
'''
with tempfile.TemporaryDirectory() as t:
    src = Path(t) / 'check.cpp'; src.write_text(code)
    exe = Path(t) / 'check'
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-Wall','-Wextra','-Werror',
                    '-Wno-unused-function','-Wno-misleading-indentation','-Wno-missing-field-initializers',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-I'+str(root/'build/ntdll-unix'),'-I'+str(root/'FEX/FEXCore/include'),
                    '-I'+str(root/'FEX/FEXCore/Source'),str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
