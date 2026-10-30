#!/usr/bin/env python3
"""Run the real x18 patcher and Mach signed-load fallback; optionally execute A64."""
from pathlib import Path
import argparse
import json
import os
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
virtual = (root/'build/ntdll-unix/virtual_ios.c').read_text()
signal = (root/'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}\n', start)+3]


roles = virtual[virtual.index('#define X18_ROLE_NONE 0'):virtual.index('static int ios_insn_x18_role(')]
data_macro = virtual[virtual.index('#define IOS_X18_DATA_WORD'):virtual.index('static unsigned char *ios_x18_build_data_map')]
functions = '\n'.join(function(virtual, sig) for sig in (
    'static int ios_insn_x18_role(', 'static int ios_x18_arith_dest(',
    'static uint32_t ios_insn_replace_x18(', 'static unsigned char *ios_x18_build_data_map(',
    'int ios_jit_patch_x18('))
fallback = function(signal, 'static int ios_emulate_x18_signed_load(')
assert 'if (!signed_load || rt != 18) state.__x[18] = thread_teb;' in signal
code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "windef.h"
#include "winternl.h"
#include "x18_scalar_load.h"
typedef unsigned int thread_t;
typedef uint64_t mach_vm_size_t,mach_vm_address_t;
_Static_assert(offsetof(TEB,Tib.Self)==0x30 && offsetof(TEB,ClientId.UniqueProcess)==0x40 &&
               offsetof(TEB,ClientId.UniqueThread)==0x48 && offsetof(TEB,Peb)==0x60,"native TEB header");
typedef struct { uint64_t __x[29],__fp,__lr,__sp,__pc;uint32_t __cpsr; } arm_thread_state64_t;
static TEB tebs[2];
static int deny_field;
static unsigned mach_task_self(void) { return 1; }
static int mach_vm_read_overwrite(unsigned task,mach_vm_address_t a,mach_vm_size_t n,
                                  mach_vm_address_t out,mach_vm_size_t *copied) {
    assert(task==1); *copied=0;
    for(unsigned t=0;t<2;t++) {
        uintptr_t base=(uintptr_t)&tebs[t];
        if(a>=base && n<=sizeof(TEB) && a-base<=sizeof(TEB)-n && !(deny_field && a-base>=0x1800)) {
            memcpy((void *)(uintptr_t)out,(void *)(uintptr_t)a,n);*copied=n;return 0;
        }
    }
    return 1;
}
static int capture(int fd,const char *format,...) { (void)fd;(void)format;return 0; }
#define dprintf capture
#define ERR(...) ((void)0)
int ios_teb_tls_slot_offset=0x8e8;
''' + roles + data_macro + functions + '\n' + fallback + r'''
static void unchanged(const arm_thread_state64_t *before,const arm_thread_state64_t *after,unsigned reg) {
    for(unsigned r=0;r<29;r++) if(r!=reg) assert(before->__x[r]==after->__x[r]);
    if(reg!=29) assert(before->__fp==after->__fp);
    if(reg!=30) assert(before->__lr==after->__lr);
    assert(before->__sp==after->__sp && before->__pc==after->__pc && before->__cpsr==after->__cpsr);
}
int main(int argc,char **argv) {
    assert(argc==2);
    for(unsigned t=0;t<2;t++) {
        tebs[t].Tib.Self=&tebs[t].Tib;tebs[t].ClientId.UniqueProcess=(void *)(uintptr_t)(0x20+t*0x40);
        tebs[t].ClientId.UniqueThread=(void *)(uintptr_t)(0x24+t*0x40);tebs[t].Peb=(void *)(uintptr_t)(0x400000000ull+t*0x200000000ull);
    }
    struct ios_arm64_scalar_load decoded;
    assert(ios_decode_scalar_load(0xb9980e48,&decoded));
    assert(decoded.reg==8 && decoded.base==18 && decoded.bytes==4 && decoded.extend==64 && decoded.offset==0x180c);
    arm_thread_state64_t state,before;
    memset(&before,0xa5,sizeof(before));before.__x[18]=0;before.__sp=0x100008;before.__pc=0x30018c2ec;
    for(unsigned t=0;t<2;t++) for(unsigned sign=0;sign<2;sign++) {
        int32_t offset=sign?-0x2000:0x2000;memcpy((char *)&tebs[t]+0x180c,&offset,4);state=before;
        assert(ios_emulate_x18_signed_load(0x14e13+t,&state,(uintptr_t)&tebs[t],0x180c,0xb9980e48));
        assert(state.__x[8]==(uint64_t)(int64_t)offset);unchanged(&before,&state,8);
    }
    state=before;assert(!ios_emulate_x18_signed_load(1,&state,0,0x180c,0xb9980e48));assert(!memcmp(&state,&before,sizeof(state)));
    state=before;deny_field=1;assert(!ios_emulate_x18_signed_load(1,&state,(uintptr_t)&tebs[0],0x180c,0xb9980e48));deny_field=0;
    assert(!memcmp(&state,&before,sizeof(state)));
    tebs[0].Tib.Self=&tebs[1].Tib;
    assert(!ios_emulate_x18_signed_load(1,&state,(uintptr_t)&tebs[0],0x180c,0xb9980e48));tebs[0].Tib.Self=&tebs[0].Tib;
    assert(!memcmp(&state,&before,sizeof(state)));
    uint32_t declined[]={0xb9980d08,0xb9180e48,0xbd980e48,0xf9980e48,0xb9d80e48};
    for(unsigned i=0;i<sizeof(declined)/sizeof(declined[0]);i++) {
        state=before;assert(!ios_emulate_x18_signed_load(1,&state,(uintptr_t)&tebs[0],0x180c,declined[i]));
        assert(!memcmp(&state,&before,sizeof(state)));
    }
    state=before;state.__x[18]=1;arm_thread_state64_t nonnull=state;
    assert(!ios_emulate_x18_signed_load(1,&state,(uintptr_t)&tebs[0],0x180c,0xb9980e48));assert(!memcmp(&state,&nonnull,sizeof(state)));
    for(unsigned r=29;r<=31;r++) {
        state=before;uint32_t insn=(0xb9980e48u&~31u)|r;
        assert(ios_emulate_x18_signed_load(1,&state,(uintptr_t)&tebs[0],0x180c,insn));unchanged(&before,&state,r);
        if(r==29) assert(state.__fp==0xffffffffffffe000ull);
        if(r==30) assert(state.__lr==0xffffffffffffe000ull);
    }
    // Actual emitted instruction sequences, not reconstructed trampoline words.
    static const uint32_t words[]={0xb9980e48u,0x39880248u,0x39c80248u,0x79840248u,0x79c40248u,
                                  0xb9420248u,0xf9410248u};
    FILE *out=fopen(argv[1],"wb");assert(out);
    for(unsigned c=0;c<sizeof(words)/sizeof(words[0]);c++) {
        assert(ios_decode_scalar_load(words[c],&decoded));
        if(decoded.extend) {
            uint64_t raw=0xfedcba987654fedcull;
            memcpy((char *)&tebs[0]+decoded.offset,&raw,decoded.bytes);state=before;
            assert(ios_emulate_x18_signed_load(1,&state,(uintptr_t)&tebs[0],decoded.offset,words[c]));
            int64_t expected=decoded.bytes==1?(int8_t)raw:decoded.bytes==2?(int16_t)raw:(int32_t)raw;
            assert(state.__x[8]==(decoded.extend==32?(uint32_t)expected:(uint64_t)expected));
            unchanged(&before,&state,8);
        }
        unsigned char *buffer=calloc(1,0x2000);assert(buffer);memcpy(buffer,&words[c],4);
        assert(ios_jit_patch_x18((char *)buffer,(char *)buffer,4,(char *)buffer+0x400,(char *)buffer+0x400,0x100,0)==1);
        uint32_t setup[4];memcpy(setup,buffer+0x400,sizeof(setup));
        assert(setup[0]==(0xd53bd060u|8)); // TSD load uses destination, never x18/x17/SP
        assert(setup[3]==ios_insn_replace_x18(words[c],X18_ROLE_RN,8));
        assert(fwrite(&words[c],4,1,out)==1 && fwrite(buffer,0x500,1,out)==1);free(buffer);
    }
    fclose(out);
    puts("PASS exact LDRSW and signed byte/halfword fallback, two TEB owners, invalid/self-mismatched/unreadable TEBs decline, registers/flags/SP/PC preserved, actual emitted scalar-load trampolines");
}
'''
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--emulate',action='store_true',help='Execute actual A64 trampolines using Unicorn')
args=parser.parse_args()
with tempfile.TemporaryDirectory(prefix='madeira-x18-loads-') as temp:
    folder=Path(temp); source,binary,frames=folder/'test.c',folder/'test',folder/'frames.bin'
    source.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror',
                    '-Wno-unused-variable','-Wno-tautological-compare',
                    '-fsanitize=address,undefined','-DWINE_UNIX_LIB','-D__WINESRC__',
                    '-I'+str(root/'wine/include'),'-I'+str(root/'build/ntdll-unix'),
                    str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary),str(frames)],check=True)
    if args.emulate:
        from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
        from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X18,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_NZCV,UC_ARM64_REG_TPIDRRO_EL0
        data=frames.read_bytes()
        for p in range(0,len(data),0x504):
            word=struct.unpack_from('<I',data,p)[0];code_bytes=data[p+4:p+0x504]
            size=1<<(word>>30);opc=(word>>22)&3;offset=((word>>10)&0xfff)*(1<<(word>>30))
            for owner in range(2):
                for bits in (0x1234,0xfedcba987654fedc):
                    mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);mu.mem_map(0x100000,0x2000);mu.mem_write(0x100000,code_bytes)
                    tsd,teb=0x200000,0x300000+owner*0x10000
                    mu.mem_map(tsd,0x2000);mu.mem_map(teb,0x10000)
                    mu.mem_write(tsd+0x8e8,struct.pack('<Q',teb));raw=(bits&((1<<(size*8))-1)).to_bytes(size,'little')
                    mu.mem_write(teb+offset,raw);mu.reg_write(UC_ARM64_REG_TPIDRRO_EL0,tsd|7)
                    for r in range(29): mu.reg_write(UC_ARM64_REG_X0+r,0x100000000+r)
                    mu.reg_write(UC_ARM64_REG_SP,0xdeadbeef0008);mu.reg_write(UC_ARM64_REG_NZCV,0xa0000000)
                    mu.hook_add(UC_HOOK_CODE,lambda m,a,n,u:m.reg_write(UC_ARM64_REG_X18,0))
                    mu.emu_start(0x100000,0x100004,count=10)
                    expected=int.from_bytes(raw,'little',signed=opc>=2)
                    if opc==3:expected&=0xffffffff
                    assert mu.reg_read(UC_ARM64_REG_X0+8)==expected&0xffffffffffffffff,(hex(word),owner,bits)
                    for r in range(29):
                        if r not in (8,18):assert mu.reg_read(UC_ARM64_REG_X0+r)==0x100000000+r
                    assert mu.reg_read(UC_ARM64_REG_SP)==0xdeadbeef0008 and mu.reg_read(UC_ARM64_REG_NZCV)==0xa0000000
                    assert mu.reg_read(UC_ARM64_REG_PC)==0x100004
        print('PASS actual A64 trampolines execute with x18 cleared before EVERY instruction: two thread TSD/TEB mappings, signed/unsigned results, x17/SP/NZCV preserved')
