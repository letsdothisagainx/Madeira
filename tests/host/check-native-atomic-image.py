#!/usr/bin/env python3
"""Exercise production unpublished-image lowering, including the shipped FEX PE.

This executes the actual PE parser, range policy and address planner. It does
not emulate the planner or alter atomics to make a fixture pass. Native ARM64
execution/ordering is covered by the separate native planner regression.
"""
from pathlib import Path
import hashlib
import os
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = ROOT / 'app/Madeira/arm64ec-windows/xtajit64.dll'
PIN = 'cc887fcc717be62d83e835e2b982651a74b2061d0fbddd1a2b828ac89b256ef9'

C = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native_atomic_image.h"

enum { SIZE=0x8000, PE=0x80, OPT=PE+24, TABLE=OPT+0xf0, LOAD=0x5000, META=0x5200, MAP=0x5300 };
static const uintptr_t rx=UINT64_C(0x300000000), source=UINT64_C(0xfbe300000);
static const intptr_t delta=0x48000000;
static const uint64_t preferred=UINT64_C(0x180000000);
static void w16(unsigned char *p,size_t at,uint16_t n){memcpy(p+at,&n,2);}
static void w32(unsigned char *p,size_t at,uint32_t n){memcpy(p+at,&n,4);}
static void w64(unsigned char *p,size_t at,uint64_t n){memcpy(p+at,&n,8);}
static uint32_t word(const unsigned char *p,size_t at){uint32_t n;memcpy(&n,p+at,4);return n;}
static uint32_t adrp(unsigned reg,uintptr_t pc,uintptr_t target){
    int64_t pages=((int64_t)(target&~(uintptr_t)0xfff)-(int64_t)(pc&~(uintptr_t)0xfff))/4096;
    uint32_t imm=(uint32_t)pages&0x1fffff;
    assert(pages>=-1048576&&pages<1048576);
    return 0x90000000u|((imm&3)<<29)|((imm>>2)<<5)|reg;
}
static uintptr_t address(const unsigned char *p,size_t at,uintptr_t base){
    uint32_t a=word(p,at),b=word(p,at+4);
    assert((a&0x9f000000u)==0x90000000u&&(b&0xffc00000u)==0x91000000u);
    uint32_t imm=((a>>29)&3)|(((a>>5)&0x7ffff)<<2);
    int64_t pages=(int64_t)(int32_t)(imm<<11)/2048;
    return (uintptr_t)((int64_t)((base+at)&~(uintptr_t)0xfff)+pages*4096)+((b>>10)&0xfff);
}
static void section(unsigned char *p,unsigned i,const char *name,uint32_t start,uint32_t size,uint32_t flags){
    size_t at=TABLE+i*40;memcpy(p+at,name,strlen(name));w32(p,at+8,size);w32(p,at+12,start);
    w32(p,at+16,size);w32(p,at+20,start);w32(p,at+36,flags);
}
static void sequence(unsigned char *p,size_t at,uintptr_t base){
    w32(p,at,adrp(8,base+at,base+0x3028));w32(p,at+4,0x9100a108);
    /* LDADD X1,X8,[X8]: result kills the transient address register. */
    w32(p,at+8,0xf8210108);w32(p,at+12,0xd65f03c0);
}
static unsigned char *fixture(unsigned machine){
    unsigned char *p=calloc(1,SIZE);assert(p);p[0]='M';p[1]='Z';w32(p,0x3c,PE);memcpy(p+PE,"PE\0\0",4);
    w16(p,PE+4,machine);w16(p,PE+6,4);w16(p,PE+20,0xf0);w16(p,OPT,0x20b);
    w64(p,OPT+24,preferred);w32(p,OPT+56,SIZE);w32(p,OPT+108,16);
    section(p,0,".text",0x1000,0x2000,0x60000020);
    section(p,1,".data",0x3000,0x1000,0xc0000040);
    section(p,2,".rdata",0x5000,0x1000,0x40000040);
    section(p,3,".pdata",0x6000,0x1000,0x40000040);
    w32(p,OPT+0x70+10*8,LOAD);w32(p,OPT+0x70+10*8+4,0xd0);w64(p,LOAD+0xc8,preferred+META);
    w32(p,META,1);w32(p,META+4,MAP);w32(p,META+8,3);
    w32(p,MAP,0x1000);w32(p,MAP+4,16);w32(p,MAP+8,0x1101);w32(p,MAP+12,16);
    w32(p,MAP+16,0x1202);w32(p,MAP+20,16);
    sequence(p,0x1000,rx);sequence(p,0x1100,rx);sequence(p,0x1200,rx);
    /* An actual ARM64 runtime-function entry and its unwind word must survive
     * byte-for-byte, as must all headers, metadata, unrelated code and data. */
    w32(p,0x6000,0x1000);w32(p,0x6004,0x6100);w32(p,0x6100,4);
    w64(p,0x3028,UINT64_C(0x1122334455667788));return p;
}
static void unchanged_except(const unsigned char *before,const unsigned char *after,size_t size,const size_t *words,size_t count){
    for(size_t n=0;n<size;n++){
        int allowed=0;for(size_t k=0;k<count;k++)if(n>=words[k]&&n<words[k]+4)allowed=1;
        if(!allowed)assert(before[n]==after[n]);
    }
}
static void accepted(unsigned machine,unsigned expected){
    unsigned char *original=fixture(machine),*copy=malloc(SIZE),*owner=malloc(SIZE),*saved=malloc(SIZE);assert(copy&&owner&&saved);
    memcpy(copy,original,SIZE);memcpy(saved,original,SIZE);
    assert(address(copy,0x1000,rx)==rx+0x3028);
    struct ios_native_atomic_image_stats stats=ios_native_atomic_image_lower(copy,SIZE,rx,source,delta);
    assert(stats.planned==expected&&stats.lse==expected&&stats.exclusive==0);
    const size_t positions[]={0x1000,0x1100,0x1200};unchanged_except(original,copy,SIZE,positions,expected);
    for(unsigned i=0;i<3;i++){
        assert(address(copy,positions[i],rx)==rx+0x3028+(i<expected?delta:0));
        assert(word(copy,positions[i]+8)==0xf8210108);
    }
    assert(!memcmp(original,saved,SIZE));
    memcpy(saved,copy,SIZE);stats=ios_native_atomic_image_lower(copy,SIZE,rx,source,delta);
    assert(!stats.planned&&!memcmp(copy,saved,SIZE));
    /* A second process's private copy uses its own RX/RW pair. ADRP remains
     * image-relative; it must never point into the first process's copy. */
    const uintptr_t other_rx=rx+0x10000000,other_source=source+0x10000000;
    memcpy(owner,original,SIZE);stats=ios_native_atomic_image_lower(owner,SIZE,other_rx,other_source,delta);
    assert(stats.planned==expected);
    for(unsigned i=0;i<expected;i++)assert(address(owner,positions[i],other_rx)==other_rx+0x3028+delta);
    assert(!memcmp(owner,copy,SIZE));free(saved);free(owner);free(copy);free(original);
}
static void rejected(unsigned char *p,size_t size,const char *reason){
    unsigned char *before=malloc(SIZE);assert(before);memcpy(before,p,SIZE);
    struct ios_native_atomic_image_stats stats=ios_native_atomic_image_lower(p,size,rx,source,delta);
    if(stats.planned||memcmp(p,before,SIZE)){fprintf(stderr,"invalid fixture modified: %s\n",reason);abort();}
    free(before);free(p);
}
static void negatives(void){
    unsigned char *p;
#define BAD(label,edit) do{p=fixture(0x8664);edit;rejected(p,SIZE,label);}while(0)
    BAD("DOS",p[0]=0);
    BAD("PE offset overflow",w32(p,0x3c,UINT32_MAX));
    BAD("PE signature",p[PE]='X');
    BAD("unknown machine",w16(p,PE+4,0x14c));
    BAD("section count",w16(p,PE+6,97));
    BAD("PE32",w16(p,OPT,0x10b));
    BAD("image size",w32(p,OPT+56,SIZE+0x1000));
    BAD("short optional header",w16(p,PE+20,0x60));
    BAD("out-of-range section",w32(p,TABLE+8,SIZE));
    BAD("overlapping sections",w32(p,TABLE+40+12,0x2000));
    BAD("writable executable code",w32(p,TABLE+36,0xe0000020));
    BAD("read-only target",w32(p,TABLE+40+36,0x40000040));
    BAD("executable target",w32(p,TABLE+40+36,0xe0000040));
    BAD("complete atomic width outside data section",w32(p,TABLE+40+8,0x2c));
    BAD("foreign target",w32(p,0x1000,adrp(8,rx+0x1000,rx+SIZE+0x3028));w32(p,0x1100,0);w32(p,0x1200,0));
    BAD("unmapped target hole",w32(p,TABLE+40+12,0x4000));
    BAD("short load config",w32(p,OPT+0x70+10*8+4,0xc8));
    BAD("missing load-config directory",w32(p,OPT+108,10));
    BAD("load config outside image",w32(p,OPT+0x70+10*8,SIZE-0x10));
    BAD("metadata pointer unknown",w64(p,LOAD+0xc8,UINT64_C(0x7777777777777777)));
    BAD("metadata pointer truncated",w64(p,LOAD+0xc8,preferred+SIZE-4));
    BAD("code map empty",w32(p,META+8,0));
    BAD("code map count overflow",w32(p,META+8,UINT32_MAX));
    BAD("code map outside image",w32(p,META+4,SIZE-4));
    BAD("late malformed code map refuses before mutation",w32(p,MAP+16,SIZE+0x1000));
    BAD("overlapping native code maps",w32(p,MAP+8,0x1001));
    BAD("unaligned native code extent",w32(p,MAP+4,15));
    BAD("code map native range in data",w32(p,MAP,0x3000);w32(p,MAP+8,0x3101);w32(p,MAP+16,0x3202));
#undef BAD
    p=fixture(0x8664);rejected(p,SIZE-1,"truncated image argument");
    p=fixture(0x8664);unsigned char *before=malloc(SIZE);assert(before);memcpy(before,p,SIZE);
    assert(!ios_native_atomic_image_lower(p,SIZE,rx,source,0).planned&&!memcmp(p,before,SIZE));
    assert(!ios_native_atomic_image_lower(p,SIZE,rx,source,1).planned&&!memcmp(p,before,SIZE));
    assert(!ios_native_atomic_image_lower(p,SIZE,rx,source,-0x1000).planned&&!memcmp(p,before,SIZE));
    assert(!ios_native_atomic_image_lower(p,SIZE,UINTPTR_MAX-0xfff,source,delta).planned&&!memcmp(p,before,SIZE));
    assert(!ios_native_atomic_image_lower(p,SIZE,UINTPTR_MAX-SIZE-0xfff,source,delta).planned&&!memcmp(p,before,SIZE));
    free(before);free(p);
}
static void pointer_forms(void){
    const uint64_t bases[]={preferred,source,rx,rx+delta};
    for(unsigned i=0;i<4;i++){
        unsigned char *p=fixture(0x8664);w64(p,LOAD+0xc8,bases[i]+META);
        assert(ios_native_atomic_image_lower(p,SIZE,rx,source,delta).planned==2);free(p);
    }
}
static void shipped(const char *name){
    FILE *file=fopen(name,"rb");assert(file);assert(!fseek(file,0,SEEK_END));long n=ftell(file);assert(n>0);rewind(file);
    unsigned char *p=malloc((size_t)n),*before=malloc((size_t)n);assert(p&&before);
    assert(fread(p,1,(size_t)n,file)==(size_t)n);fclose(file);memcpy(before,p,(size_t)n);
    const size_t at=0xffb14;assert(word(p,at)==0xf0001668&&word(p,at+4)==0x91348108&&word(p,at+8)==0xf8210108);
    assert(address(p,at,rx)==rx+0x3ced20);
    struct ios_native_atomic_image_stats stats=ios_native_atomic_image_lower(p,(size_t)n,rx,source,delta);
    assert(stats.planned&&stats.lse&&address(p,at,rx)==rx+0x3ced20+delta);
    assert(word(p,at+4)==word(before,at+4)&&word(p,at+8)==word(before,at+8));
    /* The only allowed byte changes throughout the real loaded image are ADRP
     * producer instructions. Runtime function/unwind/CHPE tables remain exact. */
    size_t changed=0;
    for(size_t i=0;i<(size_t)n;i+=4){
        size_t bytes=(size_t)n-i<4?(size_t)n-i:4;
        if(memcmp(p+i,before+i,bytes)){
            /* The exact shipped CHPE map permits native code only here. */
            assert(i>=0x1000&&i+4<=0x20bab4);
            assert(bytes==4&&(word(before,i)&0x9f000000u)==0x90000000u&&(word(p,i)&0x9f000000u)==0x90000000u);changed++;
        }
    }
    assert(changed==stats.planned);memcpy(before,p,(size_t)n);
    assert(!ios_native_atomic_image_lower(p,(size_t)n,rx,source,delta).planned&&!memcmp(p,before,(size_t)n));
    printf("PASS pinned xtajit64 loaded PE: hot producer 0xffb14 -> RW data 0x3ced20; %zu ADRP producers lowered; atomics/CFI intact; second pass idempotent\n",changed);
    free(before);free(p);
}
int main(int argc,char **argv){
    assert(argc==2);accepted(0xaa64,3);accepted(0x8664,2);accepted(0xa641,2);
    pointer_forms();negatives();shipped(argv[1]);
    puts("PASS production native-image lowering: AA64/EC range types, strict executable/data separation, original RX control vs RW result, metadata rejection before mutation, CFI/source preservation, private-copy relocation and idempotence");return 0;
}
'''

data = SHIPPED.read_bytes()
assert hashlib.sha256(data).hexdigest() == PIN, 'packaged FEX PE changed; update fixture only with verified producer evidence'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe + 24
image_size = struct.unpack_from('<I', data, optional + 56)[0]
header_size = struct.unpack_from('<I', data, optional + 60)[0]
loaded = bytearray(image_size)
loaded[:header_size] = data[:header_size]
sections = optional + struct.unpack_from('<H', data, pe + 20)[0]
for i in range(struct.unpack_from('<H', data, pe + 6)[0]):
    virtual_size, rva, raw_size, offset = struct.unpack_from('<IIII', data, sections + i * 40 + 8)
    assert rva + raw_size <= image_size and offset + raw_size <= len(data)
    loaded[rva:rva + raw_size] = data[offset:offset + raw_size]

with tempfile.TemporaryDirectory(prefix='madeira-native-atomic-image-') as directory:
    temporary = Path(directory)
    source, binary, image = temporary / 'fixture.c', temporary / 'fixture', temporary / 'xtajit64-loaded.bin'
    source.write_text(C)
    image.write_bytes(loaded)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    *(['-fno-pie', '-no-pie'] if os.uname().sysname == 'Linux' else []),
                    '-I' + str(ROOT / 'build/ntdll-unix'), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary), str(image)], check=True, timeout=60)
assert hashlib.sha256(SHIPPED.read_bytes()).hexdigest() == PIN, 'test modified packaged source bytes'
