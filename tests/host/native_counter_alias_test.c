/* SPDX-License-Identifier: MIT. Test the actual unpublished-image binder. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native_counter_alias.h"

enum { IMAGE=0xc000, PE=0x80, OPT=PE+24, SECTIONS=OPT+0xf0,
       EXPORT=0x2000, FUNCTIONS=0x2040, NAMES=0x2050, ORDINALS=0x2060,
       COUNTER_NAME=0x2080, CONTRACT_NAME=0x2090, OTHER_NAME=0x20b0,
       COUNTER=0x4000, CONTRACT=0xa100 };
static const uintptr_t rx=UINT64_C(0x300000000);
static const intptr_t delta=0x48000000;
static unsigned cases;
static void w16(unsigned char *p,size_t at,uint16_t value){memcpy(p+at,&value,2);}
static void w32(unsigned char *p,size_t at,uint32_t value){memcpy(p+at,&value,4);}
static void w64(unsigned char *p,size_t at,uint64_t value){memcpy(p+at,&value,8);}
static uint64_t r64(const unsigned char *p,size_t at){uint64_t value;memcpy(&value,p+at,8);return value;}
static void section(unsigned char *p,unsigned index,uint32_t start,uint32_t bytes,uint32_t flags)
{
    size_t at=SECTIONS+index*40;
    memcpy(p+at,".fixture",8);w32(p,at+8,bytes);w32(p,at+12,start);
    w32(p,at+16,bytes);w32(p,at+20,start);w32(p,at+36,flags);
}
static unsigned char *fixture(unsigned machine)
{
    unsigned char *p=calloc(1,IMAGE);assert(p);
    p[0]='M';p[1]='Z';w32(p,0x3c,PE);memcpy(p+PE,"PE\0\0",4);
    w16(p,PE+4,machine);w16(p,PE+6,3);w16(p,PE+20,0xf0);
    w16(p,OPT,0x20b);w64(p,OPT+24,UINT64_C(0x180000000));
    w32(p,OPT+56,IMAGE);w32(p,OPT+108,16);
    w32(p,OPT+0x70,EXPORT);w32(p,OPT+0x74,0x400);
    section(p,0,0x1000,0x1000,0x60000020); /* RX code */
    section(p,1,0x2000,0x2000,0x40000040); /* R exports */
    section(p,2,0x4000,0x7000,0xc0000040); /* private RW, nonexec */
    w32(p,EXPORT+16,1);w32(p,EXPORT+20,3);w32(p,EXPORT+24,3);
    w32(p,EXPORT+28,FUNCTIONS);w32(p,EXPORT+32,NAMES);w32(p,EXPORT+36,ORDINALS);
    w32(p,FUNCTIONS,COUNTER);w32(p,FUNCTIONS+4,CONTRACT);w32(p,FUNCTIONS+8,0x1000);
    w32(p,NAMES,COUNTER_NAME);w32(p,NAMES+4,CONTRACT_NAME);w32(p,NAMES+8,OTHER_NAME);
    w16(p,ORDINALS,0);w16(p,ORDINALS+2,1);w16(p,ORDINALS+4,2);
    memcpy(p+COUNTER_NAME,"ios_xp_nt",10);
    memcpy(p+CONTRACT_NAME,"ios_xp_nt_write_contract",25);
    memcpy(p+OTHER_NAME,"unrelated_export",17);
    /* Exact bytes deliberately include nonzero live counters. Binding must
     * never zero them, copy a parent's values, or dereference a stale writer. */
    for(size_t n=0;n<MADEIRA_NATIVE_COUNTER_BYTES;n++)p[COUNTER+n]=(unsigned char)(n*17+3);
    w64(p,CONTRACT,MADEIRA_NATIVE_COUNTER_ABI_V1);
    w32(p,CONTRACT+8,MADEIRA_NATIVE_COUNTER_BYTES);w32(p,CONTRACT+12,0);
    w64(p,CONTRACT+MADEIRA_NATIVE_COUNTER_WRITER_OFFSET,UINT64_C(0xfffffffffffffff8));
    return p;
}
static void only_writer_changed(const unsigned char *before,const unsigned char *after)
{
    size_t writer=CONTRACT+MADEIRA_NATIVE_COUNTER_WRITER_OFFSET;
    for(size_t i=0;i<IMAGE;i++)if(i<writer||i>=writer+8)assert(before[i]==after[i]);
    assert(!memcmp(before+COUNTER,after+COUNTER,MADEIRA_NATIVE_COUNTER_BYTES));
}
static void rejects(unsigned char *p,size_t size,uintptr_t base,intptr_t difference,int unpublished,const char *label)
{
    unsigned char before[IMAGE];memcpy(before,p,IMAGE);
    if(ios_native_counter_alias_bind(p,size,base,difference,unpublished)||memcmp(before,p,IMAGE)){
        fprintf(stderr,"invalid binder input modified image: %s\n",label);abort();
    }
    cases++;free(p);
}
static void positive(unsigned machine,uintptr_t base,intptr_t difference)
{
    unsigned char *p=fixture(machine),before[IMAGE];memcpy(before,p,IMAGE);
    assert(ios_native_counter_alias_bind(p,IMAGE,base,difference,1)==1);
    assert(r64(p,CONTRACT+MADEIRA_NATIVE_COUNTER_WRITER_OFFSET)==base+(uintptr_t)difference+COUNTER);
    only_writer_changed(before,p);
    memcpy(before,p,IMAGE);
    assert(ios_native_counter_alias_bind(p,IMAGE,base,difference,1)==1);
    assert(!memcmp(before,p,IMAGE)); /* repeated unpublished binding is idempotent */
    cases++;free(p);
}
int main(void)
{
    _Static_assert(sizeof(uintptr_t)==8,"native counter writer requires64bit");
    _Static_assert(MADEIRA_NATIVE_COUNTER_BYTES==24712,"existing sampler ABI unchanged");
    _Static_assert(MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES==24,"explicit contract ABI");
    _Static_assert(MADEIRA_NATIVE_COUNTER_WRITER_OFFSET==16,"writer field only");
    (void)ios_native_atomic_image_lower; /* shared header also owns the code-lowering entry */
    positive(0xaa64,rx,delta);positive(0xa641,rx+0x10000000,0x10000000);
    positive(0x8664,rx+0x20000000,0x100000000);
    /* Independent process/image generations are fresh private copies. A
     * clone starts with the parent's pointer but must rebind only its own. */
    unsigned char *parent=fixture(0xaa64),*child=malloc(IMAGE),*reload=malloc(IMAGE);
    assert(child&&reload&&ios_native_counter_alias_bind(parent,IMAGE,rx,delta,1));
    memcpy(child,parent,IMAGE);memcpy(reload,parent,IMAGE);
    uintptr_t child_rx=rx+0x08000000;
    assert(ios_native_counter_alias_bind(child,IMAGE,child_rx,delta,1));
    assert(r64(child,CONTRACT+16)==child_rx+(uintptr_t)delta+COUNTER);
    assert(r64(parent,CONTRACT+16)==rx+(uintptr_t)delta+COUNTER);
    only_writer_changed(parent,child);cases++;
    /* A retired/published image cannot be rebound even to its previous alias. */
    rejects(reload,IMAGE,rx,delta,0,"published/retired copy");
    memcpy(child,parent,IMAGE);w64(child,CONTRACT+16,1);
    assert(ios_native_counter_alias_bind(child,IMAGE,child_rx+0x10000000,delta,1));
    assert(r64(child,CONTRACT+16)==child_rx+0x10000000+(uintptr_t)delta+COUNTER);
    only_writer_changed(parent,child);cases++;free(child);free(parent);

#define BAD(label,edit) do{unsigned char *p=fixture(0xaa64);edit;rejects(p,IMAGE,rx,delta,1,label);}while(0)
    BAD("DOS",p[0]=0);
    BAD("PE signature",p[PE]='X');
    BAD("PE offset overflow",w32(p,0x3c,UINT32_MAX));
    BAD("unknown architecture",w16(p,PE+4,0x14c));
    BAD("no sections",w16(p,PE+6,0));
    BAD("excess sections",w16(p,PE+6,97));
    BAD("PE32",w16(p,OPT,0x10b));
    BAD("short optional header",w16(p,PE+20,0x70));
    BAD("optional header beyond image",w32(p,0x3c,IMAGE-32));
    BAD("wrong image size",w32(p,OPT+56,IMAGE-1));
    BAD("no export directory",w32(p,OPT+108,0));
    BAD("short exports",w32(p,OPT+0x74,39));
    BAD("export RVA overflow",w32(p,OPT+0x70,UINT32_MAX));
    BAD("export extent overflow",w32(p,OPT+0x74,UINT32_MAX));
    BAD("no functions",w32(p,EXPORT+20,0));
    BAD("huge functions",w32(p,EXPORT+20,UINT32_MAX));
    BAD("no names",w32(p,EXPORT+24,0));
    BAD("huge names",w32(p,EXPORT+24,UINT32_MAX));
    BAD("functions array bounds",w32(p,EXPORT+28,IMAGE-4));
    BAD("names array bounds",w32(p,EXPORT+32,IMAGE-4));
    BAD("ordinals array bounds",w32(p,EXPORT+36,IMAGE-2));
    BAD("name RVA bounds",w32(p,NAMES,IMAGE));
    BAD("unterminated target name",memset(p+COUNTER_NAME,'A',64));
    BAD("unterminated image tail",w32(p,NAMES,IMAGE-1);p[IMAGE-1]='A');
    BAD("ordinal out of bounds",w16(p,ORDINALS,3));
    BAD("missing counters",memcpy(p+COUNTER_NAME,"not_xp_nt",10));
    BAD("missing contract",p[CONTRACT_NAME]='X');
    BAD("duplicate counter same ordinal",w32(p,NAMES+8,COUNTER_NAME);w16(p,ORDINALS+4,0));
    BAD("duplicate counter different ordinal",w32(p,NAMES+8,COUNTER_NAME));
    BAD("duplicate contract same ordinal",w32(p,NAMES+8,CONTRACT_NAME);w16(p,ORDINALS+4,1));
    BAD("duplicate contract different ordinal",w32(p,NAMES+8,CONTRACT_NAME));
    BAD("zero counter RVA",w32(p,FUNCTIONS,0));
    BAD("zero contract RVA",w32(p,FUNCTIONS+4,0));
    BAD("counter RVA bounds",w32(p,FUNCTIONS,UINT32_MAX));
    BAD("contract RVA bounds",w32(p,FUNCTIONS+4,IMAGE-8));
    BAD("unaligned counter",w32(p,FUNCTIONS,COUNTER+1));
    BAD("unaligned contract",w32(p,FUNCTIONS+4,CONTRACT+1));
    BAD("unknown ABI",w64(p,CONTRACT,MADEIRA_NATIVE_COUNTER_ABI_V1^1));
    BAD("wrong counter ABI size",w32(p,CONTRACT+8,MADEIRA_NATIVE_COUNTER_BYTES-8));
    BAD("unknown reserved ABI bits",w32(p,CONTRACT+12,1));
    BAD("counter/contract overlap",w32(p,FUNCTIONS+4,COUNTER+8));
    BAD("section extent bounds",w32(p,SECTIONS+2*40+8,IMAGE));
    BAD("overlapping RX ownership",section(p,3,COUNTER+8,0x1000,0x60000020);w16(p,PE+6,4));
    BAD("counter span one byte short",w32(p,SECTIONS+2*40+8,MADEIRA_NATIVE_COUNTER_BYTES-1));
    BAD("contract span one byte short",w32(p,SECTIONS+2*40+8,CONTRACT+23-COUNTER));
    BAD("readonly counters/contract",w32(p,SECTIONS+2*40+36,0x40000040));
    BAD("EXEC counters/contract",w32(p,SECTIONS+2*40+36,0xe0000040));
    BAD("discardable counters/contract",w32(p,SECTIONS+2*40+36,0xc2000040));
    BAD("shared counters/contract",w32(p,SECTIONS+2*40+36,0xd0000040));
    BAD("RW without read permission",w32(p,SECTIONS+2*40+36,0x80000040));
    BAD("isolated readonly contract",w32(p,SECTIONS+2*40+8,MADEIRA_NATIVE_COUNTER_BYTES);
        section(p,3,CONTRACT,0x100,0x40000040);w16(p,PE+6,4));
    BAD("isolated executable contract",w32(p,SECTIONS+2*40+8,MADEIRA_NATIVE_COUNTER_BYTES);
        section(p,3,CONTRACT,0x100,0xe0000040);w16(p,PE+6,4));
    BAD("forwarded counter",w32(p,FUNCTIONS,0x2300);memcpy(p+0x2300,"OTHER.counter",14));
    BAD("forwarded contract even in writable export directory",w32(p,SECTIONS+40+36,0xc0000040);
        memcpy(p+0x2300,p+CONTRACT,MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES);w32(p,FUNCTIONS+4,0x2300));
#undef BAD
    rejects(fixture(0xaa64),0,rx,delta,1,"empty image");
    rejects(fixture(0xaa64),0x3f,rx,delta,1,"short DOS header");
    rejects(fixture(0xaa64),IMAGE-1,rx,delta,1,"truncated loaded image");
    rejects(fixture(0xaa64),IMAGE,0,delta,1,"null RX");
    rejects(fixture(0xaa64),IMAGE,rx+1,delta,1,"unaligned RX");
    rejects(fixture(0xaa64),IMAGE,rx,0,1,"no alias delta");
    rejects(fixture(0xaa64),IMAGE,rx,1,1,"unaligned alias delta");
    rejects(fixture(0xaa64),IMAGE,rx,-0x1000,1,"negative alias delta");
    rejects(fixture(0xaa64),IMAGE,UINTPTR_MAX&~(uintptr_t)0xfff,delta,1,"RX extent overflow");
    rejects(fixture(0xaa64),IMAGE,UINT64_C(0x8000000000000000),INTPTR_MAX&~(intptr_t)0xfff,1,"alias extent overflow");
    rejects(fixture(0xaa64),SIZE_MAX,rx,delta,1,"size/address overflow");
    assert(!ios_native_counter_alias_bind(NULL,IMAGE,rx,delta,1));cases++;
    printf("PASS production native counter binder: %u contracts; exact24712B counters preserved, writer-only private clone binding, malformed PE/exports/protections/publication rejected\n",cases);
    return 0;
}
