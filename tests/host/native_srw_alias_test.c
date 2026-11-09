/* SPDX-License-Identifier: MIT. Production private-history binding and sync. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "native_srw_alias.h"

enum { SIZE=0x18000,PE=0x80,OPT=PE+24,TABLE=OPT+0xf0,
       COUNTER=0x4000,COUNTER_CONTRACT=0xa100,RING=0xb000,INDEX=0xd100,HISTORY=0xd108 };
static const uintptr_t rx=UINT64_C(0x300000000),other=UINT64_C(0x340000000);
static const intptr_t delta=0x48000000;
static unsigned checks;
static void w16(unsigned char*p,size_t a,uint16_t n){memcpy(p+a,&n,2);}
static void w32(unsigned char*p,size_t a,uint32_t n){memcpy(p+a,&n,4);}
static void w64(unsigned char*p,size_t a,uint64_t n){memcpy(p+a,&n,8);}
static uintptr_t pointer(const unsigned char*p,size_t a){uintptr_t n;memcpy(&n,p+a,8);return n;}
static void section(unsigned char*p,unsigned i,const char*name,uint32_t a,uint32_t n,uint32_t f){
    size_t at=TABLE+40*i;memcpy(p+at,name,strlen(name));w32(p,at+8,n);w32(p,at+12,a);
    w32(p,at+16,n);w32(p,at+20,a);w32(p,at+36,f);
}
static unsigned char *fixture(unsigned machine){
    static const char*names[]={"ios_xp_nt","ios_xp_nt_write_contract","ios_srw_ring",
                             "ios_srw_ring_idx","ios_srw_history_write_contract"};
    static const unsigned rvas[]={COUNTER,COUNTER_CONTRACT,RING,INDEX,HISTORY};
    unsigned char*p=calloc(1,SIZE);assert(p);p[0]='M';p[1]='Z';w32(p,60,PE);memcpy(p+PE,"PE\0\0",4);
    w16(p,PE+4,machine);w16(p,PE+6,3);w16(p,PE+20,0xf0);w16(p,OPT,0x20b);
    w64(p,OPT+24,UINT64_C(0x180000000));w32(p,OPT+56,SIZE);w32(p,OPT+108,16);
    w32(p,OPT+112,0x1000);w32(p,OPT+116,0x1000);
    section(p,0,".edata",0x1000,0x1000,0x40000040);
    section(p,1,".text",0x2000,0x1000,0x60000020);
    section(p,2,".data",0x4000,0x11000,0xc0000040);
    w32(p,0x1000+20,5);w32(p,0x1000+24,5);w32(p,0x1000+28,0x1100);
    w32(p,0x1000+32,0x1120);w32(p,0x1000+36,0x1140);
    for(unsigned i=0;i<5;i++){
        w32(p,0x1100+4*i,rvas[i]);w32(p,0x1120+4*i,0x1200+i*64);w16(p,0x1140+2*i,i);
        memcpy(p+0x1200+i*64,names[i],strlen(names[i])+1);
    }
    w64(p,COUNTER_CONTRACT,MADEIRA_NATIVE_COUNTER_ABI_V1);
    w32(p,COUNTER_CONTRACT+8,MADEIRA_NATIVE_COUNTER_BYTES);
    w64(p,HISTORY,MADEIRA_NATIVE_SRW_ABI_V1);w32(p,HISTORY+8,MADEIRA_NATIVE_SRW_RING_BYTES);
    w32(p,HISTORY+12,MADEIRA_NATIVE_SRW_ENTRY_BYTES);
    return p;
}
static void accepted(unsigned machine){
    unsigned char*p=fixture(machine),*before=malloc(SIZE),*child=fixture(machine);assert(before);
    memcpy(before,p,SIZE);
    assert(ios_native_counter_alias_bind(p,SIZE,rx,delta,1));
    assert(ios_native_srw_alias_bind(p,SIZE,rx,delta,1));
    assert(pointer(p,HISTORY+16)==rx+RING+delta && pointer(p,HISTORY+24)==rx+INDEX+delta);
    for(size_t a=0;a<SIZE;a++){
        if((a>=COUNTER_CONTRACT+16&&a<COUNTER_CONTRACT+24)||(a>=HISTORY+16&&a<HISTORY+32))continue;
        assert(p[a]==before[a]);
    }
    memcpy(child,p,SIZE); /* An unpublished child must not adopt parent pointers. */
    assert(ios_native_counter_alias_bind(child,SIZE,other,delta,1));
    assert(ios_native_srw_alias_bind(child,SIZE,other,delta,1));
    assert(pointer(child,HISTORY+16)==other+RING+delta && pointer(child,HISTORY+24)==other+INDEX+delta);
    memcpy(before,p,SIZE);
    assert(!ios_native_srw_alias_bind(p,SIZE,other,delta,0) && !memcmp(before,p,SIZE));
    free(child);free(before);free(p);checks++;
}
static void rejected(unsigned char*p,const char*why){
    unsigned char*before=malloc(SIZE);assert(before);memcpy(before,p,SIZE);
    if(ios_native_srw_alias_bind(p,SIZE,rx,delta,1)||memcmp(before,p,SIZE)){
        fprintf(stderr,"invalid SRW contract accepted: %s\n",why);abort();
    }
    free(before);free(p);checks++;
}
static void negatives(void){
    unsigned char*p;
#define BAD(label,edit) do{p=fixture(0x8664);edit;rejected(p,label);}while(0)
    BAD("unknown SRW magic",w64(p,HISTORY,0));
    BAD("short ring",w32(p,HISTORY+8,4096));
    BAD("wrong entry width",w32(p,HISTORY+12,8));
    BAD("unknown existing counter ABI",w64(p,COUNTER_CONTRACT,0));
    BAD("I386 cannot bind native aliases",w16(p,PE+4,0x14c));
    BAD("PE32 cannot bind native aliases",w16(p,OPT,0x10b));
    BAD("ring outside writable DATA",w32(p,0x1100+8,0x17000));
    BAD("ring overlaps old counters",w32(p,0x1100+8,COUNTER+8));
    BAD("ring overlaps old contract",w32(p,0x1100+8,COUNTER_CONTRACT));
    BAD("index overlaps ring",w32(p,0x1100+12,RING+4));
    BAD("contract overlaps ring",w32(p,0x1100+16,RING));
    BAD("unaligned index",w32(p,0x1100+12,INDEX+1));
    BAD("unaligned contract",w32(p,0x1100+16,HISTORY+1));
    BAD("forwarded private export",w32(p,0x1100+8,0x1200));
    BAD("duplicate private export",w32(p,0x1120+12,0x1280));
    BAD("executable DATA",w32(p,TABLE+2*40+36,0xe0000040));
    BAD("shared DATA",w32(p,TABLE+2*40+36,0xd0000040));
    BAD("discardable DATA",w32(p,TABLE+2*40+36,0xc2000040));
    BAD("missing export",p[0x1200+128]='X');
    BAD("partial ring extent",w32(p,TABLE+2*40+8,RING+8191-0x4000));
#undef BAD
    p=fixture(0xaa64);assert(!ios_native_srw_alias_bind(p,SIZE,rx,0,1));
    assert(!ios_native_srw_alias_bind(p,SIZE,rx,1,1));assert(!ios_native_srw_alias_bind(p,SIZE,rx,-0x4000,1));
    assert(!ios_native_srw_alias_bind(p,SIZE,UINTPTR_MAX-SIZE,delta,1));free(p);checks+=4;
}
static void synchronize(void){
    static const size_t slots[]={COUNTER_CONTRACT+16,HISTORY+16,HISTORY+24};
    unsigned char*p=fixture(0x8664),*source=fixture(0x8664),*before=malloc(SIZE);assert(before);
    assert(ios_native_counter_alias_bind(p,SIZE,rx,delta,1));
    assert(ios_native_srw_alias_bind(p,SIZE,rx,delta,1));
    /* Even a parent-pointer-bearing sync source cannot rebind a live child. */
    w64(source,COUNTER_CONTRACT+16,other+COUNTER+delta);
    w64(source,HISTORY+16,other+RING+delta);w64(source,HISTORY+24,other+INDEX+delta);
    for(unsigned slot=0;slot<3;slot++)for(int start=-4;start<=12;start++)for(unsigned n=1;n<=20;n++){
        size_t at=slots[slot]+start;memcpy(before,p,SIZE);
        memset(source+at,0xa5,n);
        assert(ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,at,source+at,n));
        for(size_t i=0;i<SIZE;i++){
            int protected=0;for(unsigned k=0;k<3;k++)if(i>=slots[k]&&i<slots[k]+8)protected=1;
            assert(p[i]==((i>=at&&i<at+n&&!protected)?source[i]:before[i]));
        }
        memcpy(p,before,SIZE);memcpy(source,before,SIZE);
        checks++;
    }
    memset(source+RING,0x9b,8192);w32(source,INDEX,UINT32_MAX);
    w64(source,COUNTER_CONTRACT+16,other+COUNTER+delta);w64(source,HISTORY+16,0);w64(source,HISTORY+24,0);
    assert(ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,0,source,SIZE));
    assert(pointer(p,HISTORY+16)==rx+RING+delta && pointer(p,HISTORY+24)==rx+INDEX+delta);
    assert(pointer(p,COUNTER_CONTRACT+16)==rx+COUNTER+delta);
    assert(!memcmp(p+RING,source+RING,8192) && ios_native_u32(p+INDEX)==UINT32_MAX);
    assert(!ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,SIZE-1,source,2));
    assert(!ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,0,NULL,1));
    free(before);free(source);free(p);checks+=4;
}
static void four_aligned_index(void){
    unsigned char*p=fixture(0x8664);
    /* LONG needs four-byte alignment, independently of eight-byte contract
     * pointers and entries. A linker may place it at 4 modulo 8. */
    w32(p,0x1100+12,INDEX+4);
    assert(ios_native_srw_alias_bind(p,SIZE,rx,delta,1));
    assert(pointer(p,HISTORY+24)==rx+INDEX+4+delta);
    free(p);checks++;
}
struct reader_state { unsigned char *image; atomic_uint started,done,bad; atomic_ulong polls; };
static void *read_private_writers(void *opaque){
    struct reader_state*s=opaque;
    atomic_fetch_add(&s->started,1);
    do{
        uintptr_t counter=__atomic_load_n((uintptr_t *)(s->image+COUNTER_CONTRACT+16),__ATOMIC_ACQUIRE);
        uintptr_t ring=__atomic_load_n((uintptr_t *)(s->image+HISTORY+16),__ATOMIC_ACQUIRE);
        uintptr_t index=__atomic_load_n((uintptr_t *)(s->image+HISTORY+24),__ATOMIC_ACQUIRE);
        if(counter!=rx+COUNTER+delta || ring!=rx+RING+delta || index!=rx+INDEX+delta)
            atomic_fetch_add(&s->bad,1);
        atomic_fetch_add(&s->polls,1);
    }while(!atomic_load(&s->done));
    return NULL;
}
static void concurrent_private_writer_refresh(void){
    unsigned char*p=fixture(0x8664),*source=fixture(0x8664);
    assert(ios_native_counter_alias_bind(p,SIZE,rx,delta,1));
    assert(ios_native_srw_alias_bind(p,SIZE,rx,delta,1));
    /* The original counter-only copy function copies the two new NULL file
     * pointers. The combined production entry must never create this window. */
    assert(ios_native_counter_alias_copy(p,SIZE,rx,delta,HISTORY,source+HISTORY,32));
    assert(!pointer(p,HISTORY+16)&&!pointer(p,HISTORY+24));
    assert(ios_native_srw_alias_bind(p,SIZE,rx,delta,1)); /* before publication */
    struct reader_state state={.image=p};pthread_t readers[2];
    for(unsigned i=0;i<2;i++)assert(!pthread_create(&readers[i],NULL,read_private_writers,&state));
    while(atomic_load(&state.started)!=2){}
    for(unsigned i=0;i<4000;i++){
        assert(ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,HISTORY-8,source+HISTORY-8,48));
        assert(ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,COUNTER_CONTRACT-8,source+COUNTER_CONTRACT-8,48));
    }
    atomic_store(&state.done,1);
    for(unsigned i=0;i<2;i++)assert(!pthread_join(readers[i],NULL));
    assert(!atomic_load(&state.bad)&&atomic_load(&state.polls)>=2);
    /* Diagnostic payload refresh semantics are unchanged. This test asserts
     * immutable private writer publication, not retention of stale payload. */
    free(source);free(p);checks++;
}
int main(void){
    (void)ios_native_atomic_image_lower; /* Shared PE validators also include the unrelated code planner. */
    accepted(0xaa64);accepted(0x8664);accepted(0xa641);negatives();synchronize();four_aligned_index();
    concurrent_private_writer_refresh();
    printf("PASS production SRW history alias: %u contracts/copy boundaries; original data retained, private child binding, all three writer slots stable during8000 concurrent refreshes, malformed/mismatched layouts refused\n",checks);
}
