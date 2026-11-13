/* SPDX-License-Identifier: MIT. Real source-built FEX diagnostic writer ABI. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "native_fex_diagnostics_alias.h"
#include "native_srw_alias.h"

enum { SIZE=0x20000,PE=0x80,OPT=PE+24,TABLE=OPT+0xf0,CONTRACT=0x5000,
       FUNCTIONS=0x1100,NAMES=0x1120,ORDINALS=0x1140,MODULE=0x1180,DIAGNOSTICS=5 };
static const uintptr_t preferred=UINT64_C(0x180000000),source=UINT64_C(0x500000000),
    rx=UINT64_C(0x300000000),other=UINT64_C(0x380000000);
static const intptr_t delta=0x48000000;
static const unsigned payloads[]={0x6000,0x6200,0x6400,0x6600,0x8000};
static const unsigned lengths[]={136,32,48,192,35968};
static const char *names[]={"MadeiraFEXTelemetryWriteContract","MadeiraFEXIRTopoWriteContract",
                            "MadeiraFEXCompileWriteContract","MadeiraFEXHistoryWriteContract","MadeiraFEXTransitionWriteContract"};
/* Tags follow the production ABI, rather than a parallel definition. */
static const uint64_t tags[]={MADEIRA_FEX_TELEMETRY_TAG,MADEIRA_FEX_IRTOPO_TAG,
                              MADEIRA_FEX_COMPILE_TAG,MADEIRA_FEX_HISTORY_TAG,MADEIRA_FEX_TRANSITION_TAG};
static unsigned checks;
static void w16(unsigned char*p,size_t a,uint16_t n){memcpy(p+a,&n,2);}
static void w32(unsigned char*p,size_t a,uint32_t n){memcpy(p+a,&n,4);}
static void w64(unsigned char*p,size_t a,uint64_t n){memcpy(p+a,&n,8);}
static uintptr_t pointer(const unsigned char*p,size_t a){uintptr_t n;memcpy(&n,p+a,8);return n;}
static size_t slot(unsigned i){return CONTRACT+64*i+24;}
static void section(unsigned char*p,unsigned i,const char*name,uint32_t a,uint32_t n,uint32_t f){
    size_t at=TABLE+40*i;memcpy(p+at,name,strlen(name));w32(p,at+8,n);w32(p,at+12,a);
    w32(p,at+16,n);w32(p,at+20,a);w32(p,at+36,f);
}
static unsigned char *fixture(unsigned machine,uintptr_t domain){
    unsigned char*p=calloc(1,SIZE);assert(p);p[0]='M';p[1]='Z';w32(p,60,PE);memcpy(p+PE,"PE\0\0",4);
    w16(p,PE+4,machine);w16(p,PE+6,3);w16(p,PE+20,0xf0);w16(p,OPT,0x20b);
    w64(p,OPT+24,preferred);w32(p,OPT+56,SIZE);w32(p,OPT+108,16);
    w32(p,OPT+112,0x1000);w32(p,OPT+116,0x1000);
    section(p,0,".edata",0x1000,0x1000,0x40000040);
    section(p,1,".text",0x2000,0x1000,0x60000020);
    section(p,2,".data",0x4000,0x14000,0xc0000040);
    w32(p,0x1000+12,MODULE);memcpy(p+MODULE,"libarm64ecfex.dll",17);
    w32(p,0x1000+20,DIAGNOSTICS+1);w32(p,0x1000+24,DIAGNOSTICS+1);w32(p,0x1000+28,FUNCTIONS);
    w32(p,0x1000+32,NAMES);w32(p,0x1000+36,ORDINALS);
    for(unsigned i=0;i<DIAGNOSTICS;i++){
        w32(p,FUNCTIONS+4*i,CONTRACT+64*i);w32(p,NAMES+4*i,0x1200+64*i);w16(p,ORDINALS+2*i,i);
        memcpy(p+0x1200+64*i,names[i],strlen(names[i])+1);
        w64(p,CONTRACT+64*i,tags[i]);w32(p,CONTRACT+64*i+8,lengths[i]);
        w32(p,CONTRACT+64*i+12,i==4?64:8);w64(p,CONTRACT+64*i+16,domain+payloads[i]);
        memset(p+payloads[i],0xa0+i,lengths[i]);
    }
    w32(p,FUNCTIONS+4*DIAGNOSTICS,payloads[4]);w32(p,NAMES+4*DIAGNOSTICS,0x1400);
    w16(p,ORDINALS+2*DIAGNOSTICS,DIAGNOSTICS);memcpy(p+0x1400,"IosXpFex",9);
    return p;
}
static unsigned char *wow_fixture(void){
    unsigned char*p=fixture(0xaa64,preferred);
    memset(p+MODULE,0,64);memcpy(p+MODULE,"libwow64fex.dll",15);
    memset(p+0x1300,0,64);memcpy(p+0x1300,"MadeiraFEXSyscallWriteContract",30);
    memset(p+0x1400,0,64);memcpy(p+0x1400,"MadeiraFEXSyscallDeclined",25);
    w64(p,CONTRACT+4*64,MADEIRA_FEX_SYSCALL_TAG);
    w32(p,CONTRACT+4*64+8,4);w32(p,CONTRACT+4*64+12,4);
    return p;
}
static void check_layout(unsigned char*p,uintptr_t use_rx){
    struct ios_native_fex_diagnostics_layout layout;
    assert(ios_native_fex_diagnostics_layout_read(p,SIZE,source,use_rx,delta,&layout));
    assert(layout.spans==DIAGNOSTICS);
    for(unsigned i=0;i<DIAGNOSTICS;i++){
        assert(layout.slots[i]==slot(i));assert(layout.payloads[i]==payloads[i]);
        assert(layout.values[i]==use_rx+payloads[i]+delta);
    }
}
static void accepted(void){
    static const unsigned machines[]={0xaa64,0xa641};
    static const uintptr_t domains[]={UINT64_C(0x180000000),UINT64_C(0x500000000),
                                      UINT64_C(0x300000000),UINT64_C(0x348000000)};
    for(unsigned m=0;m<2;m++)for(unsigned d=0;d<4;d++){
        unsigned char*p=fixture(machines[m],domains[d]),*before=malloc(SIZE);assert(before);
        memcpy(before,p,SIZE);check_layout(p,rx);
        assert(ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1));
        for(unsigned i=0;i<DIAGNOSTICS;i++)assert(pointer(p,slot(i))==rx+payloads[i]+delta);
        for(size_t a=0;a<SIZE;a++){
            int changed=0;for(unsigned i=0;i<DIAGNOSTICS;i++)if(a>=slot(i)&&a<slot(i)+8)changed=1;
            if(!changed)assert(p[a]==before[a]);
        }
        memcpy(before,p,SIZE);
        assert(!ios_native_fex_diagnostics_bind(p,SIZE,source,other,delta,0));
        assert(!memcmp(before,p,SIZE));free(before);free(p);checks++;
    }
    /* Every PE copy gets its own writer; a copied parent's writer is never
     * followed/adopted. Canonical preferred-address payload proof is retained. */
    unsigned char*p=fixture(0xa641,preferred),*child=malloc(SIZE);assert(child);
    assert(ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1));memcpy(child,p,SIZE);
    assert(ios_native_fex_diagnostics_bind(child,SIZE,source,other,delta,1));
    for(unsigned i=0;i<DIAGNOSTICS;i++)assert(pointer(child,slot(i))==other+payloads[i]+delta);
    free(child);free(p);checks++;
    /* The shipped ARM64EC CPU retains an AMD64 header. Its real native code
     * map, rather than that header alone, supplies the architecture proof. */
    p=fixture(0x8664,preferred);
    w32(p,OPT+112+10*8,0x1800);w32(p,OPT+116+10*8,208);
    w32(p,0x1800,208);w64(p,0x1800+200,preferred+0x1900);
    w32(p,0x1900,1);w32(p,0x1904,0x1920);w32(p,0x1908,1);
    w32(p,0x1920,0x2001);w32(p,0x1924,0x1000);
    check_layout(p,rx);assert(ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1));
    free(p);checks++;
    p=wow_fixture();check_layout(p,rx);
    assert(ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1)==DIAGNOSTICS);
    assert(pointer(p,slot(4))==rx+payloads[4]+delta);free(p);checks++;
}
static void rejected(unsigned char*p,const char*why){
    unsigned char*before=malloc(SIZE);assert(before);memcpy(before,p,SIZE);
    struct ios_native_fex_diagnostics_layout layout;
    if(ios_native_fex_diagnostics_layout_read(p,SIZE,source,rx,delta,&layout)||
       ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1)||memcmp(before,p,SIZE)){
        fprintf(stderr,"invalid FEX diagnostic contract accepted: %s\n",why);abort();
    }
    free(before);free(p);checks++;
}
static void negatives(void){
    unsigned char*p;
#define BAD(label,edit) do{p=fixture(0xa641,preferred);edit;rejected(p,label);}while(0)
    BAD("unknown ABI",w64(p,CONTRACT,0));
    BAD("wrong payload bytes",w32(p,CONTRACT+8,128));
    BAD("wrong payload alignment",w32(p,CONTRACT+12,4));
    BAD("foreign canonical pointer",w64(p,CONTRACT+16,other+payloads[0]));
    BAD("null canonical pointer",w64(p,CONTRACT+16,0));
    BAD("pointer overflow",w64(p,CONTRACT+16,UINT64_MAX-7));
    BAD("unaligned payload",w64(p,CONTRACT+16,preferred+payloads[0]+1));
    BAD("payload outside DATA",w64(p,CONTRACT+16,preferred+0x3000));
    BAD("payload crosses DATA end",w64(p,CONTRACT+16,preferred+0x17ff8));
    BAD("contract overlaps payload",w64(p,CONTRACT+16,preferred+CONTRACT));
    BAD("payload overlaps other payload",w64(p,CONTRACT+16,preferred+payloads[1]));
    BAD("payload overlaps other contract",w64(p,CONTRACT+16,preferred+CONTRACT+64));
    BAD("unaligned contract",w32(p,FUNCTIONS,CONTRACT+1));
    BAD("duplicate contract export",w32(p,NAMES+4,0x1200));
    BAD("forwarded export",w32(p,FUNCTIONS,0x1200));
    BAD("missing contract export",p[0x1200]='X');
    BAD("bad ordinal",w16(p,ORDINALS,DIAGNOSTICS+1));
    BAD("truncated export table",w32(p,0x1000+28,SIZE-4));
    BAD("section overlap",w32(p,TABLE+2*40+12,0x2800));
    BAD("executable DATA",w32(p,TABLE+2*40+36,0xe0000040));
    BAD("shared DATA",w32(p,TABLE+2*40+36,0xd0000040));
    BAD("discardable DATA",w32(p,TABLE+2*40+36,0xc2000040));
    BAD("nonwritable DATA",w32(p,TABLE+2*40+36,0x40000040));
    BAD("PE32",w16(p,OPT,0x10b));
    BAD("I386",w16(p,PE+4,0x14c));
    BAD("AMD64 guest image",w16(p,PE+4,0x8664));
    BAD("foreign module name",p[MODULE]='X');
    BAD("wrong image size",w32(p,OPT+56,SIZE-0x1000));
    BAD("missing transition contract",p[0x1300]='X');
    BAD("wrong transition tag",w64(p,CONTRACT+4*64,0));
    BAD("wrong transition length",w32(p,CONTRACT+4*64+8,35960));
    BAD("wrong transition alignment",w32(p,CONTRACT+4*64+12,8));
    BAD("missing IosXpFex export",p[0x1400]='X');
    BAD("transition is another DATA object",w64(p,CONTRACT+4*64+16,preferred+0x9000));
    BAD("unaligned IosXpFex export",w32(p,FUNCTIONS+4*DIAGNOSTICS,payloads[4]+8));
    BAD("writer relocation",w32(p,OPT+152,0x1a00);w32(p,OPT+156,12);
        w32(p,0x1a00,CONTRACT);w32(p,0x1a04,12);w16(p,0x1a08,0xa018));
#undef BAD
    p=wow_fixture();w32(p,CONTRACT+4*64+8,8);rejected(p,"WOW counter width changed");
    p=wow_fixture();w32(p,CONTRACT+4*64+12,8);rejected(p,"WOW counter alignment changed");
    p=wow_fixture();w64(p,CONTRACT+4*64+16,preferred+0x8008);rejected(p,"WOW writer targets another object");
    p=wow_fixture();p[0x1400]='X';rejected(p,"WOW counter export missing");
    p=fixture(0xaa64,preferred);
    assert(!ios_native_fex_diagnostics_bind(p,SIZE,source,rx,0,1));
    assert(!ios_native_fex_diagnostics_bind(p,SIZE,source,rx,1,1));
    assert(!ios_native_fex_diagnostics_bind(p,SIZE,source,rx,-0x4000,1));
    assert(!ios_native_fex_diagnostics_bind(p,SIZE,source,UINTPTR_MAX-SIZE,delta,1));
    free(p);checks+=4;
}
static int protected_byte(size_t a){
    for(unsigned i=0;i<DIAGNOSTICS;i++)if(a>=slot(i)-24&&a<slot(i)+8)return 1;
    return 0;
}
static void synchronize(void){
    unsigned char*p=fixture(0xa641,preferred),*src=fixture(0xa641,preferred),*before=malloc(SIZE);
    assert(before);assert(ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1));
    /* Reproduce the former production generic ntdll-only sync: it knows no FEX
     * private writer slots and copies their file-NULL values into a live copy. */
    memcpy(before,p,SIZE);
    assert(ios_native_counter_and_srw_alias_copy(p,SIZE,rx,delta,CONTRACT,src+CONTRACT,DIAGNOSTICS*64));
    for(unsigned i=0;i<DIAGNOSTICS;i++)assert(!pointer(p,slot(i)));
    memcpy(p,before,SIZE);checks++;
    /* Unbound valid descriptors retain ordinary copy semantics. A malformed
     * contract is refused without following either source/current writer. */
    unsigned char *unbound=fixture(0xa641,preferred);
    assert(ios_native_fex_diagnostics_copy(unbound,SIZE,source,rx,delta,0,src,SIZE));
    assert(!memcmp(unbound,src,SIZE));w64(unbound,CONTRACT,0);
    memcpy(before,unbound,SIZE);
    assert(!ios_native_fex_diagnostics_copy(unbound,SIZE,source,rx,delta,0,src,SIZE));
    assert(!memcmp(unbound,before,SIZE));free(unbound);checks+=2;
    memcpy(before,p,SIZE);
    for(unsigned which=0;which<DIAGNOSTICS;which++)for(int displacement=-12;displacement<16;displacement++)
    for(unsigned n=1;n<=32;n++){
        size_t at=slot(which)+displacement;memcpy(before,p,SIZE);memset(src+at,0x5a,n);
        assert(ios_native_fex_diagnostics_copy(p,SIZE,source,rx,delta,at,src+at,n));
        for(size_t a=0;a<SIZE;a++)assert(p[a]==((a>=at&&a<at+n&&!protected_byte(a))?src[a]:before[a]));
        memcpy(p,before,SIZE);memcpy(src,before,SIZE);checks++;
    }
    /* Whole-image source refresh must not adopt NULL or copied-parent writers. */
    for(unsigned i=0;i<DIAGNOSTICS;i++){
        w64(src,slot(i),i?other+payloads[i]+delta:0);
        w64(src,slot(i)-8,other+payloads[i]);
        w32(src,slot(i)-16,999);w64(src,slot(i)-24,0);
        memset(src+payloads[i],0x70+i,lengths[i]);
    }
    assert(ios_native_fex_diagnostics_copy(p,SIZE,source,rx,delta,0,src,SIZE));
    for(unsigned i=0;i<DIAGNOSTICS;i++){
        assert(pointer(p,slot(i))==rx+payloads[i]+delta);
        assert(!memcmp(p+slot(i)-24,before+slot(i)-24,32));
        assert(!memcmp(p+payloads[i],src+payloads[i],lengths[i]));
    }
    assert(!ios_native_fex_diagnostics_copy(p,SIZE,source,rx,delta,SIZE-1,src,2));
    assert(!ios_native_fex_diagnostics_copy(p,SIZE,source,rx,delta,0,NULL,1));
    free(before);free(src);free(p);checks+=3;
}
struct readers {unsigned char*image;atomic_uint started,done,bad;atomic_ulong polls;};
static void *read_writers(void*opaque){
    struct readers*r=opaque;atomic_fetch_add(&r->started,1);
    do{
        for(unsigned i=0;i<DIAGNOSTICS;i++)if(__atomic_load_n((uintptr_t*)(r->image+slot(i)),__ATOMIC_ACQUIRE)!=rx+payloads[i]+delta)
            atomic_fetch_add(&r->bad,1);
        struct ios_native_fex_diagnostics_layout layout;
        if(!ios_native_fex_diagnostics_layout_read(r->image,SIZE,source,rx,delta,&layout))
            atomic_fetch_add(&r->bad,1);
        atomic_fetch_add(&r->polls,1);
    }while(!atomic_load(&r->done));return NULL;
}
static void concurrent_refresh(void){
    unsigned char*p=fixture(0xa641,preferred),*src=fixture(0xa641,preferred);
    assert(ios_native_fex_diagnostics_bind(p,SIZE,source,rx,delta,1));
    for(unsigned i=0;i<DIAGNOSTICS;i++){
        /* Deliberately wrong incoming metadata must never become visible to
         * a concurrent getter/proof, even through one-byte refresh slices. */
        w64(src,slot(i)-24,0);w64(src,slot(i)-8,other+payloads[i]);
        w64(src,slot(i),other+payloads[i]+delta);
    }
    struct readers state={.image=p};pthread_t readers[2];
    for(unsigned i=0;i<2;i++)assert(!pthread_create(&readers[i],NULL,read_writers,&state));
    while(atomic_load(&state.started)!=2){}
    for(unsigned n=0;n<4000;n++)for(unsigned i=0;i<DIAGNOSTICS;i++){
        size_t first=slot(i)-24+n%32,bytes=32-n%32;
        assert(ios_native_fex_diagnostics_copy(p,SIZE,source,rx,delta,first,src+first,bytes));
    }
    atomic_store(&state.done,1);for(unsigned i=0;i<2;i++)assert(!pthread_join(readers[i],NULL));
    assert(!atomic_load(&state.bad)&&atomic_load(&state.polls)>=2);
    free(src);free(p);checks++;
}
int main(void){
    (void)ios_native_atomic_image_lower;
    (void)ios_native_srw_alias_bind;
    (void)ios_native_counter_alias_bind;
    accepted();negatives();synchronize();concurrent_refresh();
    printf("PASS production FEX diagnostics alias: %u native contracts/copy boundaries; preferred/source/RX/RW proof, foreign/malformed spans refused, old production sync loses writers, new private writer publication stable in20000 concurrent refreshes\n",checks);
}
