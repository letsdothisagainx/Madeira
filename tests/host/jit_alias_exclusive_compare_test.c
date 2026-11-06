/* SPDX-License-Identifier: MIT. Production helpers/tokens/route unchanged. */
#include <stdlib.h>
#include "compare-production.h"
static unsigned cases;
static struct compare_witness active;
static uintptr_t start(void){return (uintptr_t)rx+0x100;}
static uintptr_t pc(void){return start()+20;}
static uintptr_t target(void){return (uintptr_t)rx+mapped_size/2+0x100;}
static uint64_t value(void){return __atomic_load_n((uint64_t *)(rw+mapped_size/2+0x100),__ATOMIC_SEQ_CST);}
static void put(uint64_t n){__atomic_store_n((uint64_t *)(rw+mapped_size/2+0x100),n,__ATOMIC_SEQ_CST);}
static void setreg(struct state *s,unsigned reg,uint64_t n)
{assert(reg<31);if(reg<29)s->__x[reg]=n;else if(reg==29)s->__fp=n;else s->__lr=n;}
static uint64_t reg(const struct state *s,unsigned r)
{return r<29?s->__x[r]:r==29?s->__fp:r==30?s->__lr:s->__sp;}
static void ranges(void)
{
    ios_jit_mappings[0].text_size=0;ios_jit_mappings[0].code_range_count=3;
    ios_jit_mappings[0].code_ranges[0].offset=0x100;ios_jit_mappings[0].code_ranges[0].size=28;
    ios_jit_mappings[0].code_ranges[1].offset=0x100+active.mismatch;ios_jit_mappings[0].code_ranges[1].size=8;
    ios_jit_mappings[0].code_ranges[2].offset=0x100+active.continuation;ios_jit_mappings[0].code_ranges[2].size=4;
}
static void install(const struct compare_witness *w)
{
    active=*w;memset(rw,0,mapped_size/2);
    assert(0x100+w->mismatch+8<mapped_size/2);
    memcpy(rw+0x100,w->core,28);memcpy(rw+0x100+w->mismatch,w->cleanup,8);
    memcpy(rw+0x100+w->continuation,&w->next,4);ranges();
}
static void code_intact(void)
{
    assert(!memcmp(rx+0x100,active.core,28));
    assert(!memcmp(rx+0x100+active.mismatch,active.cleanup,8));
    assert(!memcmp(rx+0x100+active.continuation,&active.next,4));
}
static void initial(struct state *s,uint64_t expected,uint64_t desired)
{
    memset(s,0,sizeof(*s));for(unsigned n=0;n<29;n++)s->__x[n]=UINT64_C(0xfeed000000000000)|n;
    s->__fp=0xfeed000000000029;s->__lr=0xfeed000000000030;s->__sp=0x700000000;s->__pc=pc();s->__cpsr=0x60000000;
    setreg(s,active.roles[0],target()-((active.core[0]>>10)&0xfff));
    setreg(s,active.roles[1],target());setreg(s,active.roles[2],target());
    setreg(s,active.roles[3],expected);setreg(s,active.roles[4],desired);setreg(s,active.roles[5],UINT64_MAX);
}
static void verify(const struct state *before,const struct state *after,unsigned status)
{
    struct state want=*before;want.__pc+=4;setreg(&want,active.roles[5],status);
    assert(!memcmp(&want,after,sizeof(want)));code_intact();
    assert(reg(after,active.roles[3])==reg(before,active.roles[3]));
    assert(reg(after,active.roles[2])==target()); /* clobbered loaded reg stays address */
}
static void accepted(uint64_t expected,uint64_t actual,uint64_t desired)
{
    struct state s,before;initial(&s,expected,desired);before=s;put(actual);
    assert(route(active.core[5],target(),&s,NULL));unsigned status=actual!=expected;
    verify(&before,&s,status);assert(value()==(status?actual:desired));
    uint32_t retry;memcpy(&retry,(void *)s.__pc,4);
    int64_t offset=(int64_t)(int32_t)(retry<<8)>>13;
    assert(s.__pc+offset*4==start()+4); /* original failed STXR retries LDXR */
    cases++;
}
static void refused(struct state *s,uintptr_t addr)
{
    struct state before=*s;uint64_t old=value();
    assert(!route(active.core[5],addr,s,NULL));assert(!memcmp(s,&before,sizeof(before))&&value()==old);cases++;
}
static void generation_reject(uintptr_t query,unsigned mapping)
{
    struct state s;uint64_t gp[32],saved[32];initial(&s,10,20);
    memcpy(gp,s.__x,sizeof(s.__x));gp[29]=s.__fp;gp[30]=s.__lr;gp[31]=s.__sp;memcpy(saved,gp,sizeof(gp));
    mutate_at=query;mutate_generation=mapping+1;uint64_t old=value();
    assert(!ios_mach_emulate_exclusive_compare_loop(active.core[5],pc(),target(),gp,s.__cpsr,(void *)0x1111));
    assert(!memcmp(gp,saved,sizeof(gp))&&value()==old&&!mutate_generation);mutate_at=0;cases++;
}
int main(void)
{
    mapped_size=2*(size_t)sysconf(_SC_PAGESIZE);FILE *file=tmpfile();assert(file&&!ftruncate(fileno(file),mapped_size));
    rw=mmap(NULL,mapped_size,PROT_READ|PROT_WRITE,MAP_SHARED,fileno(file),0);
    rx=mmap(NULL,mapped_size,PROT_READ|PROT_EXEC,MAP_SHARED,fileno(file),0);
    assert(rw!=MAP_FAILED&&rx!=MAP_FAILED);memset(rw,0,mapped_size);
    ios_jit_rx_base_global=rx;ios_jit_rw_base_global=rw;ios_jit_pool_size_global=mapped_size;ios_jit_mapping_count=2;
    for(unsigned n=0;n<2;n++){
        ios_jit_mappings[n].pe_base=(void *)(uintptr_t)(0x100000000ull+n*0x1000000);
        ios_jit_mappings[n].jit_base=rx+n*mapped_size/2;ios_jit_mappings[n].size=mapped_size/2;
        ios_jit_mappings[n].generation=ios_jit_new_generation();
    }
    install(&witnesses[1]);struct state s,before;initial(&s,10,20);before=s;put(10);
    /* Give prior helpers their entire requested window. They still reject the
     * new shape by instruction/operand/branch predicates, not missing EXEC. */
    ios_jit_mappings[0].code_range_count=0;ios_jit_mappings[0].text_offset=0x100;
    ios_jit_mappings[0].text_size=mapped_size/2-0x100;
    uint64_t gp[32],saved[32];memcpy(gp,s.__x,sizeof(s.__x));gp[29]=s.__fp;gp[30]=s.__lr;gp[31]=s.__sp;memcpy(saved,gp,sizeof(gp));
    assert(!ios_mach_emulate_exclusive_loop(active.core[5],pc(),target(),gp,(void *)0x1111));
    assert(!ios_mach_emulate_exclusive_add_loop(active.core[5],pc(),target(),gp,(void *)0x1111));
    assert(!ios_mach_emulate_exclusive_conditional_loop(active.core[5],pc(),target(),gp,s.__cpsr,(void *)0x1111));
    assert(!memcmp(gp,saved,sizeof(gp))&&value()==10);
    assert(!old_route(active.core[5],(uintptr_t)rw+mapped_size/2+0x100,target(),&s));
    assert(!memcmp(&s,&before,sizeof(s))&&value()==10);ranges();
    puts("PASS prior production control: exact C80C7D69 refused by all three existing helpers and inline handler, no mutation");
    for(unsigned n=0;n<sizeof(witnesses)/sizeof(witnesses[0]);n++){
        install(&witnesses[n]);accepted(10,10,20);accepted(10,11,20);
        accepted(10,10,1);accepted(10,10,10);accepted(0,0,0);accepted(UINT64_MAX,UINT64_MAX,0);
    }
    install(&witnesses[1]);
    for(unsigned n=0;n<7;n++){
        uint32_t bad=0xffffffff;memcpy(rw+0x100+n*4,&bad,4);initial(&s,10,20);refused(&s,target());install(&witnesses[1]);
    }
    for(unsigned n=0;n<2;n++){
        uint32_t bad=0xffffffff;memcpy(rw+0x100+active.mismatch+n*4,&bad,4);initial(&s,10,20);refused(&s,target());install(&witnesses[1]);
    }
    /* Valid ARM64 encodings with unsupported control flow must also fail. */
    uint32_t wrong=active.core[3]+(1u<<5); /* B.NE into B, past CLREX */
    memcpy(rw+0x100+3*4,&wrong,4);initial(&s,10,20);refused(&s,target());install(&witnesses[1]);
    wrong=active.core[6]+(1u<<5); /* CBNZ into CMP instead of reloading */
    memcpy(rw+0x100+6*4,&wrong,4);initial(&s,10,20);refused(&s,target());install(&witnesses[1]);
    wrong=0x14000000; /* cleanup B to itself */
    memcpy(rw+0x100+active.mismatch+4,&wrong,4);initial(&s,10,20);refused(&s,target());install(&witnesses[1]);
    initial(&s,10,20);
    for(unsigned n=0;n<3;n++)setreg(&s,active.roles[n],reg(&s,active.roles[n])+1);
    refused(&s,target()+1);
    const uint32_t bad_flags[]={0,0x40000000,0xe0000000,0x70000000};
    for(unsigned n=0;n<4;n++){initial(&s,10,20);s.__cpsr=bad_flags[n];refused(&s,target());}
    for(unsigned n=0;n<3;n++){initial(&s,10,20);setreg(&s,active.roles[n],reg(&s,active.roles[n])+8);refused(&s,target());}
    initial(&s,10,20);refused(&s,target()+8);
    permit_read=0;initial(&s,10,20);refused(&s,target());permit_read=1;
    permit_write=0;initial(&s,10,20);refused(&s,target());permit_write=1;
    permit_code=0;initial(&s,10,20);refused(&s,target());permit_code=1;
    fail_read=1;initial(&s,10,20);refused(&s,target());fail_read=0;
    permit_teb=0;initial(&s,10,20);refused(&s,target());permit_teb=1;
    for(unsigned n=0;n<3;n++){
        size_t size=ios_jit_mappings[0].code_ranges[n].size;
        ios_jit_mappings[0].code_ranges[n].size=0;initial(&s,10,20);refused(&s,target());
        ios_jit_mappings[0].code_ranges[n].size=size;
    }
    for(unsigned n=0;n<2;n++){
        ios_jit_mappings[n].owner_peb=(void *)0x1234;initial(&s,10,20);refused(&s,target());ios_jit_mappings[n].owner_peb=NULL;
        ios_jit_mappings[n].unmapped=1;initial(&s,10,20);refused(&s,target());ios_jit_mappings[n].unmapped=0;
    }
    generation_reject(start(),0);generation_reject(start()+active.mismatch,0);
    generation_reject(start()+active.continuation,0);generation_reject(target(),1);
    code_intact();assert(__atomic_load_n((uint64_t *)target(),__ATOMIC_ACQUIRE)==value());
    printf("PASS production retained-expected compare recovery:%u contracts, seven exact shipped loops, real CAS equality/conflict/descending/zero values, only status/PC changed, core/tail/continuation/data ownership and generation guards\n",cases);
    assert(!munmap(rw,mapped_size)&&!munmap(rx,mapped_size));fclose(file);return 0;
}
