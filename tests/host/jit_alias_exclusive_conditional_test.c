/* SPDX-License-Identifier: MIT. Exact production helpers/token/route included. */
#include <stdlib.h>
#include "conditional-production.h"

/* Genuine installed ARM64EC d3d11.dll SHA256
 * 08e2eccae5a758ed6c15a3e8ca34de0d56266565aa69f1d0e87d07449d318671.
 * Full g_mem_census peak[6] compare-exchange loop RVA102dc8..102e10,
 * inspected from IPA42178780286 by Actions42183066109. Not five-op inference. */
static const uint32_t captured[]={
    0x9102810a,0xc85f7d4b,0xeb0c017f,0x54000141,0x9102810c,0xc80f7d89,
    0x3500014f,0x5280002c,0x3700014c,0xeb0b013f,0xaa0b03ec,0x54fffec8,
    0x14000006,0x2a1f03ec,0xd5033f5f,0x17fffff9,0x2a1f03ec,0x17fffff7,
    0xf9401d09
};
static unsigned cases;
static uintptr_t code_start(void){return (uintptr_t)rx+0x100;}
static uintptr_t store_pc(void){return code_start()+5*4;}
static uintptr_t data_address(void){return (uintptr_t)rx+mapped_size/2+0x100;}
static uint64_t cell(void){return __atomic_load_n((uint64_t *)(rw+mapped_size/2+0x100),__ATOMIC_SEQ_CST);}
static void put(uint64_t value){__atomic_store_n((uint64_t *)(rw+mapped_size/2+0x100),value,__ATOMIC_SEQ_CST);}
static void restore_code(void){memcpy(rw+0x100,captured,sizeof(captured));}
static void initial(struct state *state,uint64_t observed,uint64_t desired)
{
    memset(state,0,sizeof(*state));
    for(unsigned n=0;n<29;n++)state->__x[n]=UINT64_C(0xfeed000000000000)|n;
    state->__fp=UINT64_C(0xfeed000000000029);state->__lr=UINT64_C(0xfeed000000000030);
    state->__sp=0x700000000;state->__pc=store_pc();state->__cpsr=0x60000000;
    state->__x[8]=data_address()-0xa0;state->__x[9]=desired;
    state->__x[10]=data_address();state->__x[11]=observed;state->__x[12]=data_address();
}
static void unchanged_except_status(const struct state *before,const struct state *after,unsigned status)
{
    struct state expected=*before;expected.__x[15]=status;expected.__pc+=4;
    assert(!memcmp(&expected,after,sizeof(expected)));
    assert(!memcmp(rx+0x100,captured,sizeof(captured)));
}
static void rejected(struct state *state,uintptr_t address,void *owner)
{
    struct state before=*state;uint64_t value=cell();
    if(route(0xc80f7d89,address,state,owner)){
        fprintf(stderr,"unexpected recovery for rejection case%u pc=%llx cpsr=%x\n",cases,
            (unsigned long long)before.__pc,before.__cpsr);abort();
    }
    assert(!memcmp(&before,state,sizeof(before))&&cell()==value);cases++;
}
static void accepted(uint64_t observed,uint64_t actual,uint64_t desired,unsigned status)
{
    struct state state,before;initial(&state,observed,desired);before=state;put(actual);
    assert(route(0xc80f7d89,data_address(),&state,NULL));
    unchanged_except_status(&before,&state,status);
    assert(cell()==(status?actual:desired));cases++;
    /* Existing production PC advance reaches the real CBNZ. Its outcome
     * remains observable: failed CAS goes to102e08; success to102de4. */
    uint32_t retry;memcpy(&retry,(const void *)state.__pc,4);
    assert(retry==captured[6]);
    uintptr_t target=state.__pc+((int64_t)(int32_t)(retry<<8)>>13)*4;
    assert(target==code_start()+16*4);
    assert((status?target:state.__pc+4)==code_start()+(status?16:7)*4);
}
static void set_reg(struct state *state,unsigned reg,uint64_t value)
{
    assert(reg<31);
    if(reg<29)state->__x[reg]=value;else if(reg==29)state->__fp=value;else state->__lr=value;
}
/* Synthetic register/offset variants of the COMPLETE proven shape. The
 * captured original above is separately replayed byte-for-byte. */
static void variant_words(uint32_t words[19],const unsigned roles[6],unsigned offset)
{
    unsigned b=roles[0],a=roles[1],l=roles[2],e=roles[3],d=roles[4],s=roles[5];
    memcpy(words,captured,sizeof(captured));
    words[0]=0x91000000u|offset<<10|b<<5|a;
    words[1]=0xc85f7c00u|a<<5|l;
    words[2]=0xeb00001fu|e<<16|l<<5;
    words[4]=0x91000000u|offset<<10|b<<5|e;
    words[5]=0xc8007c00u|s<<16|e<<5|d;
    words[6]=0x35000140u|s;
    words[7]=0x52800020u|e;
    words[8]=0x37000140u|e;
    words[9]=0xeb00001fu|l<<16|d<<5;
    words[10]=0xaa0003e0u|l<<16|e;
    words[13]=words[16]=0x2a1f03e0u|e;
    words[18]=0xd503201f; /* continuation outside the18-word contract */
}
static void register_variants(void)
{
    const unsigned roles[][6]={
        {8,10,11,12,9,15},{0,1,2,3,4,5},{19,20,21,22,23,24},
        {26,27,28,29,30,25},{8,9,10,11,12,29},{8,9,10,11,12,30},{29,30,17,16,15,14}
    };
    const unsigned offsets[]={0,1,64,160,4095};
    for(unsigned r=0;r<sizeof(roles)/sizeof(roles[0]);r++)
        for(unsigned o=0;o<sizeof(offsets)/sizeof(offsets[0]);o++)for(unsigned failure=0;failure<2;failure++){
            uint32_t words[19];struct state state,before,expected;
            variant_words(words,roles[r],offsets[o]);memcpy(rw+0x100,words,sizeof(words));
            initial(&state,10,20);
            set_reg(&state,roles[r][0],data_address()-offsets[o]);
            set_reg(&state,roles[r][1],data_address());set_reg(&state,roles[r][2],10);
            set_reg(&state,roles[r][3],data_address());set_reg(&state,roles[r][4],20);
            set_reg(&state,roles[r][5],UINT64_C(0xffffffffffffffff));
            before=state;put(failure?11:10);
            assert(route(words[5],data_address(),&state,NULL));
            expected=before;expected.__pc+=4;set_reg(&expected,roles[r][5],failure);
            assert(!memcmp(&expected,&state,sizeof(state))&&cell()==(failure?11:20));
            assert(!memcmp(rx+0x100,words,sizeof(words)));cases++;
        }
    restore_code();
}
int main(void)
{
    (void)accepted;(void)rejected;
    mapped_size=2*(size_t)sysconf(_SC_PAGESIZE);
    FILE *backing=tmpfile();assert(backing&&!ftruncate(fileno(backing),mapped_size));
    rw=mmap(NULL,mapped_size,PROT_READ|PROT_WRITE,MAP_SHARED,fileno(backing),0);
    rx=mmap(NULL,mapped_size,PROT_READ|PROT_EXEC,MAP_SHARED,fileno(backing),0);
    assert(rw!=MAP_FAILED&&rx!=MAP_FAILED);memset(rw,0,mapped_size);restore_code();
    ios_jit_rx_base_global=rx;ios_jit_rw_base_global=rw;ios_jit_pool_size_global=mapped_size;
    ios_jit_mapping_count=2;
    for(unsigned i=0;i<2;i++){
        ios_jit_mappings[i].pe_base=(void *)(uintptr_t)(0x100000000ull+i*0x1000000);
        ios_jit_mappings[i].jit_base=rx+i*mapped_size/2;
        ios_jit_mappings[i].size=mapped_size/2;
        ios_jit_mappings[i].generation=ios_jit_new_generation();
    }
    ios_jit_mappings[0].text_offset=0x100;ios_jit_mappings[0].text_size=sizeof(captured);
    struct state state,before;uint64_t gpr[32],before_gpr[32];initial(&state,10,20);before=state;put(10);
    memcpy(gpr,state.__x,sizeof(state.__x));gpr[29]=state.__fp;gpr[30]=state.__lr;gpr[31]=state.__sp;
    memcpy(before_gpr,gpr,sizeof(gpr));
    assert(!ios_mach_emulate_exclusive_loop(0xc80f7d89,store_pc(),data_address(),gpr,(void *)0x1111));
    assert(!ios_mach_emulate_exclusive_add_loop(0xc80f7d89,store_pc(),data_address(),gpr,(void *)0x1111));
    assert(!memcmp(gpr,before_gpr,sizeof(gpr))&&cell()==10);
    assert(!old_route(0xc80f7d89,(uintptr_t)rw+mapped_size/2+0x100,data_address(),&state));
    assert(!memcmp(&before,&state,sizeof(state))&&cell()==10);
    puts("PASS previous production control: exact nonadjacent conditional STXR refused, state/data intact");
#if !HAVE_CONDITIONAL_RECOVERY
    fputs("FAIL production conditional-exclusive helper is missing; captured DXMT fault remains unrecovered\n",stderr);
    return 1;
#else
    accepted(10,10,20,0);accepted(10,11,20,1);accepted(0,0,1,0);
    accepted(UINT64_MAX-1,UINT64_MAX-1,UINT64_MAX,0);
    register_variants();
    /* Every instruction in the complete conditional/retry contract matters. */
    for(unsigned i=0;i<18;i++){
        uint32_t bad=0xffffffff;memcpy(rw+0x100+i*4,&bad,4);
        initial(&state,10,20);put(10);rejected(&state,data_address(),NULL);restore_code();
    }
    initial(&state,10,20);state.__cpsr&=~0x40000000u;rejected(&state,data_address(),NULL);
    initial(&state,10,20);state.__cpsr=0x40000000;rejected(&state,data_address(),NULL);
    initial(&state,10,20);state.__cpsr=0xe0000000;rejected(&state,data_address(),NULL);
    initial(&state,10,20);state.__cpsr=0x70000000;rejected(&state,data_address(),NULL);
    initial(&state,10,10);rejected(&state,data_address(),NULL);
    initial(&state,10,9);rejected(&state,data_address(),NULL);
    initial(&state,10,20);state.__x[10]+=8;rejected(&state,data_address(),NULL);
    initial(&state,10,20);state.__x[12]+=8;rejected(&state,data_address(),NULL);
    initial(&state,10,20);state.__x[8]+=8;rejected(&state,data_address(),NULL);
    initial(&state,10,20);rejected(&state,data_address()+8,NULL);
    initial(&state,10,20);state.__pc+=4;rejected(&state,data_address(),NULL);
    permit_read=0;initial(&state,10,20);rejected(&state,data_address(),NULL);permit_read=1;
    permit_write=0;initial(&state,10,20);rejected(&state,data_address(),NULL);permit_write=1;
    permit_code=0;initial(&state,10,20);rejected(&state,data_address(),NULL);permit_code=1;
    fail_read=1;initial(&state,10,20);rejected(&state,data_address(),NULL);fail_read=0;
    code_nx=1;initial(&state,10,20);rejected(&state,data_address(),NULL);code_nx=0;
    data_nx=1;initial(&state,10,20);rejected(&state,data_address(),NULL);data_nx=0;
    permit_teb=0;initial(&state,10,20);rejected(&state,data_address(),NULL);permit_teb=1;
    for(unsigned i=0;i<2;i++){
        ios_jit_mappings[i].unmapped=1;initial(&state,10,20);rejected(&state,data_address(),NULL);
        ios_jit_mappings[i].unmapped=0;
        ios_jit_mappings[i].owner_peb=(void *)0x1234;
        initial(&state,10,20);rejected(&state,data_address(),(void *)0x5678);
        ios_jit_mappings[i].owner_peb=NULL;
        mutate_generation=i+1;initial(&state,10,20);rejected(&state,data_address(),NULL);
    }
    ios_jit_mappings[0].owner_peb=(void *)0x1234;ios_jit_mappings[1].owner_peb=(void *)0x1234;
    initial(&state,10,20);put(10);before=state;
    assert(route(0xc80f7d89,data_address(),&state,(void *)0x1234));
    unchanged_except_status(&before,&state,0);assert(cell()==20);cases++;
    ios_jit_mappings[0].owner_peb=ios_jit_mappings[1].owner_peb=NULL;
    /* Both RX and RW names expose the same physical bytes throughout. */
    assert(__atomic_load_n((uint64_t *)data_address(),__ATOMIC_ACQUIRE)==cell());
    assert(!memcmp(rx+0x100,captured,sizeof(captured)));
    printf("PASS production conditional-exclusive recovery: %u contracts; real CAS stale-value failure, original status/retry/PC/NZCV/GPR preservation, complete captured loop, ownership/generation/protection guards\n",cases);
    assert(!munmap(rw,mapped_size)&&!munmap(rx,mapped_size));fclose(backing);return 0;
#endif
}
