/* SPDX-License-Identifier: MIT. Exercise the exact production planner. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "native_data_alias.h"

static const uintptr_t rx=UINT64_C(0x180000000);
static intptr_t delta=0x48000000;
static uintptr_t low,high;
static unsigned checks,cases,allow=1,seen;
static int range(void *context,uintptr_t from,uintptr_t to,size_t width)
{
    assert(context==&checks);checks++;
    if(from==rx+0x3cca80&&width==1)seen|=1;
    if(from==rx+0x3cca90&&width==4)seen|=2;
    if(from==rx+0x3ccac0&&width==8)seen|=4;
    return allow&&from>=low&&from<high&&width<=high-from&&to==(uintptr_t)(from+delta);
}
static struct madeira_native_data_alias_plan accepted(const uint32_t *code,size_t count,
                                                       uintptr_t va,size_t producer)
{
    struct madeira_native_data_alias_plan plan;
    uint32_t before[1100];assert(count<=1100);memcpy(before,code,count*4);
    assert(madeira_native_data_alias_plan(code,count,va,delta,producer,range,&checks,&plan));
    assert(!memcmp(before,code,count*4));assert(plan.producer_index==producer);
    assert(plan.original==code[producer]&&plan.replacement!=plan.original);
    assert(plan.target_rw==(uintptr_t)(plan.target_rx+delta));
    assert(plan.kind==MADEIRA_NATIVE_DATA_ALIAS_GENERIC);cases++;return plan;
}
static void refused(const uint32_t *code,size_t count,uintptr_t va,size_t producer)
{
    struct madeira_native_data_alias_plan plan,before;
    uint32_t words[1100];assert(count<=1100);memcpy(words,code,count*4);
    memset(&plan,0xa5,sizeof(plan));before=plan;
    assert(!madeira_native_data_alias_plan(code,count,va,delta,producer,range,&checks,&plan));
    assert(!memcmp(words,code,count*4)&&!memcmp(&plan,&before,sizeof(plan)));cases++;
}
static uint32_t adrp(unsigned base){return 0xd0000000u|base;} /* PC page +0x2000 */
static uint32_t add(unsigned base,unsigned value){return 0x91000000u|value<<10|base<<5|base;}
static uint32_t store(unsigned base,unsigned value){return 0xf9000000u|base<<5|value;}

/* Exact native ARM64EC words from packaged xtajit64.dll SHA256
 * cc887fcc717be62d83e835e2b982651a74b2061d0fbddd1a2b828ac89b256ef9.
 * fex_ios_rpm_lock RVA154110..154190; unlock RVA154194..1541e0.
 * No instruction replacement, shortened retry loop or invented pointer kill. */
static const uint32_t rpm_lock[]={
    0x900013c8,0x912a0108,0x52800029,0x38040509,0xf9401a49,0xc8dffd08,
    0xb2400129,0xeb09011f,0x900013c8,0x540000a1,0xb94a9109,0x1100052b,
    0xb90a910b,0xd65f03c0,0x900013ca,0x912b014a,0xc85ffd4b,0xb50000cb,
    0xc80b7d49,0x350000ab,0x5280002b,0xb90a910b,0xd65f03c0,0xd5033f5f,
    0xd503203f,0xc85ffd4b,0xb5ffffab,0xc80c7d49,0x5280002b,0x35ffff6c,
    0xb90a910b,0xd65f03c0
};
static const uint32_t rpm_unlock[]={
    0x900013c8,0x396a0108,0x7100051f,0x540001a1,0x900013c8,0x912b0108,
    0xc8dffd09,0xf9401a4a,0xb240014a,0xeb0a013f,0x540000c1,0x900013c9,
    0xb94a912a,0x7100054a,0xb90a912a,0x54000040,0xd65f03c0,0xc89ffd1f,
    0xd65f03c0
};
int main(void)
{
    _Static_assert(sizeof(uintptr_t)==8,"64-bit planner tests");
    low=rx+0x3cc000;high=low+0x1000;
    const size_t lock_at[]={0,8,14},unlock_at[]={4,11};
    struct madeira_native_atomic_alias_plan old;
    for(unsigned i=0;i<3;i++){
        accepted(rpm_lock,32,rx+0x154110,lock_at[i]);
        assert(!madeira_native_atomic_alias_plan(rpm_lock,32,rx+0x154110,delta,lock_at[i],range,&checks,&old));
    }
    for(unsigned i=0;i<2;i++){
        accepted(rpm_unlock,19,rx+0x154194,unlock_at[i]);
        assert(!madeira_native_atomic_alias_plan(rpm_unlock,19,rx+0x154194,delta,unlock_at[i],range,&checks,&old));
    }
    assert(seen==7); /* enabled byte, depth word, owner doubleword all validated */
    refused(rpm_unlock,19,rx+0x154194,0); /* readonly ADRP/LDRB destination kills */
    low=rx+0x2000;high=rx+0x4000;
    uint32_t plain[]={adrp(9),add(9,0x100),store(9,1),0xd65f03c0};
    accepted(plain,4,rx,0);
    /* Every supported volatile producer and ordinary integer access width. */
    for(unsigned base=8;base<=17;base++)for(unsigned size=0;size<=3;size++){
        uint32_t code[]={adrp(base),add(base,0x100),
            0x39000000u|size<<30|base<<5|1,0xd65f03c0};
        struct madeira_native_data_alias_plan plan=accepted(code,4,rx,0);
        assert(plan.width==(1u<<size));
    }
    /* Native LSE/acquire-release/exclusive forms retain every opcode word. */
    const unsigned operations[]={0,1,2,3,8};
    for(unsigned size=0;size<=3;size++)for(unsigned order=0;order<4;order++){
        for(unsigned operation=0;operation<5;operation++){
            uint32_t code[]={adrp(10),add(10,0x100),
                0x38200000u|size<<30|order<<22|1<<16|operations[operation]<<12|10<<5|9,
                0xd65f03c0};
            assert(accepted(code,4,rx,0).width==(1u<<size));
        }
        uint32_t release[]={adrp(10),add(10,0x100),
            0x08dffc00u|size<<30|10<<5|9,0x089ffc00u|size<<30|10<<5|9,0xd65f03c0};
        accepted(release,5,rx,0);
        uint32_t exclusive[]={adrp(10),add(10,0x100),
            0x085f7c00u|size<<30|((order&1)<<15)|10<<5|9,
            0x08007c00u|size<<30|((order>>1)<<15)|11<<16|10<<5|9,
            0x35ffffcb,0xd65f03c0};
        accepted(exclusive,6,rx,0);
    }
    /* ADRP-only, signed constant adjustment and both writeback modes. */
    uint32_t offsets[]={adrp(9),0xf9008121,0xd65f03c0};accepted(offsets,3,rx,0);
    uint32_t back[]={adrp(9),add(9,0x180),0xd1020129,store(9,1),0xd65f03c0};
    assert(accepted(back,5,rx,0).target_rx==rx+0x2100);
    uint32_t post[]={adrp(9),add(9,0x100),0x38040528,store(9,1),0xd65f03c0};
    accepted(post,5,rx,0); /* STRB W8,[X9],#64 then STR X1,[X9] */
    uint32_t pre[]={adrp(9),add(9,0x100),0xf8040d21,0xd65f03c0};
    assert(accepted(pre,4,rx,0).target_rx==rx+0x2140);
    uint32_t negative[]={adrp(9),add(9,0x100),0xf81e0d21,store(9,1),0xd65f03c0};
    assert(accepted(negative,5,rx,0).target_rx==rx+0x20e0); /* pre-index #-32 */
    uint32_t pair[]={adrp(9),add(9,0x100),0xa9010921,0xd65f03c0};
    assert(accepted(pair,4,rx,0).width==16); /* STP X1,X2,[X9,#16] */
    high=rx+0x2118;refused(pair,4,rx,0);high=rx+0x4000;
    pair[2]=0xa9012521;refused(pair,4,rx,0); /* second stored value is base X9 */
    uint32_t zero_wb[]={adrp(9),add(9,0x100),0xf8000521,0xaa0903e0,0xd65f03c0};
    refused(zero_wb,5,rx,0); /* #0 writeback is not a pointer kill */
    /* Stable retry CFGs are safe; changing addresses around a cycle are not. */
    uint32_t loop[]={adrp(10),add(10,0x100),0xc85ffd49,0xb5000089,
        0xc80b7d41,0x35ffffab,0xd65f03c0,0xd5033f5f,0xd503203f,0x17fffff9};
    accepted(loop,10,rx,0);
    uint32_t moving[]={adrp(9),add(9,0x100),store(9,1),add(9,8),0x17fffffe};
    refused(moving,5,rx,0);
    /* Both sides of a join must contain exactly the same known address. */
    uint32_t join[]={adrp(9),add(9,0x100),0x54000060,add(9,8),0x14000002,
        0xd503201f,store(9,1),0xd65f03c0};refused(join,8,rx,0);
    join[3]=0xd503201f;accepted(join,8,rx,0);
    /* All observable pointer uses reject, including one conditional arm. */
    const uint32_t escapes[]={0xaa0903e0,0xf9000009,0xf9000129,0xf100013f,
        0xb5000029,0x36000029,0xd61f0120,0xd63f0120,0xd65f0120,0xffffffff,
        0xf86a6920,0x91000120,0x38400529};
    for(unsigned i=0;i<sizeof(escapes)/sizeof(escapes[0]);i++){
        uint32_t code[]={adrp(9),add(9,0x100),store(9,1),escapes[i],0xd65f03c0};
        refused(code,5,rx,0);
    }
    uint32_t arm[]={adrp(9),add(9,0x100),store(9,1),0x54000040,0xd65f03c0,0xaa0903e0};
    refused(arm,6,rx,0);
    uint32_t killed[]={adrp(9),add(9,0x100),store(9,1),0xf9400129,0xffffffff};
    accepted(killed,5,rx,0); /* LDR X9,[X9] consumes address then kills pointer */
    killed[3]=0xaa1f03e9;accepted(killed,5,rx,0); /* independent assignment kills */
    uint32_t lse_kill[]={adrp(9),add(9,0x100),0xf8210129,0xffffffff};
    accepted(lse_kill,4,rx,0); /* old value replaces candidate pointer */
    lse_kill[2]=0xf8290129;refused(lse_kill,4,rx,0); /* address is also input value */
    /* Exact harmless system forms; unknown system operations stay excluded. */
    uint32_t system[]={adrp(9),add(9,0x100),0xd53bd041,0xd53b4202,store(9,1),0xd65f03c0};
    accepted(system,6,rx,0);system[2]=0xd53bd061;refused(system,6,rx,0);
    /* Reserved/unknown forms must not inherit the older GP decoder's broad
     * masks, even when an apparent destination would kill the candidate. */
    const uint32_t reserved[]={0xfb0f7dce,0xbb174eba,0x6857865c,0xf86a0920,0xa9402529};
    for(unsigned i=0;i<sizeof(reserved)/sizeof(reserved[0]);i++){
        uint32_t code[]={adrp(9),add(9,0x100),store(9,1),reserved[i],0xd65f03c0};
        refused(code,5,rx,0);
    }
    /* Implicit ABI operands and dynamic branch targets remain real uses. */
    uint32_t call[]={adrp(9),add(9,0x100),store(9,1),0x94000000};accepted(call,4,rx,0);
    call[0]=adrp(8);call[1]=add(8,0x100);call[2]=store(8,1);refused(call,4,rx,0);
    /* Full-span range, alignment, arithmetic and resource limits fail closed. */
    high=rx+0x2104;refused(plain,4,rx,0);high=rx+0x4000;
    uint32_t cross[]={adrp(9),add(9,0x100),0x38040528,store(9,1),0xd65f03c0};
    high=rx+0x2144;refused(cross,5,rx,0);high=rx+0x4000;
    uint32_t unaligned[]={adrp(9),add(9,0x101),0xc89ffd21,0xd65f03c0};
    refused(unaligned,4,rx,0);
    allow=0;refused(plain,4,rx,0);allow=1;
    delta=1;refused(plain,4,rx,0);delta=INT64_C(0x100000000);refused(plain,4,rx,0);
    delta=-INT64_C(0x04000000);accepted(plain,4,rx,0);delta=0x48000000;
    uint32_t readonly[]={adrp(9),add(9,0x100),0xf9400120,0xd65f03c0};refused(readonly,4,rx,0);
    uint32_t no_end[]={adrp(9),add(9,0x100),store(9,1)};refused(no_end,3,rx,0);
    uint32_t budget[1100];for(unsigned i=0;i<1100;i++)budget[i]=0xd503201f;
    budget[0]=adrp(9);budget[1]=add(9,0x100);budget[2]=store(9,1);budget[1099]=0xd65f03c0;
    refused(budget,1100,rx,0);refused(plain,4,rx,4);
    printf("native data alias planner: %u contracts passed, %u checked spans\n",cases,checks);
    return 0;
}
