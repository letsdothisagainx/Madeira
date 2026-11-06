/* SPDX-License-Identifier: MIT. Exact production planner, never a GP emulator. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "native_atomic_alias.h"

static const uintptr_t rx=UINT64_C(0x180000000);
static intptr_t delta=0x48000000;
static unsigned checks,allow=1,cases;
static int range(void *context,uintptr_t from,uintptr_t to,size_t width)
{
    assert(context==&checks);checks++;
    return allow&&from>=rx+0x2000&&from<=rx+0x3000&&width<=rx+0x3000-from&&
           to==(uintptr_t)(from+delta)&&(width==4||width==8);
}
static uint32_t add(unsigned base,unsigned immediate)
{ return 0x91000000u|immediate<<10|base<<5|base; }
static uint32_t move_zero(unsigned base)
{ return 0xaa1f03e0u|base; }
static uint32_t lse(unsigned size,unsigned operation,unsigned order,unsigned base,unsigned result,unsigned value)
{ return 0x38200000u|size<<30|operation<<12|order<<22|value<<16|base<<5|result; }
static void accepted(uint32_t *code,size_t count,unsigned kind,unsigned width)
{
    uint32_t before[1200];struct madeira_native_atomic_alias_plan plan;
    assert(count<=1200);memcpy(before,code,count*4);
    assert(madeira_native_atomic_alias_plan(code,count,rx,delta,0,range,&checks,&plan));
    assert(!memcmp(before,code,count*4));
    assert(plan.producer_index==0&&plan.original==code[0]&&plan.replacement!=plan.original);
    assert(plan.target_rw==(uintptr_t)(plan.target_rx+delta));
    assert(plan.kind==kind&&plan.width==width);cases++;
}
static void refused(uint32_t *code,size_t count)
{
    uint32_t before[1200];struct madeira_native_atomic_alias_plan plan,old;
    assert(count<=1200);memcpy(before,code,count*4);memset(&plan,0xa5,sizeof(plan));old=plan;
    assert(!madeira_native_atomic_alias_plan(code,count,rx,delta,0,range,&checks,&plan));
    assert(!memcmp(before,code,count*4)&&!memcmp(&plan,&old,sizeof(plan)));cases++;
}
int main(void)
{
    _Static_assert(sizeof(uintptr_t)==8,"native ARM64 planner tests require64bit addresses");
    /* Golden ADRP encoding: page+2 changes only to page+0x48002. */
    uint32_t consumed[]={0xd0000009,0x91040129,0xf82a0129};
    struct madeira_native_atomic_alias_plan plan;
    accepted(consumed,3,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,8);
    assert(madeira_native_atomic_alias_plan(consumed,3,rx,delta,0,range,&checks,&plan));
    assert(plan.replacement==0xd0240009&&plan.target_rx==rx+0x2100);
    /* General family/register/order support, not an individual hot opcode. */
    const unsigned operations[]={0,1,2,3,8};
    for(unsigned base=8;base<=17;base++)for(unsigned size=2;size<=3;size++)
        for(unsigned operation=0;operation<5;operation++)for(unsigned order=0;order<4;order++){
            uint32_t code[]={0xd0000000u|base,add(base,0x100),lse(size,operations[operation],order,base,base,1)};
            accepted(code,3,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,1u<<size);
        }
    /* Independent GP operations between producer and consumer. */
    uint32_t independent[]={0xd0000009,add(9,0x100),0xaa0003e2,0xf100001f,0x9a820043,
        0x91000484,0xf82a0129};
    accepted(independent,7,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,8);
    /* Retained-base complete exclusive loop plus real captured TST/CFG shape. */
    uint32_t exclusive[]={0xd000000a,add(10,0x100),0xc85f7d49,0x91000529,
        0xc80b7d49,0x35ffffab,0xf2404d3f,0x54000060,
        move_zero(10),0x14000002,move_zero(10),0xd65f03c0};
    accepted(exclusive,12,MADEIRA_NATIVE_ATOMIC_ALIAS_EXCLUSIVE,8);
    /* Every memory-order variant preserves original words and flag/status flow. */
    for(unsigned size=2;size<=3;size++)for(unsigned acquire=0;acquire<2;acquire++)for(unsigned release=0;release<2;release++){
        uint32_t code[]={0xd000000a,add(10,0x100),
            0x085f7c00u|size<<30|acquire<<15|10<<5|9,
            (size==3?0x91000000u:0x11000000u)|1<<10|9<<5|9,
            0x08007c00u|size<<30|release<<15|11<<16|10<<5|9,
            0x35ffffab,move_zero(10),0xd65f03c0};
        accepted(code,8,MADEIRA_NATIVE_ATOMIC_ALIAS_EXCLUSIVE,1u<<size);
    }
    /* One unsafe conditional arm invalidates the whole producer plan. */
    exclusive[10]=0xf900000a;refused(exclusive,12);exclusive[10]=move_zero(10);
    /* Wrong retry register/target, mismatched value/base, discarded status. */
    for(unsigned slot=2;slot<=5;slot++){
        uint32_t save=exclusive[slot];exclusive[slot]^=1;refused(exclusive,12);exclusive[slot]=save;
    }
    /* A live address cannot escape as a value, comparison, call or branch. */
    uint32_t retained[]={0xd000000a,add(10,0x100),lse(3,0,0,10,9,1),0,0xd65f03c0};
    const uint32_t escapes[]={0xaa0a03e0,0xf900000a,0xf100015f,0xb500002a,
        0xd61f0140,0xd63f0140,0xd65f0140,0xffffffff,0x14000000};
    for(unsigned i=0;i<sizeof(escapes)/sizeof(escapes[0]);i++){retained[3]=escapes[i];refused(retained,5);}
    retained[3]=move_zero(10);accepted(retained,5,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,8);
    retained[3]=0x94000000;accepted(retained,5,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,8); /* volatile call kill */
    retained[0]=0xd0000008;retained[1]=add(8,0x100);retained[2]=lse(3,0,0,8,9,1);
    refused(retained,5); /* x8 is an implicit sret input to a native call */
    retained[3]=0xd65f03c0;accepted(retained,5,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,8);
    /* Copying/using the pointer BEFORE the atomic is equally unsafe. */
    uint32_t before[]={0xd0000009,add(9,0x100),0xaa0903e0,0xf82a0129};refused(before,4);
    before[2]=0xffffffff;refused(before,4);
    /* An atomic value operand may never be the address, even when Rt==Rn. */
    consumed[2]=lse(3,0,0,9,9,9);refused(consumed,3);consumed[2]=0xf82a0129;
    /* Callback denial, unaligned alias and out-of-range ADRP cannot change code. */
    allow=0;refused(consumed,3);allow=1;
    delta=1;refused(consumed,3);delta=INT64_C(0x100000000);refused(consumed,3);
    delta=-INT64_C(0x04000000);accepted(consumed,3,MADEIRA_NATIVE_ATOMIC_ALIAS_LSE,8);delta=0x48000000;
    uint32_t bad_logical[]={0xd000000a,add(10,0x100),lse(3,0,0,10,9,1),0x9240ffff,move_zero(10)};
    refused(bad_logical,5); /* reserved logical immediate */
    /* Proof budgets reject long-lived pointers rather than invent liveness. */
    uint32_t long_code[1200];for(unsigned i=0;i<1200;i++)long_code[i]=0xd503201f;
    long_code[0]=0xd000000a;long_code[1]=add(10,0x100);long_code[2]=lse(3,0,0,10,9,1);
    long_code[1199]=move_zero(10);refused(long_code,1200);
    assert(!madeira_native_atomic_alias_plan(consumed,3,UINTPTR_MAX-3,delta,0,range,&checks,&plan));
    assert(!madeira_native_atomic_alias_plan(consumed,3,rx,delta,3,range,&checks,&plan));
    printf("PASS production native atomic planner: %u positive/negative contracts, exact encodings, full retry/CFG proof, no mutation\n",cases);
}
