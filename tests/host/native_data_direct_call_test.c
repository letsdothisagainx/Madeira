/* Exact installed WoW64 counter callsite. Inspect run42174861623/job127750889143:
 * xtajit.dll SHA256 6a6e905dbd3adb251e9f8bdae44b21d52829226f2b6949aa1b0bde6545ebc20d.
 * The original caller/loop/branches and callee prologue are not rewritten.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native_data_alias.h"

enum { CALLER = 0x17fac, CALLEE = 0x1a7bac, CALLEE_AT = (CALLEE-CALLER)/4,
       WORDS = CALLEE_AT+40, CALL_AT = 8 };
static const uintptr_t image = UINT64_C(0x180000000), delta = 0x48000000;
static const uint32_t caller[]={
    0xd0001b88,0x913c0108,0xc85f7d09,0x91000535,0xc8097d15,0x35ffffa9,
    0xf2404ebf,0x54000301,0x94063ef8,0xd0001b89,0x913be129,0xc85f7d28,
    0xc80a7d20,0x35ffffca,0xb4000228,0xcb080008,0x910043e9,0x90000e61,
    0x910ef421,0x9e620100,0xd2d9aca8,0xf2e861a8,0x910003e2,0x52800040,
    0x9e670101,0x52801488,0xa900d7e9,0xf90003e8,0x1e601820,0xfd0013e0,
    0x9403c86f,0x39420268,0x350008a8
};
static const uint32_t callee_prefix[]={0xd10083ff,0xf9000bf3,0xf9000ffe,0xd0000f08};
static unsigned cases;
static int range(void *context,uintptr_t from,uintptr_t to,size_t width)
{
    assert(context==&cases);
    return from==image+0x389f00 && to==from+delta && width==8;
}
static uint64_t digest(const uint32_t *code)
{
    uint64_t hash=UINT64_C(1469598103934665603);
    for(size_t i=0;i<WORDS;i++) hash=(hash^code[i])*UINT64_C(1099511628211);
    return hash;
}
static void reset(uint32_t *code)
{
    for(size_t i=0;i<WORDS;i++)code[i]=0xd503201f;
    memcpy(code,caller,sizeof(caller));
    memcpy(code+CALLEE_AT,callee_prefix,sizeof(callee_prefix));
}
static void check(uint32_t *code,int accept)
{
    struct madeira_native_data_alias_plan plan,before;
    memset(&plan,0xa5,sizeof(plan));before=plan;
    uint64_t hash=digest(code);
    int result=madeira_native_data_alias_plan(code,WORDS,image+CALLER,delta,0,range,&cases,&plan);
    assert(result==accept && digest(code)==hash);
    if(!accept)assert(!memcmp(&plan,&before,sizeof(plan)));
    else {
        assert(plan.producer_index==0 && plan.consumer_index==4);
        assert(plan.original==caller[0] && plan.replacement!=plan.original);
        assert(plan.target_rx==image+0x389f00 && plan.target_rw==plan.target_rx+delta && plan.width==8);
    }
    cases++;
}
int main(void)
{
    uint32_t *code=malloc(WORDS*sizeof(*code));assert(code);
    reset(code);
#ifdef TEST_PREVIOUS_REJECTION
    check(code,0);free(code);
    puts("PASS previous X8-call guard rejects the exact captured counter producer");return 0;
#else
    check(code,1);
    /* A value read, address read, spill, control transfer or unknown operation
     * before the first full X8 write does not prove a dead implicit sret. */
    const uint32_t unsafe[]={0xaa0803e9,0xf9400109,0xf90003e8,0xf90007e8,
        0xf2800028,0x91000108,0x34000040,0x54000040,0x14000002,
        0x94000001,0xd61f0000,0xd63f0000,0xd65f03c0,0xd5033f5f,
        0xd4400020,0xffffffff};
    for(size_t i=0;i<sizeof(unsafe)/sizeof(unsafe[0]);i++){
        reset(code);code[CALLEE_AT]=unsafe[i];check(code,0);
    }
    /* W8 writes zero-extend the whole X8; a fresh MOVZ is also a kill. */
    const uint32_t kills[]={0x52800028,0xd2800028,0x10000008,0x90000008};
    for(size_t i=0;i<sizeof(kills)/sizeof(kills[0]);i++){
        reset(code);code[CALLEE_AT]=kills[i];check(code,1);
    }
    reset(code);code[CALL_AT]=0xd63f0000;check(code,0); /* indirect BLR X0 */
    reset(code);code[CALL_AT]=0xd63f0100;check(code,0); /* BLR X8 consumes pointer */
    reset(code);code[CALL_AT]=0x97ffffff;check(code,0); /* BL into caller's preceding branch */
    reset(code);code[CALL_AT]=0x95ffffff;check(code,0); /* outside validated code range */
    reset(code);code[CALL_AT]=0x96000000;check(code,0); /* before validated code range */
    reset(code);for(size_t i=0;i<32;i++)code[CALLEE_AT+i]=0xd503201f;
    code[CALLEE_AT+32]=0xd2800028;check(code,0); /* bounded prologue budget */
    free(code);
    printf("PASS production direct-call X8 lifetime: %u exact/negative contracts; atomics, retry, code and failure output unchanged\n",cases);
    return 0;
#endif
}
