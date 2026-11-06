/* SPDX-License-Identifier: MIT.
 * Prove an address-only use of one ADRP in an unpublished, Madeira-owned
 * native ARM64 image. The caller owns code-range and retained-alias validation.
 * This planner changes no instruction, protection, ordering or atomic monitor.
 */
#ifndef MADEIRA_NATIVE_DATA_ALIAS_H
#define MADEIRA_NATIVE_DATA_ALIAS_H
#include "native_atomic_alias.h"

enum madeira_native_data_alias_kind { MADEIRA_NATIVE_DATA_ALIAS_GENERIC = 1 };
struct madeira_native_data_alias_plan {
    size_t producer_index, consumer_index;
    uint32_t original, replacement;
    uintptr_t target_rx, target_rw;
    unsigned width, kind;
};
typedef madeira_native_atomic_alias_range madeira_native_data_alias_range;

struct madeira_nd_memory {
    uint32_t value_reads, writes;
    intptr_t offset, writeback;
    unsigned base, width, store, atomic, has_writeback;
};

/* The shared pure-GP decoder predates this planner. Do not inherit its broad
 * recognition of reserved MADD variants, reserved register-offset options, or
 * constrained/unallocated integer load-pair forms as proof of a known op. */
static inline int madeira_nd_known_encoding(uint32_t op)
{
    if((op&0x1fe00000)==0x1b000000&&(op&0x7fe00000)!=0x1b000000)return 0;
    if(!(op&0x04000000)&&(op&0x3b200c00)==0x38200800&&!(op&0x4000))return 0;
    if(!(op&0x04000000)&&(op&0x3a000000)==0x28000000){
        unsigned kind=op>>30,load=(op>>22)&1,mode=(op>>23)&3;
        if(load&&((op&31)==((op>>10)&31)||(kind==1&&!mode)))return 0;
    }
    return 1;
}

/* Decode only complete, allocated integer memory forms. Address registers and
 * value registers stay separate: storing/copying the candidate pointer must
 * never become an accepted memory-address use. Dynamic offsets are excluded. */
static inline int madeira_nd_memory(uint32_t op,struct madeira_nd_memory *m)
{
    unsigned rt=op&31,rn=(op>>5)&31,size=op>>30,kind=(op>>22)&3;
    *m=(struct madeira_nd_memory){0};m->base=rn;m->width=1u<<size;
    if((op&0x3ffffc00)==0x085f7c00||(op&0x3ffffc00)==0x085ffc00||
       (op&0x3ffffc00)==0x08dffc00){ /* LDXR/LDAXR/LDAR */
        m->writes=madeira_na_bit(rt);m->atomic=1;return 1;
    }
    if((op&0x3fe07c00)==0x08007c00){ /* STXR/STLXR */
        unsigned status=(op>>16)&31;
        if(status==rn||status==rt||status==31)return 0;
        m->value_reads=madeira_na_bit(rt);m->writes=madeira_na_bit(status);
        m->store=m->atomic=1;return 1;
    }
    if((op&0x3ffffc00)==0x089ffc00){ /* STLR */
        m->value_reads=madeira_na_bit(rt);m->store=m->atomic=1;return 1;
    }
    {
        uint32_t fixed=op&0x3f20fc00;
        if(fixed==0x38200000||fixed==0x38201000||fixed==0x38202000||
           fixed==0x38203000||fixed==0x38208000){ /* LSE arithmetic/SWP */
            m->value_reads=madeira_na_bit((op>>16)&31);m->writes=madeira_na_bit(rt);
            m->store=m->atomic=1;return 1;
        }
    }
    if(!(op&0x04000000)&&((op&0x3b000000)==0x39000000||
       (op&0x3b200000)==0x38000000)){
        unsigned mode=(op>>10)&3;
        if(kind>1)return 0; /* no prefetch/sign-extending forms inferred */
        if((op&0x3b000000)==0x39000000)m->offset=(intptr_t)((op>>10)&0xfff)<<size;
        else{
            intptr_t offset=(intptr_t)madeira_na_sext((op>>12)&0x1ff,9);
            if(mode==2)return 0; /* unprivileged, not needed by this contract */
            m->offset=mode==1?0:offset;
            if(mode==1||mode==3){
                if(kind&&rt==rn)return 0; /* constrained-unpredictable writeback */
                m->writeback=offset;m->has_writeback=1;m->writes=madeira_na_bit(rn);
            }
        }
        if(kind)m->writes|=madeira_na_bit(rt);
        else{m->value_reads=madeira_na_bit(rt);m->store=1;}
        return 1;
    }
    if(!(op&0x04000000)&&(op&0x3a000000)==0x28000000){
        unsigned mode=(op>>23)&3,load=(op>>22)&1,rt2=(op>>10)&31;
        intptr_t offset;
        if(size==3||(size==1&&!load)||!mode)return 0;
        m->width=size==2?16:8;
        offset=(intptr_t)madeira_na_sext((op>>15)&127,7)*(size==2?8:4);
        m->offset=mode==1?0:offset;
        if(mode==1||mode==3){
            if(load&&(rt==rn||rt2==rn))return 0;
            m->writeback=offset;m->has_writeback=1;m->writes=madeira_na_bit(rn);
        }
        if(load)m->writes|=madeira_na_bit(rt)|madeira_na_bit(rt2);
        else{m->value_reads=madeira_na_bit(rt)|madeira_na_bit(rt2);m->store=1;}
        return 1;
    }
    return 0;
}

/* X8 can carry a native implicit result pointer, so a call is not generally a
 * pointer kill. A direct target inside this already validated native code
 * range is different when its straight-line prologue fully replaces X8 before
 * reading it. Reject every unknown/control instruction and every earlier X8
 * use, including spills, address reads and read-modify-write instructions.
 * No imported/indirect target, recursive call proof or ABI guess is accepted.
 */
static inline int madeira_nd_direct_callee_kills_x8(const uint32_t *code,size_t count,size_t at)
{
    size_t target;unsigned steps;
    if(at>=count||(code[at]&0xfc000000u)!=0x94000000u||
       !madeira_na_relative(at,code[at]&0x03ffffffu,26,count,&target))return 0;
    for(steps=0;steps<32&&target<count;steps++,target++){
        uint32_t reads,writes,op=code[target];
        if(!madeira_nd_known_encoding(op)||!madeira_na_operands(op,&reads,&writes)||
           (reads&madeira_na_bit(8)))return 0;
        if(writes&madeira_na_bit(8))return 1;
    }
    return 0;
}

static inline int madeira_native_data_alias_plan(const uint32_t *code,size_t count,uintptr_t rx_va,
    intptr_t rw_delta,size_t producer_index,madeira_native_data_alias_range check,void *context,
    struct madeira_native_data_alias_plan *out)
{
    enum { LIMIT=1024 };
    uintptr_t addresses[LIMIT],page,new_page,pc;
    uint16_t work[LIMIT];unsigned char queued[LIMIT]={0};
    size_t begin,window,head=0,tail=0;unsigned base,stored=0;
    uint32_t adrp;int64_t pages,new_pages;
    struct madeira_native_data_alias_plan plan={0};
    if(!code||!out||!check||!rw_delta||((uintptr_t)rw_delta&0xfff)||(rx_va&3)||
       count>SIZE_MAX/4||rx_va>UINTPTR_MAX-count*4||producer_index>=count||
       count-producer_index<2)return 0;
    adrp=code[producer_index];base=adrp&31;
    if((adrp&0x9f000000)!=0x90000000||base<8||base>17)return 0;
    pc=rx_va+producer_index*4;
    pages=madeira_na_sext(((adrp>>29)&3)|(((adrp>>5)&0x7ffff)<<2),21);
    if(!madeira_na_add_signed(pc&~(uintptr_t)0xfff,(intptr_t)(pages*4096),&page)||
       !madeira_na_add_signed(page,rw_delta,&new_page))return 0;
    begin=producer_index+1;window=count-begin<LIMIT?count-begin:LIMIT;
    work[tail++]=0;queued[0]=1;addresses[0]=page;
    while(head<tail){
        size_t slot=work[head++],at=begin+slot,next=at+1,target=0;
        uintptr_t address=addresses[slot],next_address=address;
        uint32_t op=code[at],read,write;unsigned branch=0,fallthrough=1;
        struct madeira_nd_memory memory;
        if(!madeira_nd_known_encoding(op))return 0;
        if((op&0xfffffc1f)==0xd65f0000){
            if(((op>>5)&31)==base)return 0;
            continue; /* x8..17 are not native return-value registers */
        }
        if((op&0xfc000000)==0x94000000||(op&0xfffffc1f)==0xd63f0000){
            if((base==8&&!madeira_nd_direct_callee_kills_x8(code,count,at))||
               ((op&0xfffffc1f)==0xd63f0000&&((op>>5)&31)==base))return 0;
            continue; /* ABI kills x9..17; X8 needs the direct-target proof. */
        }
        if((op&0xff800000)==0x91000000||(op&0xff800000)==0xd1000000){
            unsigned rd=op&31,rn=(op>>5)&31;
            if(rn==base){
                intptr_t offset=(intptr_t)((op>>10)&0xfff)<<((op>>22)&1?12:0);
                if(rd!=base)return 0; /* even an ADD #0 copy escapes */
                if(op&0x40000000)offset=-offset;
                if(!madeira_na_add_signed(address,offset,&next_address))return 0;
                goto enqueue;
            }
        }
        if(madeira_nd_memory(op,&memory)){
            if(memory.value_reads&madeira_na_bit(base))return 0;
            if(memory.base==base){
                uintptr_t effective,alias;
                if(!madeira_na_add_signed(address,memory.offset,&effective)||
                   !madeira_na_add_signed(effective,rw_delta,&alias)||
                   effective>UINTPTR_MAX-(memory.width-1)||alias>UINTPTR_MAX-(memory.width-1)||
                   (memory.atomic&&((effective|alias)&(memory.width-1)))||
                   !check(context,effective,alias,memory.width))return 0;
                if(memory.store&&!stored){
                    stored=1;plan.consumer_index=at;plan.target_rx=effective;
                    plan.target_rw=alias;plan.width=memory.width;
                }
                if(memory.has_writeback){
                    if(!madeira_na_add_signed(address,memory.writeback,&next_address))return 0;
                }else if(memory.writes&madeira_na_bit(base))continue;
            }else if(memory.writes&madeira_na_bit(base))continue;
        }else if((op&0xfc000000)==0x14000000){
            if(!madeira_na_relative(at,op&0x3ffffff,26,count,&target))return 0;
            branch=1;fallthrough=0;
        }else if((op&0xff000010)==0x54000000){
            if(!madeira_na_relative(at,(op>>5)&0x7ffff,19,count,&target))return 0;
            branch=1;
        }else if((op&0x7e000000)==0x34000000){
            if((op&31)==base||!madeira_na_relative(at,(op>>5)&0x7ffff,19,count,&target))return 0;
            branch=1;
        }else if((op&0x7e000000)==0x36000000){
            if((op&31)==base||!madeira_na_relative(at,(op>>5)&0x3fff,14,count,&target))return 0;
            branch=1;
        }else if(op==0xd503203f||(op&0xfffff0ff)==0xd503305f){
            /* YIELD/CLREX preserve all GP values; atomic instructions stay native. */
        }else if((op&0xffffffe0)==0xd53bd040||(op&0xffffffe0)==0xd53b4200){
            if((op&31)==base)continue; /* MRS TPIDR_EL0/NZCV */
        }else{
            if(!madeira_na_operands(op,&read,&write)||(read&madeira_na_bit(base)))return 0;
            if(write&madeira_na_bit(base))continue;
        }
enqueue:
        if(branch){
            size_t offset;
            if(target<begin||target-begin>=window)return 0;
            offset=target-begin;
            if(queued[offset]){if(addresses[offset]!=next_address)return 0;}
            else{queued[offset]=1;addresses[offset]=next_address;work[tail++]=(uint16_t)offset;}
        }
        if(fallthrough){
            size_t offset;
            if(next<begin||next-begin>=window)return 0;
            offset=next-begin;
            if(queued[offset]){if(addresses[offset]!=next_address)return 0;}
            else{queued[offset]=1;addresses[offset]=next_address;work[tail++]=(uint16_t)offset;}
        }
    }
    if(!stored)return 0;
    if(new_page>=(pc&~(uintptr_t)0xfff)){
        uintptr_t n=(new_page-(pc&~(uintptr_t)0xfff))/4096;
        if(n>=0x100000)return 0;
        new_pages=(int64_t)n;
    }else{
        uintptr_t n=((pc&~(uintptr_t)0xfff)-new_page)/4096;
        if(n>0x100000)return 0;
        new_pages=-(int64_t)n;
    }
    {
        uint32_t encoded=(uint32_t)new_pages&0x1fffff;
        plan.producer_index=producer_index;plan.original=adrp;
        plan.replacement=(adrp&~UINT32_C(0x60ffffe0))|((encoded&3)<<29)|((encoded>>2)<<5);
    }
    plan.kind=MADEIRA_NATIVE_DATA_ALIAS_GENERIC;*out=plan;return 1;
}
#endif
