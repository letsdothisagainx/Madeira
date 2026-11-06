/* SPDX-License-Identifier: MIT.
 * Plan address lowering in an unpublished, Madeira-owned native ARM64 copy.
 * No guest/JIT stream, memory protection, atomic instruction or ordering is
 * changed here. The caller must validate code ownership/ranges and data aliases.
 */
#ifndef MADEIRA_NATIVE_ATOMIC_ALIAS_H
#define MADEIRA_NATIVE_ATOMIC_ALIAS_H
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

enum madeira_native_atomic_alias_kind {
    MADEIRA_NATIVE_ATOMIC_ALIAS_LSE = 1,
    MADEIRA_NATIVE_ATOMIC_ALIAS_EXCLUSIVE = 2
};
struct madeira_native_atomic_alias_plan {
    size_t producer_index, consumer_index;
    uint32_t original, replacement;
    uintptr_t target_rx, target_rw;
    unsigned width, kind;
};
/* Must prove the ENTIRE byte span is writable, NONEXEC data in the same
 * retained native image and maps to the corresponding owned RW alias. */
typedef int (*madeira_native_atomic_alias_range)(void *,uintptr_t,uintptr_t,size_t);

static inline uint32_t madeira_na_bit(unsigned reg)
{ return reg < 31 ? UINT32_C(1) << reg : 0; }

static inline int madeira_na_add_signed(uintptr_t value,intptr_t delta,uintptr_t *out)
{
    uintptr_t magnitude;
    if(delta>=0){magnitude=(uintptr_t)delta;if(value>UINTPTR_MAX-magnitude)return 0;*out=value+magnitude;}
    else{magnitude=(uintptr_t)(-(delta+1))+1;if(value<magnitude)return 0;*out=value-magnitude;}
    return 1;
}
static inline int64_t madeira_na_sext(uint32_t value,unsigned bits)
{
    uint32_t sign=UINT32_C(1)<<(bits-1);
    return value&sign ? (int64_t)value-(INT64_C(1)<<bits) : (int64_t)value;
}
static inline int madeira_na_relative(size_t index,uint32_t immediate,unsigned bits,size_t count,size_t *out)
{
    int64_t offset=madeira_na_sext(immediate,bits);
    if(offset<0){uint64_t n=(uint64_t)(-offset);if(n>index)return 0;*out=index-(size_t)n;}
    else{if((uint64_t)offset>SIZE_MAX-index)return 0;*out=index+(size_t)offset;}
    return *out<count;
}

/* LDADD/LDCLR/LDEOR/LDSET/SWP, W/X and all acquire/release forms. CAS/CASP,
 * signed min/max and unknown encodings are deliberately not inferred. */
static inline int madeira_na_lse(uint32_t op)
{
    uint32_t fixed=op&UINT32_C(0x3f20fc00);
    return (op>>30)>=2&&(fixed==0x38200000||fixed==0x38201000||fixed==0x38202000||
                         fixed==0x38203000||fixed==0x38208000);
}

/* Exact complete adjacent retained-value add-immediate retry loop. This
 * preserves the loaded value, arithmetic, monitor, status and retry branch;
 * only its upstream address producer may change. No monitor is emulated. */
static inline int madeira_na_exclusive(const uint32_t *code,size_t count,size_t at,
                                       unsigned base,unsigned *width)
{
    uint32_t load,add,store,retry;unsigned value,status,size;size_t target;
    if(at>=count||count-at<4)return 0;
    load=code[at];add=code[at+1];store=code[at+2];retry=code[at+3];
    size=load>>30;value=load&31;status=(store>>16)&31;
    if(size<2||((load&0x3ffffc00)!=0x085f7c00&&(load&0x3ffffc00)!=0x085ffc00)||
       ((load>>5)&31)!=base||value==31||value==base||
       (add&0xff800000)!=(size==3?0x91000000u:0x11000000u)||
       (add&31)!=value||((add>>5)&31)!=value||
       ((store&0x3fe07c00)!=0x08007c00)||store>>30!=size||
       (store&31)!=value||((store>>5)&31)!=base||status==31||status==base||status==value||
       (retry&0xff00001f)!=(0x35000000u|status)||
       !madeira_na_relative(at+3,(retry>>5)&0x7ffff,19,count,&target)||target!=at)return 0;
    *width=1u<<size;return 1;
}

/* Conservative GP operand decoder. Unknown/SIMD/system instructions reject
 * the plan. Register31 is SP/ZR, never the candidate volatile register8..17.
 * Returning masks (rather than matching an opcode's text) detects copied or
 * stored pointers, comparisons, conditional operands and address writeback. */
static inline int madeira_na_operands(uint32_t op,uint32_t *reads,uint32_t *writes)
{
    unsigned rd=op&31,rn=(op>>5)&31,rm=(op>>16)&31;
    unsigned sf=op>>31,opc=(op>>29)&3;
    *reads=*writes=0;
    if(op==0xd503201f)return 1; /* NOP */
    if((op&0xfffff0ff)==0xd50330bf||(op&0xfffff0ff)==0xd503309f||
       (op&0xfffff0ff)==0xd50330df)return 1; /* DMB/DSB/ISB */
    if((op&0x1f000000)==0x10000000){*writes=madeira_na_bit(rd);return 1;} /* ADR/P */
    if((op&0x1f800000)==0x11000000){ /* ADD/SUB immediate, including CMP */
        *reads=madeira_na_bit(rn);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1f200000)==0x0b000000){ /* ADD/SUB shifted register */
        if(((op>>22)&3)==3||(!sf&&((op>>10)&63)>=32))return 0;
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1fe00000)==0x0b200000){ /* ADD/SUB extended register */
        if(((op>>10)&7)>4)return 0;
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1f000000)==0x0a000000){ /* logical shifted register, including MOV */
        if(!sf&&((op>>10)&63)>=32)return 0;
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1f800000)==0x12000000){ /* logical immediate, including TST */
        unsigned n=(op>>22)&1,imms=(op>>10)&63,pattern=(n<<6)|((~imms)&63),levels;
        int length=6;
        while(length>=0&&!(pattern&(1u<<length)))length--;
        if(length<1||(!sf&&(n||length>5)))return 0;
        levels=(1u<<length)-1;
        if((imms&levels)==levels)return 0; /* DecodeBitMasks immediate all-ones/reserved */
        *reads=madeira_na_bit(rn);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1f800000)==0x12800000){ /* MOVN/MOVZ/MOVK */
        if(opc==1||(!sf&&((op>>21)&3)>1))return 0;
        if(opc==3)*reads=madeira_na_bit(rd);
        *writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1f800000)==0x13000000){ /* SBFM/BFM/UBFM */
        if(opc==3||((op>>22)&1)!=sf||(!sf&&(((op>>16)&63)>=32||((op>>10)&63)>=32)))return 0;
        *reads=madeira_na_bit(rn)|(opc==1?madeira_na_bit(rd):0);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x3fe00800)==0x1a800000){ /* CSEL/CSINC/CSINV/CSNEG */
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1fe0fc00)==0x1a000000){ /* ADC/SBC */
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm);*writes=madeira_na_bit(rd);return 1;
    }
    if((op&0x1fe00000)==0x1b000000){ /* MADD/MSUB */
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm)|madeira_na_bit((op>>10)&31);
        *writes=madeira_na_bit(rd);return 1;
    }
    if(madeira_na_lse(op)){
        *reads=madeira_na_bit(rn)|madeira_na_bit(rm);*writes=madeira_na_bit(rd);return 1;
    }
    /* Integer single loads/stores, unsigned, unscaled and register-offset. */
    if(!(op&0x04000000)&&((op&0x3b000000)==0x39000000||
       (op&0x3b200000)==0x38000000||(op&0x3b200c00)==0x38200800)){
        unsigned kind=(op>>22)&3,mode=(op>>10)&3;
        if(kind>1)return 0; /* no inferred sign-extending/prefetch encodings */
        *reads=madeira_na_bit(rn);
        if((op&0x3b200c00)==0x38200800)*reads|=madeira_na_bit(rm);
        else if((op&0x3b200000)==0x38000000&&(mode==1||mode==3))*writes|=madeira_na_bit(rn);
        if(kind)*writes|=madeira_na_bit(rd);else *reads|=madeira_na_bit(rd);
        return 1;
    }
    /* Integer load/store pairs, including writeback; no SIMD register guesses. */
    if(!(op&0x04000000)&&(op&0x3a000000)==0x28000000){
        unsigned kind=(op>>30)&3,load=(op>>22)&1,mode=(op>>23)&3,rt2=(op>>10)&31;
        if(kind==3||(kind==1&&!load))return 0;
        *reads=madeira_na_bit(rn);
        if(load)*writes=madeira_na_bit(rd)|madeira_na_bit(rt2);
        else *reads|=madeira_na_bit(rd)|madeira_na_bit(rt2);
        if(mode==1||mode==3)*writes|=madeira_na_bit(rn);
        return 1;
    }
    if(!(op&0x04000000)&&(op&0x3b000000)==0x18000000&&(op>>30)<3){
        *writes=madeira_na_bit(rd);return 1; /* integer LDR literal */
    }
    return 0;
}

/* A bounded, forward-only CFG proof. Joins retain the same live address;
 * arbitrary cycles/indirect branches are refused. Verified LL/SC backedges
 * are handled as complete operations, never accepted merely as visited nodes. */
static inline int madeira_na_dead(const uint32_t *code,size_t count,size_t begin,unsigned base,
    uintptr_t target_rx,uintptr_t target_rw,madeira_native_atomic_alias_range check,void *context)
{
    enum { LIMIT=1024 };uint16_t work[LIMIT];unsigned char queued[LIMIT]={0};size_t head=0,tail=0;
    size_t window;
    if(begin>=count)return 0;
    window=count-begin<LIMIT?count-begin:LIMIT;
    work[tail++]=0;queued[0]=1;
    while(head<tail){
        size_t at=begin+work[head++],next=at+1,target;uint32_t op=code[at],read,write;
        unsigned branch=0,width=0;
        if((op&0xfffffc1f)==0xd65f0000){if(((op>>5)&31)==base)return 0;continue;} /* RET */
        if((op&0xfc000000)==0x94000000||(op&0xfffffc1f)==0xd63f0000){
            if(base==8||((op&0xfffffc1f)==0xd63f0000&&((op>>5)&31)==base))return 0;
            continue; /* native ABI call kills x9..17; x8 may be an sret input */
        }
        if(madeira_na_lse(op)&&((op>>5)&31)==base){
            width=1u<<(op>>30);if(((op>>16)&31)==base||!check(context,target_rx,target_rw,width))return 0;
            if((op&31)==base)continue;
        }else if(madeira_na_exclusive(code,count,at,base,&width)){
            if(!check(context,target_rx,target_rw,width))return 0;
            next=at+4;
        }else if((op&0xfc000000)==0x14000000){
            if(!madeira_na_relative(at,op&0x3ffffff,26,count,&target))return 0;
            branch=1;next=count;
        }else if((op&0xff000010)==0x54000000){
            if(!madeira_na_relative(at,(op>>5)&0x7ffff,19,count,&target))return 0;
            branch=1;
        }else if((op&0x7e000000)==0x34000000){
            if((op&31)==base||!madeira_na_relative(at,(op>>5)&0x7ffff,19,count,&target))return 0;
            branch=1;
        }else if((op&0x7e000000)==0x36000000){
            if((op&31)==base||!madeira_na_relative(at,(op>>5)&0x3fff,14,count,&target))return 0;
            branch=1;
        }else{
            if(!madeira_na_operands(op,&read,&write)||(read&madeira_na_bit(base)))return 0;
            if(write&madeira_na_bit(base))continue;
        }
        if(branch){
            if(target<=at||target<begin||target-begin>=window)return 0;
            if(!queued[target-begin]){queued[target-begin]=1;work[tail++]=(uint16_t)(target-begin);}
        }
        if(next!=count){
            if(next<begin||next-begin>=window)return 0;
            if(!queued[next-begin]){queued[next-begin]=1;work[tail++]=(uint16_t)(next-begin);}
        }else if(!branch)return 0;
    }
    return 1;
}

static inline int madeira_native_atomic_alias_plan(const uint32_t *code,size_t count,uintptr_t rx_va,
    intptr_t rw_delta,size_t producer_index,madeira_native_atomic_alias_range check,void *context,
    struct madeira_native_atomic_alias_plan *out)
{
    struct madeira_native_atomic_alias_plan plan;uint32_t adrp,add,read,write;unsigned base,width=0,kind=0;
    size_t at,after=0;uintptr_t pc,page,new_page,target,target_rw;int64_t pages,new_pages;
    if(!code||!out||!check||!rw_delta||((uintptr_t)rw_delta&0xfff)||
       (rx_va&3)||count>SIZE_MAX/4||rx_va>UINTPTR_MAX-count*4||producer_index>=count||count-producer_index<3)return 0;
    adrp=code[producer_index];base=adrp&31;
    if((adrp&0x9f000000)!=0x90000000||base<8||base>17)return 0;
    add=code[producer_index+1];
    if((add&0xff800000)!=0x91000000||(add&31)!=base||((add>>5)&31)!=base)return 0;
    pc=rx_va+producer_index*4;
    pages=madeira_na_sext(((adrp>>29)&3)|((adrp>>5)&0x7ffff)<<2,21);
    if(!madeira_na_add_signed(pc&~(uintptr_t)0xfff,(intptr_t)(pages*4096),&page)||
       !madeira_na_add_signed(page,rw_delta,&new_page))return 0;
    {
        uintptr_t offset=(uintptr_t)((add>>10)&0xfff)<<((add>>22)&1?12:0);
        if(page>UINTPTR_MAX-offset)return 0;
        target=page+offset;
        if(!madeira_na_add_signed(target,rw_delta,&target_rw))return 0;
    }
    for(at=producer_index+2;at<count&&at-producer_index<=64;at++){
        uint32_t op=code[at];
        if(madeira_na_lse(op)&&((op>>5)&31)==base){
            if(((op>>16)&31)==base)return 0;
            width=1u<<(op>>30);kind=MADEIRA_NATIVE_ATOMIC_ALIAS_LSE;
            after=at+1;break;
        }
        if(madeira_na_exclusive(code,count,at,base,&width)){kind=MADEIRA_NATIVE_ATOMIC_ALIAS_EXCLUSIVE;after=at+4;break;}
        if(!madeira_na_operands(op,&read,&write)||((read|write)&madeira_na_bit(base)))return 0;
    }
    if(!kind||!width||((target|target_rw)&(width-1))||target>UINTPTR_MAX-(width-1)||
       target_rw>UINTPTR_MAX-(width-1)||!check(context,target,target_rw,width))return 0;
    if(!(kind==MADEIRA_NATIVE_ATOMIC_ALIAS_LSE&&(code[at]&31)==base)&&
       !madeira_na_dead(code,count,after,base,target,target_rw,check,context))return 0;
    if(new_page>=(pc&~(uintptr_t)0xfff)){
        uintptr_t n=(new_page-(pc&~(uintptr_t)0xfff))/4096;if(n>=0x100000)return 0;new_pages=(int64_t)n;
    }else{
        uintptr_t n=((pc&~(uintptr_t)0xfff)-new_page)/4096;if(n>0x100000)return 0;new_pages=-(int64_t)n;
    }
    {
        uint32_t encoded=(uint32_t)new_pages&0x1fffff;
        plan.producer_index=producer_index;plan.consumer_index=at;plan.original=adrp;
        plan.replacement=(adrp&~UINT32_C(0x60ffffe0))|((encoded&3)<<29)|((encoded>>2)<<5);
    }
    plan.target_rx=target;plan.target_rw=target_rw;plan.width=width;plan.kind=kind;*out=plan;return 1;
}
#endif
