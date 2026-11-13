/* SPDX-License-Identifier: MIT
 * Bind only explicit Madeira-built FEX diagnostic spans. This helper
 * knows no guest address or arbitrary native pointer: every payload must be
 * wholly private DATA in this very image. The caller supplies the retained
 * aliases of an owned copy and binds only before that copy is published.
 */
#ifndef MADEIRA_NATIVE_FEX_DIAGNOSTICS_ALIAS_H
#define MADEIRA_NATIVE_FEX_DIAGNOSTICS_ALIAS_H
#include <strings.h>
#include "native_counter_alias.h"

#define MADEIRA_FEX_TELEMETRY_TAG UINT64_C(0x31544d584546574d)
#define MADEIRA_FEX_IRTOPO_TAG UINT64_C(0x315249584546574d)
#define MADEIRA_FEX_COMPILE_TAG UINT64_C(0x314243584546574d)
#define MADEIRA_FEX_HISTORY_TAG UINT64_C(0x314852584546574d)
#define MADEIRA_FEX_TRANSITION_TAG UINT64_C(0x315058584546574d)
#define MADEIRA_FEX_SYSCALL_TAG UINT64_C(0x315359584546574d)
#define MADEIRA_FEX_DIAGNOSTIC_SPANS 5u
#define MADEIRA_FEX_DIAGNOSTIC_CONTRACT_BYTES 32u
#define MADEIRA_FEX_DIAGNOSTIC_WRITER_OFFSET 24u

struct ios_native_fex_diagnostics_layout {
    unsigned spans;
    size_t slots[MADEIRA_FEX_DIAGNOSTIC_SPANS],payloads[MADEIRA_FEX_DIAGNOSTIC_SPANS];
    uintptr_t values[MADEIRA_FEX_DIAGNOSTIC_SPANS];
};

static int ios_native_fex_name(const char *name)
{
    const char *const allowed[]={"libarm64ecfex.dll","xtajit64.dll","libwow64fex.dll","xtajit.dll"};
    unsigned i;
    for(i=0;i<4;i++){
        const unsigned char *a=(const unsigned char *)name,*b=(const unsigned char *)allowed[i];
        for(;;a++,b++){
            unsigned x=*a,y=*b;
            if(x>='A'&&x<='Z')x+='a'-'A';
            if(y>='A'&&y<='Z')y+='a'-'A';
            if(x!=y)break;
            if(!x)return 1;
        }
    }
    return 0;
}

static int ios_native_fex_diagnostics_layout_read(const unsigned char *image,size_t size,
    uintptr_t source,uintptr_t rx,intptr_t delta,struct ios_native_fex_diagnostics_layout *layout)
{
    const char *wanted[]={"MadeiraFEXTelemetryWriteContract","MadeiraFEXIRTopoWriteContract","MadeiraFEXCompileWriteContract","MadeiraFEXHistoryWriteContract",NULL};
    uint64_t tags[]={MADEIRA_FEX_TELEMETRY_TAG,MADEIRA_FEX_IRTOPO_TAG,MADEIRA_FEX_COMPILE_TAG,MADEIRA_FEX_HISTORY_TAG,0};
    size_t bytes[]={136,32,48,192,0},alignment[]={8,8,8,8,0};
    const char *specific_name;
    size_t pe,opt,sections,export_rva,export_bytes,functions,names,ordinals,module,i,j;
    size_t contracts[MADEIRA_FEX_DIAGNOSTIC_SPANS]={SIZE_MAX,SIZE_MAX,SIZE_MAX,SIZE_MAX,SIZE_MAX},payloads[MADEIRA_FEX_DIAGNOSTIC_SPANS],transition=SIZE_MAX;
    unsigned count,opt_bytes,machine,spans;
    uint32_t function_count,name_count;
    uint64_t preferred;
    if(!image||!layout||sizeof(uintptr_t)!=8||!source||!rx||(rx&0xfff)||delta<=0||
       ((uintptr_t)delta&0xfff)||size<0x40||source>UINTPTR_MAX-size||rx>UINTPTR_MAX-size||
       (uintptr_t)delta>UINTPTR_MAX-rx-size||image[0]!='M'||image[1]!='Z')return 0;
    pe=ios_native_u32(image+0x3c);
    if(!ios_native_span(pe,24,size)||memcmp(image+pe,"PE\0\0",4))return 0;
    machine=ios_native_u16(image+pe+4);count=ios_native_u16(image+pe+6);
    opt_bytes=ios_native_u16(image+pe+20);opt=pe+24;
    if((machine!=0xaa64&&machine!=0xa641&&machine!=0x8664)||!count||count>96||opt_bytes<240||
       !ios_native_span(opt,opt_bytes,size)||ios_native_u16(image+opt)!=0x20b||
       ios_native_u32(image+opt+56)!=size||ios_native_u32(image+opt+108)<11)return 0;
    preferred=ios_native_u64(image+opt+24);
    sections=opt+opt_bytes;
    if(!ios_native_span(sections,count*40u,size))return 0;
    for(i=0;i<count;i++){
        const unsigned char *s=image+sections+40*i;
        size_t start=ios_native_u32(s+12),length=ios_native_u32(s+8);
        if(!length)length=ios_native_u32(s+16);
        if(!ios_native_span(start,length,size))return 0;
        for(j=0;j<i;j++){
            const unsigned char *t=image+sections+40*j;
            size_t a=ios_native_u32(t+12),n=ios_native_u32(t+8);
            if(!n)n=ios_native_u32(t+16);
            if(length&&n&&start<a+n&&a<start+length)return 0;
        }
    }
    /* Some ARM64EC toolchains retain an AMD64 PE header. Accept one only
     * when its own CHPE metadata proves an actual native ARM64 code range. */
    if(machine==0x8664){
        size_t config=ios_native_u32(image+opt+112+10*8),config_bytes=ios_native_u32(image+opt+116+10*8);
        size_t metadata,map,n;
        unsigned native=0;
        if(config_bytes<208||!ios_native_span(config,208,size)||ios_native_u32(image+config)<208)return 0;
        metadata=ios_native_meta_rva(ios_native_u64(image+config+200),preferred,source,rx,rx+(uintptr_t)delta,size);
        if(!ios_native_span(metadata,12,size)||(ios_native_u32(image+metadata)!=1&&ios_native_u32(image+metadata)!=2))return 0;
        map=ios_native_u32(image+metadata+4);n=ios_native_u32(image+metadata+8);
        if(!n||n>65536||!ios_native_span(map,n*8,size))return 0;
        for(i=0;i<n;i++){
            size_t encoded=ios_native_u32(image+map+i*8),a=encoded&~(size_t)3,length=ios_native_u32(image+map+i*8+4);
            if((encoded&3)!=1||!length)continue;
            for(j=0;j<count;j++){
                const unsigned char *s=image+sections+40*j;
                size_t start=ios_native_u32(s+12),span=ios_native_u32(s+8);
                if(!span)span=ios_native_u32(s+16);
                if((ios_native_u32(s+36)&0xe0000000u)==0x60000000u&&a>=start&&
                   a-start<=span&&length<=span-(a-start))native=1;
            }
        }
        if(!native)return 0;
    }
    export_rva=ios_native_u32(image+opt+112);export_bytes=ios_native_u32(image+opt+116);
    if(export_bytes<40||!ios_native_span(export_rva,export_bytes,size))return 0;
    module=ios_native_u32(image+export_rva+12);
    if(module>=size||!memchr(image+module,0,size-module<64?size-module:64)||
       !ios_native_fex_name((const char *)image+module))return 0;
    spans=MADEIRA_FEX_DIAGNOSTIC_SPANS;
    if(!strcasecmp((const char *)image+module,"libarm64ecfex.dll")||
       !strcasecmp((const char *)image+module,"xtajit64.dll")){
        wanted[4]="MadeiraFEXTransitionWriteContract";tags[4]=MADEIRA_FEX_TRANSITION_TAG;
        bytes[4]=35968;alignment[4]=64;specific_name="IosXpFex";
    }else{
        wanted[4]="MadeiraFEXSyscallWriteContract";tags[4]=MADEIRA_FEX_SYSCALL_TAG;
        bytes[4]=4;alignment[4]=4;specific_name="MadeiraFEXSyscallDeclined";
    }
    function_count=ios_native_u32(image+export_rva+20);name_count=ios_native_u32(image+export_rva+24);
    functions=ios_native_u32(image+export_rva+28);names=ios_native_u32(image+export_rva+32);ordinals=ios_native_u32(image+export_rva+36);
    if(!function_count||!name_count||function_count>size/4||name_count>size/4||
       !ios_native_span(functions,function_count*4u,size)||!ios_native_span(names,name_count*4u,size)||
       !ios_native_span(ordinals,name_count*2u,size))return 0;
    for(i=0;i<name_count;i++){
        size_t name=ios_native_u32(image+names+4*i),rva;
        unsigned ordinal=ios_native_u16(image+ordinals+2*i);
        const char *text;
        if(name>=size||ordinal>=function_count)return 0;
        text=(const char *)image+name;
        if(!memchr(text,0,size-name<64?size-name:64))continue;
        if(!strcmp(text,specific_name)){
            rva=ios_native_u32(image+functions+4*ordinal);
            if(transition!=SIZE_MAX||(rva>=export_rva&&rva-export_rva<export_bytes)||
               !ios_native_counter_data_aligned(image,size,sections,count,rva,bytes[4],alignment[4]))return 0;
            transition=rva;
        }
        for(j=0;j<spans;j++){
            if(strcmp(text,wanted[j]))continue;
            rva=ios_native_u32(image+functions+4*ordinal);
            if(contracts[j]!=SIZE_MAX||(rva>=export_rva&&rva-export_rva<export_bytes)||
               !ios_native_counter_data(image,size,sections,count,rva,32))return 0;
            contracts[j]=rva;
        }
    }
    for(i=0;i<spans;i++){
        size_t contract=contracts[i];
        if(contract==SIZE_MAX||ios_native_u64(image+contract)!=tags[i]||
           ios_native_u32(image+contract+8)!=bytes[i]||ios_native_u32(image+contract+12)!=alignment[i])return 0;
        payloads[i]=ios_native_meta_rva(ios_native_u64(image+contract+16),preferred,source,rx,rx+(uintptr_t)delta,size);
        if(!ios_native_counter_data_aligned(image,size,sections,count,payloads[i],bytes[i],alignment[i])||
           (i==4&&payloads[i]!=transition))return 0;
        for(j=0;j<spans;j++){
            if(contracts[j]==SIZE_MAX)return 0;
            if(payloads[i]<contracts[j]+32&&contracts[j]<payloads[i]+bytes[i])return 0;
            if(j<i&&contracts[i]<contracts[j]+32&&contracts[j]<contracts[i]+32)return 0;
            if(j<i&&payloads[i]<payloads[j]+bytes[j]&&payloads[j]<payloads[i]+bytes[i])return 0;
        }
    }
    /* Wine must never relocate one of the private writer slots after this
     * initial binding. The initialized payload pointer may have DIR64, but a
     * writer is NULL in the file and has no relocation of its own. */
    {
        size_t at=ios_native_u32(image+opt+112+5*8),length=ios_native_u32(image+opt+116+5*8),end;
        if(length&&!ios_native_span(at,length,size))return 0;
        end=at+length;
        while(at<end){
            size_t page,block,n;
            if(end-at<8)return 0;
            page=ios_native_u32(image+at);block=ios_native_u32(image+at+4);
            if(block<8||(block&1)||block>end-at)return 0;
            for(n=at+8;n<at+block;n+=2){
                unsigned relocation=ios_native_u16(image+n),kind=relocation>>12;
                size_t target=page+(relocation&0xfff);
                if(!kind)continue;
                if(!ios_native_span(target,kind==10?8:4,size))return 0;
                for(i=0;i<spans;i++)if(target<contracts[i]+32&&contracts[i]+24<target+(kind==10?8:4))return 0;
            }
            at+=block;
        }
    }
    layout->spans=spans;
    for(i=0;i<spans;i++){
        layout->slots[i]=contracts[i]+24;layout->payloads[i]=payloads[i];
        layout->values[i]=rx+(uintptr_t)delta+payloads[i];
    }
    return 1;
}

static int ios_native_fex_diagnostics_bind(unsigned char *image,size_t size,uintptr_t source,
    uintptr_t rx,intptr_t delta,int unpublished)
{
    struct ios_native_fex_diagnostics_layout layout;
    unsigned i;
    if(!unpublished||!ios_native_fex_diagnostics_layout_read(image,size,source,rx,delta,&layout))return 0;
    for(i=0;i<layout.spans;i++)memcpy(image+layout.slots[i],&layout.values[i],8);
    return (int)layout.spans;
}

static int ios_native_fex_diagnostics_copy(unsigned char *image,size_t size,uintptr_t source,
    uintptr_t rx,intptr_t delta,size_t offset,const void *input,size_t bytes)
{
    struct ios_native_fex_diagnostics_layout layout;
    size_t contracts[MADEIRA_FEX_DIAGNOSTIC_SPANS],n=0,i,j,at,end;
    const unsigned char *src=input;
    uintptr_t current;
    if(!image||!ios_native_span(offset,bytes,size)||(bytes&&!input)||(uintptr_t)image>UINTPTR_MAX-size||
       !ios_native_fex_diagnostics_layout_read(image,size,source,rx,delta,&layout))return 0;
    if(!bytes)return 1;
    for(i=0;i<layout.spans;i++){
        memcpy(&current,image+layout.slots[i],8);
        if(current==layout.values[i])contracts[n++]=layout.slots[i]-24;
    }
    /* These descriptors are immutable host-private ABI metadata after binding.
     * Preserve the complete descriptor, not only its writer. In particular a
     * concurrent canonical-source refresh must not transiently replace its
     * payload pointer/base and make another reader abandon writer protection.
     * All diagnostic payload bytes keep ordinary source synchronization. */
    for(i=0;i<n;i++)for(j=i+1;j<n;j++)if(contracts[j]<contracts[i]){size_t swap=contracts[i];contracts[i]=contracts[j];contracts[j]=swap;}
    at=offset;end=offset+bytes;
    for(i=0;i<n;i++){
        size_t stop=contracts[i],after=stop+32;
        if(at>=after||end<=stop)continue;
        if(at<stop)memcpy(image+at,src+at-offset,stop-at);
        at=after<end?after:end;
    }
    if(at<end)memcpy(image+at,src+at-offset,end-at);
    return 1;
}
#endif
