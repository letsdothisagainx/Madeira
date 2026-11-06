/* SPDX-License-Identifier: MIT
 * Bind only the explicit source-built counter contract of an unpublished
 * native image. No code, counter contents, protections or allocation changes.
 */
#ifndef MADEIRA_NATIVE_COUNTER_ALIAS_H
#define MADEIRA_NATIVE_COUNTER_ALIAS_H
#include "native_counter_alias_abi.h"
#include "native_atomic_image.h"

static int ios_native_counter_data(const unsigned char *image, size_t size,
                                  size_t sections, unsigned count, size_t rva, size_t bytes)
{
    unsigned i;
    if ((rva & 7) || !ios_native_span(rva,bytes,size)) return 0;
    for (i=0;i<count;i++)
    {
        const unsigned char *s=image+sections+40*i;
        size_t start=ios_native_u32(s+12), length=ios_native_u32(s+8);
        if (!length) length=ios_native_u32(s+16);
        /* Dedicated, readable/writable, nonexecuting, nondiscardable,
         * nonshared data. This is an arbitrary span, not an atomic width. */
        if ((ios_native_u32(s+36)&0xf2000000u)==0xc0000000u &&
            rva>=start && rva-start<=length && bytes<=length-(rva-start)) return 1;
    }
    return 0;
}

static int ios_native_counter_alias_bind(unsigned char *image, size_t size,
                                        uintptr_t rx, intptr_t delta, int unpublished)
{
    size_t pe,opt,sections,export_rva,export_bytes,functions,names,ordinals;
    size_t counter=SIZE_MAX,contract=SIZE_MAX,i;
    unsigned count,opt_bytes,machine;
    uint32_t function_count,name_count;
    uintptr_t writer;
    if (!unpublished || !image || sizeof(uintptr_t)!=8 || !rx || (rx&0xfff) ||
        delta<=0 || ((uintptr_t)delta&0xfff) || size<0x40 ||
        rx>UINTPTR_MAX-size || (uintptr_t)delta>UINTPTR_MAX-rx-size ||
        image[0]!='M' || image[1]!='Z') return 0;
    pe=ios_native_u32(image+0x3c);
    if (!ios_native_span(pe,24,size) || memcmp(image+pe,"PE\0\0",4)) return 0;
    machine=ios_native_u16(image+pe+4); count=ios_native_u16(image+pe+6);
    opt_bytes=ios_native_u16(image+pe+20); opt=pe+24;
    if ((machine!=0xaa64 && machine!=0x8664 && machine!=0xa641) ||
        !count || count>96 || opt_bytes<0x78 || !ios_native_span(opt,opt_bytes,size) ||
        ios_native_u16(image+opt)!=0x20b || ios_native_u32(image+opt+56)!=size ||
        !ios_native_u32(image+opt+108)) return 0;
    sections=opt+opt_bytes;
    if (!ios_native_span(sections,count*40u,size)) return 0;
    /* Reject ambiguous code/data ownership before considering either export. */
    for (i=0;i<count;i++)
    {
        const unsigned char *s=image+sections+40*i;
        size_t start=ios_native_u32(s+12),length=ios_native_u32(s+8),j;
        if (!length) length=ios_native_u32(s+16);
        if (!ios_native_span(start,length,size)) return 0;
        for (j=0;j<i;j++)
        {
            const unsigned char *t=image+sections+40*j;
            size_t a=ios_native_u32(t+12),n=ios_native_u32(t+8);
            if (!n) n=ios_native_u32(t+16);
            if (length && n && start<a+n && a<start+length) return 0;
        }
    }
    export_rva=ios_native_u32(image+opt+0x70);
    export_bytes=ios_native_u32(image+opt+0x74);
    if (export_bytes<40 || !ios_native_span(export_rva,export_bytes,size)) return 0;
    function_count=ios_native_u32(image+export_rva+20);
    name_count=ios_native_u32(image+export_rva+24);
    functions=ios_native_u32(image+export_rva+28);
    names=ios_native_u32(image+export_rva+32);
    ordinals=ios_native_u32(image+export_rva+36);
    if (!function_count || !name_count || function_count>size/4 || name_count>size/4 ||
        !ios_native_span(functions,function_count*4u,size) ||
        !ios_native_span(names,name_count*4u,size) ||
        !ios_native_span(ordinals,name_count*2u,size)) return 0;
    for (i=0;i<name_count;i++)
    {
        size_t name=ios_native_u32(image+names+4*i),rva;
        unsigned ordinal=ios_native_u16(image+ordinals+2*i);
        const char *text;
        if (name>=size || ordinal>=function_count) return 0;
        text=(const char *)image+name;
        if (!memchr(text,0,size-name<64?size-name:64)) continue;
        if (strcmp(text,"ios_xp_nt") && strcmp(text,"ios_xp_nt_write_contract")) continue;
        rva=ios_native_u32(image+functions+4*ordinal);
        if (rva>=export_rva && rva-export_rva<export_bytes) return 0; /* no forwarders */
        if (!strcmp(text,"ios_xp_nt"))
        {
            if (counter!=SIZE_MAX) return 0;
            counter=rva;
        }
        else
        {
            if (contract!=SIZE_MAX) return 0;
            contract=rva;
        }
    }
    if (counter==SIZE_MAX || contract==SIZE_MAX ||
        !ios_native_counter_data(image,size,sections,count,counter,MADEIRA_NATIVE_COUNTER_BYTES) ||
        !ios_native_counter_data(image,size,sections,count,contract,MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES) ||
        (counter<contract+MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES &&
         contract<counter+MADEIRA_NATIVE_COUNTER_BYTES) ||
        ios_native_u64(image+contract)!=MADEIRA_NATIVE_COUNTER_ABI_V1 ||
        ios_native_u32(image+contract+8)!=MADEIRA_NATIVE_COUNTER_BYTES ||
        ios_native_u32(image+contract+12)) return 0;
    writer=rx+counter+(uintptr_t)delta;
    /* Never dereference or adopt a copied parent's pointer. A fresh child or
     * unloaded-image rebuild binds its own retained alias before publication. */
    memcpy(image+contract+MADEIRA_NATIVE_COUNTER_WRITER_OFFSET,&writer,sizeof(writer));
    return 1;
}
#endif
