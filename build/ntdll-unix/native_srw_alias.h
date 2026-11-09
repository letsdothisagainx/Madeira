/* SPDX-License-Identifier: MIT
 * Private source-built ntdll SRW history writers. The Windows lock, history
 * entries, index, and original data addresses are unchanged. Only the two
 * host-private writer pointers bind to this unpublished copy's retained RW
 * alias. Unknown contracts keep the original fault/emulation path.
 */
#ifndef MADEIRA_NATIVE_SRW_ALIAS_H
#define MADEIRA_NATIVE_SRW_ALIAS_H
#include "native_counter_alias.h"

struct ios_native_srw_alias_layout
{
    size_t ring_slot, index_slot;
    uintptr_t ring_value, index_value;
};

static int ios_native_srw_alias_layout_read(const unsigned char *image, size_t size,
                                           uintptr_t rx, intptr_t delta,
                                           struct ios_native_srw_alias_layout *layout)
{
    struct ios_native_counter_alias_layout counter;
    size_t pe,opt,sections,export_rva,export_bytes,functions,names,ordinals;
    size_t rvas[3]={SIZE_MAX,SIZE_MAX,SIZE_MAX},i,j;
    const char *const wanted[]={"ios_srw_ring","ios_srw_ring_idx","ios_srw_history_write_contract"};
    const size_t lengths[]={MADEIRA_NATIVE_SRW_RING_BYTES,sizeof(uint32_t),MADEIRA_NATIVE_SRW_CONTRACT_BYTES};
    unsigned count,opt_bytes;
    uint32_t function_count,name_count;
    /* The existing counter ABI validates the entire PE/section/export layout,
     * image size, native machine, RX/RW arithmetic and readable/writable DATA.
     * Requiring both source contracts also rejects an unrelated named DLL. */
    if (!layout || !ios_native_counter_alias_layout_read(image,size,rx,delta,&counter)) return 0;
    pe=ios_native_u32(image+0x3c);
    if (!ios_native_span(pe,24,size)) return 0;
    opt=pe+24; opt_bytes=ios_native_u16(image+pe+20);
    count=ios_native_u16(image+pe+6); sections=opt+opt_bytes;
    if (!count || count>96 || opt_bytes<0x78 || !ios_native_span(opt,opt_bytes,size) ||
        !ios_native_span(sections,count*40u,size)) return 0;
    export_rva=ios_native_u32(image+opt+0x70); export_bytes=ios_native_u32(image+opt+0x74);
    if (export_bytes<40 || !ios_native_span(export_rva,export_bytes,size)) return 0;
    function_count=ios_native_u32(image+export_rva+20); name_count=ios_native_u32(image+export_rva+24);
    functions=ios_native_u32(image+export_rva+28);
    names=ios_native_u32(image+export_rva+32); ordinals=ios_native_u32(image+export_rva+36);
    if (!function_count || !name_count || function_count>size/4 || name_count>size/4 ||
        !ios_native_span(functions,function_count*4u,size) || !ios_native_span(names,name_count*4u,size) ||
        !ios_native_span(ordinals,name_count*2u,size)) return 0;
    for (i=0;i<name_count;i++)
    {
        size_t name=ios_native_u32(image+names+4*i),rva;
        unsigned ordinal=ios_native_u16(image+ordinals+2*i);
        const char *text;
        if (name>=size || ordinal>=function_count) return 0;
        text=(const char *)image+name;
        if (!memchr(text,0,size-name<64?size-name:64)) continue;
        for (j=0;j<3;j++)
        {
            if (strcmp(text,wanted[j])) continue;
            rva=ios_native_u32(image+functions+4*ordinal);
            if (rvas[j]!=SIZE_MAX || (rva>=export_rva && rva-export_rva<export_bytes) ||
                !ios_native_counter_data_aligned(image,size,sections,count,rva,lengths[j],j==1?4:8)) return 0;
            rvas[j]=rva;
        }
    }
    for (i=0;i<3;i++)
    {
        size_t old_counter=(size_t)(counter.writer_value-rx-(uintptr_t)delta);
        size_t old_contract=counter.writer_offset-MADEIRA_NATIVE_COUNTER_WRITER_OFFSET;
        if (rvas[i]==SIZE_MAX || (rvas[i]&(i==1?3:7))) return 0;
        if ((rvas[i]<old_counter+MADEIRA_NATIVE_COUNTER_BYTES && old_counter<rvas[i]+lengths[i]) ||
            (rvas[i]<old_contract+MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES && old_contract<rvas[i]+lengths[i])) return 0;
        for (j=0;j<i;j++)
            if (rvas[i]<rvas[j]+lengths[j] && rvas[j]<rvas[i]+lengths[i]) return 0;
    }
    if (ios_native_u64(image+rvas[2])!=MADEIRA_NATIVE_SRW_ABI_V1 ||
        ios_native_u32(image+rvas[2]+8)!=MADEIRA_NATIVE_SRW_RING_BYTES ||
        ios_native_u32(image+rvas[2]+12)!=MADEIRA_NATIVE_SRW_ENTRY_BYTES) return 0;
    layout->ring_slot=rvas[2]+MADEIRA_NATIVE_SRW_RING_WRITER_OFFSET;
    layout->index_slot=rvas[2]+MADEIRA_NATIVE_SRW_INDEX_WRITER_OFFSET;
    layout->ring_value=rx+rvas[0]+(uintptr_t)delta;
    layout->index_value=rx+rvas[1]+(uintptr_t)delta;
    return 1;
}

static int ios_native_srw_alias_bind(unsigned char *image, size_t size,
                                     uintptr_t rx, intptr_t delta, int unpublished)
{
    struct ios_native_srw_alias_layout layout;
    if (!unpublished || !ios_native_srw_alias_layout_read(image,size,rx,delta,&layout)) return 0;
    /* Ignore copied parent pointers. Publication occurs only after BOTH
     * fields describe this copy, with no observer in this unpublished image. */
    memcpy(image+layout.ring_slot,&layout.ring_value,sizeof(layout.ring_value));
    memcpy(image+layout.index_slot,&layout.index_value,sizeof(layout.index_value));
    return 1;
}

/* One data copy preserves all independently validated writer fields. Running
 * two copy functions in sequence would transiently overwrite the other's
 * pointer with a source NULL/parent value. No pointer is rebound after publish. */
static inline int ios_native_counter_and_srw_alias_copy(unsigned char *image, size_t size,
                                                        uintptr_t rx, intptr_t delta,
                                                        size_t offset,const void *source,size_t bytes)
{
    struct ios_native_counter_alias_layout counter;
    struct ios_native_srw_alias_layout history;
    size_t slots[3],count=0,i,j,at,end;
    uintptr_t current,ring,index;
    const unsigned char *src=source;
    if (!image || !ios_native_span(offset,bytes,size) || (bytes&&!source) ||
        (uintptr_t)image>UINTPTR_MAX-size) return 0;
    if (!bytes) return 1;
    if (ios_native_counter_alias_layout_read(image,size,rx,delta,&counter))
    {
        memcpy(&current,image+counter.writer_offset,sizeof(current));
        if (current==counter.writer_value) slots[count++]=counter.writer_offset;
    }
    if (ios_native_srw_alias_layout_read(image,size,rx,delta,&history))
    {
        memcpy(&ring,image+history.ring_slot,sizeof(ring));
        memcpy(&index,image+history.index_slot,sizeof(index));
        if (ring==history.ring_value && index==history.index_value)
        {
            slots[count++]=history.ring_slot; slots[count++]=history.index_slot;
        }
    }
    for (i=0;i<count;i++) for (j=i+1;j<count;j++)
        if (slots[j]<slots[i]) { size_t swap=slots[i]; slots[i]=slots[j]; slots[j]=swap; }
    at=offset; end=offset+bytes;
    for (i=0;i<count;i++)
    {
        size_t stop=slots[i],after=stop+sizeof(uintptr_t);
        if (at>=after || end<=stop) continue;
        if (at<stop) memcpy(image+at,src+at-offset,stop-at);
        at=after<end?after:end;
    }
    if (at<end) memcpy(image+at,src+at-offset,end-at);
    return 1;
}
#endif
