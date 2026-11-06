/* SPDX-License-Identifier: MIT. Single-writer diagnostic accounting only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fault_site_counters.h"

static struct ios_fault_site_table table;
static unsigned calls;
static unsigned long long code_generation=1,data_generation=1;
static void snapshot(void *context,const struct ios_fault_site_key *key,struct ios_fault_site_metadata *meta)
{
    assert(context==&calls);calls++;
    meta->pid=0x20;meta->tid=key->teb+0x44;meta->peb=key->teb+0x1000;meta->teb_read=1;
    meta->code=(struct ios_fault_mapping_meta){.pe_base=0x100000,.rx_base=0x200000,.owner=meta->peb,
        .image_size=0x10000,.generation=code_generation,.generation_address=&code_generation};
    meta->data=(struct ios_fault_mapping_meta){.pe_base=0x100000,.rx_base=0x200000,.owner=meta->peb,
        .image_size=0x10000,.generation=data_generation,.generation_address=&data_generation};
}
static struct ios_fault_site_key key(unsigned n,unsigned family)
{
    struct ios_fault_site_key result={.pc=0x100000+n*4,.teb=0x4000000,.target_page=0x204000,
        .port=7,.insn=0xf9000120,.family=family};return result;
}
static void verify(void)
{
    uint64_t total=0,tracked=0,overflow=0,entries=0;unsigned occupied=0;
    assert(table.total==table.tracked+table.overflow);
    for(unsigned f=0;f<MADEIRA_STORE_FAMILIES;f++){
        assert(table.family_total[f]==table.family_tracked[f]+table.family_overflow[f]);
        total+=table.family_total[f];tracked+=table.family_tracked[f];overflow+=table.family_overflow[f];
    }
    assert(total==table.total&&tracked==table.tracked&&overflow==table.overflow);
    for(unsigned i=0;i<IOS_FAULT_SITE_SLOTS;i++)if(table.entries[i].count){
        entries+=table.entries[i].count;occupied++;
    }
    assert(entries==table.tracked&&occupied==table.occupied);
}
int main(void)
{
    struct ios_fault_site_key basic=key(1,MADEIRA_STORE_GPR);
    const struct ios_fault_site_entry *top[MADEIRA_STORE_FAMILIES][2];
    for(unsigned i=0;i<1000;i++)assert(!ios_fault_site_note(&table,&basic,snapshot,&calls));
    assert(calls==1&&table.occupied==1&&table.tracked==1000);verify();
    ios_fault_site_top(&table,top);
    assert(top[MADEIRA_STORE_GPR][0]->count==1000&&!top[MADEIRA_STORE_GPR][1]);
    assert(ios_fault_site_generation(top[MADEIRA_STORE_GPR][0])==1);
    /* Identical raw addresses after lease reuse must not merge with old keys. */
    code_generation++;data_generation++;
    assert(ios_fault_site_generation(top[MADEIRA_STORE_GPR][0])==-1);
    assert(!ios_fault_site_note(&table,&basic,snapshot,&calls));
    assert(calls==2&&table.occupied==2);verify();
    ios_fault_site_top(&table,top);
    assert(top[MADEIRA_STORE_GPR][0]->count==1000&&top[MADEIRA_STORE_GPR][1]->count==1);
    assert(ios_fault_site_generation(top[MADEIRA_STORE_GPR][1])==1);
    /* All key dimensions matter, including raw TEB, port, page and opcode. */
    struct ios_fault_site_key changed=basic;
    changed.teb++;ios_fault_site_note(&table,&changed,snapshot,&calls);
    changed=basic;changed.port++;ios_fault_site_note(&table,&changed,snapshot,&calls);
    changed=basic;changed.target_page+=0x4000;ios_fault_site_note(&table,&changed,snapshot,&calls);
    changed=basic;changed.insn^=1;ios_fault_site_note(&table,&changed,snapshot,&calls);
    changed=basic;changed.pc+=4;ios_fault_site_note(&table,&changed,snapshot,&calls);
    changed=basic;changed.family=MADEIRA_STORE_RELEASE;ios_fault_site_note(&table,&changed,snapshot,&calls);
    assert(table.occupied==8&&calls==8);verify();
    ios_fault_site_reset(&table);calls=0;assert(table.epoch==1&&!table.total&&!table.occupied);
    /* A saturated probe chain overflows explicitly; it never evicts the
     * highest-count record or silently drops a hit from a tracked key. */
    struct ios_fault_site_key collision[IOS_FAULT_SITE_PROBES+1];unsigned found=0;
    for(unsigned n=0;found<IOS_FAULT_SITE_PROBES+1;n++){
        struct ios_fault_site_key next=key(n,MADEIRA_STORE_EXCLUSIVE);
        if(ios_fault_site_hash(&next)==37)collision[found++]=next;
    }
    for(unsigned i=0;i<IOS_FAULT_SITE_PROBES;i++)ios_fault_site_note(&table,&collision[i],snapshot,&calls);
    assert(calls==IOS_FAULT_SITE_PROBES&&table.occupied==IOS_FAULT_SITE_PROBES);
    for(unsigned i=0;i<17;i++)ios_fault_site_note(&table,&collision[IOS_FAULT_SITE_PROBES],snapshot,&calls);
    assert(table.overflow==17&&calls==IOS_FAULT_SITE_PROBES);
    for(unsigned i=0;i<99;i++)ios_fault_site_note(&table,&collision[0],snapshot,&calls);
    ios_fault_site_top(&table,top);assert(top[MADEIRA_STORE_EXCLUSIVE][0]->count==100);
    assert(table.family_overflow[MADEIRA_STORE_EXCLUSIVE]==17);verify();
    /* Exercise every physical slot without relying on a random collision
     * distribution. A full-table miss remains explicitly accounted. */
    ios_fault_site_reset(&table);calls=0;
    unsigned char buckets[IOS_FAULT_SITE_SLOTS]={0};unsigned populated=0;
    for(unsigned n=0;populated<IOS_FAULT_SITE_SLOTS;n++){
        struct ios_fault_site_key next=key(n,MADEIRA_STORE_LSE);unsigned bucket=ios_fault_site_hash(&next);
        if(buckets[bucket])continue;
        buckets[bucket]=1;populated++;ios_fault_site_note(&table,&next,snapshot,&calls);
    }
    assert(table.occupied==IOS_FAULT_SITE_SLOTS&&calls==IOS_FAULT_SITE_SLOTS&&!table.overflow);
    changed=key(0x800000,MADEIRA_STORE_LSE);
    ios_fault_site_note(&table,&changed,snapshot,&calls);
    assert(table.overflow==1&&calls==IOS_FAULT_SITE_SLOTS);verify();
    /* Per-family top two are exact among the retained keys and reporting is
     * read-only. A missing mapping token is explicitly unverifiable. */
    ios_fault_site_reset(&table);calls=0;
    for(unsigned f=0;f<MADEIRA_STORE_FAMILIES;f++)for(unsigned k=0;k<3;k++){
        struct ios_fault_site_key next=key(100+f*3+k,f);
        for(unsigned n=0;n<k+1;n++)ios_fault_site_note(&table,&next,NULL,NULL);
    }
    ios_fault_site_top(&table,top);
    for(unsigned f=0;f<MADEIRA_STORE_FAMILIES;f++){
        assert(top[f][0]->count==3&&top[f][1]->count==2);
        assert(ios_fault_site_generation(top[f][0])==0);
    }
    verify();assert(!calls&&table.total==MADEIRA_STORE_FAMILIES*6);
    /* A million-event epoch closes exactly on the millionth event, with one
     * metadata snapshot and no per-hit callback or dropped accounting. */
    ios_fault_site_reset(&table);calls=0;
    for(unsigned n=1;n<=IOS_FAULT_SITE_EPOCH;n++)
        assert(ios_fault_site_note(&table,&basic,snapshot,&calls)==(n==IOS_FAULT_SITE_EPOCH));
    assert(calls==1&&table.total==IOS_FAULT_SITE_EPOCH&&table.tracked==table.total&&!table.overflow);
    verify();unsigned long long epoch=table.epoch;ios_fault_site_reset(&table);
    assert(table.epoch==epoch+1&&!table.total&&!table.tracked&&!table.overflow&&!table.occupied);
    changed=basic;changed.family=MADEIRA_STORE_FAMILIES;
    assert(ios_fault_site_note(&table,&changed,snapshot,&calls)==-1&&!table.total);
    puts("PASS exact fault-site counters: totals/families, collisions, bounded overflow, generations, top2 and million-event reset");
    return 0;
}
