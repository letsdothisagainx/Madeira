/* SPDX-License-Identifier: MIT.
 * Exact, non-evicting fault counts within a bounded diagnostic epoch. Only the
 * single Mach exception thread may access this table. Snapshot callbacks occur
 * on insertion only; hits need no heap, lock, VM query or callback. */
#ifndef MADEIRA_FAULT_SITE_COUNTERS_H
#define MADEIRA_FAULT_SITE_COUNTERS_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "jit_store_census.h"
#include "fault_site_mapping.h"

enum { IOS_FAULT_SITE_SLOTS=4096, IOS_FAULT_SITE_PROBES=64, IOS_FAULT_SITE_EPOCH=1000000 };
struct ios_fault_site_key {
    uintptr_t pc,teb,target_page;
    uint32_t port,insn;
    unsigned family;
};
struct ios_fault_site_metadata {
    uintptr_t pid,tid,peb,target;
    unsigned teb_read;
    struct ios_fault_mapping_meta code,data;
};
struct ios_fault_site_entry {
    struct ios_fault_site_key key;
    struct ios_fault_site_metadata first;
    uint64_t count;
};
struct ios_fault_site_table {
    uint64_t epoch,total,tracked,overflow;
    uint64_t family_total[MADEIRA_STORE_FAMILIES];
    uint64_t family_tracked[MADEIRA_STORE_FAMILIES];
    uint64_t family_overflow[MADEIRA_STORE_FAMILIES];
    unsigned occupied;
    struct ios_fault_site_entry entries[IOS_FAULT_SITE_SLOTS];
};
typedef void (*ios_fault_site_snapshot)(void *,const struct ios_fault_site_key *,
                                       struct ios_fault_site_metadata *);

static inline uint64_t ios_fault_site_mix(uint64_t v)
{
    v^=v>>30;v*=UINT64_C(0xbf58476d1ce4e5b9);
    v^=v>>27;v*=UINT64_C(0x94d049bb133111eb);return v^(v>>31);
}
static inline unsigned ios_fault_site_hash(const struct ios_fault_site_key *key)
{
    uint64_t h=ios_fault_site_mix(key->pc)^ios_fault_site_mix(key->teb)^ 
        ios_fault_site_mix(key->target_page)^ios_fault_site_mix(((uint64_t)key->port<<32)|key->insn)^ 
        ios_fault_site_mix(key->family);
    return (unsigned)h&(IOS_FAULT_SITE_SLOTS-1);
}
static inline int ios_fault_site_same(const struct ios_fault_site_key *a,const struct ios_fault_site_key *b)
{
    return a->pc==b->pc&&a->teb==b->teb&&a->target_page==b->target_page&&
        a->port==b->port&&a->insn==b->insn&&a->family==b->family;
}
/* -1 = one known mapping was retired/reused; 0 = some attribution unknown;
 * 1 = both stable mapping-generation tokens still match the first event.
 * Tokens must point into a never-freed registry, not an image allocation. */
static inline int ios_fault_site_generation(const struct ios_fault_site_entry *entry)
{
    const struct ios_fault_mapping_meta *code=&entry->first.code,*data=&entry->first.data;
    if((code->generation_address&&__atomic_load_n(code->generation_address,__ATOMIC_RELAXED)!=code->generation)||
       (data->generation_address&&__atomic_load_n(data->generation_address,__ATOMIC_RELAXED)!=data->generation))return -1;
    return code->generation_address&&data->generation_address?1:0;
}
/* Returns 1 when the caller should report then reset this epoch, 0 otherwise.
 * The fixed probe budget is explicit: a new key outside it increments overflow
 * even if another part of the table has space. Existing tracked keys are never
 * evicted and retain exact counts. Invalid-family input is rejected with -1. */
static inline int ios_fault_site_note(struct ios_fault_site_table *table,
    const struct ios_fault_site_key *key,ios_fault_site_snapshot snapshot,void *context)
{
    unsigned start,probe,family=key->family;
    if(family>=MADEIRA_STORE_FAMILIES)return -1;
    table->total++;table->family_total[family]++;
    start=ios_fault_site_hash(key);
    for(probe=0;probe<IOS_FAULT_SITE_PROBES;probe++){
        struct ios_fault_site_entry *entry=&table->entries[(start+probe)&(IOS_FAULT_SITE_SLOTS-1)];
        if(!entry->count){
            entry->key=*key;memset(&entry->first,0,sizeof(entry->first));
            if(snapshot)snapshot(context,key,&entry->first);
            entry->count=1;table->occupied++;
            table->tracked++;table->family_tracked[family]++;
            return table->total>=IOS_FAULT_SITE_EPOCH;
        }
        if(ios_fault_site_same(&entry->key,key)&&ios_fault_site_generation(entry)>=0){
            entry->count++;table->tracked++;table->family_tracked[family]++;
            return table->total>=IOS_FAULT_SITE_EPOCH;
        }
    }
    table->overflow++;table->family_overflow[family]++;
    return table->total>=IOS_FAULT_SITE_EPOCH;
}
/* At most two tracked entries per family. This is not a claim about keys
 * counted as overflow. Selection changes neither table entries nor counts. */
static inline void ios_fault_site_top(const struct ios_fault_site_table *table,
    const struct ios_fault_site_entry *top[MADEIRA_STORE_FAMILIES][2])
{
    unsigned slot;
    memset(top,0,sizeof(*top)*MADEIRA_STORE_FAMILIES);
    for(slot=0;slot<IOS_FAULT_SITE_SLOTS;slot++){
        const struct ios_fault_site_entry *entry=&table->entries[slot];unsigned family=entry->key.family;
        if(!entry->count)continue;
        if(!top[family][0]||entry->count>top[family][0]->count){
            top[family][1]=top[family][0];top[family][0]=entry;
        }else if(!top[family][1]||entry->count>top[family][1]->count)top[family][1]=entry;
    }
}
static inline void ios_fault_site_reset(struct ios_fault_site_table *table)
{
    uint64_t epoch=table->epoch+1;
    memset(table,0,sizeof(*table));table->epoch=epoch;
}
#endif
