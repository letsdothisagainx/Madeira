/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Passive, fixed-size initial-CS2-thread operation counters. No locks, payload
 * reads, allocation, formatting, scheduling or I/O. Members are atomic, not a
 * transactional snapshot. Inclusive/nested times must not be summed as CPU. */
#ifndef MADEIRA_RUNTIME_PROGRESS_H
#define MADEIRA_RUNTIME_PROGRESS_H
#define IOS_RUNTIME_SLOTS 4
#define IOS_RUNTIME_KINDS 4
struct ios_runtime_slot {
    uint64_t owner, lease, native_id, pid, tid;
    uint64_t count[4], elapsed[4], active[4], depth[4], detail[4], updates;
};
static struct ios_runtime_slot ios_runtime_slots[IOS_RUNTIME_SLOTS];
static __thread struct ios_runtime_slot *ios_runtime_current;
void ios_runtime_register(uint64_t owner,uint64_t lease,unsigned pid,unsigned tid,uint64_t native_id)
{
    ios_runtime_current=NULL;
    if(!owner || !lease || !pid || !tid || !native_id)return;
    for(unsigned i=0;i<IOS_RUNTIME_SLOTS;++i){
        struct ios_runtime_slot *s=ios_runtime_slots+i;uint64_t empty=0;
        if(__atomic_load_n(&s->native_id,__ATOMIC_ACQUIRE)==native_id){
            if(s->owner==owner && s->lease==lease)ios_runtime_current=s;
            return;
        }
        if(!__atomic_compare_exchange_n(&s->native_id,&empty,UINT64_MAX,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))continue;
        s->owner=owner;s->lease=lease;s->pid=pid;s->tid=tid;
        __atomic_store_n(&s->native_id,native_id,__ATOMIC_RELEASE);ios_runtime_current=s;return;
    }
}
uint64_t ios_runtime_begin(unsigned kind,uint64_t detail)
{
    struct ios_runtime_slot *s=ios_runtime_current;uint64_t now,zero=0;
    if(!s || kind>=IOS_RUNTIME_KINDS)return 0;
    now=ios_evidence_now();if(!now)return 0;
    __atomic_fetch_add(&s->depth[kind],1,__ATOMIC_RELAXED);
    __atomic_compare_exchange_n(&s->active[kind],&zero,now,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED);
    __atomic_fetch_add(&s->count[kind],1,__ATOMIC_RELAXED);
    __atomic_store_n(&s->detail[kind],detail,__ATOMIC_RELAXED);
    __atomic_fetch_add(&s->updates,1,__ATOMIC_RELEASE);return now;
}
void ios_runtime_end(unsigned kind,uint64_t start)
{
    struct ios_runtime_slot *s=ios_runtime_current;uint64_t now;
    if(!s || !start || kind>=IOS_RUNTIME_KINDS)return;
    now=ios_evidence_now();
    if(now>=start)__atomic_fetch_add(&s->elapsed[kind],now-start,__ATOMIC_RELAXED);
    if(__atomic_fetch_sub(&s->depth[kind],1,__ATOMIC_RELAXED)==1)
        __atomic_store_n(&s->active[kind],0,__ATOMIC_RELAXED);
    __atomic_fetch_add(&s->updates,1,__ATOMIC_RELEASE);
}
void ios_runtime_identity(uint64_t *out)
{
    struct ios_runtime_slot *s=ios_runtime_current;
    for(unsigned i=0;i<5;++i)out[i]=0;
    if(s){out[0]=s->owner;out[1]=s->lease;out[2]=s->pid;out[3]=s->tid;out[4]=__atomic_load_n(&s->native_id,__ATOMIC_ACQUIRE);}
}
static __attribute__((unused)) void ios_runtime_snapshot(uint64_t native_id,uint64_t owner,uint64_t lease,uint64_t capture_ns)
{
    for(unsigned i=0;i<IOS_RUNTIME_SLOTS;++i){
        const struct ios_runtime_slot *s=ios_runtime_slots+i;
        if(__atomic_load_n(&s->native_id,__ATOMIC_ACQUIRE)!=native_id || s->owner!=owner || s->lease!=lease)continue;
        struct ios_evidence_record r={{0}};r.w[1]=16;r.w[4]=owner;r.w[5]=lease;r.w[6]=s->pid;r.w[7]=s->tid;r.w[8]=native_id;
        r.w[9]=capture_ns;r.w[10]=ios_evidence_now();r.w[11]=__atomic_load_n(&s->updates,__ATOMIC_ACQUIRE);
        for(unsigned k=0;k<IOS_RUNTIME_KINDS;++k){
            r.w[16+k]=__atomic_load_n(&s->count[k],__ATOMIC_RELAXED);
            r.w[20+k]=__atomic_load_n(&s->elapsed[k],__ATOMIC_RELAXED);
            r.w[24+k]=__atomic_load_n(&s->active[k],__ATOMIC_RELAXED);
            r.w[28+k]=__atomic_load_n(&s->detail[k],__ATOMIC_RELAXED);
            r.w[32+k]=__atomic_load_n(&s->depth[k],__ATOMIC_RELAXED);
        }
        r.w[12]=__atomic_load_n(&s->updates,__ATOMIC_ACQUIRE);ios_evidence_emit(&r);return;
    }
}
#endif
