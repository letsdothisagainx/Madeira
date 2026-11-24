/* Bounded metadata/event transport. No allocation, logging, syscall or Wine
 * call under this lock. Consumer alone owns submitted key/button state. */
#ifndef MADEIRA_INPUT_QUEUE_H
#define MADEIRA_INPUT_QUEUE_H
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#define WINIOS_RING_SIZE 256
#define WINIOS_EV_MOUSE 0
#define WINIOS_EV_KEY 1
#define WINIOS_EV_TEXT 2
#define WINIOS_KEY_UP 0x0002
#define WINIOS_INPUT_DRAIN_LIMIT 64
#define WINIOS_INPUT_MOTION_NS UINT64_C(100000000)
enum { IQ_PUSHED,IQ_COALESCED,IQ_MOTION_DROPPED,IQ_EDGE_OVERFLOW,IQ_LOCK_BUSY,
       IQ_POPPED,IQ_STALE,IQ_RESETS,IQ_NEUTRAL_RELEASES,IQ_MAX_DEPTH,IQ_MAX_AGE_NS,
       IQ_REJECTED_CONTEXT,IQ_TEXT_DROPPED,IQ_CLIPPED,IQ_DRAIN_TURNS,IQ_COUNT };
typedef struct {
    unsigned type;int x,y;unsigned flags,data;
    uint64_t first_ns,ns,generation;
} winios_input_event_t;
struct winios_input_queue {
    pthread_mutex_t lock;
    winios_input_event_t buf[WINIOS_RING_SIZE];
    unsigned head,tail;
    uint64_t epoch;
    _Atomic uint64_t generation,counts[IQ_COUNT];
    _Atomic unsigned blocked; /* app inactive, library owner, native UI focus */
    _Atomic unsigned depth; /* observation never acquires the producer lock */
};
#define WINIOS_INPUT_QUEUE_INIT { .lock=PTHREAD_MUTEX_INITIALIZER,.generation=1 }
static inline void iq_add(struct winios_input_queue*q,unsigned c,uint64_t n){atomic_fetch_add_explicit(&q->counts[c],n,memory_order_relaxed);}
static inline void iq_max(struct winios_input_queue*q,unsigned c,uint64_t n){
    uint64_t old=atomic_load_explicit(&q->counts[c],memory_order_relaxed);
    /* Diagnostic only: never spin indefinitely against another producer. */
    for(unsigned i=0;i<3 && n>old;++i)if(atomic_compare_exchange_weak(&q->counts[c],&old,n))break;
}
static inline int iq_motion(const winios_input_event_t*e){return e->type==WINIOS_EV_MOUSE && (e->flags==1 || e->flags==0x8001) && !e->data;}
static inline int iq_release(const winios_input_event_t*e){
    return e->type==WINIOS_EV_KEY ? !!(e->flags&2) : e->type==WINIOS_EV_MOUSE && !(e->flags&(2|8|0x20|0x80)) && !!(e->flags&(4|0x10|0x40|0x100));
}
static inline int iq_matching_release(const winios_input_event_t*press,const winios_input_event_t*after){
    if(press->type!=after->type || !iq_release(after))return 0;
    if(press->type==WINIOS_EV_KEY)return press->x==after->x;
    if(press->type!=WINIOS_EV_MOUSE)return 0;
    /* Producers emit single-button transitions. Leave unusual combined
     * button masks intact rather than guessing their partial state. */
    const unsigned down=press->flags&(2|8|0x20|0x80);
    return down==2 ? !!(after->flags&4) : down==8 ? !!(after->flags&0x10) :
           down==0x20 ? !!(after->flags&0x40) : down==0x80 && press->data==after->data && !!(after->flags&0x100);
}
static inline uint64_t iq_reset(struct winios_input_queue*q){iq_add(q,IQ_RESETS,1);return atomic_fetch_add_explicit(&q->generation,1,memory_order_acq_rel)+1;}
static inline void iq_context(struct winios_input_queue*q,unsigned bit,int blocked){
    unsigned before=blocked?atomic_fetch_or(&q->blocked,bit):atomic_fetch_and(&q->blocked,~bit);
    if(!!(before&bit)!=!!blocked)iq_reset(q);
}
static inline void iq_sync_epoch(struct winios_input_queue*q,uint64_t generation){
    if(q->epoch!=generation){q->head=q->tail=0;q->epoch=generation;atomic_store(&q->depth,0);}
}
static inline int iq_sum(struct winios_input_queue*q,int a,int b){
    int64_t v=(int64_t)a+b;
    if(v>INT_MAX || v<INT_MIN){iq_add(q,IQ_CLIPPED,1);return v>0?INT_MAX:INT_MIN;}return(int)v;
}
static inline int iq_push(struct winios_input_queue*q,winios_input_event_t e,uint64_t ns){
    e.ns=e.first_ns=ns;e.generation=atomic_load_explicit(&q->generation,memory_order_acquire);
    if(atomic_load(&q->blocked) && !iq_release(&e)){iq_add(q,IQ_REJECTED_CONTEXT,1);return 0;}
    if(pthread_mutex_trylock(&q->lock)){
        iq_add(q,IQ_LOCK_BUSY,1);
        if(iq_motion(&e))iq_add(q,IQ_MOTION_DROPPED,1);
        else if(e.type==WINIOS_EV_TEXT)iq_add(q,IQ_TEXT_DROPPED,1);
        else {iq_add(q,IQ_EDGE_OVERFLOW,1);iq_reset(q);} /* cannot lose an up silently */
        return 0;
    }
    const uint64_t generation=atomic_load(&q->generation);
    iq_sync_epoch(q,generation);e.generation=generation;
    if(atomic_load(&q->blocked) && !iq_release(&e)){iq_add(q,IQ_REJECTED_CONTEXT,1);goto refused;}
    if(iq_motion(&e) && q->head!=q->tail){
        winios_input_event_t*last=&q->buf[(q->head+WINIOS_RING_SIZE-1)%WINIOS_RING_SIZE];
        if(iq_motion(last) && last->flags==e.flags && last->generation==generation){
            if(ns>=last->first_ns && ns-last->first_ns<=WINIOS_INPUT_MOTION_NS){
                if(e.flags&0x8000){last->x=e.x;last->y=e.y;}
                else {last->x=iq_sum(q,last->x,e.x);last->y=iq_sum(q,last->y,e.y);}
                last->ns=ns;
            } else {*last=e;iq_add(q,IQ_MOTION_DROPPED,1);}
            iq_add(q,IQ_COALESCED,1);pthread_mutex_unlock(&q->lock);return 1;
        }
    }
    unsigned used=(q->head+WINIOS_RING_SIZE-q->tail)%WINIOS_RING_SIZE;
    if(e.type==WINIOS_EV_TEXT && used>=WINIOS_RING_SIZE-16){iq_add(q,IQ_TEXT_DROPPED,1);goto refused;}
    if(used==WINIOS_RING_SIZE-1){
        if(iq_motion(&e)){iq_add(q,IQ_MOTION_DROPPED,1);goto refused;}
        /* Remove only a pure motion; never move motion across an edge. */
        unsigned at=q->tail;
        while(at!=q->head && !iq_motion(&q->buf[at]))at=(at+1)%WINIOS_RING_SIZE;
        if(at!=q->head){
            for(unsigned next=(at+1)%WINIOS_RING_SIZE;next!=q->head;next=(next+1)%WINIOS_RING_SIZE){q->buf[at]=q->buf[next];at=next;}
            q->head=(q->head+WINIOS_RING_SIZE-1)%WINIOS_RING_SIZE;iq_add(q,IQ_MOTION_DROPPED,1);
        } else {
            /* Finite storage cannot preserve an unbounded edge history.
             * Publish a neutralization epoch, drop that history explicitly,
             * then accept fresh samples. Consumer releases submitted holds. */
            iq_add(q,IQ_EDGE_OVERFLOW,1);iq_sync_epoch(q,iq_reset(q));goto refused;
        }
    }
    q->buf[q->head]=e;q->head=(q->head+1)%WINIOS_RING_SIZE;
    atomic_store(&q->depth,(q->head+WINIOS_RING_SIZE-q->tail)%WINIOS_RING_SIZE);
    iq_add(q,IQ_PUSHED,1);iq_max(q,IQ_MAX_DEPTH,(q->head+WINIOS_RING_SIZE-q->tail)%WINIOS_RING_SIZE);
    pthread_mutex_unlock(&q->lock);return 1;
refused:pthread_mutex_unlock(&q->lock);return 0;
}
/* Pop only; injection/formatting/clock acquisition stay outside the lock. */
static inline int iq_pop(struct winios_input_queue*q,winios_input_event_t*e,uint64_t ns,uint64_t text_generation,uint64_t paced_generation,int text_ready){
    if(pthread_mutex_trylock(&q->lock))return 0;
    iq_sync_epoch(q,atomic_load(&q->generation));
    if(q->head==q->tail){pthread_mutex_unlock(&q->lock);return 0;}
    *e=q->buf[q->tail];
    if(e->type==WINIOS_EV_TEXT && e->data==text_generation && e->data==paced_generation && !text_ready){pthread_mutex_unlock(&q->lock);return 0;}
    q->tail=(q->tail+1)%WINIOS_RING_SIZE;
    int delayed_pair=0;
    if(e->type!=WINIOS_EV_TEXT && !iq_release(e) && !iq_motion(e) && ns>=e->ns && ns-e->ns>UINT64_C(1000000000)) {
        for(unsigned at=q->tail;at!=q->head;at=(at+1)%WINIOS_RING_SIZE)
            if(iq_matching_release(e,&q->buf[at])){delayed_pair=1;break;}
        /* An old wheel pulse can be dropped, but a still-held key/button
         * must reach a slow consumer. Resetting it every second would starve
         * continuous movement at <=1 FPS. Lifecycle epochs remain separate. */
        if(e->type==WINIOS_EV_MOUSE && (e->flags&(0x800|0x1000)))delayed_pair=1;
    }
    atomic_store(&q->depth,(q->head+WINIOS_RING_SIZE-q->tail)%WINIOS_RING_SIZE);pthread_mutex_unlock(&q->lock);
    iq_add(q,IQ_POPPED,1);if(ns>=e->ns)iq_max(q,IQ_MAX_AGE_NS,ns-e->ns);
    if(iq_motion(e) && ns>=e->ns && ns-e->ns>WINIOS_INPUT_MOTION_NS){iq_add(q,IQ_STALE,1);return -1;}
    if(delayed_pair){iq_add(q,IQ_STALE,1);return -1;}
    return 1;
}
/* Caller owns the one consumer lock. A reset or stale edge releases only
 * controls previously submitted by this bridge before consuming fresh input. */
struct winios_input_holds {uint64_t keys[4],generation;unsigned buttons;};
static inline void iq_submitted(struct winios_input_holds*h,const winios_input_event_t*e){
    if(e->type==WINIOS_EV_KEY && (unsigned)e->x<256){uint64_t bit=UINT64_C(1)<<((unsigned)e->x&63);if(e->flags&2)h->keys[(unsigned)e->x>>6]&=~bit;else h->keys[(unsigned)e->x>>6]|=bit;}
    if(e->type==WINIOS_EV_MOUSE){
        const unsigned down[]={2,8,0x20,0x80,0x80},up[]={4,0x10,0x40,0x100,0x100};
        for(unsigned i=0;i<5;++i){if(i>=3 && e->data!=i-2)continue;if(e->flags&down[i])h->buttons|=1u<<i;if(e->flags&up[i])h->buttons&=~(1u<<i);}
    }
}
static inline int iq_neutral(struct winios_input_queue*q,struct winios_input_holds*h,winios_input_event_t*e){
    uint64_t generation=atomic_load_explicit(&q->generation,memory_order_acquire);
    if(h->generation==generation)return 0;
    memset(e,0,sizeof(*e));e->generation=generation;
    for(unsigned vk=0;vk<256;++vk)if(h->keys[vk>>6]&(UINT64_C(1)<<(vk&63))){e->type=WINIOS_EV_KEY;e->x=vk;e->flags=2;h->keys[vk>>6]&=~(UINT64_C(1)<<(vk&63));iq_add(q,IQ_NEUTRAL_RELEASES,1);return 1;}
    for(unsigned b=0;b<5;++b)if(h->buttons&(1u<<b)){e->type=WINIOS_EV_MOUSE;e->flags=(unsigned[]){4,0x10,0x40,0x100,0x100}[b];e->data=b>=3?b-2:0;h->buttons&=~(1u<<b);iq_add(q,IQ_NEUTRAL_RELEASES,1);return 1;}
    h->generation=generation;return 0;
}
#endif
