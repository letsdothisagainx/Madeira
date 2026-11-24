/* Ordinary in-memory events only; never generate device input or memory faults. */
#include <stdio.h>
#include <assert.h>
#include "InputQueue.h"
#include "input_queue_baseline.h"
static struct winios_input_queue q=WINIOS_INPUT_QUEUE_INIT;
static struct winios_input_holds holds;
static winios_input_event_t events[1024];static unsigned delivered;
static void push(unsigned type,int x,int y,unsigned flags,unsigned data,uint64_t ns){
    winios_input_event_t e={.type=type,.x=x,.y=y,.flags=flags,.data=data};assert(iq_push(&q,e,ns));
}
static void turn(uint64_t ns){
    for(unsigned budget=0;budget<WINIOS_INPUT_DRAIN_LIMIT;++budget){
        winios_input_event_t e;int neutral=iq_neutral(&q,&holds,&e);
        if(!neutral){int n=iq_pop(&q,&e,ns,1,0,1);if(!n)break;if(n<0)continue;if(e.generation!=atomic_load(&q.generation))continue;}
        assert(delivered<1024);events[delivered++]=e;iq_submitted(&holds,&e);
    }
}
int main(void){
    /* Actual old push rejects the incoming release at 255 entries. */
    for(unsigned i=0;i<255;++i)baseline_push(WINIOS_EV_MOUSE,1,1,1,0);
    baseline_push(WINIOS_EV_KEY,0x57,0,2,0);
    assert((baseline_queue.head+256-baseline_queue.tail)%256==255);
    unsigned releases=0;for(unsigned i=0;i<255;++i)releases+=baseline_queue.buf[i].type==WINIOS_EV_KEY;
    assert(!releases);puts("baseline actual queue: incoming key release lost after 255 motion entries");
    push(WINIOS_EV_KEY,0x57,0,0,0,1);
    for(unsigned i=0;i<10000;++i)push(WINIOS_EV_MOUSE,1,2,1,0,2+i);
    push(WINIOS_EV_MOUSE,0,0,8,0,10003);
    push(WINIOS_EV_MOUSE,3,4,1,0,10004);
    push(WINIOS_EV_KEY,0x57,0,2,0,10005);
    push(WINIOS_EV_MOUSE,0,0,0x10,0,10006);
    turn(10007);assert(delivered==6);
    assert(events[0].type==WINIOS_EV_KEY && !events[0].flags);
    assert(events[1].x==10000 && events[1].y==20000 && events[2].flags==8);
    assert(events[3].x==3 && events[4].type==WINIOS_EV_KEY && events[4].flags==2 && events[5].flags==0x10);
    assert(!holds.keys[1] && !holds.buttons && atomic_load(&q.counts[IQ_COALESCED])==9999);
    /* Absolute and relative motion cannot cross each other's mode or edges. */
    delivered=0;push(0,10,20,0x8001,0,20000);push(0,30,40,0x8001,0,20001);push(0,2,3,1,0,20002);push(0,0,0,0x800,120,20003);
    turn(20004);assert(delivered==3 && events[0].x==30 && events[0].y==40 && events[1].x==2 && events[2].flags==0x800);
    /* Continuous delayed motion retains at most its last 100ms, not minutes. */
    delivered=0;push(0,100,100,1,0,30000);push(0,1,2,1,0,200000001);turn(200000002);assert(delivered==1 && events[0].x==1);
    push(0,1,1,1,0,200000003);delivered=0;turn(400000004);assert(!delivered && atomic_load(&q.counts[IQ_STALE]));
    /* Lifecycle neutralizes submitted keys, drops stale queue contents, and
     * orders releases ahead of fresh samples without changing a window. */
    push(1,0x57,0,0,0,500000000);turn(500000001);assert(holds.keys[1]);
    push(0,100,100,1,0,500000002);iq_context(&q,1,1);
    winios_input_event_t down={.type=1,.x=0x41};assert(!iq_push(&q,down,500000003));
    delivered=0;turn(500000004);assert(delivered==1 && events[0].type==1 && events[0].flags==2 && !holds.keys[1]);
    iq_context(&q,1,0);push(1,0x44,0,0,0,500000005);delivered=0;turn(500000006);assert(delivered==1 && events[0].x==0x44);
    /* All-edge overflow has an explicit fail-safe; no unbounded queue and no
     * permanently held key. Later fresh input still works. */
    for(unsigned i=0;i<255;++i)push(1,0x32,0,(i&1)?2:0,0,500001000+i);
    winios_input_event_t up={.type=1,.x=0x44,.flags=2};assert(!iq_push(&q,up,500002000));
    assert(atomic_load(&q.counts[IQ_EDGE_OVERFLOW])==1);
    delivered=0;turn(500002001);assert(delivered==1 && events[0].x==0x44 && events[0].flags==2 && !holds.keys[1]);
    push(1,0x57,0,0,0,500002002);push(1,0x57,0,2,0,500002003);delivered=0;turn(500002004);assert(delivered==2 && !holds.keys[1]);
    /* Bounded contention never blocks a producer; losing an edge schedules
     * neutralization rather than silently leaving a submitted press down. */
    assert(!pthread_mutex_lock(&q.lock));assert(!iq_push(&q,up,500002005));assert(!pthread_mutex_unlock(&q.lock));
    assert(atomic_load(&q.counts[IQ_LOCK_BUSY])==1 && atomic_load(&q.counts[IQ_EDGE_OVERFLOW])==2);
    for(unsigned i=0;i<80;++i)push(1,0x32,0,(i&1)?2:0,0,600000000+i);
    delivered=0;turn(600000100);assert(delivered==64);turn(600000101);assert(delivered==80);
    _Static_assert(sizeof(q)+sizeof(holds)<16384,"fixed input payload cap");
    puts("PASS actual queue: order, compatible motion, releases, bounded age/drain, lifecycle, overflow/try-lock accounting and <16KiB payload");
}
