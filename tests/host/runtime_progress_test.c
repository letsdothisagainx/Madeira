/* Ordinary in-memory metadata/counters only; no guest execution or VM faults. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include "run_evidence_native.h"
static void *other(void *unused) {
    (void)unused;ios_runtime_register(0x2000,35,17,18,99);
    for(unsigned n=0;n<100000;n++){uint64_t t=ios_runtime_begin(0,7);ios_runtime_end(0,t);}return NULL;
}
int main(void) {
    uint64_t out[48*64],stats[9],token,a,b,start,disabled,enabled;volatile uint64_t sum=0;
    assert(sizeof(ios_runtime_slots)<1024);
    errno=EDOM;assert(!ios_runtime_begin(0,0)&&errno==EDOM);
    start=ios_evidence_now();for(unsigned i=0;i<500000;i++){a=ios_runtime_begin(0,i);ios_runtime_end(0,a);sum+=a;}disabled=ios_evidence_now()-start;
    ios_runtime_register(0x1000,34,1,2,98);
    a=ios_runtime_begin(1,0x20);b=ios_runtime_begin(1,0x20);
    ios_runtime_snapshot(98,0x1000,34,1);assert(madeira_evidence_poll(out,64,stats)==1);
    assert(out[1]==16&&out[4]==0x1000&&out[5]==34&&out[8]==98&&out[17]==2&&out[33]==2&&out[25]);
    ios_runtime_end(1,b);ios_runtime_end(1,a);
    ios_runtime_snapshot(98,0x1000,35,1);assert(!madeira_evidence_poll(out,64,stats));
    ios_runtime_snapshot(98,0x1000,34,1);assert(madeira_evidence_poll(out,64,stats)==1&&!out[33]&&!out[25]&&out[21]>0);
    token=ios_evidence_begin(3,0x5000,4096,12,1);ios_evidence_end(token,-1,EINVAL);
    assert(madeira_evidence_poll(out,64,stats)==1&&out[1]==4&&out[4]==0x1000&&out[5]==34&&out[8]==token&&out[20]==98&&out[16]==EINVAL);
    pthread_t worker;assert(!pthread_create(&worker,NULL,other,NULL));
    for(unsigned i=0;i<1000;i++)ios_runtime_snapshot(99,0x2000,35,1);
    pthread_join(worker,NULL);assert(ios_runtime_slots[1].count[0]==100000);
    while(madeira_evidence_poll(out,64,stats));
    start=ios_evidence_now();for(unsigned i=0;i<500000;i++){a=ios_runtime_begin(0,i);ios_runtime_end(0,a);sum+=a;}enabled=ios_evidence_now()-start;
    assert(errno==EDOM);printf("runtime counters: identity/lease rejection, nested completion, VM issuer, concurrent observation PASS; local host disabled %.1f ns/pair registered %.1f ns/pair (not iPhone cost) sum=%llu\n",disabled/500000.0,enabled/500000.0,(unsigned long long)sum);
    ios_runtime_register(0,0,0,0,0);assert(!ios_runtime_begin(0,1));
}
