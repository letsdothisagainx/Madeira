/* Normal metadata input only; no mapping/protection/fault experiments. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <pthread.h>
#include "run_evidence_native.h"
static void *produce(void *arg) {
    for (unsigned i=0;i<2000;++i) { struct ios_evidence_record r={{0}}; r.w[1]=IOS_EV_MAIN;r.w[4]=(uintptr_t)arg;ios_evidence_emit(&r); }
    return 0;
}
int main(void) {
    uint64_t out[48*64],stats[9]={0}, prior=0; unsigned n,seen=0;
    errno=EDOM; assert(ios_evidence_now()>0 && errno==EDOM);
    for (unsigned i=0;i<1500;++i) { struct ios_evidence_record r={{0}};r.w[1]=IOS_EV_MAIN;ios_evidence_emit(&r); }
    do { n=madeira_evidence_poll(out,64,stats); for(unsigned i=0;i<n;++i) { assert(out[i*48]==1 && out[i*48+2]>prior);prior=out[i*48+2]; } seen+=n; } while(n);
    assert(seen==1024 && stats[3]==476 && stats[1]==1500);
    uint64_t token=ios_evidence_begin(1,0x123400,4096,7,1); assert(token);
    n=madeira_evidence_poll(out,64,stats);assert(n==1 && out[1]==IOS_EV_INFLIGHT && out[8]==token && out[11]==0x123400);
    ios_evidence_end(token,0,0);
    assert(madeira_evidence_poll(out,64,stats)==0 && stats[5]==1);
    token=ios_evidence_begin(4,0,16,8,1);ios_evidence_end(token,-1,EINVAL);
    assert(madeira_evidence_poll(out,64,stats)==1 && out[1]==IOS_EV_VM && out[8]==token && out[16]==EINVAL);
    /* A busy diagnostic consumer must not block VM completion or recycle an
     * in-flight slot while a snapshot could be reading immutable fields. */
    token=ios_evidence_begin(3,0,16,9,1); ios_ev_lock=1; ios_evidence_end(token,0,0); ios_ev_lock=0;
    madeira_evidence_poll(out,64,stats); assert(!ios_ev_flight[token%64].token && stats[2]>0);
    ios_evidence_backing_file=7;
    token=ios_evidence_begin(5,0,4096,12345,2);ios_evidence_end(token,0,0);
    assert(ios_ev_by_op[5][2][0]==1 && ios_ev_by_op[5][2][1]==4096);
    token=ios_evidence_begin(5,0,8192,23456,1);ios_evidence_end(token,0,0);
    assert(ios_ev_by_op[5][1][0]==1 && ios_ev_by_op[5][1][1]==8192);
    ios_ev_aggregate_ns=0;
    n=madeira_evidence_poll(out,64,stats);
    unsigned aggregates=0;for(unsigned i=0;i<n;++i)if(out[48*i+1]==12)aggregates++;
    assert(aggregates>=2);
    pthread_t threads[4]; for(unsigned i=0;i<4;++i) assert(!pthread_create(threads+i,0,produce,(void *)(uintptr_t)(i+1)));
    for(unsigned i=0;i<4;++i) pthread_join(threads[i],0);
    while(madeira_evidence_poll(out,64,stats));
    assert(stats[2]>0 || stats[3]>476);
    _Static_assert(sizeof(ios_ev_ring)+sizeof(ios_ev_flight)<400000,"native payload budget");
    puts("native recorder: rotation, monotonic sequencing, try-only contention, in-flight snapshots, errno and metadata-only concurrent producers PASS");
}
