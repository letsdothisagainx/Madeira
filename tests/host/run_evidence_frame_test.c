/* Normal identity/counter inputs; no guest execution, memory protection or faults. */
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
struct ios_evidence_record {uint64_t w[48];};
static uint64_t ios_ev_resource_next,ios_ev_resource_stats[16];
static struct ios_evidence_record last;
static int ios_evidence_emit_checked(struct ios_evidence_record *r) {last=*r;return 1;}
#define IOS_CS2_STALL_PROCESSES 4
static struct {uint64_t owner,lease;unsigned pid;} ios_cs2_stall_watches[4];
static uint64_t owner=0x100,lease=2,now=100;static unsigned pid=20;static int busy;
static void *ios_jit_current_peb(void) {return (void *)(uintptr_t)owner;}
static uint64_t ios_evidence_now(void) {return ++now;}
static unsigned long long ios_thread_process_try_observation_lease(void *o,unsigned p) {return !busy && (uintptr_t)o==owner && p==pid ? lease : 0;}
#include "actual_evidence_frames.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"frame identity failure line %d\n",__LINE__);return 1;}}while(0)
int main(void) {
    uint64_t out[5];
    ios_cs2_stall_watches[0].owner=owner;ios_cs2_stall_watches[0].lease=1;ios_cs2_stall_watches[0].pid=10;
    ios_cs2_stall_watches[1].owner=owner;ios_cs2_stall_watches[1].lease=2;ios_cs2_stall_watches[1].pid=20;
    ios_evidence_present_note();madeira_evidence_frame(out);
    CHECK(!ios_ev_frame_count[0] && ios_ev_frame_count[1]==1 && out[4]==2 && out[0]==1);
    busy=1;ios_evidence_present_note();madeira_evidence_frame(out);CHECK(!out[3] && ios_ev_frame_count[1]==1);
    busy=0;lease=3;madeira_evidence_frame(out);CHECK(!out[3]);
    lease=2;uint64_t words[20]={0},stamp=0,prior=0;
    words[0]=2;words[16]=0x8007000e;
    errno=EDOM;
    for(unsigned i=0;i<1000;++i) {
        uint64_t id=madeira_evidence_resource(44,0,0,words,&stamp);CHECK(id>prior);prior=id;
        madeira_evidence_resource(45,id,stamp,words,&stamp);
        CHECK(last.w[8]==id && last.w[5]==2 && last.w[6]==20 && last.w[25]==0x8007000e && !last.w[7]);
    }
    CHECK(errno==EDOM && ios_ev_resource_stats[0]==1000 && ios_ev_resource_stats[2]==1000 && ios_ev_resource_stats[5]==1000 && ios_ev_resource_stats[10]==1000);
    busy=1;madeira_evidence_resource(45,prior,stamp,words,&stamp);CHECK(!last.w[5] && !last.w[6]);
    puts("actual frame observer: recycled owner, distinct PID/lease, busy/inactive identity and unchanged present count PASS");return 0;
}
