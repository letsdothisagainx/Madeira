/* Normal identity/counter inputs; no guest execution, memory protection or faults. */
#include <stdint.h>
#include <stdio.h>
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
    puts("actual frame observer: recycled owner, distinct PID/lease, busy/inactive identity and unchanged present count PASS");return 0;
}
