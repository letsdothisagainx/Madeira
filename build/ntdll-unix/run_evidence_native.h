/* Included once by server_ios.c. Fixed ring payload: 393,216 bytes; 4,608 bytes of in-flight metadata; 1,024 bytes per-operation aggregates.
 * The app drains it on a utility queue, not on a guest or VM critical path. */
#include "run_evidence.h"
#include <string.h>
#include <errno.h>
static struct ios_evidence_record ios_ev_ring[IOS_EVIDENCE_RECORDS];
static struct { uint64_t token, start, address, bytes, generation, op, lock_scope, file_lifetime, extent; } ios_ev_flight[64];
static unsigned ios_ev_lock;
static uint64_t ios_ev_head, ios_ev_tail, ios_ev_dropped, ios_ev_overwritten, ios_ev_sequence, ios_ev_ticket;
uint64_t ios_evidence_backing_file;
static uint64_t ios_ev_by_op[8][4][4], ios_ev_aggregate_ns;
static uint64_t ios_ev_resource_next, ios_ev_resource_stats[16];
static uint64_t ios_ev_operations, ios_ev_op_bytes, ios_ev_op_errors, ios_ev_op_ns;
uint64_t ios_evidence_now(void)
{
    struct timespec ts; int saved=errno;
    uint64_t value=clock_gettime(CLOCK_MONOTONIC, &ts) ? 0 : (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
    errno=saved; return value;
}
int ios_evidence_emit_checked(struct ios_evidence_record *r)
{
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&ios_ev_lock,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))
    { __atomic_fetch_add(&ios_ev_dropped,1,__ATOMIC_RELAXED); return 0; }
    r->w[0] = 1; r->w[2] = ++ios_ev_sequence;
    if (!r->w[3]) r->w[3] = ios_evidence_now();
    if (ios_ev_head - ios_ev_tail == IOS_EVIDENCE_RECORDS) { ++ios_ev_tail; ++ios_ev_overwritten; }
    ios_ev_ring[ios_ev_head++ % IOS_EVIDENCE_RECORDS] = *r;
    __atomic_store_n(&ios_ev_lock,0,__ATOMIC_RELEASE); return 1;
}
void ios_evidence_emit(struct ios_evidence_record *r) { (void)ios_evidence_emit_checked(r); }
uint64_t ios_evidence_begin_extent(unsigned op, uintptr_t address, uint64_t bytes, uint64_t generation, unsigned lock_scope, uint64_t extent)
{
    uint64_t token = __atomic_add_fetch(&ios_ev_ticket,1,__ATOMIC_RELAXED), empty = 0;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&ios_ev_lock,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))
    { __atomic_fetch_add(&ios_ev_dropped,1,__ATOMIC_RELAXED); return 0; }
    unsigned i = token % 64;
    if (!__atomic_compare_exchange_n(&ios_ev_flight[i].token,&empty,UINT64_MAX,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))
    { __atomic_fetch_add(&ios_ev_dropped,1,__ATOMIC_RELAXED); __atomic_store_n(&ios_ev_lock,0,__ATOMIC_RELEASE); return 0; }
    ios_ev_flight[i].start=ios_evidence_now(); ios_ev_flight[i].address=address;
    ios_ev_flight[i].bytes=bytes; ios_ev_flight[i].generation=generation;
    ios_ev_flight[i].extent=extent;ios_ev_flight[i].op=op; ios_ev_flight[i].lock_scope=lock_scope;
    ios_ev_flight[i].file_lifetime=__atomic_load_n(&ios_evidence_backing_file,__ATOMIC_ACQUIRE);
    __atomic_store_n(&ios_ev_flight[i].token,token,__ATOMIC_RELEASE);
    __atomic_store_n(&ios_ev_lock,0,__ATOMIC_RELEASE);
    return token;
}
uint64_t ios_evidence_begin(unsigned op, uintptr_t address, uint64_t bytes, uint64_t generation, unsigned lock_scope)
{ return ios_evidence_begin_extent(op,address,bytes,generation,lock_scope,0); }
void ios_evidence_end(uint64_t token, int result, int error)
{
    struct ios_evidence_record r = {{0}};
    unsigned i = token % 64;
    uint64_t elapsed;
    if (!token) return;
    /* The slot remains owned until it is copied; consumers use the same lock
     * below to avoid a data race with this final read/reuse. */
    if (__atomic_exchange_n(&ios_ev_lock,1,__ATOMIC_ACQUIRE))
    { /* Never wait on the diagnostic consumer: abandon this observation. */
      __atomic_store_n(&ios_ev_flight[i].token,token | (UINT64_C(1)<<63),__ATOMIC_RELEASE);
      __atomic_fetch_add(&ios_ev_dropped,1,__ATOMIC_RELAXED); return; }
    elapsed = ios_evidence_now() - ios_ev_flight[i].start;
    r.w[8]=token; r.w[1]=IOS_EV_VM; r.w[9]=ios_ev_flight[i].start; r.w[10]=ios_ev_flight[i].op;
    r.w[11]=ios_ev_flight[i].address; r.w[12]=ios_ev_flight[i].bytes;
    r.w[13]=ios_ev_flight[i].generation; r.w[14]=ios_ev_flight[i].lock_scope;
    r.w[18]=ios_ev_flight[i].file_lifetime;r.w[19]=ios_ev_flight[i].extent;
    r.w[15]=(int64_t)result; r.w[16]=error; r.w[17]=elapsed;
    ++ios_ev_operations; ios_ev_op_bytes+=r.w[12]; ios_ev_op_ns+=elapsed;
    if (result) ++ios_ev_op_errors;
    if (r.w[10]<8 && r.w[14]<4) {
        uint64_t *s=ios_ev_by_op[r.w[10]][r.w[14]];
        ++s[0];s[1]+=r.w[12];s[2]+=result!=0;s[3]+=elapsed;
    }
    __atomic_store_n(&ios_ev_flight[i].token,0,__ATOMIC_RELEASE);
    __atomic_store_n(&ios_ev_lock,0,__ATOMIC_RELEASE);
    if (elapsed >= 5000000 || result) ios_evidence_emit(&r);
}
/* Called only by the app's asynchronous recorder. A busy ring is a missed
 * drain, not a guest wait. Snapshot table reads are protected by the ring lock;
 * producers publish immutable fields before their token. */
unsigned madeira_evidence_poll(uint64_t *out, unsigned records, uint64_t *stats)
{
    unsigned expected=0, n=0, i;
    if (!records || !out || !stats) return 0;
    stats[0]=0;
    if (!__atomic_compare_exchange_n(&ios_ev_lock,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) return 0;
    while (n < records && ios_ev_tail < ios_ev_head)
    { memcpy(out + n++ * IOS_EVIDENCE_WORDS, &ios_ev_ring[ios_ev_tail++ % IOS_EVIDENCE_RECORDS], sizeof(struct ios_evidence_record)); }
    /* In-flight records have no event sequence; token is their identity. */
    for (i=0; i<64 && n<records; ++i)
    {
        uint64_t token=__atomic_load_n(&ios_ev_flight[i].token,__ATOMIC_ACQUIRE);
        if (token & (UINT64_C(1)<<63)) { __atomic_store_n(&ios_ev_flight[i].token,0,__ATOMIC_RELEASE); continue; }
        if (token && token != UINT64_MAX)
        {
            struct ios_evidence_record r={{0}};
            r.w[0]=1; r.w[1]=IOS_EV_INFLIGHT; r.w[3]=ios_evidence_now(); r.w[8]=token;
            r.w[9]=ios_ev_flight[i].start; r.w[10]=ios_ev_flight[i].op;
            r.w[11]=ios_ev_flight[i].address; r.w[12]=ios_ev_flight[i].bytes;
            r.w[13]=ios_ev_flight[i].generation; r.w[14]=ios_ev_flight[i].lock_scope;
            r.w[18]=ios_ev_flight[i].file_lifetime;r.w[19]=ios_ev_flight[i].extent;
            memcpy(out+n++*IOS_EVIDENCE_WORDS,&r,sizeof(r));
        }
    }
    if (n+32<=records && ios_evidence_now()-ios_ev_aggregate_ns>=1000000000) {
        for (i=1;i<8;++i) for (unsigned mode=0;mode<4;++mode) {
            uint64_t *s=ios_ev_by_op[i][mode];
            if (!s[0]) continue;
            struct ios_evidence_record r={{0}};r.w[0]=1;r.w[1]=12;r.w[3]=ios_evidence_now();
            r.w[9]=i;r.w[10]=mode;r.w[11]=s[0];r.w[12]=s[1];r.w[13]=s[2];r.w[14]=s[3];
            memcpy(out+n++*IOS_EVIDENCE_WORDS,&r,sizeof(r));
        }
        if (n<records && __atomic_load_n(&ios_ev_resource_next,__ATOMIC_RELAXED)) {
            struct ios_evidence_record r={{0}};r.w[0]=1;r.w[1]=14;r.w[3]=ios_evidence_now();
            for(unsigned j=0;j<16;++j)r.w[9+j]=__atomic_load_n(&ios_ev_resource_stats[j],__ATOMIC_RELAXED);
            memcpy(out+n++*IOS_EVIDENCE_WORDS,&r,sizeof(r));
        }
        ios_ev_aggregate_ns=ios_evidence_now();
    }
    stats[0]=1; stats[1]=ios_ev_sequence; stats[2]=__atomic_load_n(&ios_ev_dropped,__ATOMIC_RELAXED);
    stats[3]=ios_ev_overwritten; stats[4]=ios_evidence_now(); stats[5]=ios_ev_operations;
    stats[6]=ios_ev_op_bytes; stats[7]=ios_ev_op_errors; stats[8]=ios_ev_op_ns;
    __atomic_store_n(&ios_ev_lock,0,__ATOMIC_RELEASE);
    return n;
}
