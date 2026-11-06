/* Matched high-volume IosL1Misses operation, not a synthetic plain store.
 * The full captured native function is supplied by the exact-image fixture.
 * Only normal address/call relocation and the platform clock backend differ.
 */
#define _DARWIN_C_SOURCE
#define main madeira_atomic_fixture_unexecuted_counter_entry
#include "native-atomic-alias-performance.c"
#undef main
#include "native_data_alias.h"
#include "native_l1_counter_fixture.h"
enum { COUNTER_ENTRY=0x1000,CLOCK_ENTRY=0x2000,MISSES=0xf00,LAST_NS=0xef8,
       CLOCK_CALLS=0xee0,COUNTER_ROUNDS=400 };
static uint64_t warmup_faults;

static uint32_t branch_link(uintptr_t from,uintptr_t to)
{
    intptr_t difference=(intptr_t)to-(intptr_t)from;
    assert(!(difference&3)&&difference>=-0x8000000&&difference<0x8000000);
    return 0x94000000u|((uint32_t)(difference/4)&0x03ffffffu);
}
static void emit_counter(void)
{
    uint32_t *code=(void *)(active.rw+COUNTER_ENTRY),*clock=(void *)(active.rw+CLOCK_ENTRY);
    uintptr_t rx=(uintptr_t)active.rx+COUNTER_ENTRY,data=(uintptr_t)active.rx+active.page;
    memcpy(code,captured_l1_counter,sizeof(captured_l1_counter));
    assert(code[10]==0xd0001b88&&code[19]==0xd0001b89&&code[18]==0x94063ef8);
    code[10]=adrp(8,rx+10*4,data+MISSES);code[19]=adrp(9,rx+19*4,data+LAST_NS);
    code[18]=branch_link(rx+18*4,(uintptr_t)active.rx+CLOCK_ENTRY);
    /* The actual steady_clock prologue, then a fixture clock backend. It
     * returns one nanosecond and records calls without using incoming X8.
     * This bypasses no product check: only the test clock API is adapted. */
    const uint32_t backend[]={0xd10083ff,0xf9000bf3,0xf9000ffe,0xd0000f08,
        0x913b8108,0xf9400109,0x91000529,0xf9000109,0xd2800020,
        0xf9400ffe,0xf9400bf3,0x910083ff,0xd65f03c0};
    memcpy(clock,backend,sizeof(backend));
    clock[3]=adrp(8,(uintptr_t)active.rx+CLOCK_ENTRY+12,(uintptr_t)active.rw+active.page+CLOCK_CALLS);
    clock[4]=0x91000000u|CLOCK_CALLS<<10|8<<5|8;
    size_t count=(CLOCK_ENTRY-COUNTER_ENTRY+sizeof(backend))/4;
    unsigned misses_lowered=0;
    for(size_t index=0;index<count;index++){
        struct madeira_native_data_alias_plan plan;
        if(!madeira_native_data_alias_plan(code,count,rx,(intptr_t)alias_distance,
                                          index,permitted_data,&active,&plan))continue;
        if(index==10)misses_lowered++;
        code[index]=plan.replacement;
    }
    assert(misses_lowered==PERF_EXPECT_FIXED);
    memset(active.rw+active.page+LAST_NS,0,8);
    memset(active.rw+active.page+CLOCK_CALLS,0,8);
    *(uint64_t *)(active.rw+active.page+MISSES)=0xfffff;
    __builtin___clear_cache((char *)code,(char *)clock+sizeof(backend));
    __builtin___clear_cache((char *)active.rx+COUNTER_ENTRY,(char *)active.rx+CLOCK_ENTRY+sizeof(backend));
}
static void register_counter_thread(void)
{
    mach_port_t self=mach_thread_self();
    assert(thread_set_exception_ports(self,EXC_MASK_BAD_ACCESS,exception_port,
           EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,ARM_THREAD_STATE64)==KERN_SUCCESS);
    mach_port_deallocate(mach_task_self(),self);
}
static void counter_once(unsigned char context[256])
{
    void (*operation)(void *,void *)=(void *)(active.rx+COUNTER_ENTRY);
    /* This legitimate per-thread input selects the function's documented
     * fast branch after its counter operation; the original branch remains. */
    memset(context,0,256);operation(context,NULL);
    assert(*(uint64_t *)(context+0x80)==1);
}
struct counter_worker { unsigned direct; };
static void *run_counter_worker(void *argument)
{
    const struct counter_worker *worker=argument;_Alignas(16) unsigned char context[256];
    register_counter_thread();uint64_t start=clock_ns(CLOCK_THREAD_CPUTIME_ID);
    for(unsigned i=0;i<COUNTER_ROUNDS;i++){
        if(worker->direct)__atomic_fetch_add((uint64_t *)(active.rw+active.page+MISSES),1,__ATOMIC_RELAXED);
        else counter_once(context);
    }
    __atomic_add_fetch(&worker_cpu_ns,clock_ns(CLOCK_THREAD_CPUTIME_ID)-start,__ATOMIC_RELAXED);
    return NULL;
}
int main(void)
{
    assert(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&exception_port)==KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(),exception_port,exception_port,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
    pthread_t server;assert(!pthread_create(&server,NULL,exception_server,NULL));
    while(!__atomic_load_n(&server_thread_port,__ATOMIC_ACQUIRE))sched_yield();
    active=map_image();emit_counter();register_counter_thread();
    unsigned char before[0x1100];memcpy(before,active.rx+COUNTER_ENTRY,sizeof(before));
    _Alignas(16) unsigned char context[256];
    counter_once(context);warmup_faults=fault_count;
    assert(*(uint64_t *)(active.rw+active.page+MISSES)==0x100000);
    assert(*(uint64_t *)(active.rw+active.page+LAST_NS)==1);
    assert(*(uint64_t *)(active.rw+active.page+CLOCK_CALLS)==1);
    worker_cpu_ns=0;uint64_t begin=clock_ns(CLOCK_MONOTONIC),handler_begin=server_cpu_ns();
    pthread_t workers[WORKERS+1];struct counter_worker inputs[WORKERS+1];
    for(unsigned i=0;i<=WORKERS;i++){
        inputs[i]=(struct counter_worker){i==WORKERS};
        assert(!pthread_create(&workers[i],NULL,run_counter_worker,&inputs[i]));
    }
    for(unsigned i=0;i<=WORKERS;i++)assert(!pthread_join(workers[i],NULL));
    uint64_t wall=clock_ns(CLOCK_MONOTONIC)-begin,handler_cpu=server_cpu_ns()-handler_begin;
    uint64_t measured_faults=fault_count-warmup_faults;
    assert(*(uint64_t *)(active.rw+active.page+MISSES)==0x100000+(WORKERS+1)*COUNTER_ROUNDS);
    assert(*(uint64_t *)(active.rw+active.page+CLOCK_CALLS)==1);
    assert(!memcmp(before,active.rx+COUNTER_ENTRY,sizeof(before))&&!phase_failures);
    if(PERF_EXPECT_FIXED)assert(!fault_count);else assert(warmup_faults&&measured_faults>=WORKERS*COUNTER_ROUNDS);
    check_protection(active.rx,PROT_READ|PROT_EXEC,PROT_WRITE);
    check_protection(active.rw,PROT_READ|PROT_WRITE,PROT_EXEC);
    printf("[native-counter-call-throughput] pattern=captured-IosL1Misses mode=%s operations=%u "
           "warmup-faults=%" PRIu64 " measured-faults=%" PRIu64 " clock-backend-calls=1 "
           "wall-ns=%" PRIu64 " worker-cpu-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64
           " counter=correct retry=original code=unchanged RX=executable-nonwritable\n",
           PERF_EXPECT_FIXED?"production-direct-call-proof":"previous-production-X8-guard",
           (WORKERS+1)*COUNTER_ROUNDS,warmup_faults,measured_faults,wall,worker_cpu_ns,handler_cpu);
    assert(!munmap(active.reserved,active.reservation));memset(&active,0,sizeof(active));
    mach_msg_header_t stop={0};stop.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0);
    stop.msgh_size=sizeof(stop);stop.msgh_remote_port=exception_port;stop.msgh_id=1;
    assert(mach_msg(&stop,MACH_SEND_MSG,sizeof(stop),0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
    assert(!pthread_join(server,NULL));mach_port_deallocate(mach_task_self(),server_thread_port);
    assert(mach_port_deallocate(mach_task_self(),exception_port)==KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(),exception_port,MACH_PORT_RIGHT_RECEIVE,-1)==KERN_SUCCESS);
    return 0;
}
