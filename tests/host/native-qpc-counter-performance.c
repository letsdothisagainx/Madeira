/* Real staged Wine QPC source, real Mach faults, real disjoint RX/RW aliases.
 * Clock/TEB API adapters use the ordinary macOS continuous clock and TLS TID.
 * This compiles source for Apple ARM64, not the packaged Windows COFF image.
 */
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mach/arm/thread_status.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/ndr.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "native_counter_alias.h"

typedef uint64_t ULONGLONG, ULONG_PTR;
typedef int64_t LONGLONG, LONG64;
typedef uint32_t DWORD, ULONG;
typedef int32_t LONG;
typedef int BOOL;
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
#define TRUE 1
#define WINAPI
#define DECLSPEC_HOTPATCH __attribute__((noinline))
#define TICKSPERSEC 10000000
#include "production-qpc-types.h"

enum { WORKERS=4, ROUNDS=750, IMAGE_BYTES=0x10000, COUNTER_RVA=0x4000, CONTRACT_RVA=0x2000 };
static const uintptr_t alias_distance=0x48000000;
struct image { unsigned char *reserved,*rx,*rw; size_t reservation; };
static struct image active;
static struct ios_xp_nt *fixture_counter_rx;
static struct ios_xp_nt_write_contract *fixture_contract_rx;
static _Thread_local DWORD fixture_tid;
static mach_timebase_info_data_t timebase;
static mach_port_t exception_port,server_thread_port;
static uint64_t fault_count,indexed_faults,pair_faults,worker_cpu_ns;

static DWORD GetCurrentThreadId(void) { return fixture_tid; }
static void NtQueryPerformanceCounter(LARGE_INTEGER *out, void *frequency)
{
    (void)frequency;
    out->QuadPart=(LONGLONG)(((__uint128_t)mach_continuous_time()*timebase.numer/timebase.denom)/100);
}
#include "production-qpc-body.h"
_Static_assert(sizeof(struct ios_xp_nt)==MADEIRA_NATIVE_COUNTER_BYTES,"production counter ABI");
_Static_assert(sizeof(struct ios_xp_nt_write_contract)==MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES,"production contract ABI");

static int inside(uintptr_t p,size_t bytes,uintptr_t begin,size_t length)
{ return p>=begin && p-begin<=length && bytes<=length-(p-begin); }
static uintptr_t ios_write_alias(uintptr_t address)
{
    return inside(address,1,(uintptr_t)active.rx+COUNTER_RVA,sizeof(struct ios_xp_nt))
           ? (uintptr_t)active.rw+(address-(uintptr_t)active.rx) : 0;
}
static int ios_alias_write_is_trapped(uintptr_t address)
{ return !inside(address,1,(uintptr_t)active.rx+COUNTER_RVA,sizeof(struct ios_xp_nt)); }
static int quiet_dprintf(int fd,const char *format,...)
{ (void)fd;(void)format;return 0; }
#define dprintf quiet_dprintf
#include "production-qpc-emulation.h"
#undef dprintf

static uint64_t clock_ns(clockid_t clock)
{
    struct timespec ts;
    assert(!clock_gettime(clock,&ts));
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}
static uint64_t server_cpu_ns(void)
{
    thread_basic_info_data_t info;
    mach_msg_type_number_t count=THREAD_BASIC_INFO_COUNT;
    assert(thread_info(server_thread_port,THREAD_BASIC_INFO,(thread_info_t)&info,&count)==KERN_SUCCESS);
    return ((uint64_t)info.user_time.seconds+info.system_time.seconds)*1000000000+
           ((uint64_t)info.user_time.microseconds+info.system_time.microseconds)*1000;
}

#pragma pack(push,4)
struct exception_request {
    mach_msg_header_t head;mach_msg_body_t body;
    mach_msg_port_descriptor_t thread,task;NDR_record_t ndr;
    exception_type_t exception;mach_msg_type_number_t code_count;int64_t code[2];
};
struct exception_reply { mach_msg_header_t head;NDR_record_t ndr;kern_return_t result; };
#pragma pack(pop)
static void *exception_server(void *unused)
{
    (void)unused;
    __atomic_store_n(&server_thread_port,mach_thread_self(),__ATOMIC_RELEASE);
    for (;;) {
        union {struct exception_request req;unsigned char buffer[1024];} message;
        assert(mach_msg(&message.req.head,MACH_RCV_MSG,0,sizeof(message),exception_port,
                        MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
        struct exception_request *req=&message.req;
        if(req->head.msgh_id==1)return NULL;
        arm_thread_state64_t state;
        mach_msg_type_number_t count=ARM_THREAD_STATE64_COUNT;
        assert(req->exception==EXC_BAD_ACCESS && req->code_count==2);
        assert(thread_get_state(req->thread.name,ARM_THREAD_STATE64,(thread_state_t)&state,&count)==KERN_SUCCESS);
        uintptr_t pc=arm_thread_state64_get_pc(state),fault=(uintptr_t)req->code[1];
        uint32_t instruction=0;
        /* Closed-world fixture: only the compiled production QPC hot body may
         * fault, only within the actual exported counter block. */
        int valid=!(pc&3) && inside(pc,4,(uintptr_t)RtlQueryPerformanceCounter,4096) &&
                  inside(fault,1,(uintptr_t)active.rx+COUNTER_RVA,sizeof(struct ios_xp_nt));
        if(valid)memcpy(&instruction,(const void *)pc,4);
        if(!valid || !emulate_qpc_store(instruction,pc,fault,&state)) {
            fprintf(stderr,"unexpected QPC exception pc=%#" PRIxPTR " instruction=%08x fault=%#" PRIxPTR "\n",pc,instruction,fault);
            abort();
        }
        __darwin_arm_thread_state64_set_pc_fptr(state,(void *)(pc+4));
        assert(thread_set_state(req->thread.name,ARM_THREAD_STATE64,(thread_state_t)&state,ARM_THREAD_STATE64_COUNT)==KERN_SUCCESS);
        __atomic_add_fetch(&fault_count,1,__ATOMIC_RELAXED);
        if((instruction&0xffe00c00)==0xf8200800)__atomic_add_fetch(&indexed_faults,1,__ATOMIC_RELAXED);
        if((instruction&0x7e400000u)==0x28000000u)__atomic_add_fetch(&pair_faults,1,__ATOMIC_RELAXED);
        struct exception_reply reply={0};
        reply.head.msgh_bits=MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->head.msgh_bits),0);
        reply.head.msgh_size=sizeof(reply);reply.head.msgh_remote_port=req->head.msgh_remote_port;
        reply.head.msgh_id=req->head.msgh_id+100;reply.ndr=NDR_record;reply.result=KERN_SUCCESS;
        assert(mach_msg(&reply.head,MACH_SEND_MSG,sizeof(reply),0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
        assert(mach_port_deallocate(mach_task_self(),req->thread.name)==KERN_SUCCESS);
        assert(mach_port_deallocate(mach_task_self(),req->task.name)==KERN_SUCCESS);
    }
}

static void w16(unsigned char *p,size_t at,uint16_t v){memcpy(p+at,&v,2);}
static void w32(unsigned char *p,size_t at,uint32_t v){memcpy(p+at,&v,4);}
static void initialize_image(unsigned char *p)
{
    memset(p,0,IMAGE_BYTES);
    p[0]='M';p[1]='Z';w32(p,0x3c,0x80);memcpy(p+0x80,"PE\0\0",4);
    w16(p,0x84,0xaa64);w16(p,0x86,1);w16(p,0x94,0xf0);
    w16(p,0x98,0x20b);w32(p,0x98+56,IMAGE_BYTES);w32(p,0x98+108,16);
    w32(p,0x98+112,0x1000);w32(p,0x98+116,0x200);
    memcpy(p+0x188,".data",6);w32(p,0x188+8,0xf000);w32(p,0x188+12,0x1000);
    w32(p,0x188+16,0xf000);w32(p,0x188+36,0xc0000040);
    w32(p,0x1000+20,2);w32(p,0x1000+24,2);
    w32(p,0x1000+28,0x1100);w32(p,0x1000+32,0x1110);w32(p,0x1000+36,0x1120);
    w32(p,0x1100,COUNTER_RVA);w32(p,0x1104,CONTRACT_RVA);
    w32(p,0x1110,0x1130);w32(p,0x1114,0x1140);w16(p,0x1120,0);w16(p,0x1122,1);
    memcpy(p+0x1130,"ios_xp_nt",10);memcpy(p+0x1140,"ios_xp_nt_write_contract",25);
    struct ios_xp_nt_write_contract contract={MADEIRA_NATIVE_COUNTER_ABI_V1,sizeof(struct ios_xp_nt),0,NULL};
    memcpy(p+CONTRACT_RVA,&contract,sizeof(contract));
}
static struct image map_image(void)
{
    struct image image={0};image.reservation=alias_distance+IMAGE_BYTES;
    image.reserved=mmap(NULL,image.reservation,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(image.reserved!=MAP_FAILED);
    char path[]="/tmp/madeira-qpc-alias-XXXXXX";int fd=mkstemp(path);
    assert(fd>=0 && !unlink(path) && !ftruncate(fd,IMAGE_BYTES));
    image.rx=mmap(image.reserved,IMAGE_BYTES,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
    image.rw=mmap(image.reserved+alias_distance,IMAGE_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
    assert(image.rx==image.reserved && image.rw==image.reserved+alias_distance && !close(fd));
    initialize_image(image.rw);return image;
}
static void check_protection(void *pointer,int required,int forbidden)
{
    mach_vm_address_t address=(uintptr_t)pointer;mach_vm_size_t length=0;
    vm_region_basic_info_data_64_t info;mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object=MACH_PORT_NULL;
    assert(mach_vm_region(mach_task_self(),&address,&length,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object)==KERN_SUCCESS);
    assert((info.protection&required)==required && !(info.protection&forbidden));
    if(object)assert(mach_port_deallocate(mach_task_self(),object)==KERN_SUCCESS);
}
static void publish_active(struct image image)
{
    active=image;fixture_counter_rx=(void *)(active.rx+COUNTER_RVA);
    fixture_contract_rx=(void *)(active.rx+CONTRACT_RVA);
}
static void bind_writer(void)
{
    unsigned char before[IMAGE_BYTES];memcpy(before,active.rx,sizeof(before));
    assert(ios_native_counter_alias_bind(active.rw,IMAGE_BYTES,(uintptr_t)active.rx,alias_distance,1)==1);
    assert(fixture_contract_rx->writer==active.rw+COUNTER_RVA);
    size_t offset=CONTRACT_RVA+MADEIRA_NATIVE_COUNTER_WRITER_OFFSET;
    for(size_t n=0;n<IMAGE_BYTES;n++)if(n<offset || n>=offset+8)assert(before[n]==active.rx[n]);
}
static void *run_worker(void *argument)
{
    unsigned index=(unsigned)(uintptr_t)argument;fixture_tid=4*(index+1);
    mach_port_t self=mach_thread_self();
    assert(thread_set_exception_ports(self,EXC_MASK_BAD_ACCESS,exception_port,
               EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,ARM_THREAD_STATE64)==KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(),self)==KERN_SUCCESS);
    uint64_t begin=clock_ns(CLOCK_THREAD_CPUTIME_ID);LONGLONG previous=0;
    for(unsigned n=0;n<ROUNDS;n++) {
        LARGE_INTEGER qpc,system;assert(RtlQueryPerformanceCounter(&qpc));
        NtQueryPerformanceCounter(&system,NULL);
        assert(qpc.QuadPart>=previous && qpc.QuadPart>0);
        assert(llabs(system.QuadPart-qpc.QuadPart)<TICKSPERSEC);
        previous=qpc.QuadPart;
    }
    __atomic_add_fetch(&worker_cpu_ns,clock_ns(CLOCK_THREAD_CPUTIME_ID)-begin,__ATOMIC_RELAXED);
    return NULL;
}
static void run_phase(int bound)
{
    bind_writer();
    ios_xp_nt_init();
    struct ios_xp_nt *counter=(void *)(active.rw+COUNTER_RVA);
    assert(counter->magic==UINT64_C(0x31544e5058444d41) && counter->freq);
    /* Seed slots through the actual production QPC path before measuring its
     * steady-state diagnostic stores; first-use memset is not the regression. */
    for(unsigned n=0;n<WORKERS;n++) {
        fixture_tid=4*(n+1);LARGE_INTEGER value;assert(RtlQueryPerformanceCounter(&value));
        struct ios_xp_nt_qpc *slot=&counter->qpc[n+1];assert(slot->tid==fixture_tid);
        slot->calls=0;memset(slot->hist,0,sizeof(slot->hist));
    }
    if(!bound)__atomic_store_n(&((struct ios_xp_nt_write_contract *)(active.rw+CONTRACT_RVA))->writer,NULL,__ATOMIC_RELEASE);
    unsigned char prefix[offsetof(struct ios_xp_nt,qpc)];memcpy(prefix,counter,sizeof(prefix));
    uint64_t before=__atomic_load_n(&fault_count,__ATOMIC_RELAXED),indexed_before=indexed_faults,pair_before=pair_faults;
    uint64_t handler_before=server_cpu_ns(),wall_before=clock_ns(CLOCK_MONOTONIC);worker_cpu_ns=0;
    pthread_t workers[WORKERS];
    for(unsigned n=0;n<WORKERS;n++)assert(!pthread_create(&workers[n],NULL,run_worker,(void *)(uintptr_t)n));
    for(unsigned n=0;n<WORKERS;n++)assert(!pthread_join(workers[n],NULL));
    uint64_t wall=clock_ns(CLOCK_MONOTONIC)-wall_before,handler=server_cpu_ns()-handler_before;
    uint64_t faults=__atomic_load_n(&fault_count,__ATOMIC_RELAXED)-before;
    assert(!memcmp(prefix,counter,sizeof(prefix)));
    for(unsigned n=0;n<WORKERS;n++) {
        struct ios_xp_nt_qpc *slot=&counter->qpc[n+1];ULONGLONG sum=0;
        for(unsigned bucket=0;bucket<5;bucket++)sum+=slot->hist[bucket];
        assert(slot->tid==4*(n+1) && slot->calls==ROUNDS && sum==ROUNDS);
    }
    if(bound)assert(!faults);else assert(faults>=WORKERS*ROUNDS);
    check_protection(active.rx,PROT_READ|PROT_EXEC,PROT_WRITE);
    check_protection(active.rw,PROT_READ|PROT_WRITE,PROT_EXEC);
    printf("[native-qpc-throughput] mode=%s workers=%u operations=%u mach-store-faults=%" PRIu64
           " indexed-str=%" PRIu64 " gpr-pair=%" PRIu64 " wall-ns=%" PRIu64
           " worker-cpu-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64
           " qpc=monotonic-clock-agrees hist=exact calls=exact rx=nonwritable rw=nonexecuting\n",
           bound?"production-bound-writer":"production-rx-fallback",WORKERS,WORKERS*ROUNDS,faults,
           indexed_faults-indexed_before,pair_faults-pair_before,wall,worker_cpu_ns,handler);
}
int main(void)
{
    /* The binder shares the native-image parser header; its separate FEX
     * lowering entry is exercised by the existing image test, not this probe. */
    (void)ios_native_atomic_image_lower;
    assert(mach_timebase_info(&timebase)==KERN_SUCCESS);
    assert(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&exception_port)==KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(),exception_port,exception_port,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
    pthread_t server;assert(!pthread_create(&server,NULL,exception_server,NULL));
    while(!__atomic_load_n(&server_thread_port,__ATOMIC_ACQUIRE))sched_yield();
    publish_active(map_image());run_phase(0);run_phase(1);
    /* A new private image may contain a parent's writer pointer. Binding must
     * replace it without touching the previous generation or its counters. */
    struct image old=active;unsigned char old_bytes[IMAGE_BYTES];memcpy(old_bytes,old.rx,IMAGE_BYTES);
    struct image successor=map_image();
    ((struct ios_xp_nt_write_contract *)(successor.rw+CONTRACT_RVA))->writer=old.rw+COUNTER_RVA;
    publish_active(successor);run_phase(1);assert(!memcmp(old_bytes,old.rx,IMAGE_BYTES));
    assert(!munmap(old.reserved,old.reservation));assert(!munmap(active.reserved,active.reservation));
    mach_msg_header_t stop={0};stop.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0);
    stop.msgh_size=sizeof(stop);stop.msgh_remote_port=exception_port;stop.msgh_id=1;
    assert(mach_msg(&stop,MACH_SEND_MSG,sizeof(stop),0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
    assert(!pthread_join(server,NULL));assert(mach_port_deallocate(mach_task_self(),server_thread_port)==KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(),exception_port)==KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(),exception_port,MACH_PORT_RIGHT_RECEIVE,-1)==KERN_SUCCESS);
    puts("PASS actual staged Wine QPC source: matched Mach baseline/bound writer, exact diagnostics, isolated generation rebind");
    return 0;
}
