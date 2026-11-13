/* Actual staged Module.S probes, copied at identical page-relative offsets.
 * The baseline really writes the nonwritable RX mapping and resumes through
 * the existing production Mach emulator. No instruction is elided or patched.
 */
#define _DARWIN_C_SOURCE
#include <stdint.h>
#include "jit_store_census.h"
static uintptr_t ios_write_alias(uintptr_t);
static int ios_alias_write_is_trapped(uintptr_t);
static int transition_read_code(uint64_t,uint32_t *);
static int transition_target_valid(uintptr_t,uint32_t,const void *);
static void transition_record_fault(uint32_t);
#define MADEIRA_PERF_CODE_READ(pc,out) transition_read_code(pc,out)
#define MADEIRA_PERF_TARGET_VALID(address) transition_target_valid(address,insn,&state)
#define MADEIRA_PERF_RECORD_FAULT(insn) transition_record_fault(insn)
#define main madeira_atomic_fixture_unexecuted_transition_entry
#include "native-atomic-alias-performance.c"
#undef main
#include "production-fex-diagnostics-fixture.h"

extern const unsigned char madeira_transition_template[];
enum { TRANSITION_ROUNDS=2048,TRANSITION_BYTES=35968,TRANSITION_RING=3200,
       TRANSITION_RING_COUNT=3136,TRANSITION_RING_SEED=4090 };
static uint64_t transition_families[MADEIRA_STORE_FAMILIES];
static unsigned transition_operation;
static _Alignas(64) unsigned char transition_frame[4160];
static unsigned char transition_reference[TRANSITION_BYTES];
static uint64_t transition_results[TRANSITION_ROUNDS];

static int transition_read_code(uint64_t pc,uint32_t *out)
{
    if((pc&3)||!inside(pc,4,(uintptr_t)active.rx+0x2000,0x800))return 0;
    memcpy(out,(const void *)(uintptr_t)pc,4);return 1;
}

static uint64_t transition_register(const arm_thread_state64_t *state,unsigned reg)
{
    return reg==29?state->__fp:reg==30?state->__lr:reg==31?state->__sp:state->__x[reg];
}

static int transition_target_valid(uintptr_t address,uint32_t instruction,const void *input)
{
    const arm_thread_state64_t *state=input;
    uintptr_t payload=(uintptr_t)active.rx+FEX_DIAG_TRANSITION;
    if((address&7)||!inside(address,8,payload,TRANSITION_BYTES)||(instruction>>30)!=3)return 0;
    unsigned rn=(instruction>>5)&31;
    uint64_t base=transition_register(state,rn);
    unsigned family=madeira_jit_store_family(instruction);
    size_t at=address-payload;
    if(family==MADEIRA_STORE_LSE){
        size_t counter=transition_operation<2?(transition_operation?2112:1088):64;
        return base==address&&(at==TRANSITION_RING_COUNT||
               (at>=counter&&at<=counter+15*64&&!((at-counter)&63)));
    }
    /* Exact STR x9,[x17,x23,LSL#3] from both source probes. Validate the
     * hardware fault's effective address independently before production
     * emulation stores through the private, bounded alias. */
    if(family!=MADEIRA_STORE_GPR||(instruction&0xffe00c00u)!=0xf8200800u||
       (instruction&31)!=9||rn!=17||((instruction>>16)&31)!=23||
       ((instruction>>13)&7)!=3||!(instruction&0x1000))return 0;
    return at>=TRANSITION_RING&&base+(state->__x[23]<<3)==address;
}

static uintptr_t ios_write_alias(uintptr_t address)
{
    if(!inside(address,8,(uintptr_t)active.rx+FEX_DIAG_TRANSITION,TRANSITION_BYTES))return 0;
    return (uintptr_t)active.rw+address-(uintptr_t)active.rx;
}
static int ios_alias_write_is_trapped(uintptr_t address){return !ios_write_alias(address);}
static void transition_record_fault(uint32_t instruction)
{
    unsigned family=madeira_jit_store_family(instruction);assert(family<MADEIRA_STORE_FAMILIES);
    transition_families[family]++;
}

static struct image transition_map_image(void)
{
    struct image result={0};result.page=(size_t)getpagesize();result.size=FEX_DIAG_IMAGE_SIZE;
    result.reservation=alias_distance+result.size;
    result.reserved=mmap(NULL,result.reservation,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(result.reserved!=MAP_FAILED);
    char path[]="/tmp/madeira-transition-writer-XXXXXX";int fd=mkstemp(path);
    assert(fd>=0&&!unlink(path)&&!ftruncate(fd,(off_t)result.size));
    result.rx=mmap(result.reserved,result.size,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
    result.rw=mmap(result.reserved+alias_distance,result.size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
    assert(result.rx==result.reserved&&result.rw==result.reserved+alias_distance&&!close(fd));
    return result;
}

static uint64_t transition_target(unsigned iteration)
{
    return UINT64_C(0x140000000)+iteration*4;
}

static void transition_check_payload(unsigned operation,unsigned shard)
{
    unsigned char expected[TRANSITION_BYTES]={0};
    uint64_t counter=TRANSITION_ROUNDS,ring=TRANSITION_RING_SEED;
    size_t at=(operation<2?(operation?2112:1088):64)+shard*64;
    memcpy(expected+at,&counter,8);
    if(operation>=2){
        for(unsigned i=0;i<TRANSITION_ROUNDS;i++){
            if(operation==2?((i+1)&63)!=0:(i&63)!=0)continue;
            uint64_t target=transition_target(i);
            memcpy(expected+TRANSITION_RING+(ring&4095)*8,&target,8);ring++;
        }
    }
    memcpy(expected+TRANSITION_RING_COUNT,&ring,8);
    assert(!memcmp(expected,active.rx+FEX_DIAG_TRANSITION,sizeof(expected)));
    uint64_t frame_count=0;memcpy(&frame_count,transition_frame+4088,8);
    assert(frame_count==(operation==2?TRANSITION_ROUNDS:0));
    for(size_t i=0;i<sizeof(transition_frame);i++)
        if(i<4088||i>=4096)assert(transition_frame[i]==0xa5);
}

static void transition_phase(unsigned operation,unsigned mode)
{
    /* Use one calling thread and identical wrappers in all three phases, so
     * the production SP-shard and all target-ring positions must agree. */
    active=transition_map_image();transition_operation=operation;
    diagnostic_pe_fixture(active.rw);
    assert(!((uintptr_t)madeira_transition_template&0x3fff));
    memcpy(active.rw+0x2000,madeira_transition_template+0x2000,0x800);
    if(mode==2)assert(ios_native_fex_diagnostics_bind(active.rw,active.size,UINT64_C(0x500000000),
                                                  (uintptr_t)active.rx,(intptr_t)alias_distance,1)==5);
    uint64_t writer=0;memcpy(&writer,active.rx+FEX_DIAG_CONTRACT+4*64+24,8);
    assert(writer==(mode==2?(uintptr_t)active.rw+FEX_DIAG_TRANSITION:0));
    diag_w64(active.rw,FEX_DIAG_TRANSITION+TRANSITION_RING_COUNT,TRANSITION_RING_SEED);
    memset(transition_frame,0xa5,sizeof(transition_frame));memset(transition_frame+4088,0,8);
    unsigned char before[FEX_DIAG_IMAGE_SIZE];memcpy(before,active.rx,sizeof(before));
    __builtin___clear_cache((char *)active.rw+0x2000,(char *)active.rw+0x2800);
    __builtin___clear_cache((char *)active.rx+0x2000,(char *)active.rx+0x2800);
    uint64_t (*probe)(void *,uint64_t,uint64_t)=(void *)(active.rx+0x2000+(operation*2+(mode!=0))*0x100);
    memset(transition_families,0,sizeof(transition_families));
    uint64_t faults_before=fault_count,handler_before=server_cpu_ns(),worker_before=clock_ns(CLOCK_THREAD_CPUTIME_ID);
    uint64_t wall_before=clock_ns(CLOCK_MONOTONIC);unsigned shard=16;
    for(unsigned i=0;i<TRANSITION_ROUNDS;i++){
        uint64_t result=probe(transition_frame,transition_target(i),UINT64_C(0xa0000000));
        if(shard==16)shard=(unsigned)(result&15);
        assert((result&15)==shard);
        if(operation<2)assert((result&UINT64_C(0xf0000000))==UINT64_C(0xa0000000));
        if(!mode)transition_results[i]=result;else assert(result==transition_results[i]);
    }
    uint64_t wall=clock_ns(CLOCK_MONOTONIC)-wall_before,worker=clock_ns(CLOCK_THREAD_CPUTIME_ID)-worker_before;
    uint64_t handler=server_cpu_ns()-handler_before,faults=fault_count-faults_before;
    assert(!phase_failures);transition_check_payload(operation,shard);
    if(!mode)memcpy(transition_reference,active.rx+FEX_DIAG_TRANSITION,TRANSITION_BYTES);
    else assert(!memcmp(transition_reference,active.rx+FEX_DIAG_TRANSITION,TRANSITION_BYTES));
    for(size_t i=0;i<active.size;i++)if(i<FEX_DIAG_TRANSITION||i>=FEX_DIAG_TRANSITION+TRANSITION_BYTES)
        assert(active.rx[i]==before[i]);
    uint64_t ring_writes=operation>=2?TRANSITION_ROUNDS/64:0;
    uint64_t counter_writes=operation==2?TRANSITION_ROUNDS/64:TRANSITION_ROUNDS;
    if(mode==2)assert(!faults);
    else{
        assert(faults==counter_writes+ring_writes*2);
        assert(transition_families[MADEIRA_STORE_LSE]==counter_writes+ring_writes);
        assert(transition_families[MADEIRA_STORE_GPR]==ring_writes);
    }
    for(unsigned i=0;i<MADEIRA_STORE_FAMILIES;i++)
        if(mode==2||(i!=MADEIRA_STORE_LSE&&i!=MADEIRA_STORE_GPR))assert(!transition_families[i]);
    check_protection(active.rx,PROT_READ|PROT_EXEC,PROT_WRITE);
    check_protection(active.rw,PROT_READ|PROT_WRITE,PROT_EXEC);
    printf("[fex-transition-throughput] operation=%s mode=%s events=%u mach-store-faults=%" PRIu64
           " lse=%" PRIu64 " ring-stores=%" PRIu64 " wall-ns=%" PRIu64 " worker-cpu-ns=%" PRIu64
           " handler-cpu-ns=%" PRIu64 " payload=exact ring=checked NZCV=preserved RX=nonwritable RW=nonexecutable\n",
           operation==0?"IOS_XP_COUNT-fpcr":operation==1?"IOS_XP_COUNT-callback":operation==2?"ExitFunctionECJit-probe":"ExitFunctionEC-probe",
           mode==0?"original-production-emulation":mode==1?"staged-null-writer-emulation":"production-private-writer",
           TRANSITION_ROUNDS,faults,transition_families[MADEIRA_STORE_LSE],transition_families[MADEIRA_STORE_GPR],wall,worker,handler);
    assert(!munmap(active.reserved,active.reservation));memset(&active,0,sizeof(active));
}

int main(void)
{
    assert(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&exception_port)==KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(),exception_port,exception_port,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
    pthread_t server;assert(!pthread_create(&server,NULL,exception_server,NULL));
    while(!__atomic_load_n(&server_thread_port,__ATOMIC_ACQUIRE))sched_yield();
    mach_port_t self=mach_thread_self();
    assert(thread_set_exception_ports(self,EXC_MASK_BAD_ACCESS,exception_port,
        EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,ARM_THREAD_STATE64)==KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(),self)==KERN_SUCCESS);
    for(unsigned operation=0;operation<4;operation++)for(unsigned mode=0;mode<3;mode++)transition_phase(operation,mode);
    mach_msg_header_t stop={0};stop.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0);stop.msgh_size=sizeof(stop);
    stop.msgh_remote_port=exception_port;stop.msgh_id=1;
    assert(mach_msg(&stop,MACH_SEND_MSG,sizeof(stop),0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
    assert(!pthread_join(server,NULL));mach_port_deallocate(mach_task_self(),server_thread_port);
    assert(mach_port_deallocate(mach_task_self(),exception_port)==KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(),exception_port,MACH_PORT_RIGHT_RECEIVE,-1)==KERN_SUCCESS);
    puts("PASS real Mach transition fixture: actual source probes and complete 35968-byte payload agree; native writer has zero faults");
    return 0;
}
