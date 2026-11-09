/* Execute the actual source-staged ios_srw_note through real shared RX/RW
 * mappings. Old and new modes differ only in the production private binding;
 * no history event, increment or Windows synchronization instruction is skipped. */
#define _DARWIN_C_SOURCE
#include <stdint.h>
#include <dlfcn.h>
#include "jit_store_census.h"
static int srw_read_code(uint64_t pc,uint32_t *out);
static void srw_record_fault(uint32_t instruction);
static int srw_target_valid(uintptr_t address,uint32_t instruction);
static uintptr_t ios_write_alias(uintptr_t address);
static int ios_alias_write_is_trapped(uintptr_t address);
#define MADEIRA_PERF_RECORD_FAULT(insn) srw_record_fault(insn)
#define MADEIRA_PERF_CODE_READ(pc,out) srw_read_code(pc,out)
#define MADEIRA_PERF_TARGET_VALID(address) srw_target_valid(address,insn)
#define main madeira_atomic_fixture_unexecuted_srw_entry
#include "native-atomic-alias-performance.c"
#undef main
#include "production-srw-producer.h"
#include "production-srw-fixture.h"

enum { SRW_THREADS=8,SRW_ROUNDS=400 };
static unsigned srw_ready,srw_start;
static uint64_t srw_families[MADEIRA_STORE_FAMILIES],srw_gpr_widths[4];
static void srw_record_fault(uint32_t instruction) {
    unsigned family=madeira_jit_store_family(instruction);
    assert(family<MADEIRA_STORE_FAMILIES);
    __atomic_fetch_add(&srw_families[family],1,__ATOMIC_RELAXED);
    if(family==MADEIRA_STORE_GPR)__atomic_fetch_add(&srw_gpr_widths[instruction>>30],1,__ATOMIC_RELAXED);
}

struct srw_code_region { uintptr_t base; size_t size; };
static struct srw_code_region srw_code_regions[2];
static void srw_validate_code_regions(void) {
    const uintptr_t functions[]={(uintptr_t)srw_note_original,(uintptr_t)srw_note_bound};
    Dl_info wanted;assert(dladdr((void *)functions[0],&wanted));
    for(unsigned i=0;i<2;i++) {
        Dl_info actual;assert(dladdr((void *)functions[i],&actual)&&actual.dli_fbase==wanted.dli_fbase);
        mach_vm_address_t address=functions[i];mach_vm_size_t span=0;vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t object=MACH_PORT_NULL;
        kern_return_t status=mach_vm_region(mach_task_self(),&address,&span,VM_REGION_BASIC_INFO_64,
                                           (vm_region_info_t)&info,&count,&object);
        if(object)mach_port_deallocate(mach_task_self(),object);
        assert(status==KERN_SUCCESS&&address<=functions[i]&&functions[i]-address<span&&
               (info.protection&(VM_PROT_READ|VM_PROT_EXECUTE))==(VM_PROT_READ|VM_PROT_EXECUTE)&&
               !(info.protection&VM_PROT_WRITE));
        srw_code_regions[i]=(struct srw_code_region){(uintptr_t)address,(size_t)span};
    }
}
static int srw_read_code(uint64_t pc,uint32_t *out) {
    if(pc&3)return 0;
    /* The test executable is pinned and immutable for the process lifetime.
     * Cache its verified identity before timing. Keep the production helper's
     * per-instruction Mach read, without extra symbol/region queries. */
    for(unsigned i=0;i<2;i++)if(inside(pc,4,srw_code_regions[i].base,srw_code_regions[i].size)) {
        mach_vm_size_t got=0;
        return mach_vm_read_overwrite(mach_task_self(),pc,4,(mach_vm_address_t)out,&got)==KERN_SUCCESS&&got==4;
    }
    return 0;
}
static int srw_target_valid(uintptr_t address,uint32_t instruction) {
    size_t width=(size_t)1u<<(instruction>>30);
    if((width!=4&&width!=8)||(address&(width-1)))return 0;
    unsigned family=madeira_jit_store_family(instruction);
    if(family==MADEIRA_STORE_EXCLUSIVE)return width==4&&address==(uintptr_t)active.rx+SRW_INDEX_OFFSET;
    if(family!=MADEIRA_STORE_GPR||!inside(address,width,(uintptr_t)active.rx+SRW_RING_OFFSET,MADEIRA_NATIVE_SRW_RING_BYTES))return 0;
    uintptr_t field=(address-(uintptr_t)active.rx-SRW_RING_OFFSET)%16;
    return (width==8&&field==0)||(width==4&&field==8);
}
static uintptr_t ios_write_alias(uintptr_t address) {
    return (inside(address,1,(uintptr_t)active.rx+SRW_RING_OFFSET,MADEIRA_NATIVE_SRW_RING_BYTES)||
            inside(address,1,(uintptr_t)active.rx+SRW_INDEX_OFFSET,sizeof(LONG)))?
        (uintptr_t)active.rw+(address-(uintptr_t)active.rx):0;
}
static int ios_alias_write_is_trapped(uintptr_t address) {return !ios_write_alias(address);}
static struct image srw_map_image(void) {
    struct image result={0};result.page=(size_t)getpagesize();result.size=SRW_IMAGE_SIZE;
    result.reservation=alias_distance+result.size;
    result.reserved=mmap(NULL,result.reservation,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);assert(result.reserved!=MAP_FAILED);
    char path[]="/tmp/madeira-srw-alias-XXXXXX";int fd=mkstemp(path);
    assert(fd>=0&&!unlink(path)&&!ftruncate(fd,(off_t)result.size));
    result.rx=mmap(result.reserved,result.size,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
    result.rw=mmap(result.reserved+alias_distance,result.size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
    assert(result.rx==result.reserved&&result.rw==result.reserved+alias_distance&&!close(fd));return result;
}
struct srw_worker {unsigned index,bound;};
static void srw_register_thread(void) {
    mach_port_t thread=mach_thread_self();
    assert(thread_set_exception_ports(thread,EXC_MASK_BAD_ACCESS,exception_port,
           EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,ARM_THREAD_STATE64)==KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(),thread)==KERN_SUCCESS);
}
static void *srw_worker_run(void *argument) {
    const struct srw_worker *worker=argument;srw_register_thread();
    srw_teb.ClientId.UniqueThread=(void *)(uintptr_t)(worker->index+1);
    __atomic_add_fetch(&srw_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&srw_start,__ATOMIC_ACQUIRE))__asm__ volatile("yield");
    uint64_t start=clock_ns(CLOCK_THREAD_CPUTIME_ID);
    for(unsigned i=0;i<SRW_ROUNDS;i++) {
        const void *lock=(const void *)(uintptr_t)(0x100000+(worker->index*SRW_ROUNDS+i)*16);
        if(worker->bound)srw_note_bound(lock,i&3);else srw_note_original(lock,i&3);
    }
    __atomic_add_fetch(&worker_cpu_ns,clock_ns(CLOCK_THREAD_CPUTIME_ID)-start,__ATOMIC_RELAXED);return NULL;
}
static void srw_phase(unsigned bound) {
    active=srw_map_image();srw_source_rx=active.rx;srw_pe_fixture(active.rw);
    if(bound) {
        assert(ios_native_counter_alias_bind(active.rw,active.size,(uintptr_t)active.rx,(intptr_t)alias_distance,1));
        assert(ios_native_srw_alias_bind(active.rw,active.size,(uintptr_t)active.rx,(intptr_t)alias_distance,1));
    }
    unsigned char before[0x4000];memcpy(before,active.rx,sizeof(before));
    worker_cpu_ns=0;srw_ready=srw_start=0;
    memset(srw_families,0,sizeof(srw_families));memset(srw_gpr_widths,0,sizeof(srw_gpr_widths));
    uint64_t faults_before=fault_count,handler_before=server_cpu_ns(),start=clock_ns(CLOCK_MONOTONIC);
    pthread_t threads[SRW_THREADS];struct srw_worker workers[SRW_THREADS];
    for(unsigned i=0;i<SRW_THREADS;i++) {
        workers[i]=(struct srw_worker){i,bound};assert(!pthread_create(&threads[i],NULL,srw_worker_run,&workers[i]));
    }
    while(__atomic_load_n(&srw_ready,__ATOMIC_ACQUIRE)!=SRW_THREADS)sched_yield();
    __atomic_store_n(&srw_start,1,__ATOMIC_RELEASE);
    for(unsigned i=0;i<SRW_THREADS;i++)assert(!pthread_join(threads[i],NULL));
    uint64_t wall=clock_ns(CLOCK_MONOTONIC)-start,handler=server_cpu_ns()-handler_before,faults=fault_count-faults_before;
    assert(!phase_failures&&*(ULONG *)(active.rx+SRW_INDEX_OFFSET)==SRW_THREADS*SRW_ROUNDS);
    assert(!memcmp(before,active.rx,sizeof(before)));
    const struct ios_srw_ring_ent *ring=(const void *)(active.rx+SRW_RING_OFFSET);
    for(unsigned i=0;i<512;i++) {
        uintptr_t pointer=(uintptr_t)ring[i].lock;
        assert(pointer>=0x100000&&pointer<0x100000+SRW_THREADS*SRW_ROUNDS*16&&!(pointer&15));
        /* On wrap, the original ring's separate stores need not be a coherent
         * snapshot if two generations race on one slot. Both fields must still
         * hold genuine event values; the portable bounded test proves exact
         * per-event pairing before wrap without inventing a stronger contract. */
        unsigned tid=ring[i].tid_mode>>2;assert(tid>=1&&tid<=SRW_THREADS);
    }
    if(bound) {
        assert(!faults);
        for(unsigned i=0;i<MADEIRA_STORE_FAMILIES;i++)assert(!srw_families[i]);
    } else {
        assert(faults>=3*SRW_THREADS*SRW_ROUNDS);
        assert(srw_families[MADEIRA_STORE_EXCLUSIVE]>=SRW_THREADS*SRW_ROUNDS);
        assert(srw_families[MADEIRA_STORE_GPR]==2*SRW_THREADS*SRW_ROUNDS);
        assert(srw_gpr_widths[3]==SRW_THREADS*SRW_ROUNDS&&srw_gpr_widths[2]==SRW_THREADS*SRW_ROUNDS);
        for(unsigned i=0;i<MADEIRA_STORE_FAMILIES;i++)
            if(i!=MADEIRA_STORE_EXCLUSIVE&&i!=MADEIRA_STORE_GPR)assert(!srw_families[i]);
    }
    check_protection(active.rx,PROT_READ|PROT_EXEC,PROT_WRITE);
    check_protection(active.rw,PROT_READ|PROT_WRITE,PROT_EXEC);
    printf("[native-srw-throughput] operation=actual-source-ios_srw_note mode=%s workers=%u events=%u "
           "mach-store-faults=%" PRIu64 " exclusive=%" PRIu64 " gpr64=%" PRIu64 " gpr32=%" PRIu64 " wall-ns=%" PRIu64 " worker-cpu-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64
           " index=exact history=preserved lock-bodies=unchanged RX=nonwritable RW=nonexecutable\n",
           bound?"production-private-writer":"original-production-emulation",SRW_THREADS,SRW_THREADS*SRW_ROUNDS,
           faults,srw_families[MADEIRA_STORE_EXCLUSIVE],srw_gpr_widths[3],srw_gpr_widths[2],wall,worker_cpu_ns,handler);
    assert(!munmap(active.reserved,active.reservation));memset(&active,0,sizeof(active));srw_source_rx=NULL;
}
int main(void) {
    srw_validate_code_regions();
    assert(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&exception_port)==KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(),exception_port,exception_port,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
    pthread_t server;assert(!pthread_create(&server,NULL,exception_server,NULL));
    while(!__atomic_load_n(&server_thread_port,__ATOMIC_ACQUIRE))sched_yield();
    srw_phase(0);srw_phase(1);
    mach_msg_header_t stop={0};stop.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0);
    stop.msgh_size=sizeof(stop);stop.msgh_remote_port=exception_port;stop.msgh_id=1;
    assert(mach_msg(&stop,MACH_SEND_MSG,sizeof(stop),0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
    assert(!pthread_join(server,NULL));mach_port_deallocate(mach_task_self(),server_thread_port);
    assert(mach_port_deallocate(mach_task_self(),exception_port)==KERN_SUCCESS);
    assert(mach_port_mod_refs(mach_task_self(),exception_port,MACH_PORT_RIGHT_RECEIVE,-1)==KERN_SUCCESS);
    puts("PASS actual SRW source hardware: native atomic increment and both history stores retained; original genuine Mach exceptions versus bound zero faults");return 0;
}
