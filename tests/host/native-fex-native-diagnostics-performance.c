/* Focused real-Mach execution of captured telemetry writes and the actual
 * source-staged IR diagnostic producer. Ownership/region metadata belongs to
 * this fixture; production store/exclusive emulation is extracted unchanged. */
#define _DARWIN_C_SOURCE
#include <stdint.h>
#include <dlfcn.h>
#include "jit_store_census.h"
extern void madeira_diag_image(void *,void *);
extern uintptr_t madeira_diag_telemetry_address(unsigned,unsigned);
extern void madeira_diag_stsetl(uint64_t,uintptr_t);
extern void madeira_diag_ir_old(void),madeira_diag_ir_bound(void);
extern uintptr_t madeira_diag_history_frame(unsigned),madeira_diag_history_address(void);
extern void madeira_diag_history_old(unsigned,uint64_t,uint64_t),madeira_diag_history_bound(unsigned,uint64_t,uint64_t);
static uintptr_t ios_write_alias(uintptr_t);
static int ios_alias_write_is_trapped(uintptr_t);
static int diag_read_code(uint64_t,uint32_t *);
static int diag_target_valid(uintptr_t,uint32_t,const void *);
static void diag_record_fault(uint32_t);
#define MADEIRA_PERF_CODE_READ(pc,out) diag_read_code(pc,out)
#define MADEIRA_PERF_TARGET_VALID(address) diag_target_valid(address,insn,&state)
#define MADEIRA_PERF_RECORD_FAULT(insn) diag_record_fault(insn)
#define main madeira_atomic_fixture_unexecuted_fex_diagnostics_entry
#include "native-atomic-alias-performance.c"
#undef main
#include "production-fex-diagnostics-fixture.h"
enum { DIAG_THREADS=8,DIAG_ROUNDS=400 };
static uint64_t diag_families[MADEIRA_STORE_FAMILIES];
static unsigned diag_case,diag_ready,diag_start;
static uintptr_t telemetry_targets[2];
struct diag_code_region {uintptr_t base;size_t size;};
static struct diag_code_region diag_code_regions[5];
static void diag_validate_code_regions(void) {
  const uintptr_t functions[]={(uintptr_t)madeira_diag_stsetl,(uintptr_t)madeira_diag_ir_old,(uintptr_t)madeira_diag_ir_bound,
                              (uintptr_t)madeira_diag_history_old,(uintptr_t)madeira_diag_history_bound};
  Dl_info wanted;assert(dladdr((void *)functions[0],&wanted));
  for(unsigned i=0;i<5;i++){
    Dl_info actual;assert(dladdr((void *)functions[i],&actual)&&actual.dli_fbase==wanted.dli_fbase);
    mach_vm_address_t address=functions[i];mach_vm_size_t span=0;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t object=MACH_PORT_NULL;
    kern_return_t status=mach_vm_region(mach_task_self(),&address,&span,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object);
    if(object)mach_port_deallocate(mach_task_self(),object);
    assert(status==KERN_SUCCESS&&address<=functions[i]&&functions[i]-address<span&&
           (info.protection&(VM_PROT_READ|VM_PROT_EXECUTE))==(VM_PROT_READ|VM_PROT_EXECUTE)&&!(info.protection&VM_PROT_WRITE));
    diag_code_regions[i]=(struct diag_code_region){(uintptr_t)address,(size_t)span};
  }
}
static int diag_read_code(uint64_t pc,uint32_t *out) {
  if(pc&3)return 0;
  for(unsigned i=0;i<5;i++)if(inside(pc,4,diag_code_regions[i].base,diag_code_regions[i].size)){
    mach_vm_size_t got=0;
    return mach_vm_read_overwrite(mach_task_self(),pc,4,(mach_vm_address_t)out,&got)==KERN_SUCCESS&&got==4;
  }
  return 0;
}
/* This fixture accepts only whole 64-bit history stores. Hardware supplied
 * the fault address; independently check its encoded effective address before
 * the unchanged production branch writes through the bounded private alias.
 * Unsigned addition preserves A64's modulo-64-bit address arithmetic, including
 * negative SXTW/SXTX indices. Rn=31 is SP, while Rm=31 is the zero register.
 */
static uint64_t diag_history_register(const arm_thread_state64_t *state,unsigned reg) {
  return reg==29?state->__fp:reg==30?state->__lr:state->__x[reg];
}
static int diag_history_store_target(uintptr_t address,uint32_t instruction,const void *input) {
  const arm_thread_state64_t *state=input;
  unsigned rn=(instruction>>5)&31;
  uint64_t base=rn==31?state->__sp:diag_history_register(state,rn),offset;
  if(!inside(address,8,(uintptr_t)active.rx+FEX_DIAG_HISTORY,192)||(address&7))return 0;
  if((instruction&0xffc00000u)==0xf9000000u)offset=((instruction>>10)&0xfff)*UINT64_C(8);
  else if((instruction&0xffe00c00u)==0xf8200800u){
    unsigned rm=(instruction>>16)&31,option=(instruction>>13)&7;
    if(!(option&2))return 0; /* unallocated register-extend option */
    offset=rm==31?0:diag_history_register(state,rm);
    if(option==2)offset=(uint32_t)offset;
    else if(option==6)offset=(uint64_t)(int64_t)(int32_t)offset;
    if(instruction&0x1000u)offset<<=3;
  }else return 0;
  return base+offset==(uint64_t)address;
}
static int diag_target_valid(uintptr_t address,uint32_t instruction,const void *state) {
  if(address&7)return 0;
  if(!diag_case)return instruction==0xf860303fu&&
    (address==(uintptr_t)active.rx+FEX_DIAG_TELEMETRY+12*8||address==(uintptr_t)active.rx+FEX_DIAG_TELEMETRY+15*8);
  if(diag_case==2)return diag_history_store_target(address,instruction,state);
  return (instruction>>30)==3&&madeira_jit_store_family(instruction)==MADEIRA_STORE_EXCLUSIVE&&
         address==(uintptr_t)active.rx+FEX_DIAG_IRTOPO;
}
static uintptr_t ios_write_alias(uintptr_t address) {
  if(!inside(address,1,(uintptr_t)active.rx+FEX_DIAG_HISTORY,192))return 0;
  return (uintptr_t)active.rw+address-(uintptr_t)active.rx;
}
static int ios_alias_write_is_trapped(uintptr_t address) {return !ios_write_alias(address);}
static void diag_record_fault(uint32_t instruction) {
  unsigned family=madeira_jit_store_family(instruction);assert(family<MADEIRA_STORE_FAMILIES);
  __atomic_fetch_add(&diag_families[family],1,__ATOMIC_RELAXED);
}
static struct image diagnostic_map_image(void){
  struct image result={0};result.page=(size_t)getpagesize();result.size=FEX_DIAG_IMAGE_SIZE;
  result.reservation=alias_distance+result.size;
  result.reserved=mmap(NULL,result.reservation,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);assert(result.reserved!=MAP_FAILED);
  char path[]="/tmp/madeira-fex-diagnostic-XXXXXX";int fd=mkstemp(path);
  assert(fd>=0&&!unlink(path)&&!ftruncate(fd,(off_t)result.size));
  result.rx=mmap(result.reserved,result.size,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
  result.rw=mmap(result.reserved+alias_distance,result.size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
  assert(result.rx==result.reserved&&result.rw==result.reserved+alias_distance&&!close(fd));return result;
}
struct diagnostic_worker {unsigned index,bound;};
static void *diagnostic_worker_run(void *argument){
  const struct diagnostic_worker *worker=argument;
  mach_port_t thread=mach_thread_self();
  assert(thread_set_exception_ports(thread,EXC_MASK_BAD_ACCESS,exception_port,EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,ARM_THREAD_STATE64)==KERN_SUCCESS);
  assert(mach_port_deallocate(mach_task_self(),thread)==KERN_SUCCESS);
  __atomic_add_fetch(&diag_ready,1,__ATOMIC_RELEASE);
  while(!__atomic_load_n(&diag_start,__ATOMIC_ACQUIRE))__asm__ volatile("yield");
  uint64_t start=clock_ns(CLOCK_THREAD_CPUTIME_ID);
  for(unsigned i=0;i<DIAG_ROUNDS;i++){
    if(!diag_case)madeira_diag_stsetl(1,telemetry_targets[worker->index&1]);
    else if(diag_case==1){if(worker->bound)madeira_diag_ir_bound();else madeira_diag_ir_old();}
    else{
      uint64_t crsp=i%7?UINT64_C(0x10000)+worker->index*0x1000+(i%5)*0x40:0;
      uint64_t rip=UINT64_C(0x140000000)+worker->index*0x1000+i*4;
      if(worker->bound)madeira_diag_history_bound(worker->index,crsp,rip);
      else madeira_diag_history_old(worker->index,crsp,rip);
    }
  }
  __atomic_add_fetch(&worker_cpu_ns,clock_ns(CLOCK_THREAD_CPUTIME_ID)-start,__ATOMIC_RELAXED);return NULL;
}
static int diagnostic_mutable_byte(size_t at){
  if(diag_case==2)return at>=FEX_DIAG_HISTORY&&at<FEX_DIAG_HISTORY+192;
  if(diag_case==1)return at>=FEX_DIAG_IRTOPO&&at<FEX_DIAG_IRTOPO+8;
  return (at>=FEX_DIAG_TELEMETRY+12*8&&at<FEX_DIAG_TELEMETRY+13*8)||
         (at>=FEX_DIAG_TELEMETRY+15*8&&at<FEX_DIAG_TELEMETRY+16*8);
}
static void diagnostic_phase(unsigned operation,unsigned bound){
  static unsigned char original_history[192];
  unsigned worker_count=operation==2?4:DIAG_THREADS;
  diag_case=operation;active=diagnostic_map_image();diagnostic_pe_fixture(active.rw);
  madeira_diag_image(active.rx,active.rw);
  if(bound)assert(ios_native_fex_diagnostics_bind(active.rw,active.size,UINT64_C(0x500000000),(uintptr_t)active.rx,(intptr_t)alias_distance,1));
  assert(madeira_diag_history_address()==(uintptr_t)(bound?active.rw:active.rx)+FEX_DIAG_HISTORY);
  for(unsigned i=0;i<2;i++){
    unsigned index=i?15:12;
    telemetry_targets[i]=madeira_diag_telemetry_address(bound,index);
    assert(telemetry_targets[i]==(uintptr_t)(bound?active.rw:active.rx)+FEX_DIAG_TELEMETRY+index*8);
  }
  unsigned char before[FEX_DIAG_IMAGE_SIZE];memcpy(before,active.rx,sizeof(before));
  memset(diag_families,0,sizeof(diag_families));worker_cpu_ns=0;diag_ready=diag_start=0;
  uint64_t faults_before=fault_count,handler_before=server_cpu_ns(),start=clock_ns(CLOCK_MONOTONIC);
  pthread_t threads[DIAG_THREADS];struct diagnostic_worker workers[DIAG_THREADS];
  for(unsigned i=0;i<worker_count;i++){
    workers[i]=(struct diagnostic_worker){i,bound};assert(!pthread_create(&threads[i],NULL,diagnostic_worker_run,&workers[i]));
  }
  while(__atomic_load_n(&diag_ready,__ATOMIC_ACQUIRE)!=worker_count)sched_yield();
  __atomic_store_n(&diag_start,1,__ATOMIC_RELEASE);
  for(unsigned i=0;i<worker_count;i++)assert(!pthread_join(threads[i],NULL));
  uint64_t wall=clock_ns(CLOCK_MONOTONIC)-start,handler=server_cpu_ns()-handler_before,faults=fault_count-faults_before;
  assert(!phase_failures);
  if(!operation){
    assert(*(uint64_t*)(active.rx+FEX_DIAG_TELEMETRY+12*8)==1&&*(uint64_t*)(active.rx+FEX_DIAG_TELEMETRY+15*8)==1);
  }else if(operation==1)assert(*(uint64_t*)(active.rx+FEX_DIAG_IRTOPO)==worker_count*DIAG_ROUNDS);
  else{
    const uint64_t *history=(const void *)(active.rx+FEX_DIAG_HISTORY);
    for(unsigned i=0;i<worker_count;i++){
      unsigned slot=(madeira_diag_history_frame(i)>>6)&3;
      assert(history[slot]==madeira_diag_history_frame(i));
      assert(history[4+slot]==UINT64_C(0x10000)+i*0x1000);
      assert(history[8+slot]==UINT64_C(0x10100)+i*0x1000);
      assert(history[12+slot]==0&&history[16+slot]==DIAG_ROUNDS);
      assert(history[20+slot]==UINT64_C(0x140000000)+i*0x1000+(DIAG_ROUNDS-1)*4);
    }
    if(bound)assert(!memcmp(original_history,history,192));else memcpy(original_history,history,192);
  }
  for(size_t i=0;i<active.size;i++)if(!diagnostic_mutable_byte(i))assert(active.rx[i]==before[i]);
  unsigned expected=operation==2?MADEIRA_STORE_GPR:operation?MADEIRA_STORE_EXCLUSIVE:MADEIRA_STORE_LSE;
  if(bound){assert(!faults);for(unsigned i=0;i<MADEIRA_STORE_FAMILIES;i++)assert(!diag_families[i]);}
  else{
    if(operation==2)assert(faults>=worker_count*DIAG_ROUNDS*4);
    else if(operation)assert(faults>=worker_count*DIAG_ROUNDS);else assert(faults==worker_count*DIAG_ROUNDS);
    assert(diag_families[expected]==faults);
    for(unsigned i=0;i<MADEIRA_STORE_FAMILIES;i++)if(i!=expected)assert(!diag_families[i]);
  }
  check_protection(active.rx,PROT_READ|PROT_EXEC,PROT_WRITE);check_protection(active.rw,PROT_READ|PROT_WRITE,PROT_EXEC);
  printf("[fex-native-diagnostics-throughput] operation=%s mode=%s workers=%u events=%u mach-store-faults=%" PRIu64
         " lse=%" PRIu64 " exclusive=%" PRIu64 " gpr=%" PRIu64 " wall-ns=%" PRIu64 " worker-cpu-ns=%" PRIu64 " handler-cpu-ns=%" PRIu64
         " payload=exact neighbors=unchanged RX=nonwritable RW=nonexecutable\n",
         operation==2?"actual-source-CompileBlock-callret-history":operation?"actual-source-IRTopoNoteChecked":"captured-STSETL-source-selected-flags12-15",
         bound?"production-private-writer":"original-production-emulation",worker_count,worker_count*DIAG_ROUNDS,
         faults,diag_families[MADEIRA_STORE_LSE],diag_families[MADEIRA_STORE_EXCLUSIVE],diag_families[MADEIRA_STORE_GPR],wall,worker_cpu_ns,handler);
  assert(!munmap(active.reserved,active.reservation));memset(&active,0,sizeof(active));
}
int main(void){
  diag_validate_code_regions();
  assert(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&exception_port)==KERN_SUCCESS);
  assert(mach_port_insert_right(mach_task_self(),exception_port,exception_port,MACH_MSG_TYPE_MAKE_SEND)==KERN_SUCCESS);
  pthread_t server;assert(!pthread_create(&server,NULL,exception_server,NULL));
  while(!__atomic_load_n(&server_thread_port,__ATOMIC_ACQUIRE))sched_yield();
  for(unsigned operation=0;operation<3;operation++){diagnostic_phase(operation,0);diagnostic_phase(operation,1);}
  mach_msg_header_t stop={0};stop.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0);stop.msgh_size=sizeof(stop);
  stop.msgh_remote_port=exception_port;stop.msgh_id=1;
  assert(mach_msg(&stop,MACH_SEND_MSG,sizeof(stop),0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)==KERN_SUCCESS);
  assert(!pthread_join(server,NULL));mach_port_deallocate(mach_task_self(),server_thread_port);
  assert(mach_port_deallocate(mach_task_self(),exception_port)==KERN_SUCCESS);
  assert(mach_port_mod_refs(mach_task_self(),exception_port,MACH_PORT_RIGHT_RECEIVE,-1)==KERN_SUCCESS);
  puts("PASS real Mach FEX diagnostic producer fixture: captured telemetry STSETL, actual staged IR and CompileBlock history preserve complete payloads; bound phases zero faults");return 0;
}
