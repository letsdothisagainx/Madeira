/* Real Darwin Mach integration. Only the attached-debugger callbacks are
 * supplied: ordinary host Mach allocations/aliases stand in for its backing.
 * This does not test iOS code signing, entitlement or StikDebug acceptance. */
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ucontext.h>
#include <libkern/OSCacheControl.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"native Mach line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
static unsigned debug_allocations,preparations;
static void jit_log(const char* format,...){(void)format;}
/* ACTUAL TASK MAP QUERY INSERTED HERE */
/* ACTUAL EXECUTION PROBE INSERTED HERE */
static uint64_t jit26_pool_capabilities(void){return UINT64_C(0x4d4a5031);}
static void* jit26_pool_allocate(size_t size){
 vm_address_t address=0;debug_allocations++;
 CHECK(vm_allocate(mach_task_self(),&address,(vm_size_t)size,VM_FLAGS_ANYWHERE)==KERN_SUCCESS);
 CHECK(vm_protect(mach_task_self(),address,(vm_size_t)size,FALSE,VM_PROT_READ|VM_PROT_EXECUTE)==KERN_SUCCESS);
 return(void*)(uintptr_t)address;
}
static void* jit26_pool_prepare(void* pointer,size_t size){
 /* Match the debugger's byte markers without making its RX destination
  * writable. All native vm_allocate/remap/protect/region/read calls in the
  * production transaction execute unchanged against this host kernel. */
 vm_address_t writable=0;vm_prot_t current=0,maximum=0;preparations++;
 CHECK(vm_remap(mach_task_self(),&writable,(vm_size_t)size,0,VM_FLAGS_ANYWHERE,
                mach_task_self(),(vm_address_t)(uintptr_t)pointer,FALSE,&current,&maximum,VM_INHERIT_NONE)==KERN_SUCCESS);
 CHECK(vm_protect(mach_task_self(),writable,(vm_size_t)size,FALSE,VM_PROT_READ|VM_PROT_WRITE)==KERN_SUCCESS);
 for(size_t offset=0;offset<size;offset+=0x4000)((volatile unsigned char*)(uintptr_t)writable)[offset]=0x69;
 CHECK(vm_deallocate(mach_task_self(),writable,(vm_size_t)size)==KERN_SUCCESS);
 return pointer;
}
/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */
/* ACTUAL POLICY GETTERS INSERTED HERE */
int main(void){
 uint64_t rx=0,rw=0,base=0,bytes=0,object=0;uint32_t stage=0;int32_t error=0;
 jit_required_early_hold();
 CHECK(jit_required_pool.state==1&&jit_required_pool.size==((uint64_t)1152<<20));
 CHECK(jit_required_range(jit_required_pool.rx,jit_required_pool.size,251,VM_PROT_NONE,NULL));
 CHECK(jit_required_range(jit_required_pool.rw,jit_required_pool.size,252,VM_PROT_NONE,NULL));
 CHECK(!debug_allocations);
 if(!jit_required_pool_create((uint64_t)1152<<20,UINT64_C(0x140000000),UINT64_C(0x8000000),&rx,&rw,&stage,&error)){
  fprintf(stderr,"native full-pool transaction failed stage=%u Mach=%d\n",stage,error);return 1;
 }
 CHECK(stage==10&&error==0&&rx&&rw&&rx!=rw&&debug_allocations==1&&preparations==1);
 CHECK(jit_cs2_image_arena_mb()==768&&jit_cs2_code_tail_limit_mb()==384);
 CHECK(jit_required_range(rx,(uint64_t)1152<<20,-1,VM_PROT_READ|VM_PROT_EXECUTE,NULL));
 CHECK(jit_required_range(rw,(uint64_t)1152<<20,-1,VM_PROT_READ|VM_PROT_WRITE,NULL));
 for(uint64_t offset=0;offset<((uint64_t)1152<<20);offset+=0x4000)
  CHECK(*(volatile unsigned char*)(uintptr_t)(rw+offset)==0x69);
 CHECK(!jit_required_pool_release_early());
 if(jit_required_pool_fex_reservation(&base,&bytes,&object))CHECK(bytes==((uint64_t)8<<30)&&base>=UINT64_C(0x7c00000000));
 printf("PASS real Darwin Mach: full1152MiB RX=0x%llx RW=0x%llx; shared page markers, W^X, all73728 guarded ARM64 execution probes; partition768/384; StikDebug/iPhone unverified\n",(unsigned long long)rx,(unsigned long long)rw);
 /* Only owned fixture results are removed; production correctly refuses its
  * early-release API once a live pool is published. No guest executes here. */
 CHECK(vm_deallocate(mach_task_self(),(vm_address_t)rx,(vm_size_t)1152<<20)==KERN_SUCCESS);
 CHECK(vm_deallocate(mach_task_self(),(vm_address_t)rw,(vm_size_t)1152<<20)==KERN_SUCCESS);
 if(base)CHECK(vm_deallocate(mach_task_self(),(vm_address_t)base,(vm_size_t)bytes)==KERN_SUCCESS);
 return 0;
}
