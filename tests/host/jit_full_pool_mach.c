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
static unsigned native_prepare_zero;
static void jit_log(const char* format,...){(void)format;}
/* ACTUAL TASK MAP QUERY INSERTED HERE */
/* ACTUAL EXECUTION PROBE INSERTED HERE */
static uint64_t jit26_pool_capabilities(void){return native_prepare_zero?UINT64_C(0x4d4a5032):UINT64_C(0x4d4a5031);}
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
 for(size_t offset=0;offset<size;offset+=0x4000)((volatile unsigned char*)(uintptr_t)writable)[offset]=native_prepare_zero?0:0x69;
 CHECK(vm_deallocate(mach_task_self(),writable,(vm_size_t)size)==KERN_SUCCESS);
 return(void*)((uintptr_t)pointer|(native_prepare_zero?1u:0u));
}
/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */
/* ACTUAL POLICY GETTERS INSERTED HERE */
/* ACTUAL WINE RECEIPT PARSER INSERTED HERE */

static void native_failure_region(const char* label,uint64_t wanted){
 vm_address_t at=0;vm_size_t length=0;vm_region_submap_info_data_64_t info;
 kern_return_t kr=jit_required_region(wanted,&at,&length,&info);
 fprintf(stderr,"NATIVE_REGION %s wanted=0x%llx kr=%d at=0x%llx length=0x%llx prot=%d max=%d tag=%u object=%llu offset=0x%llx\n",
         label,(unsigned long long)wanted,kr,(unsigned long long)at,(unsigned long long)length,
         info.protection,info.max_protection,info.user_tag,(unsigned long long)info.object_id,(unsigned long long)info.offset);
}
static void native_fresh_probe(const char* label,int use_mach_write){
 vm_address_t fresh=0;const vm_size_t size=0x8000;
 kern_return_t kr=vm_allocate(mach_task_self(),&fresh,size,VM_FLAGS_ANYWHERE|VM_MAKE_TAG(251u));
 fprintf(stderr,"NATIVE_FRESH %s allocate=%d base=0x%llx bytes=0x8000\n",label,kr,(unsigned long long)fresh);
 if(kr!=KERN_SUCCESS)return;
 native_failure_region("before-page0",fresh);native_failure_region("before-page1",fresh+0x4000);
 if(use_mach_write){unsigned char zero=0;kr=vm_write(mach_task_self(),fresh,(vm_offset_t)(uintptr_t)&zero,1);
  fprintf(stderr,"NATIVE_FRESH %s vm-write-one=%d\n",label,kr);
 }else{
  vm_address_t at;vm_size_t length;vm_region_submap_info_data_64_t info;
  kr=jit_required_region(fresh,&at,&length,&info);
  if(kr==KERN_SUCCESS&&(uint64_t)at<=fresh&&(info.protection&VM_PROT_WRITE)){
   *(volatile unsigned char*)(uintptr_t)fresh=0;
   fprintf(stderr,"NATIVE_FRESH %s direct-store=completed\n",label);
  }else fprintf(stderr,"NATIVE_FRESH %s direct-store=refused-query-or-rights kr=%d\n",label,kr);
 }
 native_failure_region("after-page0",fresh);native_failure_region("after-page1",fresh+0x4000);
 /* This exact fresh range was obtained by this function's successful ANYWHERE
  * call and was never handed to any other owner or replacement operation. */
 kr=vm_deallocate(mach_task_self(),fresh,size);
 fprintf(stderr,"NATIVE_FRESH %s cleanup=%d\n",label,kr);
}
static void native_failure_diagnostics(void){
 uint64_t low=0,high=0;int measured=jit_task_map_range(&low,&high);
 fprintf(stderr,"NATIVE_HOLD_FAILURE measured=%d map=[0x%llx,0x%llx) vm-address-bytes=%zu vm-offset-bytes=%zu state=%u RX=0x%llx RW=0x%llx FEX=0x%llx RX-object=%llu RW-object=%llu FEX-object=%llu\n",
 measured,(unsigned long long)low,(unsigned long long)high,sizeof(vm_address_t),sizeof(vm_offset_t),jit_required_pool.state,
 (unsigned long long)jit_required_pool.rx,(unsigned long long)jit_required_pool.rw,(unsigned long long)jit_required_pool.fex,
 (unsigned long long)jit_required_pool.rx_object,(unsigned long long)jit_required_pool.rw_object,(unsigned long long)jit_required_pool.fex_object);
 native_failure_region("cpu-preference",UINT64_C(0x300000000));
 native_failure_region("host-start",UINT64_C(0x7c00000000));
 native_failure_region("host-upper",UINT64_C(0x7e00000000));
 if(!jit_required_pool.state){
  struct jit_required_pool local;int32_t error=0;
  int held=jit_required_hold(&local,(uint64_t)1152<<20,UINT64_C(0x140000000),UINT64_C(0x8000000),NULL,0,&error);
  fprintf(stderr,"NATIVE_RECHECK result=%d error=%d RX=0x%llx RW=0x%llx FEX=0x%llx\n",held,error,(unsigned long long)local.rx,(unsigned long long)local.rw,(unsigned long long)local.fex);
  if(held>0)fprintf(stderr,"NATIVE_RECHECK owned-cleanup=%d\n",jit_required_drop(&local));
  /* Failed/unknown ownership is never reclaimed by the fixture. Process exit
   * disposes its own task; an existing quarantined production group is untouched. */
 }
 native_fresh_probe("mach-vm-write",1);
 native_fresh_probe("separate-direct-store",0);
}

int main(int argc,char** argv){
 uint64_t rx=0,rw=0,base=0,bytes=0;const char* receipt=NULL;uint32_t stage=0;int32_t error=0;
 if(argc>1){CHECK(argc==2&&!strcmp(argv[1],"--mjp2-zero"));native_prepare_zero=1;}
 jit_required_early_hold();
 if(jit_required_pool.state!=1||jit_required_pool.size!=((uint64_t)1152<<20))native_failure_diagnostics();
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
  CHECK(*(volatile unsigned char*)(uintptr_t)(rw+offset)==(native_prepare_zero?0:0x69));
 CHECK(!jit_required_pool_release_early());
 if(jit_required_pool_fex_reservation(&base,&bytes,&receipt)){
  CHECK(bytes==((uint64_t)8<<30)&&base>=UINT64_C(0x7c00000000)&&receipt);
  CHECK(!setenv("WINE_IOS_FEX_EARLY_V2",receipt,1));
  struct ios_native_fex_receipt parsed;
  CHECK(ios_native_fex_hold_description(&parsed)&&parsed.base==base&&parsed.size==bytes&&parsed.count);
  CHECK(parsed.count<=IOS_NATIVE_FEX_RECEIPT_MAX);
 }
 printf("PASS real Darwin Mach: full1152MiB RX=0x%llx RW=0x%llx; shared page markers, W^X, all73728 guarded ARM64 execution probes; partition768/384; preparation=MJP%u marker=%02x; StikDebug/iPhone unverified\n",(unsigned long long)rx,(unsigned long long)rw,native_prepare_zero?2u:1u,native_prepare_zero?0u:0x69u);
 /* Only owned fixture results are removed; production correctly refuses its
  * early-release API once a live pool is published. No guest executes here. */
 CHECK(vm_deallocate(mach_task_self(),(vm_address_t)rx,(vm_size_t)1152<<20)==KERN_SUCCESS);
 CHECK(vm_deallocate(mach_task_self(),(vm_address_t)rw,(vm_size_t)1152<<20)==KERN_SUCCESS);
 if(base)CHECK(vm_deallocate(mach_task_self(),(vm_address_t)base,(vm_size_t)bytes)==KERN_SUCCESS);
 return 0;
}
