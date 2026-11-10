/* Kernel-boundary fixture for literal production placement functions.
 * The placement policy is inserted unchanged below. OS allocation/protection
 * calls use real shared mmap backing at controlled fixture addresses; the
 * region inventory and debugger responses are explicitly synthetic. */
#define _GNU_SOURCE 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line%d %s\n",__LINE__,#x);exit(1);}}while(0)
#define MB (UINT64_C(1)<<20)
#define GB (UINT64_C(1)<<30)
#define PAGE UINT64_C(0x4000)
#define FULL (UINT64_C(1152)<<20)
#define HOST UINT64_C(0x7c00000000)
#define CPU UINT64_C(0x1000000000)
#define LOW UINT64_C(0x119000000)
typedef uint64_t vm_address_t,vm_size_t,vm_offset_t;
typedef unsigned natural_t,mach_msg_type_number_t;
typedef int kern_return_t,vm_prot_t,boolean_t;
typedef int *vm_region_recurse_info_t;
typedef struct {unsigned user_tag;vm_prot_t protection,max_protection;unsigned is_submap;uint64_t object_id,offset;} vm_region_submap_info_data_64_t;
#define VM_REGION_SUBMAP_INFO_COUNT_64 8
#define KERN_SUCCESS 0
#define KERN_INVALID_ADDRESS 1
#define KERN_PROTECTION_FAILURE 2
#define KERN_NO_SPACE 3
#define KERN_INVALID_ARGUMENT 4
#define KERN_FAILURE 5
#define KERN_ABORTED 14
#define KERN_NOT_SUPPORTED 46
#define VM_PROT_NONE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_FLAGS_FIXED 0
#define VM_FLAGS_OVERWRITE 0x4000u
#define VM_MAKE_TAG(x) ((unsigned)(x)<<24)
#define VM_INHERIT_NONE 2
#define FALSE 0
struct region {uint64_t base,size,object;int fd,prot;unsigned tag,mapped,owned;};
static struct region regions[256];static unsigned count;static uint64_t serial=100;
static uint64_t map_min=0x100ab8000ULL,map_max=0x8000000000ULL;
static unsigned allocation_calls,debug_allocations,preparations,remaps,deallocations,executions,expected_debug=1,expected_preparations=1;
static int query_error,lose_first,remap_fail,protect_fail,missing_markers,wrong_return,bad_backing,cleanup_fail,cow_prepare,multi_objects,multi_active,fresh_zero,cap_supported=1;
static int prepare_blocks,cap_entered,cap_release,deep_submap,one_submap;
static pthread_mutex_t boundary_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t boundary_condition=PTHREAD_COND_INITIALIZER;
static uint64_t last_rx,last_rw;
static int mach_task_self(void){return 1;}
static void jit_log(const char* fmt,...){(void)fmt;}
static void sys_dcache_flush(void* p,size_t n){(void)p;(void)n;}
static void sys_icache_invalidate(void* p,size_t n){__builtin___clear_cache((char*)p,(char*)p+n);}
static bool jit_task_map_range(uint64_t* lo,uint64_t* hi){*lo=map_min;*hi=map_max;return true;}
static int backing(void){char path[]="/tmp/madeira-owned-jit-XXXXXX";int fd=mkstemp(path);CHECK(fd>=0);CHECK(!unlink(path));CHECK(!ftruncate(fd,FULL));return fd;}
static int index_at(uint64_t address){for(unsigned i=0;i<count;i++)if(address>=regions[i].base&&address-regions[i].base<regions[i].size)return (int)i;return -1;}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return a<b+m&&b<a+n;}
#ifdef __APPLE__
extern int test_darwin_fixed_reserve(uint64_t,uint64_t);
#endif
static int reserve_actual(uint64_t base,uint64_t size){
#ifdef __APPLE__
 return test_darwin_fixed_reserve(base,size);
#else
 void* p=mmap((void*)(uintptr_t)base,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 return p==MAP_FAILED?-1:((uint64_t)(uintptr_t)p==base?0:-1);
#endif
}
static void add_system(uint64_t base,uint64_t size){CHECK(count<256);regions[count++]=(struct region){base,size,++serial,-1,0,0,0,0};}
static int vm_allocate(int task,vm_address_t* address,vm_size_t size,int flags){
 CHECK(task==1&&size&&!(size&(PAGE-1))&&!((unsigned)flags&VM_FLAGS_OVERWRITE));allocation_calls++;
 pthread_mutex_lock(&boundary_mutex);
 for(unsigned i=0;i<count;i++)if(overlap(*address,size,regions[i].base,regions[i].size)){pthread_mutex_unlock(&boundary_mutex);return KERN_NO_SPACE;}
 if(lose_first){lose_first=0;CHECK(!reserve_actual(*address,PAGE));CHECK(count<256);
  regions[count++]=(struct region){*address,PAGE,++serial,-1,3,99,1,0};
  *(uint32_t*)(uintptr_t)*address=0x1234abcd;pthread_mutex_unlock(&boundary_mutex);return KERN_NO_SPACE;}
 if(reserve_actual(*address,size)){pthread_mutex_unlock(&boundary_mutex);return KERN_NO_SPACE;}
 CHECK(count<256);regions[count++]=(struct region){*address,size,fresh_zero?0:++serial,-1,3,(unsigned)flags>>24,1,1};
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_protect(int task,vm_address_t address,vm_size_t size,int maximum,int prot){
 CHECK(task==1&&!maximum);pthread_mutex_lock(&boundary_mutex);int i=index_at(address);
 CHECK(i>=0&&regions[i].base==address&&regions[i].size==size&&regions[i].owned);
 if(protect_fail&&prot==3){protect_fail--;pthread_mutex_unlock(&boundary_mutex);return KERN_PROTECTION_FAILURE;}
 CHECK(!mprotect((void*)(uintptr_t)address,size,prot));regions[i].prot=prot;
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_deallocate(int task,vm_address_t address,vm_size_t size){
 CHECK(task==1);pthread_mutex_lock(&boundary_mutex);int i=index_at(address);
 CHECK(i>=0&&regions[i].base==address&&regions[i].size==size&&regions[i].owned);
 if(cleanup_fail){pthread_mutex_unlock(&boundary_mutex);return KERN_FAILURE;}
 CHECK(!munmap((void*)(uintptr_t)address,size));if(regions[i].fd>=0)close(regions[i].fd);
 regions[i]=regions[--count];deallocations++;pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_region_recurse_64(int task,vm_address_t* address,vm_size_t* size,natural_t* depth,
 vm_region_recurse_info_t information,mach_msg_type_number_t* length){
 CHECK(task==1&&*length==VM_REGION_SUBMAP_INFO_COUNT_64);
 vm_region_submap_info_data_64_t* info=(void*)information;
 if(query_error)return query_error;
 if(deep_submap){*size=4*GB;info->is_submap=1;return 0;}
 if(one_submap){
  if(!*depth){*address=12*GB;*size=4*GB;info->is_submap=1;return 0;}
  if(*address>=14*GB)return KERN_INVALID_ADDRESS;
  *address=14*GB;*size=PAGE;info->protection=1;info->user_tag=77;info->object_id=22;return 0;
 }
 pthread_mutex_lock(&boundary_mutex);int best=-1;
 for(unsigned i=0;i<count;i++)if(regions[i].base+regions[i].size>*address&&(best<0||regions[i].base<regions[best].base))best=(int)i;
 if(best<0){pthread_mutex_unlock(&boundary_mutex);return KERN_INVALID_ADDRESS;}
 struct region r=regions[best];uint64_t requested=*address;*address=r.base;*size=r.size;
 *info=(vm_region_submap_info_data_64_t){r.tag,r.prot,7,0,r.object,0};
 if(multi_active&&(r.base==last_rx||r.base==last_rw)){
  uint64_t page=requested>r.base?(requested-r.base)/PAGE:0;
  *address=r.base+page*PAGE;*size=PAGE;info->object_id=r.object+page;info->offset=0;
 }
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_remap(int task,vm_address_t* address,vm_size_t size,uint64_t mask,int flags,
 int source_task,vm_address_t source,int copy,vm_prot_t* current,vm_prot_t* maximum,int inherit){
 CHECK(task==1&&source_task==1&&!mask&&!copy&&inherit==2&&((unsigned)flags&VM_FLAGS_OVERWRITE));
 /* Actual XNU user remap flags exclude VM_FLAGS_ALIAS_MASK. A tag is legal
  * for vm_allocate, not for vm_remap. Do not let a permissive stub hide this. */
 if((unsigned)flags&0xff000000u){puts("KERNEL_CONTROL rejected VM_FLAGS_ALIAS_MASK in vm_remap");return KERN_INVALID_ARGUMENT;}
 pthread_mutex_lock(&boundary_mutex);remaps++;int destination=index_at(*address),origin=index_at(source);
 CHECK(destination>=0&&origin>=0);struct region d=regions[destination],s=regions[origin];
 CHECK(d.owned&&d.base==*address&&d.size==size&&d.prot==0&&s.fd>=0&&s.base==source&&s.size==size);
 CHECK(d.tag==251||d.tag==252);
 if(d.tag==251)last_rx=*address;else last_rw=*address;
 if(!s.object){s.object=++serial;regions[origin].object=s.object;}
 if(remap_fail){if(remap_fail>0)remap_fail--;pthread_mutex_unlock(&boundary_mutex);return KERN_FAILURE;}
 int fd=bad_backing&&d.tag==252?backing():dup(s.fd);CHECK(fd>=0);
 void* mapped=mmap((void*)(uintptr_t)*address,size,s.prot,MAP_SHARED|MAP_FIXED,fd,0);
 CHECK(mapped==(void*)(uintptr_t)*address);
 regions[destination]=(struct region){*address,size,bad_backing&&d.tag==252?++serial:s.object,fd,s.prot,s.tag,1,1};
 *current=s.prot;*maximum=7;pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_write(int task,vm_address_t address,vm_offset_t input,mach_msg_type_number_t size){
 CHECK(task==1);int i=index_at(address);CHECK(i>=0&&regions[i].owned&&regions[i].prot==3);
 memcpy((void*)(uintptr_t)address,(const void*)(uintptr_t)input,size);if(!regions[i].object)regions[i].object=++serial;return 0;
}
static int vm_read_overwrite(int task,vm_address_t address,vm_size_t size,vm_address_t out,vm_size_t* copied){
 CHECK(task==1);memcpy((void*)(uintptr_t)out,(void*)(uintptr_t)address,size);*copied=size;return 0;
}
static uint64_t jit26_pool_capabilities(void){
 pthread_mutex_lock(&boundary_mutex);
 if(prepare_blocks){cap_entered=1;pthread_cond_broadcast(&boundary_condition);while(!cap_release)pthread_cond_wait(&boundary_condition,&boundary_mutex);}
 pthread_mutex_unlock(&boundary_mutex);return cap_supported?0x4d4a5031ULL:0;
}
static void* jit26_pool_allocate(size_t size){
 CHECK(size==FULL);debug_allocations++;
 uint64_t target=map_max>CPU?0x7000000000ULL:(12*GB+2*FULL);
 pthread_mutex_lock(&boundary_mutex);for(unsigned i=0;i<count;i++)CHECK(!overlap(target,size,regions[i].base,regions[i].size));
 CHECK(!reserve_actual(target,size));int fd=backing();
 CHECK(mmap((void*)(uintptr_t)target,size,5,MAP_SHARED|MAP_FIXED,fd,0)==(void*)(uintptr_t)target);
 CHECK(count<256);regions[count++]=(struct region){target,size,++serial,fd,5,42,1,1};
 pthread_mutex_unlock(&boundary_mutex);return(void*)(uintptr_t)target;
}
static void* jit26_pool_prepare(void* pointer,size_t size){
 CHECK(size==FULL);preparations++;if(wrong_return)return(void*)((uintptr_t)pointer+PAGE);
 if(missing_markers==1)return pointer;
 pthread_mutex_lock(&boundary_mutex);int i=index_at((uint64_t)(uintptr_t)pointer);CHECK(i>=0&&regions[i].prot==5&&regions[i].fd>=0);
 if(cow_prepare){
  int previous=regions[i].fd, replacement=backing();
  CHECK(mmap(pointer,size,5,MAP_SHARED|MAP_FIXED,replacement,0)==pointer);
  regions[i].fd=replacement;regions[i].object=++serial;close(previous);
 }
 int fd=regions[i].fd;void* write=mmap(NULL,size,3,MAP_SHARED,fd,0);CHECK(write!=MAP_FAILED);
 uint64_t end=missing_markers==2?PAGE:size;
 for(uint64_t offset=0;offset<end;offset+=PAGE)((unsigned char*)write)[offset]=0x69;
 CHECK(!munmap(write,size));if(multi_objects)multi_active=1;pthread_mutex_unlock(&boundary_mutex);return pointer;
}
/* Linux's x86 kernel cannot execute ARM64 code. Actual ARM64 guarded execution
 * is compiled unchanged in the separate real Mach integration on Apple CI. */
static int jit_required_execute_pages(uint64_t rx,uint64_t rw,uint64_t size){
 CHECK(rx&&rw&&size==FULL);executions++;return 1;
}

/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */

static void clear_all(void){
 for(unsigned i=0;i<count;i++){if(regions[i].mapped)CHECK(!munmap((void*)(uintptr_t)regions[i].base,regions[i].size));if(regions[i].fd>=0)close(regions[i].fd);}
 count=0;madeira_early_pool_base=madeira_early_pool_size=jit_legacy_pool_object=jit_legacy_pool_state=0;free(jit_required_pool.rx_snapshot);free(jit_required_pool.rw_snapshot);memset(&jit_required_pool,0,sizeof(jit_required_pool));
 allocation_calls=debug_allocations=preparations=remaps=deallocations=executions=0;expected_debug=1;expected_preparations=1;
 query_error=lose_first=remap_fail=protect_fail=missing_markers=wrong_return=bad_backing=cleanup_fail=cow_prepare=multi_objects=multi_active=fresh_zero=0;last_rx=last_rw=0;
 prepare_blocks=cap_entered=cap_release=deep_submap=one_submap=0;cap_supported=1;
}
static void setup(int high){
 clear_all();map_max=high?0x8000000000ULL:0xfc0000000ULL;
 if(high){
  const uint64_t bases[]={0x11da5c000ULL,0x123000000ULL,0x12ac00000ULL,0x148000000ULL,0x16f834000ULL};
  const uint64_t lengths[]={78*MB,74*MB,340*MB,0x16f248000ULL-0x148000000ULL,263*MB};
  uint64_t cursor=LOW;for(unsigned i=0;i<5;i++){if(bases[i]>cursor)add_system(cursor,bases[i]-cursor);cursor=bases[i]+lengths[i];}
  /* Above the captured low holes this is a conservative SYNTHETIC occupied
   * region, not a claim about the missing device's full Mach inventory. */
  add_system(cursor,0x7000000000ULL-cursor);
 }else{
  add_system(LOW,12*GB-LOW);add_system(16*GB,map_max-16*GB);
 }
}
static void legacy_setup(void){
 setup(1);vm_address_t address=0x148000000ULL;uint8_t zero=0;
 CHECK(vm_allocate(1,&address,624*MB,VM_FLAGS_FIXED|VM_MAKE_TAG(250u))==KERN_SUCCESS);
 CHECK(vm_write(1,address,(vm_offset_t)(uintptr_t)&zero,1)==KERN_SUCCESS);
 CHECK(jit_required_capture(address,624*MB,250,3,&jit_legacy_pool_object)&&jit_legacy_pool_object);
 CHECK(vm_protect(1,address,624*MB,0,0)==KERN_SUCCESS);
 madeira_early_pool_base=address;madeira_early_pool_size=624*MB;jit_legacy_pool_state=1;
}
static unsigned owned_count(void){unsigned result=0;for(unsigned i=0;i<count;i++)result+=regions[i].owned;return result;}
static int create(uint64_t* rx,uint64_t* rw,uint32_t* stage,int32_t* error){return jit_required_pool_create(FULL,0x140000000ULL,128*MB,rx,rw,stage,error);}
static void successful(int high){
 uint64_t rx=0,rw=0,fex=0,fex_size=0,fex_object=0;uint32_t stage=0;int32_t error=0;
 CHECK(create(&rx,&rw,&stage,&error));CHECK(stage==10&&!error&&jit_required_pool.state==3);
 CHECK(rx!=rw&&jit_required_pool.size==FULL&&debug_allocations==expected_debug&&preparations==expected_preparations&&executions==1);
 CHECK(jit_required_range(rx,FULL,-1,5,NULL)&&jit_required_range(rw,FULL,-1,3,NULL));
 CHECK(!jit_required_pool_release_early());
 if(high){CHECK(rx>=HOST&&rw>=HOST);CHECK(jit_required_pool_fex_reservation(&fex,&fex_size,&fex_object));CHECK(fex_size==8*GB&&fex>=HOST);
  CHECK(!overlap(rx,FULL,fex,fex_size)&&!overlap(rw,FULL,fex,fex_size));CHECK(owned_count()==3);
 }else{CHECK(rx==12*GB&&rw==12*GB+FULL);CHECK(!jit_required_pool_fex_reservation(&fex,&fex_size,&fex_object));CHECK(owned_count()==2);}
 for(uint64_t offset=0;offset<FULL;offset+=PAGE)CHECK(*(unsigned char*)(uintptr_t)(rw+offset)==0x69);
 CHECK(*(uint32_t*)(uintptr_t)(rw+4)==0&&*(uint32_t*)(uintptr_t)(rw+FULL-4)==0);
 uint64_t second_rx=1,second_rw=1;CHECK(!create(&second_rx,&second_rw,&stage,&error));CHECK(!second_rx&&!second_rw&&stage==11&&debug_allocations==expected_debug);
}
static void* creator_thread(void* value){uint64_t rx,rw;uint32_t stage;int32_t error;*(int*)value=create(&rx,&rw,&stage,&error);return NULL;}
int main(void){
 uint64_t rx,rw;uint32_t stage;int32_t error;
 setup(0);jit_required_early_hold();CHECK(jit_required_pool.state==1&&owned_count()==2);CHECK(!debug_allocations);
 successful(0);puts("PASS literal production legacy63GiB placement: full1152MiB paired early holds; shared RX/RW; published range cannot be released/reallocated");
 setup(1);jit_required_early_hold();CHECK(jit_required_pool.state==1&&jit_required_pool.rx==HOST&&owned_count()==3);
 cap_supported=0;CHECK(!create(&rx,&rw,&stage,&error));CHECK(stage==1&&error==KERN_NOT_SUPPORTED&&!debug_allocations&&jit_required_pool.state==1&&owned_count()==3);
 cap_supported=1;successful(1);puts("PASS literal production iOS27-shaped low fragmentation: both full aliases plus8GiB FEX held before debugger; old protocol rejected without allocating");
 setup(1);jit_required_early_hold();CHECK(jit_required_pool_release_early());CHECK(!owned_count()&&!jit_required_pool.state&&!debug_allocations);
 CHECK(jit_required_pool_release_early());puts("PASS early holds released exactly once for legacy non-CS2 launch");
 setup(1);lose_first=1;jit_required_early_hold();CHECK(jit_required_pool.state==1&&jit_required_pool.rx==HOST+16*MB);
 CHECK(*(uint32_t*)(uintptr_t)HOST==0x1234abcd);successful(1);CHECK(*(uint32_t*)(uintptr_t)HOST==0x1234abcd);
 puts("PASS a concurrent kernel placement collision chooses another aligned range and preserves foreign bytes");
 setup(1);jit_required_early_hold();uint64_t original_rx=jit_required_pool.rx;
 remap_fail=1;expected_debug=2;successful(1);CHECK(jit_required_pool.rx!=original_rx);
 puts("PASS failed first remap cleans all owned aliases/backing/FEX and retries a distinct complete pair");
 setup(1);jit_required_early_hold();protect_fail=1;expected_debug=2;expected_preparations=2;successful(1);
 puts("PASS RW protect failure cleans its genuine temporary RX state before safe retry");
 setup(1);jit_required_early_hold();cow_prepare=1;successful(1);
 puts("PASS debugger preparation may COW the final RX object; RW is created afterwards and shares the genuinely prepared object");

 setup(1);jit_required_early_hold();cow_prepare=1;multi_objects=1;successful(1);
 puts("PASS all73728 per-page COW object/offset snapshots are retained through remap/protection and released after publication");
 setup(1);fresh_zero=1;jit_required_early_hold();CHECK(jit_required_pool.rx_object&&jit_required_pool.rw_object&&jit_required_pool.fex_object);
 successful(1);puts("PASS initially objectless holds acquire nonzero ownership identities from only their first zero-written page");

 for(int mode=0;mode<4;mode++){
  setup(1);jit_required_early_hold();
  if(mode==0)remap_fail=-1;if(mode==1)missing_markers=1;if(mode==2)missing_markers=2;if(mode==3)wrong_return=1;
  CHECK(!create(&rx,&rw,&stage,&error));CHECK(!rx&&!rw&&!owned_count()&&!jit_required_pool.state&&debug_allocations==3);
 }
 puts("PASS persistent remap failure, opaque-helper false OK, partial page preparation and wrong prepare return never publish; three attempts release all proven ownership");
 setup(1);jit_required_early_hold();bad_backing=1;CHECK(!create(&rx,&rw,&stage,&error));CHECK(!owned_count()&&!jit_required_pool.state);
 puts("PASS real different shared backing is rejected by actual per-page/alias readback");
 setup(1);query_error=KERN_FAILURE;CHECK(!create(&rx,&rw,&stage,&error));CHECK(!owned_count()&&!allocation_calls&&!debug_allocations);
 puts("PASS a Mach query error is not treated as a free trailing gap");
 setup(1);add_system(HOST,16*GB);CHECK(!create(&rx,&rw,&stage,&error));CHECK(!owned_count()&&!debug_allocations);
 puts("PASS genuinely exhausted safe host bands return failure without guest/GPU allocation");
 setup(1);jit_required_early_hold();uint64_t foreign=jit_required_pool.rx;int ix=index_at(foreign);CHECK(ix>=0);
 CHECK(!mprotect((void*)(uintptr_t)foreign,PAGE,3));regions[ix].prot=3;regions[ix].tag=99;regions[ix].owned=0;
 *(uint32_t*)(uintptr_t)foreign=0x87654321;CHECK(!create(&rx,&rw,&stage,&error));
 CHECK(stage==9&&jit_required_pool.state==4&&!owned_count()&&*(uint32_t*)(uintptr_t)foreign==0x87654321);
 CHECK(!create(&rx,&rw,&stage,&error)&&stage==11&&!debug_allocations);
 puts("PASS a replaced/foreign reservation is never overwritten or deallocated; it quarantines reuse and preserves unrelated bytes");

 setup(1);jit_required_early_hold();foreign=jit_required_pool.rx;ix=index_at(foreign);CHECK(ix>=0);
 regions[ix].object=++serial;regions[ix].owned=0; /* A foreign reallocation reused the same public tag/protection. */
 CHECK(!create(&rx,&rw,&stage,&error));CHECK(stage==9&&jit_required_pool.state==4&&!debug_allocations&&!owned_count());
 puts("PASS same-tag/protection ABA cannot authorize overwriting or cleanup of a foreign VM object");

 setup(1);jit_required_early_hold();cleanup_fail=1;CHECK(!jit_required_pool_release_early());CHECK(jit_required_pool.state==4);
 CHECK(!create(&rx,&rw,&stage,&error)&&stage==11&&!debug_allocations);
 puts("PASS failed ownership cleanup reports quarantine and cannot allocate another pool");
 setup(1);vm_address_t at;vm_size_t length;vm_region_submap_info_data_64_t info;
 one_submap=1;CHECK(jit_required_region(12*GB,&at,&length,&info)==KERN_SUCCESS&&at==14*GB&&info.user_tag==77&&!info.is_submap);
 CHECK(jit_required_region(14*GB+PAGE,&at,&length,&info)==KERN_SUCCESS&&at==14*GB+PAGE&&length==2*GB-PAGE&&info.protection==0);
 one_submap=0;deep_submap=1;CHECK(jit_required_region(12*GB,&at,&length,&info)==KERN_FAILURE);deep_submap=0;
 CHECK(!jit_required_allowed(64*GB,FULL,map_min,map_max,0,0));CHECK(!jit_required_allowed(448*GB,FULL,map_min,map_max,0,0));
 CHECK(!jit_required_allowed(495*GB,FULL,map_min,map_max,0,0));CHECK(jit_required_allowed(HOST,FULL,map_min,map_max,0,0));
 CHECK(!jit_required_allowed(UINT64_MAX-PAGE,FULL,map_min,map_max,0,0));
 for(unsigned bits=6;bits<9;bits++)CHECK(!jit_required_allowed(20*GB,FULL,map_min,(UINT64_C(1)<<bits)*GB,0,0));
 puts("PASS recursive leaf inspection, conservative exhausted submaps, recursion bound, alignment/overflow and guest/GPU exclusions");
 setup(1);jit_required_early_hold();prepare_blocks=1;int first_result=0;pthread_t thread;CHECK(!pthread_create(&thread,NULL,creator_thread,&first_result));
 pthread_mutex_lock(&boundary_mutex);while(!cap_entered)pthread_cond_wait(&boundary_condition,&boundary_mutex);pthread_mutex_unlock(&boundary_mutex);
 CHECK(!pthread_mutex_trylock(&jit_required_mutex));pthread_mutex_unlock(&jit_required_mutex);
 CHECK(!create(&rx,&rw,&stage,&error)&&stage==11&&!debug_allocations);
 pthread_mutex_lock(&boundary_mutex);cap_release=1;pthread_cond_broadcast(&boundary_condition);pthread_mutex_unlock(&boundary_mutex);
 CHECK(!pthread_join(thread,NULL)&&first_result&&jit_required_pool.state==3&&debug_allocations==1&&owned_count()==3);
 puts("PASS concurrent requests publish one pool, reject the second, and hold no placement mutex across debugger service");

 legacy_setup();CHECK(jit_legacy_pool_release_owned(&error)&&!error&&jit_legacy_pool_state==2&&!owned_count());
 vm_address_t reused=0x148000000ULL;CHECK(vm_allocate(1,&reused,PAGE,VM_FLAGS_FIXED|VM_MAKE_TAG(99u))==KERN_SUCCESS);
 ix=index_at(reused);CHECK(ix>=0);regions[ix].owned=0;*(uint32_t*)(uintptr_t)reused=0x90abcdef;
 unsigned old_deallocations=deallocations;CHECK(jit_legacy_pool_release_owned(&error)&&!error&&deallocations==old_deallocations);
 CHECK(*(uint32_t*)(uintptr_t)reused==0x90abcdef);
 legacy_setup();foreign=madeira_early_pool_base;ix=index_at(foreign);CHECK(ix>=0);
 regions[ix].owned=0;regions[ix].object=++serial;
 CHECK(!jit_legacy_pool_release_owned(&error)&&error==KERN_INVALID_ADDRESS&&!deallocations);
 CHECK(!jit_legacy_pool_release_owned(&error)&&!deallocations);
 puts("PASS actual legacy624MiB release: nonzero kernel identity, exact once-only cleanup, same-tag foreign ABA refusal and preserved later allocation");
 clear_all();return 0;
}
