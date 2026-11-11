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
/* XNU vm_map_enter chunks large anonymous allocations at ANON_CHUNK_SIZE.
 * Each leaf starts without an object; touching one leaf cannot bind its peers.
 * file_offset is only our POSIX backing boundary, offset is Mach object offset. */
#define ANON_CHUNK (UINT64_C(128)<<20)
struct region {uint64_t base,size,object,offset,file_offset,group;int fd,prot;unsigned tag,mapped,owned;};
static struct region regions[512];static unsigned count;static uint64_t serial=100,group_serial;
static uint64_t map_min=0x100ab8000ULL,map_max=0x8000000000ULL;
static unsigned allocation_calls,debug_allocations,preparations,remaps,deallocations,executions,expected_debug=1,expected_preparations=1,materialized_leaves;
static int query_error,lose_first,remap_fail,protect_fail,missing_markers,wrong_return,bad_backing,cleanup_fail,cow_prepare,multi_objects,multi_active,fresh_zero,cap_supported=1;
static unsigned cap_version=1,prepare_zero,prepare_tag,prepared_pages,execution_pages_checked;
static int execution_refused,left_breakpoint;
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
static void add_system(uint64_t base,uint64_t size){CHECK(count<512);regions[count++]=(struct region){.base=base,.size=size,.object=++serial,.fd=-1};}
static void append_chunks(uint64_t base,uint64_t size,unsigned tag,int prot,int fd,uint64_t group){
 for(uint64_t offset=0;offset<size;offset+=ANON_CHUNK){
  uint64_t length=size-offset<ANON_CHUNK?size-offset:ANON_CHUNK;CHECK(count<512);
  regions[count++]=(struct region){.base=base+offset,.size=length,.file_offset=offset,.group=group,
    .fd=fd<0?-1:dup(fd),.prot=prot,.tag=tag,.mapped=1,.owned=1};
 }
}
static int span_owned(uint64_t base,uint64_t size,int prot){
 uint64_t cursor=base,end=base+size;if(!size||end<base)return 0;
 while(cursor<end){int i=index_at(cursor);if(i<0||regions[i].base!=cursor||!regions[i].owned||
   regions[i].size>end-cursor||(prot>=0&&regions[i].prot!=prot))return 0;cursor+=regions[i].size;}
 return cursor==end;
}
static void erase_span(uint64_t base,uint64_t size){
 for(unsigned i=0;i<count;){if(regions[i].base>=base&&regions[i].base-base<size){
   if(regions[i].fd>=0)CHECK(!close(regions[i].fd));regions[i]=regions[--count];
  }else i++;}
}
static int vm_allocate(int task,vm_address_t* address,vm_size_t size,int flags){
 CHECK(task==1&&size&&!(size&(PAGE-1))&&!((unsigned)flags&VM_FLAGS_OVERWRITE));allocation_calls++;
 pthread_mutex_lock(&boundary_mutex);
 for(unsigned i=0;i<count;i++)if(overlap(*address,size,regions[i].base,regions[i].size)){pthread_mutex_unlock(&boundary_mutex);return KERN_NO_SPACE;}
 if(lose_first){lose_first=0;CHECK(!reserve_actual(*address,PAGE));CHECK(count<512);
  regions[count++]=(struct region){.base=*address,.size=PAGE,.object=++serial,.fd=-1,.prot=3,.tag=99,.mapped=1};
  *(uint32_t*)(uintptr_t)*address=0x1234abcd;pthread_mutex_unlock(&boundary_mutex);return KERN_NO_SPACE;}
 if(reserve_actual(*address,size)){pthread_mutex_unlock(&boundary_mutex);return KERN_NO_SPACE;}
 append_chunks(*address,size,(unsigned)flags>>24,3,-1,++group_serial);
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_protect(int task,vm_address_t address,vm_size_t size,int maximum,int prot){
 CHECK(task==1&&!maximum);pthread_mutex_lock(&boundary_mutex);CHECK(span_owned(address,size,-1));
 if(protect_fail&&prot==3){protect_fail--;pthread_mutex_unlock(&boundary_mutex);return KERN_PROTECTION_FAILURE;}
 CHECK(!mprotect((void*)(uintptr_t)address,size,prot));
 for(unsigned i=0;i<count;i++)if(regions[i].base>=address&&regions[i].base-address<size)regions[i].prot=prot;
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_deallocate(int task,vm_address_t address,vm_size_t size){
 CHECK(task==1);pthread_mutex_lock(&boundary_mutex);CHECK(span_owned(address,size,-1));
 if(cleanup_fail){pthread_mutex_unlock(&boundary_mutex);return KERN_FAILURE;}
 CHECK(!munmap((void*)(uintptr_t)address,size));erase_span(address,size);
 deallocations++;pthread_mutex_unlock(&boundary_mutex);return 0;
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
 *info=(vm_region_submap_info_data_64_t){r.tag,r.prot,7,0,r.object,r.offset};
 if(multi_active&&((r.base>=last_rx&&r.base-last_rx<FULL)||(r.base>=last_rw&&r.base-last_rw<FULL))){
  uint64_t page=requested>r.base?(requested-r.base)/PAGE:0;
  *address=r.base+page*PAGE;*size=PAGE;info->object_id=r.object*100000+page;info->offset=0;
 }
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_remap(int task,vm_address_t* address,vm_size_t size,uint64_t mask,int flags,
 int source_task,vm_address_t source,int copy,vm_prot_t* current,vm_prot_t* maximum,int inherit){
 CHECK(task==1&&source_task==1&&!mask&&!copy&&inherit==2&&((unsigned)flags&VM_FLAGS_OVERWRITE));
 if((unsigned)flags&0xff000000u){puts("KERNEL_CONTROL rejected VM_FLAGS_ALIAS_MASK in vm_remap");return KERN_INVALID_ARGUMENT;}
 pthread_mutex_lock(&boundary_mutex);remaps++;int destination=index_at(*address),origin=index_at(source);
 CHECK(destination>=0&&origin>=0&&span_owned(*address,size,0)&&span_owned(source,size,-1));
 struct region d=regions[destination],source_leaves[512];unsigned source_count=0;
 CHECK(d.tag==251||d.tag==252);if(d.tag==251)last_rx=*address;else last_rw=*address;
 if(remap_fail){if(remap_fail>0)remap_fail--;pthread_mutex_unlock(&boundary_mutex);return KERN_FAILURE;}
 for(uint64_t cursor=source;cursor-source<size;){int i=index_at(cursor);CHECK(i>=0&&regions[i].fd>=0);
  if(!regions[i].object)regions[i].object=++serial;
  source_leaves[source_count++]=regions[i];cursor+=regions[i].size;}
 int replacement=bad_backing&&d.tag==252?backing():-1;
 for(unsigned j=0;j<source_count;j++){struct region leaf=source_leaves[j];
  uint64_t target=*address+leaf.base-source;int fd=replacement>=0?replacement:leaf.fd;
  CHECK(mmap((void*)(uintptr_t)target,leaf.size,leaf.prot,MAP_SHARED|MAP_FIXED,fd,leaf.file_offset)==(void*)(uintptr_t)target);
 }
 erase_span(*address,size);
 for(unsigned j=0;j<source_count;j++){struct region leaf=source_leaves[j];CHECK(count<512);
  leaf.base=*address+leaf.base-source;leaf.group=d.group;leaf.fd=dup(replacement>=0?replacement:leaf.fd);CHECK(leaf.fd>=0);
  if(replacement>=0)leaf.object=++serial;regions[count++]=leaf;
 }
 if(replacement>=0)CHECK(!close(replacement));*current=source_leaves[0].prot;*maximum=7;
 pthread_mutex_unlock(&boundary_mutex);return 0;
}
static int vm_write(int task,vm_address_t address,vm_offset_t input,mach_msg_type_number_t size){
 CHECK(task==1);int i=index_at(address);CHECK(i>=0&&regions[i].owned&&regions[i].prot==3&&size<=regions[i].size-(address-regions[i].base));
 memcpy((void*)(uintptr_t)address,(const void*)(uintptr_t)input,size);
 if(!regions[i].object){regions[i].object=++serial;materialized_leaves++;}return 0;
}
static int vm_read_overwrite(int task,vm_address_t address,vm_size_t size,vm_address_t out,vm_size_t* copied){
 CHECK(task==1);memcpy((void*)(uintptr_t)out,(void*)(uintptr_t)address,size);*copied=size;return 0;
}
static uint64_t jit26_pool_capabilities(void){
 pthread_mutex_lock(&boundary_mutex);
 if(prepare_blocks){cap_entered=1;pthread_cond_broadcast(&boundary_condition);while(!cap_release)pthread_cond_wait(&boundary_condition,&boundary_mutex);}
 pthread_mutex_unlock(&boundary_mutex);return cap_supported?0x4d4a5030ULL+cap_version:0;
}
static void* jit26_pool_allocate(size_t size){
 CHECK(size==FULL);debug_allocations++;
 uint64_t target=map_max>CPU?0x7000000000ULL:(12*GB+2*FULL);
 pthread_mutex_lock(&boundary_mutex);for(unsigned i=0;i<count;i++)CHECK(!overlap(target,size,regions[i].base,regions[i].size));
 CHECK(!reserve_actual(target,size));int fd=backing();
 CHECK(mmap((void*)(uintptr_t)target,size,5,MAP_SHARED|MAP_FIXED,fd,0)==(void*)(uintptr_t)target);
 append_chunks(target,size,42,5,fd,++group_serial);CHECK(!close(fd));
 pthread_mutex_unlock(&boundary_mutex);return(void*)(uintptr_t)target;
}
static void* jit26_pool_prepare(void* pointer,size_t size){
 CHECK(size==FULL);preparations++;if(wrong_return)return(void*)((uintptr_t)pointer+PAGE);
 if(missing_markers==1)return(void*)((uintptr_t)pointer|prepare_tag);
 pthread_mutex_lock(&boundary_mutex);int i=index_at((uint64_t)(uintptr_t)pointer);CHECK(i>=0&&regions[i].prot==5&&regions[i].fd>=0);
 uint64_t group=regions[i].group;int fd=dup(regions[i].fd);CHECK(fd>=0);
 if(cow_prepare){CHECK(!close(fd));fd=backing();CHECK(mmap(pointer,size,5,MAP_SHARED|MAP_FIXED,fd,0)==pointer);
  for(unsigned j=0;j<count;j++)if(regions[j].group==group){CHECK(!close(regions[j].fd));regions[j].fd=dup(fd);CHECK(regions[j].fd>=0);regions[j].object=++serial;}
 }
 void* write=mmap(NULL,size,3,MAP_SHARED,fd,0);CHECK(write!=MAP_FAILED);
 uint64_t end=missing_markers==2?PAGE:size;
 for(uint64_t offset=0;offset<end;offset+=PAGE)((unsigned char*)write)[offset]=prepare_zero?0:0x69;
 if(left_breakpoint)((uint32_t*)((unsigned char*)write+size-PAGE))[0]=UINT32_C(0xd4200000);
 prepared_pages=(unsigned)(end/PAGE);
 for(unsigned j=0;j<count;j++)if(regions[j].group==group&&!regions[j].object&&regions[j].base-(uint64_t)(uintptr_t)pointer<end)regions[j].object=++serial;
 CHECK(!munmap(write,size));CHECK(!close(fd));if(multi_objects)multi_active=1;pthread_mutex_unlock(&boundary_mutex);return(void*)((uintptr_t)pointer|prepare_tag);
}
/* Linux's x86 kernel cannot execute ARM64 code. Actual ARM64 guarded execution
 * is compiled unchanged in the separate real Mach integration on Apple CI. */
static int jit_required_execute_pages(uint64_t rx,uint64_t rw,uint64_t size){
 CHECK(rx&&rw&&size==FULL);executions++;
 /* This is the explicit host permission boundary, not an ARM64 emulator.
  * Fresh zero bytes alone cannot stand in for per-page execute permission. */
 for(unsigned page=0;page<FULL/PAGE;page++){
  execution_pages_checked++;
  if(execution_refused||page>=prepared_pages)return 0;
 }
 return 1;
}

/* ACTUAL PRODUCTION PLACEMENT INSERTED HERE */

static void clear_all(void){
 for(unsigned i=0;i<count;i++){if(regions[i].mapped)CHECK(!munmap((void*)(uintptr_t)regions[i].base,regions[i].size));if(regions[i].fd>=0)close(regions[i].fd);}
 count=0;madeira_early_pool_base=madeira_early_pool_size=jit_legacy_pool_object=jit_legacy_pool_state=0;jit_required_snapshot_free(jit_legacy_pool_snapshot);jit_legacy_pool_snapshot=NULL;jit_required_snapshot_free(jit_required_pool.rx_snapshot);jit_required_snapshot_free(jit_required_pool.rw_snapshot);jit_required_snapshot_free(jit_required_pool.fex_snapshot);jit_required_snapshot_free(jit_required_pool.temporary_snapshot);memset(&jit_required_pool,0,sizeof(jit_required_pool));
 allocation_calls=debug_allocations=preparations=remaps=deallocations=executions=materialized_leaves=0;expected_debug=1;expected_preparations=1;
 query_error=lose_first=remap_fail=protect_fail=missing_markers=wrong_return=bad_backing=cleanup_fail=cow_prepare=multi_objects=multi_active=fresh_zero=0;last_rx=last_rw=0;
 prepare_blocks=cap_entered=cap_release=deep_submap=one_submap=0;cap_supported=1;
 cap_version=1;prepare_zero=prepare_tag=prepared_pages=execution_pages_checked=0;execution_refused=left_breakpoint=0;
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
 (void)zero;jit_legacy_pool_snapshot=jit_required_early_snapshot(250);
 CHECK(jit_required_snapshot_fill(address,624*MB,250,3,1,jit_legacy_pool_snapshot));
 CHECK(jit_legacy_pool_snapshot->count==5&&materialized_leaves==5);
 jit_legacy_pool_object=jit_legacy_pool_snapshot->entries[0].object;CHECK(jit_legacy_pool_object);
 CHECK(vm_protect(1,address,624*MB,0,0)==KERN_SUCCESS);
 CHECK(jit_required_snapshot_matches(address,624*MB,250,0,jit_legacy_pool_snapshot));
 madeira_early_pool_base=address;madeira_early_pool_size=624*MB;jit_legacy_pool_state=1;
}
static unsigned owned_count(void){unsigned result=0;
 for(unsigned i=0;i<count;i++)if(regions[i].owned){unsigned j;
  for(j=0;j<i;j++)if(regions[j].owned&&regions[j].group==regions[i].group)break;
  if(j==i)result++;
 }return result;
}
static int create(uint64_t* rx,uint64_t* rw,uint32_t* stage,int32_t* error){return jit_required_pool_create(FULL,0x140000000ULL,128*MB,rx,rw,stage,error);}
static void successful(int high){
 uint64_t rx=0,rw=0,fex=0,fex_size=0;const char* fex_receipt=NULL;uint32_t stage=0;int32_t error=0;
 CHECK(create(&rx,&rw,&stage,&error));CHECK(stage==10&&!error&&jit_required_pool.state==3);
 CHECK(rx!=rw&&jit_required_pool.size==FULL&&debug_allocations==expected_debug&&preparations==expected_preparations&&executions==1);
 CHECK(jit_required_range(rx,FULL,-1,5,NULL)&&jit_required_range(rw,FULL,-1,3,NULL));
 CHECK(!jit_required_pool_release_early());
 if(high){CHECK(rx>=HOST&&rw>=HOST);CHECK(jit_required_pool_fex_reservation(&fex,&fex_size,&fex_receipt));CHECK(fex_size==8*GB&&fex>=HOST&&fex_receipt&&strlen(fex_receipt)<16384);
  unsigned version,leaves;unsigned long long receipt_base,receipt_size;
  CHECK(sscanf(fex_receipt,"%u:%llx:%llx:%x",&version,&receipt_base,&receipt_size,&leaves)==4);
  CHECK(version==2&&receipt_base==fex&&receipt_size==8*GB&&leaves==64);
  CHECK(!overlap(rx,FULL,fex,fex_size)&&!overlap(rw,FULL,fex,fex_size));CHECK(owned_count()==3);
 }else{CHECK(rx==12*GB&&rw==12*GB+FULL);CHECK(!jit_required_pool_fex_reservation(&fex,&fex_size,&fex_receipt));CHECK(owned_count()==2);}
 for(uint64_t offset=0;offset<FULL;offset+=PAGE)CHECK(*(unsigned char*)(uintptr_t)(rw+offset)==(prepare_zero?0:0x69));
 CHECK(jit_required_pool.prepare_marker==(prepare_zero?0:0x69)&&execution_pages_checked==FULL/PAGE);
 CHECK(*(uint32_t*)(uintptr_t)(rw+4)==0&&*(uint32_t*)(uintptr_t)(rw+FULL-4)==0);
 uint64_t second_rx=1,second_rw=1;CHECK(!create(&second_rx,&second_rw,&stage,&error));CHECK(!second_rx&&!second_rw&&stage==11&&debug_allocations==expected_debug);
}
static void* creator_thread(void* value){uint64_t rx,rw;uint32_t stage;int32_t error;*(int*)value=create(&rx,&rw,&stage,&error);return NULL;}
int main(void){
 uint64_t rx,rw;uint32_t stage;int32_t error;
 setup(0);jit_required_early_hold();CHECK(jit_required_pool.state==1&&owned_count()==2);CHECK(!debug_allocations&&materialized_leaves==18);
 successful(0);puts("PASS literal production legacy63GiB placement: full1152MiB paired early holds; shared RX/RW; published range cannot be released/reallocated");
 setup(1);jit_required_early_hold();CHECK(jit_required_pool.state==1&&jit_required_pool.rx==HOST&&owned_count()==3&&materialized_leaves==82);
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
 setup(1);jit_required_early_hold();cap_version=2;prepare_zero=prepare_tag=1;successful(1);
 puts("PASS MJP2 tagged completed breakpoint preparation selects zero contents and still verifies every73728 page permission before publication");
 setup(1);jit_required_early_hold();cap_version=2;successful(1);
 puts("PASS MJP2 ordinary return keeps native/serial69-marker fallback valid");
 setup(1);jit_required_early_hold();cap_version=2;prepare_zero=prepare_tag=1;cow_prepare=multi_objects=1;successful(1);
 puts("PASS MJP2 zero preparation supports per-page debugger COW while retaining complete object/offset sharing proof");
 for(int mode=0;mode<5;mode++){
  setup(1);jit_required_early_hold();cap_version=2;
  if(mode==0){prepare_zero=prepare_tag=1;cap_version=1;}
  if(mode==1)prepare_tag=1; /* A zero tag cannot authorize69 contents. */
  if(mode==2)prepare_zero=1; /* Ordinary response still promises69. */
  if(mode==3){prepare_zero=1;prepare_tag=4;cap_version=1;}
  if(mode==4){prepare_zero=prepare_tag=1;missing_markers=2;}
  CHECK(!create(&rx,&rw,&stage,&error));CHECK(!rx&&!rw&&!owned_count()&&!jit_required_pool.state);
  CHECK(debug_allocations==3);
  if(mode<4)CHECK(!executions);else CHECK(executions==3&&stage==12);
 }
 puts("PASS MJP1 cannot decode MJP2 tag; wrong tags/content and partial zero-page authorization never publish");
 for(unsigned poison=2;poison<=4;poison+=2){
  setup(1);jit_required_early_hold();cap_version=2;prepare_zero=1;prepare_tag=poison;
  unsigned before_poison_deallocations=deallocations;
  CHECK(!create(&rx,&rw,&stage,&error));
  CHECK(stage==13&&error==KERN_ABORTED&&!rx&&!rw&&jit_required_pool.state==4&&owned_count()==4);
  CHECK(debug_allocations==1&&preparations==1&&!executions&&deallocations==before_poison_deallocations);
  CHECK(!create(&rx,&rw,&stage,&error));
  CHECK(stage==11&&jit_required_pool.state==4&&owned_count()==4&&debug_allocations==1&&preparations==1&&deallocations==before_poison_deallocations);
 }
 puts("PASS MJP2 cleanup-poison and unknown tags quarantine every unpublished extent without deallocation, retry or another debugger request");
 setup(1);jit_required_early_hold();cap_version=2;prepare_zero=prepare_tag=1;left_breakpoint=1;
 int accepted_left_breakpoint=create(&rx,&rw,&stage,&error);
 CHECK(!accepted_left_breakpoint);CHECK(stage==8&&!rx&&!rw&&!owned_count()&&!jit_required_pool.state&&!executions);
 puts("PASS leftover ARM64 breakpoint whose first byte is zero cannot pass the MJP2 complete restored-opcode validation");
 setup(1);jit_required_early_hold();cap_version=2;prepare_zero=prepare_tag=1;execution_refused=1;
 CHECK(!create(&rx,&rw,&stage,&error));CHECK(stage==12&&!rx&&!rw&&!owned_count()&&!jit_required_pool.state&&executions==3);
 puts("PASS zero markers cannot bypass the required real-execution boundary; rejection releases only verified ownership");
 setup(1);jit_required_early_hold();cap_version=3;
 CHECK(!create(&rx,&rw,&stage,&error));CHECK(stage==1&&error==KERN_NOT_SUPPORTED&&!debug_allocations&&jit_required_pool.state==1);
 puts("PASS unsupported future preparation capability is refused before allocation");
 setup(1);fresh_zero=1;jit_required_early_hold();CHECK(jit_required_pool.rx_object&&jit_required_pool.rw_object&&jit_required_pool.fex_object);
 successful(1);puts("PASS initially objectless holds bind all82 anonymous leaves with82 bounded page materializations;9-leaf temporary source remains fully tracked");

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
 CHECK(stage==9&&jit_required_pool.state==4&&owned_count()==1&&*(uint32_t*)(uintptr_t)foreign==0x87654321);
 CHECK(!create(&rx,&rw,&stage,&error)&&stage==11&&!debug_allocations);
 puts("PASS a replaced/foreign reservation is never overwritten or deallocated; it quarantines reuse and preserves unrelated bytes");

 setup(1);jit_required_early_hold();foreign=jit_required_pool.rx;ix=index_at(foreign);CHECK(ix>=0);
 regions[ix].object=++serial;regions[ix].owned=0; /* A foreign reallocation reused the same public tag/protection. */
 CHECK(!create(&rx,&rw,&stage,&error));CHECK(stage==9&&jit_required_pool.state==4&&!debug_allocations&&owned_count()==1);
 puts("PASS same-tag/protection ABA cannot authorize overwriting or cleanup of a foreign VM object");
 setup(1);jit_required_early_hold();foreign=jit_required_pool.rx+ANON_CHUNK;ix=index_at(foreign);CHECK(ix>=0);
 regions[ix].offset=PAGE;regions[ix].owned=0;
 CHECK(!create(&rx,&rw,&stage,&error));CHECK(stage==9&&jit_required_pool.state==4&&!debug_allocations&&owned_count()==1);
 CHECK(index_at(foreign)>=0&&regions[index_at(foreign)].offset==PAGE);
 puts("PASS changed backing offset in a later128MiB leaf preserves the foreign mapping and quarantines the incomplete group");

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
