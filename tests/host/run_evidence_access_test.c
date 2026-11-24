/* Metadata queries on an ordinary allocation. No page protections, writes,
 * revocation, instruction execution or induced exceptions. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "run_evidence.h"
#ifdef __APPLE__
#define host_page_size sdk_host_page_size
#include <mach/mach.h>
#include <mach/mach_vm.h>
#undef host_page_size
#else
typedef uint64_t mach_vm_address_t;typedef uint64_t mach_vm_size_t;typedef unsigned natural_t,mach_msg_type_number_t;typedef int kern_return_t,integer_t;typedef void *vm_region_recurse_info_t;
typedef struct {unsigned is_submap,protection,max_protection,share_mode,external_pager,pages_resident,pages_swapped_out,pages_dirtied;uint64_t offset;} vm_region_submap_info_data_64_t;
#define VM_REGION_SUBMAP_INFO_COUNT_64 1
#define KERN_SUCCESS 0
#define mach_task_self() 1
static int mach_vm_region_recurse(int task,mach_vm_address_t *a,mach_vm_size_t *s,natural_t *d,void *out,mach_msg_type_number_t *c) {
    (void)task;(void)d;(void)c;*a &= ~UINT64_C(4095);*s=4096;vm_region_submap_info_data_64_t *i=out;memset(i,0,sizeof(*i));i->protection=3;i->max_protection=7;return 0;
}
static int mach_vm_page_query(int task,uint64_t addr,integer_t *d,integer_t *r) {(void)task;(void)addr;*d=5;*r=1;return 0;}
#endif
#define SEC_IMAGE 0x100
#define SEC_FILE 0x200
struct file_view {void *base;size_t size;uint64_t ios_evidence_id,ios_evidence_owner;unsigned protect,ios_flags;};
static struct file_view view;
static uint64_t host_page_size,host_page_mask,page_size=4096,ios_ev_vm_generation=9;
static pthread_mutex_t virtual_mutex=PTHREAD_MUTEX_INITIALIZER;
static struct {void *va;size_t len;uint64_t evidence_id,off;} ios_swap_ext[1];
static unsigned ios_swap_n=1;
uint64_t ios_evidence_backing_file=77;
static uint64_t lease=34; static struct ios_evidence_record captured,pages;
uint64_t ios_evidence_now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void ios_evidence_emit(struct ios_evidence_record *r) {if(r->w[1]==11)pages=*r;else captured=*r;}
unsigned long long ios_thread_process_try_observation_lease(void *owner,unsigned pid) {(void)owner;(void)pid;return lease;}
static int is_view_valloc(struct file_view *v) {(void)v;return 1;}
static struct file_view *find_view(void *p,size_t n) {(void)n;return (uintptr_t)p>=(uintptr_t)view.base && (uintptr_t)p-(uintptr_t)view.base<view.size ? &view : NULL;}
static unsigned get_page_vprot(void *p) {(void)p;return 0x23;}
static int ios_swap_is_fexjit(uintptr_t p,size_t n) {(void)p;(void)n;return 0;}
#include "actual_evidence_access.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"metadata fixture failed line %d\n",__LINE__);return 1;}}while(0)
int main(void) {
    void *p=malloc(65536);CHECK(p);host_page_size=(uint64_t)sysconf(_SC_PAGESIZE);host_page_mask=host_page_size-1;
    view=(struct file_view){p,65536,88,0x123400,0,0};ios_swap_ext[0].va=p;ios_swap_ext[0].len=65536;ios_swap_ext[0].evidence_id=99;ios_swap_ext[0].off=123456;
    struct ios_evidence_record r={{0}};r.w[1]=IOS_EV_ACCESS;r.w[4]=0x123400;r.w[5]=34;r.w[6]=0x380;r.w[9]=ios_evidence_now();r.w[12]=(uintptr_t)p+8;r.w[13]=8;
    errno=EDOM;ios_evidence_access(&r);CHECK(errno==EDOM && captured.w[35]==3 && captured.w[19]==2 && captured.w[16]==88 && captured.w[20]==99 && captured.w[21]==123464 && captured.w[47]==1);
    CHECK(pages.w[1]==11 && pages.w[36]==1 && pages.w[16]==77 && pages.w[22]==KERN_SUCCESS);
    CHECK(captured.w[36]==KERN_SUCCESS && captured.w[43]==1 && (captured.w[28]&1));
    CHECK(pages.w[36]==1 && pages.w[20]==((uintptr_t)p & ~host_page_mask));
    /* Query two ordinary owned pages as METADATA, without accessing their bytes. */
    r.w[12]=(((uintptr_t)p+2*host_page_size)&~host_page_mask)-4;r.w[13]=8;
    ios_evidence_access(&r);CHECK(captured.w[42]==1 && pages.w[36]==2 && pages.w[28]==pages.w[20]+host_page_size);
    pthread_mutex_lock(&virtual_mutex);ios_evidence_access(&r);pthread_mutex_unlock(&virtual_mutex);CHECK(captured.w[35]==1 && captured.w[43]==0);
    lease=35;ios_evidence_access(&r);CHECK(captured.w[47]==2);
    free(p);puts("actual after-resume access observer: ordinary allocation, live metadata/offset, lease mismatch, busy VM lock, errno PASS");return 0;
}
