/* Compile the actual source-staged SRW diagnostic producer. Windows lock
 * functions are not substituted or executed by this fixture. */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "production-srw-producer.h"
#include "production-srw-fixture.h"

static const uintptr_t delta=0x48000000u;
static unsigned char *reservation,*rx,*rw;
static size_t reserved;
static void note(unsigned number,unsigned event) {
    srw_teb.ClientId.UniqueThread=(void *)(uintptr_t)number;
    srw_note_bound((void *)(uintptr_t)(0x100000+event*16),event&3);
}
static void must_fault(int bound) {
    pid_t child=fork();assert(child>=0);
    if(!child) {
        struct rlimit limit={0,0};setrlimit(RLIMIT_CORE,&limit);
        signal(SIGSEGV,SIG_DFL);signal(SIGBUS,SIG_DFL);
        srw_teb.ClientId.UniqueThread=(void *)3;
        if(bound)srw_note_bound((void *)0x1234,2);else srw_note_original((void *)0x1234,2);
        _exit(0);
    }
    int status=0;assert(waitpid(child,&status,0)==child);
    assert(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS));
}
static void clear_events(void) {
    memset(rw+SRW_RING_OFFSET,0,MADEIRA_NATIVE_SRW_RING_BYTES);
    *(LONG *)(rw+SRW_INDEX_OFFSET)=0;
}
static void *worker(void *argument) {
    unsigned who=(unsigned)(uintptr_t)argument;
    for(unsigned i=0;i<32;i++)note(who+1,who*32+i);
    return NULL;
}
static void protections(void) {
#ifdef __linux__
    FILE *maps=fopen("/proc/self/maps","r");assert(maps);char line[512];unsigned got=0;
    while(fgets(line,sizeof(line),maps)) {
        uintptr_t lo,hi;char perms[5];
        if(sscanf(line,"%" SCNxPTR "-%" SCNxPTR " %4s",&lo,&hi,perms)!=3)continue;
        if((uintptr_t)rx>=lo&&(uintptr_t)rx<hi){assert(perms[0]=='r'&&perms[1]!='w'&&perms[2]=='x');got|=1;}
        if((uintptr_t)rw>=lo&&(uintptr_t)rw<hi){assert(perms[0]=='r'&&perms[1]=='w'&&perms[2]!='x');got|=2;}
    }
    assert(got==3);fclose(maps);
#endif
}
int main(void) {
    reserved=delta+SRW_IMAGE_SIZE;
    reservation=mmap(NULL,reserved,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);assert(reservation!=MAP_FAILED);
    char file[]="/tmp/madeira-native-srw-XXXXXX";int fd=mkstemp(file);assert(fd>=0&&!unlink(file)&&!ftruncate(fd,SRW_IMAGE_SIZE));
    rx=mmap(reservation,SRW_IMAGE_SIZE,PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0);
    rw=mmap(reservation+delta,SRW_IMAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,fd,0);
    assert(rx==reservation&&rw==reservation+delta&&!close(fd));srw_source_rx=rx;srw_pe_fixture(rw);
    assert(sizeof(struct ios_srw_ring_ent)==16&&sizeof(ios_srw_history_write_contract)==32);
    must_fault(0);must_fault(1); /* original and unbound staged producer use the protected RX view */
    assert(!ios_native_srw_alias_bind(rw,SRW_IMAGE_SIZE,(uintptr_t)rx,(intptr_t)delta,0));
    assert(!ios_srw_history_write_contract.ring_writer&&!ios_srw_history_write_contract.index_writer);
    assert(ios_native_srw_alias_bind(rw,SRW_IMAGE_SIZE,(uintptr_t)rx,(intptr_t)delta,1));
    assert((unsigned char *)ios_srw_ring_writer()==rw+SRW_RING_OFFSET);
    assert((unsigned char *)ios_srw_index_writer()==rw+SRW_INDEX_OFFSET);
    unsigned char before[0x1000];memcpy(before,rx+0x1000,sizeof(before));
    const unsigned count=10000;
    for(unsigned i=0;i<count;i++)note(3,i);
    assert(*(ULONG *)(rx+SRW_INDEX_OFFSET)==count);
    struct ios_srw_ring_ent *ring=(void *)(rx+SRW_RING_OFFSET);
    for(unsigned i=count-512;i<count;i++) {
        const struct ios_srw_ring_ent *event=&ring[(i+1)&511];
        assert((uintptr_t)event->lock==0x100000+i*16&&event->tid_mode==((3u<<2)|(i&3)));
    }
    clear_events();pthread_t threads[8];
    for(uintptr_t i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,worker,(void *)i));
    for(unsigned i=0;i<8;i++)assert(!pthread_join(threads[i],NULL));
    assert(*(ULONG *)(rx+SRW_INDEX_OFFSET)==256);unsigned seen[256]={0};
    for(unsigned i=1;i<=256;i++) {
        const struct ios_srw_ring_ent *event=&ring[i];
        uintptr_t pointer=(uintptr_t)event->lock;assert(pointer>=0x100000&&(pointer-0x100000)%16==0);
        unsigned id=(unsigned)((pointer-0x100000)/16);assert(id<256&&!seen[id]);seen[id]=1;
        assert(event->tid_mode==(((id/32+1)<<2)|(id&3)));
    }
    for(unsigned i=0;i<256;i++)assert(seen[i]);
    /* Existing lean mode remains opt-in; the correction does not enable it. */
    ios_sync_lean=1;note(7,5);assert(*(ULONG *)(rx+SRW_INDEX_OFFSET)==256);ios_sync_lean=0;
    *(ULONG *)(rw+SRW_INDEX_OFFSET)=UINT32_MAX-1;note(4,0);note(4,1);note(4,2);
    assert(*(ULONG *)(rx+SRW_INDEX_OFFSET)==1);
    assert(!memcmp(before,rx+0x1000,sizeof(before)));protections();
    /* Every source-built ring reader uses the same owned writer mapping. */
    struct srw_lock lock={1,2};ios_srw_dump_park((const char *)&lock+2);
    assert(!munmap(reservation,reserved));
    puts("PASS actual staged SRW producer: original/unbound real RX faults, valid owned RW binding,10000 exact events/512-slot wrap,8-thread256-event contention without lost indices or events,32-bit wrap,unchanged lock bodies/code/RX protection");
    return 0;
}
