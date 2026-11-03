/* SPDX-License-Identifier: MIT
 * Synthetic owner/module/lease values only. No Steam or native lease assertion.
 */
#include "ready_state.h"
#include "htmlipc_policy.h"
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

using Ready=madeira_htmlipc_ready;
using Values=madeira_ready::Values;
static std::atomic<unsigned long long> assertions;
[[noreturn]] static void fail(const char *expression,int line){
    std::fprintf(stderr,"FAIL ready publisher line %d: %s\n",line,expression);
    std::exit(1);
}
#define CHECK(x) do{assertions.fetch_add(1,std::memory_order_relaxed);if(!(x))fail(#x,__LINE__);}while(0)

static_assert(sizeof(Ready)==80);
static_assert(offsetof(Ready,magic)==0);
static_assert(offsetof(Ready,size)==8);
static_assert(offsetof(Ready,version)==12);
static_assert(offsetof(Ready,sequence)==16);
static_assert(offsetof(Ready,flags)==20);
static_assert(offsetof(Ready,pid)==24);
static_assert(offsetof(Ready,provider_error)==28);
static_assert(offsetof(Ready,installer_error)==32);
static_assert(offsetof(Ready,reserved)==36);
static_assert(offsetof(Ready,owner_peb)==40);
static_assert(offsetof(Ready,owner_lease)==48);
static_assert(offsetof(Ready,self_module)==56);
static_assert(offsetof(Ready,installed_module)==64);
static_assert(offsetof(Ready,generation)==72);

/* Each field is read atomically rather than racing a host C++ plain memcpy.
 * The native adapter uses bounded fresh guest-memory reads; this host fixture
 * independently exercises the same complete two-snapshot validation policy. */
static Ready read_snapshot(){
    Ready r{};
#define READ(member) r.member=__atomic_load_n(&MadeiraRuntimeReady.member,__ATOMIC_SEQ_CST)
    READ(magic);READ(size);READ(version);READ(sequence);READ(flags);
    READ(pid);READ(provider_error);READ(installer_error);READ(reserved);
    READ(owner_peb);READ(owner_lease);READ(self_module);READ(installed_module);READ(generation);
#undef READ
    return r;
}
static Values values(unsigned tag=1,unsigned counter=1){
    Values v{};
    v.flags=MADEIRA_HTMLIPC_READY_FLAGS;v.pid=1000+tag;
    v.owner_peb=UINT64_C(0x7100000000)+UINT64_C(0x10000)*tag;
    v.owner_lease=UINT64_C(0x40ab00000000)+tag;
    v.self_module=UINT64_C(0x180000000)+UINT64_C(0x1000000)*tag;
    v.installed_module=UINT64_C(0x280000000)+UINT64_C(0x1000000)*tag;
    v.generation=(uint64_t(tag)<<48)|counter;v.native_owner=true;
    return v;
}
static bool valid(const Ready &a,const Ready &b,const Values &expected){
    return madeira_htmlipc_ready_valid(&a,&b,expected.owner_peb,
        expected.owner_lease,expected.pid,expected.self_module)!=0;
}
static bool valid_any(const Ready &a,const Ready &b){
    if(a.pid<1001||a.pid>1004)return false;
    Values v=values(a.pid-1000);
    return valid(a,b,v)&&a.installed_module==v.installed_module&&
        (a.generation>>48)==a.pid-1000&&(a.generation&UINT64_C(0xffffffffffff));
}
static void check_not_ready(){
    Ready a=read_snapshot(),b=read_snapshot();
    CHECK(!valid_any(a,b));
}
static void check_coherent_snapshot(){
    Ready a=read_snapshot(),b=read_snapshot();
    if(a.sequence&&!(a.sequence&1)&&!std::memcmp(&a,&b,sizeof(a))&&
        a.flags==MADEIRA_HTMLIPC_READY_FLAGS){
        CHECK(valid_any(a,b));
    }
}
static void basic_valid(){
    CHECK((reinterpret_cast<uintptr_t>(&MadeiraRuntimeReady)&7)==0);
    check_not_ready();Values v=values();
    CHECK(madeira_ready::publish(v,901));
    Ready a=read_snapshot(),b=read_snapshot();
    CHECK(valid(a,b,v));CHECK(a.sequence&&!(a.sequence&1));
    CHECK(a.generation==v.generation);CHECK(a.installed_module==v.installed_module);
    CHECK(!a.provider_error&&!a.installer_error&&!a.reserved);
    uint32_t before=a.sequence;v.generation++;
    CHECK(madeira_ready::publish(v,901));
    a=read_snapshot();b=read_snapshot();CHECK(valid(a,b,v));
    CHECK(a.sequence>before);CHECK(a.generation==v.generation);
}
static void invalid_owner(unsigned which){
    Values v=values();
    switch(which){
        case 0:v.native_owner=false;break;
        case 1:v.pid=0;break;
        case 2:v.owner_peb=0;break;
        case 3:v.owner_lease=0;break;
        case 4:v.self_module=0;break;
        case 5:v.installed_module=0;break;
        case 6:v.generation=0;break;
        default:fail("unknown identity fixture",__LINE__);
    }
    (void)madeira_ready::publish(v,902);
    Ready a=read_snapshot();CHECK(a.flags!=MADEIRA_HTMLIPC_READY_FLAGS);
    check_not_ready();
}
static void partial(){
    Values v=values();
    for(uint32_t flags:{0u,MADEIRA_HTMLIPC_READY_PREPARED,
        MADEIRA_HTMLIPC_READY_PREPARED|MADEIRA_HTMLIPC_READY_CACHE_VERIFIED}){
        v.flags=flags;(void)madeira_ready::publish(v,903);
        Ready a=read_snapshot();CHECK(a.flags!=MADEIRA_HTMLIPC_READY_FLAGS);check_not_ready();
    }
}
static void stock_mode(){
    Values v=values();v.native_owner=false;
    /* A nonzero fixture lease alone cannot override explicit stock-Wine mode. */
    for(unsigned i=0;i<1000;++i){v.generation++;
        (void)madeira_ready::publish(v,904);
        CHECK(read_snapshot().flags!=MADEIRA_HTMLIPC_READY_FLAGS);check_not_ready();}
}
static void revoked(){
    Values v=values();CHECK(madeira_ready::publish(v,905));
    madeira_ready::revoke(41,42);
    Ready a=read_snapshot();CHECK(!(a.flags&MADEIRA_HTMLIPC_READY_INSTALLED));
    CHECK(a.provider_error==41);CHECK(a.installer_error==42);
    for(unsigned i=0;i<1000;++i){v.generation++;
        (void)madeira_ready::publish(v,905);check_not_ready();
        CHECK(!(read_snapshot().flags&MADEIRA_HTMLIPC_READY_INSTALLED));}
}
static void detached(){
    Values v=values();CHECK(madeira_ready::publish(v,906));
    madeira_ready::detach();CHECK(!(read_snapshot().flags&MADEIRA_HTMLIPC_READY_INSTALLED));
    for(unsigned i=0;i<100;++i){(void)madeira_ready::publish(v,906);check_not_ready();}
}
static void busy(){
    Values v=values();CHECK(madeira_ready::publish(v,907));
    uint32_t sequence=read_snapshot().sequence;
    __atomic_store_n(&MadeiraRuntimeReady.sequence,sequence+1,__ATOMIC_SEQ_CST);
    CHECK(!madeira_ready::publish(v,907));
    CHECK(!(read_snapshot().flags&MADEIRA_HTMLIPC_READY_INSTALLED));check_not_ready();
    /* Model the paused original publisher finishing. The sticky revocation
     * must still prevent a later successful publisher from resurrecting Ready. */
    __atomic_store_n(&MadeiraRuntimeReady.sequence,sequence+2,__ATOMIC_SEQ_CST);
    (void)madeira_ready::publish(v,907);check_not_ready();
}
static void wrap(){
    Values v=values();CHECK(madeira_ready::publish(v,908));
    __atomic_store_n(&MadeiraRuntimeReady.sequence,UINT32_C(0xfffffffe),__ATOMIC_SEQ_CST);
    CHECK(!madeira_ready::publish(v,908));
    Ready a=read_snapshot();CHECK(a.sequence>=UINT32_C(0xfffffffe));
    CHECK(!(a.flags&MADEIRA_HTMLIPC_READY_INSTALLED));check_not_ready();
}
static void concurrent_writers(){
    Values first=values();CHECK(madeira_ready::publish(first,909));
    std::atomic<bool> start=false,done=false;
    std::atomic<unsigned> remaining=4;
    std::vector<std::thread> writers;
    for(unsigned t=1;t<=4;++t)writers.emplace_back([&,t]{
        Values v=values(t);while(!start.load(std::memory_order_acquire))std::this_thread::yield();
        for(unsigned n=1;n<=5000;++n){v.generation=(uint64_t(t)<<48)|n;
            (void)madeira_ready::publish(v,909);}
        if(remaining.fetch_sub(1,std::memory_order_acq_rel)==1)done.store(true,std::memory_order_release);
    });
    start.store(true,std::memory_order_release);
    while(!done.load(std::memory_order_acquire))check_coherent_snapshot();
    for(auto &thread:writers)thread.join();
    check_coherent_snapshot();
    /* Contention may explicitly revoke, but no accepted positive may mix
     * independently valid synthetic owner/module identity sets. */
}
static void concurrent_revoke(){
    Values v=values();CHECK(madeira_ready::publish(v,910));
    std::atomic<bool> start=false,complete=false;
    std::atomic<unsigned> publications=0;
    std::thread writer([&]{
        Values local=values();while(!start.load(std::memory_order_acquire))std::this_thread::yield();
        for(unsigned n=2;n<=100000;++n){local.generation=(uint64_t(1)<<48)|n;
            (void)madeira_ready::publish(local,910);publications.fetch_add(1,std::memory_order_release);}
        complete.store(true,std::memory_order_release);
    });
    start.store(true,std::memory_order_release);
    bool saw_odd=false;
    for(unsigned n=0;n<5000000&&!complete.load(std::memory_order_acquire);++n){
        if(__atomic_load_n(&MadeiraRuntimeReady.sequence,__ATOMIC_SEQ_CST)&1){saw_odd=true;break;}
    }
    CHECK(saw_odd);CHECK(publications.load(std::memory_order_acquire)<100000);
    madeira_ready::revoke(77,88);
    /* Completion of revoke happens-before every subsequent read in this
     * thread. A concurrent cached publication must never restore flags7. */
    while(!complete.load(std::memory_order_acquire))check_not_ready();
    writer.join();
    for(unsigned n=0;n<10000;++n)check_not_ready();
    CHECK(!(read_snapshot().flags&MADEIRA_HTMLIPC_READY_INSTALLED));
}
int main(int argc,char **argv){
    if(argc!=2)fail("one fresh-process mode required",__LINE__);
    if(!std::strcmp(argv[1],"valid"))basic_valid();
    else if(!std::strncmp(argv[1],"owner",5))invalid_owner(unsigned(std::atoi(argv[1]+5)));
    else if(!std::strcmp(argv[1],"partial"))partial();
    else if(!std::strcmp(argv[1],"stock"))stock_mode();
    else if(!std::strcmp(argv[1],"revoke"))revoked();
    else if(!std::strcmp(argv[1],"detach"))detached();
    else if(!std::strcmp(argv[1],"busy"))busy();
    else if(!std::strcmp(argv[1],"wrap"))wrap();
    else if(!std::strcmp(argv[1],"writers"))concurrent_writers();
    else if(!std::strcmp(argv[1],"race"))concurrent_revoke();
    else fail("unknown mode",__LINE__);
    std::printf("PASS ready DATA %s: %llu assertions\n",argv[1],assertions.load());
}
