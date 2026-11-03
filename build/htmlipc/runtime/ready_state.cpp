/* SPDX-License-Identifier: MIT */
#include "ready_state.h"
#if defined(_WIN32)
#define READY_EXPORT __declspec(dllexport)
#else
#define READY_EXPORT
#endif
extern "C" {
alignas(8) READY_EXPORT madeira_htmlipc_ready MadeiraRuntimeReady={
    MADEIRA_HTMLIPC_READY_MAGIC,sizeof(madeira_htmlipc_ready),
    MADEIRA_HTMLIPC_READY_VERSION,2,0,0,0,0,0,0,0,0,0,0};
}
namespace madeira_ready {
namespace {
static uint32_t killed,provider_failure,installer_failure;
static void retain_first(uint32_t *slot,uint32_t error){
    if(!error)return;
    uint32_t empty=0;
    (void)__atomic_compare_exchange_n(slot,&empty,error,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
}
static void errors(){
    __atomic_store_n(&MadeiraRuntimeReady.provider_error,
        __atomic_load_n(&provider_failure,__ATOMIC_SEQ_CST),__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.installer_error,
        __atomic_load_n(&installer_failure,__ATOMIC_SEQ_CST),__ATOMIC_RELAXED);
}
}
void revoke(uint32_t provider_error,uint32_t installer_error){
    retain_first(&provider_failure,provider_error);retain_first(&installer_failure,installer_error);
    /* SC ordering pairs with the publisher's final latch check: a cached
     * positive store can never resurrect Installed after completed revocation. */
    __atomic_store_n(&killed,1u,__ATOMIC_SEQ_CST);
    __atomic_fetch_and(&MadeiraRuntimeReady.flags,~uint32_t(MADEIRA_HTMLIPC_READY_INSTALLED),__ATOMIC_SEQ_CST);
    errors();
}
void detach(){revoke(0,0);}
bool publish(const Values &v,uint32_t publication_error){
    if(__atomic_load_n(&killed,__ATOMIC_SEQ_CST)){
        __atomic_fetch_and(&MadeiraRuntimeReady.flags,~uint32_t(MADEIRA_HTMLIPC_READY_INSTALLED),__ATOMIC_SEQ_CST);
        errors();return false;
    }
    uint32_t sequence=__atomic_load_n(&MadeiraRuntimeReady.sequence,__ATOMIC_ACQUIRE);
    if((sequence&1)||sequence>UINT32_MAX-2){revoke(publication_error,0);return false;}
    uint32_t expected=sequence;
    if(!__atomic_compare_exchange_n(&MadeiraRuntimeReady.sequence,&expected,sequence+1,false,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
        revoke(publication_error,0);return false;
    }
    __atomic_store_n(&MadeiraRuntimeReady.magic,MADEIRA_HTMLIPC_READY_MAGIC,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.size,uint32_t(sizeof(madeira_htmlipc_ready)),__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.version,uint32_t(MADEIRA_HTMLIPC_READY_VERSION),__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.pid,v.pid,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.reserved,0u,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.owner_peb,v.owner_peb,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.owner_lease,v.owner_lease,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.self_module,v.self_module,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.installed_module,v.installed_module,__ATOMIC_RELAXED);
    __atomic_store_n(&MadeiraRuntimeReady.generation,v.generation,__ATOMIC_RELAXED);
    uint32_t flags=0;
    if(v.native_owner&&v.pid&&v.owner_peb&&v.owner_lease&&v.self_module&&v.generation){
        flags=v.flags&MADEIRA_HTMLIPC_READY_FLAGS;
        if(!v.installed_module)flags&=~uint32_t(MADEIRA_HTMLIPC_READY_INSTALLED);
    }
    errors();
    __atomic_store_n(&MadeiraRuntimeReady.flags,flags,__ATOMIC_SEQ_CST);
    bool alive=!__atomic_load_n(&killed,__ATOMIC_SEQ_CST);
    if(!alive){
        __atomic_fetch_and(&MadeiraRuntimeReady.flags,~uint32_t(MADEIRA_HTMLIPC_READY_INSTALLED),__ATOMIC_SEQ_CST);
        errors();
    }
    __atomic_store_n(&MadeiraRuntimeReady.sequence,sequence+2,__ATOMIC_RELEASE);
    return alive;
}
}
