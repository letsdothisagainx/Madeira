/* SPDX-License-Identifier: MIT. Native readers consume DATA, never call guest. */
#ifndef MADEIRA_RUNTIME_READY_STATE_H
#define MADEIRA_RUNTIME_READY_STATE_H
#include "../../scm-rpc/htmlipc_ready_abi.h"
extern "C" {
#if defined(_WIN32)
extern __declspec(dllexport) madeira_htmlipc_ready MadeiraRuntimeReady;
#else
extern madeira_htmlipc_ready MadeiraRuntimeReady;
#endif
}
namespace madeira_ready {
struct Values {
    uint32_t flags,pid;
    uint64_t owner_peb,owner_lease,self_module,installed_module,generation;
    bool native_owner;
};
/* One bounded CAS publication, with no OS call/allocation/logging in its odd
 * window. Contention, sequence exhaustion and sticky failure fail closed. */
bool publish(const Values &,uint32_t publication_error);
/* Revocation precedes diagnostics and never waits for a positive publisher.
 * A positive publisher rechecks this sticky latch after writing its flags. */
void revoke(uint32_t provider_error,uint32_t installer_error);
void detach();
}
#endif
