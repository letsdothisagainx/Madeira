/* SPDX-License-Identifier: MIT. Guest AMD64 experimental provider only. */
#ifndef MADEIRA_HTMLIPC_RUNTIME_PROVIDER_H
#define MADEIRA_HTMLIPC_RUNTIME_PROVIDER_H
#include "../stream-install/installer.h"
#include "../wire-codec/wire_codec.h"

namespace madeira_runtime {
using U32=madeira_stream_install::U32;
using U64=madeira_stream_install::U64;
enum class Error:U32 {
    None,WrongProcess,MissingProvenMap,ModuleMetadata,PinOpen,PinSize,PinRead,
    Allocation,InstallerUnavailable,ControllerInvalid,PartialPublication,
    StreamInvalid,RegistryFull,GenerationOverflow,ThreadSlotsFull,
    CodecConfiguration,CodecFailure,SourcePinFailed,DuplicateDestroy,
    OriginalUnwind,CacheNotVerified,RegistryLockTimeout,StateLockTimeout,
    DrainTimeout,ReentrantDestroy,Quarantined,
    OwnerLeaseUnavailable,OwnerLeaseLength,OwnerIdentity,CacheEnvMissing,
    CacheEnvInvalid,ExecutionModeMissing,ReadyPublication,StockCacheEnv,
};
struct Status {
    U32 size,version,pid,prepared;
    U32 installer_phase,installer_error,provider_error,wire_error;
    U32 first_command,first_direction,entry_count,failed_generations;
    U64 installed_module,generation,calls,failed_calls;
};
}

extern "C" {
/* Optional loader callbacks; enabled only by MADEIRA_RUNTIME_PROVIDER. Prepare
 * performs file/heap work during explicit experimental attach, never a genuine
 * controller factory call. The notification callback publishes Installer/status
 * and emits at most one fixed numeric install-error diagnostic. */
bool MadeiraRuntimePrepareConfig(void *own_module,
    madeira_stream_install::Config *out);
void MadeiraRuntimeNoteInstaller(madeira_stream_install::Installer *);
void MadeiraRuntimeDetach();
__declspec(dllexport) bool MadeiraRuntimeGetStatus(madeira_runtime::Status *,
    madeira_runtime::U32 bytes);

/* Required ONLY when MADEIRA_RUNTIME_HAS_PROVEN_MAP is defined. The separately
 * compiled implementation owns hash/provenance checks and provides actual
 * current/actual-I386 command pairs. There is no fixture/default identity map.
 * Its returned storage must remain immutable through every generation. */
bool MadeiraRuntimeGetWireMap(madeira_wire::MapView *out);
}
#endif
