/* Actual source-staged address selection and IR counter body, linked to the
 * C Mach harness. Only canonical storage placement and quiet logging are
 * platform fixture adaptations. No FEX source file is edited. */
#include <new>
#include "production-fex-diagnostics-source.h"
extern "C" void madeira_diag_image(void *rx,void *rw) {
  diagnostic_source_rx=static_cast<unsigned char*>(rx);
  auto *values=new(static_cast<unsigned char*>(rw)+FEX_DIAG_TELEMETRY) FEXCore::Telemetry::Values;
  for(auto& value:*values)value.store(0,std::memory_order_relaxed);
  new(static_cast<unsigned char*>(rw)+FEX_DIAG_IRTOPO) MadeiraFEXDiagnostics::IRTopoState;
  new(static_cast<unsigned char*>(rw)+FEX_DIAG_COMPILE) MadeiraFEXDiagnostics::CompileState;
}
extern "C" uintptr_t madeira_diag_telemetry_address(unsigned bound,unsigned index) {
  assert(index<17);
  return reinterpret_cast<uintptr_t>(bound?
    &FEXCore::Telemetry::GetTelemetryValue(static_cast<FEXCore::Telemetry::TelemetryType>(index)):
    &FEXCore::Telemetry::OldGetTelemetryValue(static_cast<FEXCore::Telemetry::TelemetryType>(index)));
}
extern "C" __attribute__((noinline)) void madeira_diag_stsetl(uint64_t value,uintptr_t address) {
#if defined(__aarch64__)
  register uint64_t source __asm__("x0")=value;
  register uintptr_t target __asm__("x1")=address;
  /* Exact captured STSETL X0,[X1], emitted for the same boolean flag operation.
   * .inst retains the LSE instruction while other source counters compile to
   * the captured generic ARMv8 LL/SC family. Apple ARM64 supports this opcode. */
  __asm__ volatile(".inst 0xf860303f" : : "r"(source),"r"(target) : "memory");
#else
  __atomic_fetch_or(reinterpret_cast<uint64_t*>(address),value,__ATOMIC_RELEASE);
#endif
}
extern "C" __attribute__((noinline)) void madeira_diag_ir_old(void) {FEXCore::IR::OldIRTopoNoteChecked();}
extern "C" __attribute__((noinline)) void madeira_diag_ir_bound(void) {FEXCore::IR::IRTopoNoteChecked();}
