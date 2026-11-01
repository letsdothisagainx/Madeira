# Build 10 SCM RPC ABI investigation

The supplied report quotes the device log for f54d83a / run 40973038350. The
complete 7,248-line log and a live iPhone were not attached to this task. Device
addresses below are supplied evidence, not independently remeasured here.

## Producer and consumer evidence

The checked-in hybrid sechost.dll has an x64 OpenSCManagerW fast-forward export
at RVA 0x20810 targeting native EC code at 0x134a0. That wrapper passes the mask
in w2 and the address of its output handle in x3 to svcctl_OpenSCManagerW at
0x19e18. The generated stub stores the mask at [sp] and the output pointer at
[sp+8], puts the argument-window pointer in x4 and its size (16) in x5, then
calls NdrClientCall2 through its auxiliary delay-import slot. Its four RPC
arguments are machine, database, access and output pointer. The fifth NDR format
entry is the return value, not a fifth input argument; client_do_args routes it
through pRetVal.

rpcrt4's NdrClientCall2 FFS at 0x60800 targets native code at 0x2c1f0. Its native
entry spills x2/x3 immediately before the caller's stack-argument window and
passes that contiguous window to NdrpClientCall2. This is correct when invoked
with the EC ABI. The descriptor is not an access mask/output-pointer pair.

The unresolved sechost delay-import path selects a compiled exit thunk at
0x1d26c. Its `stp x4,x5,[sp,#0x20]` stores the descriptor itself. FEX's
ExitToX64 then pushes the 8-byte return address: x64 argument slots at RSP+0x28
and RSP+0x30 now hold the argument-window address and 0x10. That matches the
reported bad pair. It is neither a universal 8-byte StackTop shift nor evidence
that the generated SCM caller reverses its two arguments.

The pinned Wine/FEX source already documents this native EC -> lazy x64 -> EC
round trip (ml237/246/316/317/318). Correcting all bitmap classification was
previously documented to regress CEF. This change does not alter that global
classifier, FEX, generic NDR offsets, exception handling, or user pointers.
FEX/AGENTS.md also disallows generated contributions to that submodule.

## Fix: bind the SCM producer before execution

The IPA previously consumed the tracked, delay-importing sechost DLL instead
of rebuilding it with the repository's existing UNDELAY=1 path. The build now
rebuilds sechost from the pinned Wine source with rpcrt4 as a normal import,
after Wine host tools/headers are ready. Normal import_dll /
arm64ec_redirect_ptr binding resolves the main IAT, but the native import stub
reads AuxiliaryIAT, which Wine leaves pointing at its continuation (also
documented by ios_jit_heal_aux_iat in virtual_ios.c). Eager loading alone is
therefore insufficient. A versioned loader overlay fills the validated native
auxiliary slot and its owning process's translated execution copy for exactly
sechost -> rpcrt4!NdrClientCall2. The target must be real resolved EC code;
invalid metadata/protection/sync failures abort DLL import instead of entering
the known corrupt path. AuxiliaryIAT is read-only .rdata in the execution view.
The existing owner-aware Unix PE-write helper now accepts exactly a DWORD
(TLS index) or pointer (auxiliary IAT), copying through the writable JIT alias
and verifying the read-only view; the loader never writes through RX or relies
on fault emulation. Unix-call ordinal and parameter layout stay unchanged.
Page protection is restored even when synchronization fails. It does not rewrite the public
x64 export or retain pointers across unloads. A bounded [scm-rpc-bind] marker
records this genuine binding, without argument contents. ntdll is rebuilt with
this overlay, and the pinned Wine checkout is restored even on build failure.
The call preserves x4/x5 and the real argument window. This avoids the corrupt lazy ABI detour at its producer/linkage boundary; it is not
a general repair of every FEX varargs transition to genuinely x64 code.

A PE gate rejects a producer that still delay-loads rpcrt4 or lacks the normal
NdrClientCall2 import/native auxiliary IAT. Existing service checks remain
closed on actual API/installer failures. No SCM result, registry entry, service
pipe or signature is fabricated. Valve binaries are unchanged.

## Regression and evidence limits

The test executes actual DLL ARM64 instructions with Unicorn. Its negative
fixture executes the build-10 compiled exit thunk and reproduces the wrong
(pointer, 0x10) x64 stack slots. Its positive path executes the real generated
SCM stub and native NdrClientCall2 entry with the patched loader's native
auxiliary-IAT binding modeled explicitly. A separate host test compiles the
shared RVA validation used by the loader and checks bounds/alignment/overflow
failures. A production-backend regression maps real shared read-only/RW views
and checks full-pointer writes, process-owner isolation, canaries and failure
reporting. The existing DWORD TLS-index tests still pass. The machine-code
test checks masks 1, 0x10, 0xf003f and 0x12345678,
all four RPC argument positions, the output-address canary, NDR procedure 15,
all five format offsets, and the scalar's 32-bit width (padding is unspecified).
Execution stops at NdrpClientCall2; no server response is synthesized. This is
machine-code/ABI regression evidence, not an end-to-end iPhone/FEX/SCM run.
CI repeats it against the newly built sechost from the actual IPA on Linux.

Both patched ntdll and eager-importing sechost compiled successfully on Linux
using the 20260421 LLVM-MinGW release. The image gates and ABI regression also
passed against that newly built sechost and the shipped rpcrt4. Dock, the real
service helper and the minimal probe cross-compiled with the same toolchain.
This does not substitute for a macOS IPA build or execution on the device.

The separately packaged x64 `madeira-scm-probe.exe` calls only the real
OpenSCManagerW(NULL,NULL,SC_MANAGER_CONNECT), reporting before/after results.
Run it from a desktop session whose SCM is already running. It neither starts
nor registers a service; error 1722 remains an actual failure. It uses the same
x64 architecture as the service helper, not an unvalidated native-ARM64 switch.
The service helper now emits a bounded `scm-call` marker before its first API
call, so another crash cannot look like the helper was never reached. No user,
Valve, account or credential contents are traced.

## Required fresh device evidence

Update the same app identity without uninstalling or resetting the prefix or
existing game installation. Collect a new log showing real helper events:

- `[steam-service] scm-call=1`, followed by `scm=0`;
- `open-service=1060` and the genuine installer's exit/requery if missing, or
  `open-service=0` if already registered;
- `service-state=4` and `result=0` from genuine SCM status.

If it fails, retain the actual exception and numeric errors. A diagnostic label
such as `[ndr-shift]` can also trigger on a valid small access mask; it is not
proof of corruption by itself. Do not change NDR slots to make it disappear.
Only after real service success should game startup and official VAC secure
play be retested. Successful SCM/service startup does not guarantee VAC
compatibility. No device success or new VAC outcome is claimed by host tests.
