# Steam service: November 12 complete run export

Baseline: `44dd545e35bd4f0685c63f10b8b8d2fd56b048a6`. Evidence is the
attached Madeira-Run-Diagnostics ZIP, including its real Steam service/content
logs and embedded VAC export. No installed game or prefix file is edited.

## Confirmed compatibility defect and correction

The genuine I386 service PID `00bc`, worker `01c0`, calls
`SetNamedSecurityInfoW` with object type 13 (`SE_REGISTRY_WOW64_64KEY`). The
export records Wine's unsupported-object warnings for types 12 and 13 at session
rows 15484/15487. The pinned implementation returns `ERROR_SUCCESS` from this
unsupported branch without opening a registry key or setting its security.
That is a false success in a real service operation, independently of VAC.
The sanitized export does not retain the affected registry path or descriptor.

The correction implements the explicit 32/64-bit registry selectors for both
named security APIs. They add the corresponding `KEY_WOW64_32KEY` or
`KEY_WOW64_64KEY` access flag when opening the key, then call the existing
`SetSecurityInfo` / `GetSecurityInfo` with `SE_REGISTRY_KEY`. The returned handle
already identifies the registry view. The existing backend applies the actual
descriptor and access checks; its failures are propagated. Other object types,
default-view calls, descriptor contents and trust/signature APIs are unchanged.

The Wine pin stays intact. A checked staging transaction applies the small
patch during compilation and restores its exact input afterward, including on
build failure. `advapi32.dll` is rebuilt for I386, ARM64EC and ARM64. Packaging
requires source hashes, actual compiler-object-to-linked-function proofs and
identical bytes in the final IPA. A cached old DLL cannot satisfy that gate.

## DLL-loading error is a separate finding

The current persistent service log has one `Failed to load Steam Service
(GLE 126)` at November 12 00:37:26 UTC. Native64 Steam PID `0068`, TID `00b4`,
receives `c000007b` followed by `c0000135` between local 19:37:26.746 and
19:37:26.999; the measured offset is -300 minutes. This is timestamp correlation,
not by itself proof of the writer of the persistent log. A native I386 DLL cannot execute
inside an AMD64 process. The failed bare-name fallback can produce module-not-
found independently of a transitive import failure.

Separately, both genuine I386 service instances map SteamService.dll, bind its
observed dependencies and execute its TLS/worker code. The later service stays
alive and creates more threads. Its debug-print exceptions are handled, not a
DLL initialization crash. SCM reports genuine state 4; Madeira never supplies
that state itself. The observed SCM pipe waits finish with `outcome=event`.
None of this alone establishes all private Valve service IPC operations.
No missing static dependency in those successful DLL loads is identified.
The registry fix must not be described as a proven cure for GLE 126.

Read-only inspection of the authenticated current Steam 1794424036 packages
locates that log producer in AMD64 `steamclient64.dll`,
`CSteamServiceBaseImpl::BlockingServiceStart`. It attempts executable loading of
`bin/steamservice.dll`; the published DLL and EXE are I386, and the package has
no SteamService64.dll. The module loader performs ordinary W/A loading or
`LoadLibraryEx` with `LOAD_WITH_ALTERED_SEARCH_PATH` (8). The caller's argument 4
is an internal flag, not a Windows load flag. A null module logs the error and
then invokes a further service-start fallback at RVA `0x9c99dc`. A false fallback
result emits a separate `BlockingServiceStart: failed to start`, absent from the
current persistent service log. Thus GLE 126 is not itself evidence of terminal
service failure or a missing transitive import. The static proof is retained in
[Actions 43131940386](https://github.com/letsdothisagainx/Madeira/actions/runs/43131940386).

## Real content verification and VAC limits

Steam's own current content log records App ID 730 downloading depot chunks,
verifying 1,850 MB of staged content, committing 79 updated files and completing
build 26598758 with `No Error` at local 19:39:09. This is a genuine Steam
update/verification result, not a Madeira cached-hash audit. It is not a full
validation of every installed byte, and it does not establish VAC acceptance.
The existing Verify files action delegates to real Steam `steam://validate/730`.

The user reports the signature popup at local 19:43:36.222. There is no exposed
rejected-file identity or proof that either the client DLL probe or the registry
operation causes the popup. Valve's
[Trusted Mode FAQ](https://help.steampowered.com/en/faqs/view/09A0-4879-4353-EF95)
restricts foreign software; it does not document acceptance of Madeira's Windows
CS2/Wine/FEX/iOS combination. Matching Windows-CS2 signature failures are also
reported in [Valve's Proton tracker](https://github.com/ValveSoftware/Proton/issues/2704).
These establish a support/compatibility concern, not the exact private check or
proof that every Wine environment can never connect. No security decision,
module visibility, game signature, service response or Valve binary is changed.
Only a legitimate VAC-secured server connection can verify the objective.

## Validation and installation boundaries

The host test executes the pinned and patched production function bodies: the
old type-13 false success is reproduced, then view selection, access masks,
descriptor/output forwarding, honest errors, handle closure and staging
restoration are checked under sanitizers. Its transport edges are controlled;
it is not a running Steam service. The native Windows test separately uses real
registry/security APIs and independent Windows reference calls in both process
architectures. The IPA gate verifies the built binaries rather than test fixtures.

The native Windows comparison passed in both x86 and x64 processes: 102 checks
per architecture, real DACL writes to distinct registry views, errors matching
stock Windows on nonexistent/permission-denied keys, unchanged neighboring
view/owner/group, and 128 concurrent writes. This is
[Actions 43132009766](https://github.com/letsdothisagainx/Madeira/actions/runs/43132009766),
not an on-device Steam or VAC test.

The iPhone must still establish service operations after the correction and
real secure-server acceptance. JIT placement/preparation, 1152 MiB partition,
browser bridge, graphics, controls, prefix, account state and exports are left
unchanged. Install over the existing app using the same signing identity; do
not uninstall. Rollback is a code revert of the registry patch/stager/build step
and its packaging gate, or reinstalling the prior IPA over the existing app.
