# Steam service startup and registration

The November 4 `4b579035` device capture passes browser preparation and starts
Wine. Its I386 SteamService thread then has an `APC_ASYNC_IO` readiness completion
dropped with status `0x101`, immediately raises RPC error 1726, and exits zero.
SCM observes that early process exit after 4,384 ms and correctly returns 1053;
there is no verified updater successor and no 30-second timeout to extend.

Wine's dropped-APC destructor completes the I/O with the APC status and zero
bytes instead of letting the native callback fetch the real RPC header. With
the device's madsync-disabled backend, ordinary waits already reach the server
(after any bounded fastsync peek), so the completion can be retained until that
kernel wait. The staged thread correction also allows a later same-process
waiter to adopt the non-thread-affine internal I/O callback. User APCs, other
kernel APCs, foreign processes, suspended/dead threads and FIFO order retain
their restrictions. It neither invents I/O bytes nor reports a service running.
The madsync-enabled path is unchanged: it needs a separate kernel-APC wake
contract before retaining additional completions there would be safe.

The reported transition from `BOpenSCMgr`/1722 to `BOpenService`/1060 establishes
that the later call reached SCM and its database lacked that named service.
It does not establish why a previous installer failed or whether a service pipe
was ever created in those earlier registration failures.

## Confirmed source findings

- `app/Madeira/SteamRuntime.swift` unpacks pinned, hash-verified Valve component
  ZIPs and writes client discovery values. Extracting files does not execute a
  Windows installer and does not register a service.
- In the pinned Dock, `src/launch.c` calls `sh_ceg_scm_prepare` only inside the
  custom-executable preparation branch. Ordinary launches do not reach its
  `bin\SteamService.exe /install` fallback. `--start-services` starts Wine SCM,
  not Valve's client service. The old Steam Testing batch likewise started
  services.exe then steam.exe without service registration.
- Wine `dlls/sechost/service.c` selects CreateServiceWOW64W for a WoW64 caller.
  `programs/services/services.c` loads service ImagePath, Type, Start and its
  WOW64 marker from `HKLM\SYSTEM\CurrentControlSet\Services`. These SYSTEM
  service keys are shared rather than a second service database beneath
  Software\Wow6432Node. Discovery under Software\Valve\Steam has two views.
- Wine SCM creates `\\.\pipe\net\NtControlPipe%u` before launching a service;
  sechost's service dispatcher connects to that control pipe. This is distinct
  from any private pipe created by Valve's service. Starting SCM alone cannot
  create Valve's private endpoints. A 1060 at OpenService happens before SCM
  can start that missing service.

These are compatibility integration gaps, not proof that every observed 1060
has the same cause. Missing service installer files/dependencies, an x86 WoW64
loader failure, access denial, installer failure, invalid registration, and
startup failures must remain distinguishable.

## Implemented behavior

A separate Madeira-owned Windows helper runs before Steam Testing and ordinary
Dock launches, including non-CEG launches. It serializes Madeira preparation
calls with a mutex. When SCM is unreachable (1722), it follows Wine's standard
named startup event and starts services.exe only if no other launcher holds the
event. It polls OpenSCManager, not a fixed sleep or the event alone. An existing
but nonresponsive startup event times out without starting a second SCM.

Only OpenService 1060 permits running the user's existing, unmodified
`<Steam folder>\bin\SteamService.exe /install`, with the Steam folder as its
working directory. Desktop supplies that folder; Dock uses Valve's existing
machine InstallPath, checking both registry views. GetBinaryType accepts x86 or
x64 installers; Wine selects the actual loader. It never forces a different
machine type, copies a substitute service binary, grants privileges, creates a
service registration, writes SYSTEM keys, or modifies signatures.

The actual installer exit code and subsequent OpenService result are separate.
Exit zero without a registration remains 1060. Existing registrations are not
reinstalled or overwritten. StartService's errors and real SCM state/checkpoint,
wait hint, Win32 exit and service-specific exit remain observable. Access denied,
marked-for-deletion, unsupported executable and timeout errors remain failures
of the helper; there is no fabricated success or service response. Services remain running for
the Wine session. A timed-out installer is not killed; close the session before
retrying so a second launch does not overlap that outstanding installer.

The native-client scripts now log a failed preparation result and still invoke
the genuine `steam.exe`, returning that client's actual exit code. The separate
Dock host keeps its existing prerequisite. Madeira's former unconditional
1053-to-batch-exit policy prevented Steam from making its own decision. Genuine
Steam already reached its sign-in UI while reporting an unavailable service
(`Failed to connect to Steam Service (GLE 2)`) in
[runtime test 41806572342](https://github.com/letsdothisagainx/Madeira/actions/runs/41806572342).
That proves client startup can be legitimate without the service, not that any
game or VAC operation can omit it. Steam retains all update, authentication and
game-launch requirements; no service or security response is fabricated.

## Numeric diagnostics

`[steam-service]` records SCM readiness, installer inspection/spawn/exit results,
installer binary type (0=32-bit, 6=64-bit; this API does not identify the CPU), registration visibility in both registry
views, the existing Type/Start/WOW64 DWORDs, ImagePath kind/size (without its
contents), API configuration presence, service type/start mode,
and real SCM service state. It logs no paths, usernames, account identifiers,
credentials, or pipe names. Result 0 means SCM reported SERVICE_RUNNING.

The optional evidence from named-pipe enumeration is only the count of names
beginning with Steam before/after startup. Enumeration failures are reported
numerically. Counts can include other Steam pipes or miss names with other
prefixes: they neither identify a particular endpoint nor prove readiness,
authentication, protocol validity, signatures, entitlement, or VAC support.
The helper never creates/opens a Valve pipe or sends protocol messages.
In the device capture, enumeration error 66 is a diagnostic limitation of
`FindFirstFileW` on the named-pipe device. It returns from a void observer and
does not affect preparation. `StartServiceW` runs on another thread with its own
last-error value, and SCM independently observes the actual child exit.

## Validation and evidence limits

`check-service-async-apc.py` executes the actual pinned and staged queue,
wait, dequeue, cancellation and APC-destruction functions with host transport
edges. It reproduces the old `0x101/0` completion and verifies the corrected
16-byte non-alertable completion, late sibling delivery, FIFO/user affinity,
reference lifetimes and rejection of unsafe owners. The Wine source stays
pinned; its staged thread object and the packaged native image must contain
the delivery correction or the build fails.

The service startup integration compiles an I386 service fixture and the real
Madeira helper, then exercises Wine SCM dispatcher/control pipes and genuine
status transitions. Early exit remains 1053. A separately verified updater
fixture permits one genuine SCM retry. The scripts are generated by actual
production Swift, then executed by Wine CMD; helper failure still reaches the
client fixture and preserves that client's exit status. These fixtures do not
prove that Valve's service reaches SERVICE_RUNNING on this iPhone.

Host tests compile the production preparation policy with synthetic API outcomes:
SCM ordering, missing-only installation, access/marked-delete failures, installer
errors (including 193/216 and timeout), post-install requery, and startup failure.
They do not impersonate a service in production or validate a Valve binary.
The helper is cross-compiled as x86 and x64; only x64 is shipped. The app's Swift
launch contract and real IPA ZIP resource gates are checked in CI. Packaging
must include the helper, Dock and license notices without changing bundle ID.

On-device testing is still required. Preserve the existing app/prefix and games;
do not uninstall the app. Capture only the numeric helper diagnostics and the
relevant failure lines from the genuine client's service_log.txt, redacting
identifiers and paths before sharing. Verify the installed service's actual
ImagePath, Type, Start, WoW64 marker and SCM status, and whether Valve's own
service creates its private endpoint. Repeat Steam launch, then game startup.
A successfully installed/running Steam Client Service does **not** guarantee VAC
compatibility or successful official VAC secure play. No bypass or fabricated
response is part of this change.

## November 9 `DB9C3F84` capture

The new export measures the phone's `Steam/bin/SteamService.dll` and both
service executables as PE machine `014c`. These are disk-header snapshots at
export time, not file hashes, import-table captures or authenticated/loaded-image
identity. The lower-case-only DLL candidate is absent; Windows path lookup can
resolve the observed lower-case request to the existing official-case file.
The precise resolved file and its load flags at the earlier failure are not
recorded.

Wine creates service PID `004c` with main TID `0050`, selects its I386 guest
window and maps SteamService.dll on worker TID `0064`, followed by CFGMGR32.dll
and setupapi.dll. Separate Steam PID `0068` is AMD64 (64-bit pointers,
`IsWow64Process=0`); its `SteamServiceConnect` TID `00b0` receives `c000007b`
for the explicit DLL request and `c0000135` for bare-name fallback, then exits
zero. An ordinary AMD64 process cannot load native I386 code as a DLL. Wine's
`is_valid_binary` machine check precedes import binding; this evidence does not
identify a missing imported symbol/dependency or justify weakening that check.
The service's earlier successful load is a different process and architecture.
The relationship of the client attempt to secure-game rejection remains unknown.

The raw helper status is `service-state=4` and its result is zero, but unrelated
native diagnostics are interleaved between the `fprintf` format pieces. Even
the tag, key and numeric value occupy different physical rows. This explains
why the strict exported summary has no accepted running-state record; it does
not establish a stopped service. No parser should reconstruct arbitrary log
fragments as a service/security result.

The helper now formats each numeric event into a 128-byte local buffer and
submits one `WriteFile` to its inherited stderr. Logging preserves incoming
`GetLastError`; invalid handles, truncation, failure and short writes remain
diagnostic loss, with no retry of partial records and no change to SCM results.
No Valve pipe is opened or written. `check-steam-service-log.py`, called by the
existing service check, executes the unchanged pinned Wine printf narrow
string/integer path to reproduce the old five-fragment output. It executes the
actual new producer with owned Win32 transport edges, failure cases and 1,024
concurrent records under sanitizers. This checks the producer boundary; final
record delivery through the iPhone's full logging transport still needs a
device capture.

There is no genuine Steam verification request/result or WinVerifyTrust return
in the new attached evidence. Cached game hashes and embedded VPK consistency
remain separate observations. The existing trust-wrapper host test substitutes
the verifier's return to test noninterference, while native/package tests check
compilation and exports. They do not execute cryptographic verification.
Wine's ordinary `softpub.c:test_wintrust_digest` fixtures provide self-signed,
unsigned and tampered PE inputs for a future isolated real-verifier test.
Self-signed chain/policy errors must remain actual errors; `WTD_HASH_ONLY_FLAG`
success measures digest consistency, not trusted signing or VAC acceptance.
