# Steam service registration investigation

The reported transition from `BOpenSCMgr`/1722 to `BOpenService`/1060 establishes
that the later call reached SCM and its database lacked that named service.
It does not establish why a previous installer failed or whether a service pipe
was ever created. No device prefix or service log was available for independent
inspection in this task; device-specific causes remain hypotheses.

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
marked-for-deletion, unsupported executable and timeout errors fail the launch;
there is no fabricated success or service response. Services remain running for
the Wine session. A timed-out installer is not killed; close the session before
retrying so a second launch does not overlap that outstanding installer.

## Numeric diagnostics

`[steam-service]` records SCM readiness, installer inspection/spawn/exit results,
installer binary type (0=x86, 6=x64), registration visibility in both registry
views, the existing WOW64 marker, ImagePath presence, service type/start mode,
and real SCM service state. It logs no paths, usernames, account identifiers,
credentials, or pipe names. Result 0 means SCM reported SERVICE_RUNNING.

The optional evidence from named-pipe enumeration is only the count of names
beginning with Steam before/after startup. Enumeration failures are reported
numerically. Counts can include other Steam pipes or miss names with other
prefixes: they neither identify a particular endpoint nor prove readiness,
authentication, protocol validity, signatures, entitlement, or VAC support.
The helper never creates/opens a Valve pipe or sends protocol messages.

## Validation and evidence limits

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
