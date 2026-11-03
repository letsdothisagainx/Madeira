# Windows Steam: verified fixes and the remaining address-space limit

## Current device evidence

The 19:06 capture on iPhone18,3 / iOS 26.6.1 matches native UUID
`653A3A58-4AF4-3DD7-A9B7-0A2701A87F73`, source `809f8dc`.
Both installed entitlements and the embedded profile now grant extended virtual
addressing. `TASK_VM_INFO.max_address` remains `0xfc0000000` (63 GiB), before
Wine starts as well as during guest allocation. The first Chromium reservation
still fails: its largest available gap is 32,000 MiB, below the temporary
32 GiB request. The screenshot's readable “Steamwebhelper is not responding”
dialog does not establish a working browser or Library.

The prior native helper fixes are verified in these captures:

* Fresh native ntdll selection works in both architecture directions.
* Per-thread WoW64 queries return the owner's actual PEB32. The previous
  `wow64.dll` null-relative `0x480` write is absent.
* Native Wine system DLL selection avoids executing hybrid x86 entry points
  as ARM64; the previous kernelbase fault is absent.
* Both native FEX retirement callbacks return `result=0x100`, and their owners
  retire/reclaim. The previous native PC=0 teardown loop is absent.

Library responsiveness and authenticated CS2 process creation remain unverified.

## Correction: extended VA did not promise a 512 GiB map

Earlier guidance incorrectly attributed the 63 GiB ceiling to missing EVA and
implied that re-signing would provide a larger map. The new device evidence
rules that out. Public Apple XNU source explains the observed behavior:

* [kern_exec.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c#L3578)
  treats JIT permission, increased memory and EVA as alternative reasons to
  request the same jumbo map.
* [vm_map.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/vm/vm_map.c#L21677)
  describes that policy as 64 GB.
* [vm_param.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/arm/vm_param.h#L153)
  defines `MACH_VM_JUMBO_ADDRESS` as `0xfc0000000`, exactly the measured limit.

These public sources predate iOS 26.6.1, but their constant and behavior match
independent task-info and allocation probes. Increased memory was already
present before EVA was added. A larger private kernel entitlement is not a
supported developer-app solution and must not be added or spoofed.

The delivered IPA's actual main executable requests EVA, increased memory and
get-task-allow; [41544564638](https://github.com/letsdothisagainx/Madeira/actions/runs/41544564638)
verified those values and the exact UUID without rebuilding it. Further signing
changes are not the next compatibility fix on this device. The in-app update
screen's earlier signing advice has been corrected accordingly.

## Exact Chromium allocation contract

[41552679648](https://github.com/letsdothisagainx/Madeira/actions/runs/41552679648)
inspected Valve's hash-verified current Win64 packages, without rebuilding the
Madeira IPA. The extracted chrome_elf.dll matches the captured FEX module
identity `chrome_elf.dll-c19aa5b303d01ae8`:

* AMD64, image size `0x166000`, Chromium `126.0.6478.183`.
* SHA-256 `6358830f96f36efa7516b3277cf69c1f132f97d4d93c365ccf061a7cf11e1e39`.
* PDB GUID `AAFBA60F-A38A-0B1C-4C4C-44205044422E`, age 1. No PDB function-name
  symbolication was obtained; the following evidence is from actual machine
  instructions and PE unwind boundaries.

The initializer at RVA `0x417f0` requests a 16 GiB pool aligned to 16 GiB, then a
second 16 GiB pool with a preceding 64 KiB guard. It registers each pool with
size 16 GiB. Total retained space is 32 GiB plus the guard. The first failed
`0x7ffff0000` request is temporary alignment over-allocation for the first
16 GiB pool, not a retained 32 GiB first pool. The second pool's fallback would
temporarily require 32 GiB.

This matches Chromium 126's three fixed random-address attempts followed by
[over-reserve and trim](https://github.com/chromium/chromium/blob/126.0.6478.183/base/allocator/partition_allocator/src/partition_alloc/page_allocator.cc#L240).
Windows uses ordinary VirtualAlloc; the inspected implementation has no
VirtualAlloc2 aligned-allocation route. Under the measured map, after retaining
a 16 GiB-aligned pool at 16–32 GiB, the upper tail is only 31 GiB; after placing
it at 32–48 GiB, the lower usable range is at most 28 GiB. Moving the FEX arena
alone therefore cannot finish this fallback sequence. Arbitrary fixed requests
must not be relocated, reservations fabricated, or Chromium checks disabled.
The saved `nrip=chrome_elf+0x4e0ca` is an error/lock-helper return, not a
symbolicated allocation caller.

The current Win64 manifest (version `1792618285`, ostype `win10`) has one CEF
package and one webhelper package; no newer OS-specific alternative was missed.
Its core references `bin/cef/cef.win64/steamwebhelper.exe`. No verified compatible
current 32-bit CEF route was found. Legacy flags or the old installed cef.win7
folder must not be selected merely because historical workarounds mention them.

## Cleanup bridge and validation

The native retirement callback issues NtFreeVirtualMemory. Previously a direct
Unix-to-PE call reused the active syscall frame and kernel stack, overwriting
the exit caller and restoring LR=0. Native hold-release and retirement now use
Wine's existing nested user-callback transition: a fresh chained frame and the
owned native user stack. Invalid owner/stack contexts refuse with bounded
diagnostics. Fresh restore flags and FPCR/FPSR packing are initialized correctly.

All 79 host checks, compilation and final ABI checks passed in
[41540474630](https://github.com/letsdothisagainx/Madeira/actions/runs/41540474630).
The ARM64 regression executes the actual callback and syscall dispatchers,
reproduces the old PC=0 failure, and validates repeated nested frees, dirty
stacks, owners, trace modes and preserved nonvolatile state. These results do
not prove native Steam Library or CS2 success.

## Legitimate CS2 launch path available for testing

The 19:06 capture confirms AppID 730's manifest and executable are present,
but contains no `native-steam-play-v1`, `-applaunch`, cs2.exe or game-action-error
event. It does not test a CS2 launch or establish current core authentication.

The existing route is Madeira Library → CS2 → Game details → Steam → Start with
→ Steam client → Play. Close the current Wine session first; relaunch Madeira
if its one-session guard requests it. NativeSteamPlay validates the existing
manifest, install directory and Steam library registration, then starts genuine
`steam.exe -applaunch 730`. Steam handles authentication, ownership and launch.
This route's behavior while Chromium fails remains unverified. It does not
replace the native Library, fake authentication or bypass VAC.

## The 19:52 Play attempt exposes a separate service startup defect

The next capture, still UUID `653A3A58`, does contain
`native-steam-play-v1 app=730 ... mechanism=steam-applaunch`. It starts the
native ARM64 command processor, then the AMD64 Steam service-preparation helper.
Before the batch reaches steam.exe, the real 32-bit SteamService.exe child
faults in native ntdll's PE-header lookup with a null module pointer. No cs2.exe
process or Chromium pool allocation is reached in this capture.

The child loader's snapshot is correct: guest ntdll `fff40000`. Its pool-only
native ntdll clone also contains that value, but GetProcAddress returns a data
export in the original session PE backing, which is correctly empty for the
ARM64 command processor. Both forms of access therefore disagree. Publishing
the child data into the shared parent would corrupt process isolation.

All 32-bit children now use a real private native ntdll PE image, even when the
session architecture matches their native host. The existing fresh-image path
writes the owner's startup block into both its private PE export and JIT alias.
Required guest32 startup addresses are validated before callbacks are published.
Native ARM64 and compatible hybrid AMD64 clone paths remain unchanged. The
bounded `wow-native-export-v1` marker records the actual PE export and guest
startup pointers.

The regression reproduces an empty parent PE export alongside a populated child
pool, then verifies private PE/export and alias agreement across alternating
native/hybrid parents and distinct owners. Missing, zero or out-of-range startup
data is rejected before publication; parent and sibling bytes remain unchanged.
This is a source fix for service startup, not a fix for the separate Chromium
address-space constraint. Service readiness, actual steam.exe -applaunch730
execution and CS2 process creation require a new device run.

## The 20:19 capture fails earlier: root DLL farm selection

The uploaded UUID `F14031EE-3E62-302D-8B74-CECB70A7B019` matches source
`cfd4ee6ce761ec0bc190a9c2ab5495105dd8be03`, built by Actions 41556960229.
The root ARM64 cmd.exe cannot load kernel32.dll (`c000007b`), before any service
child or Steam process starts. This capture therefore does not exercise the
private child-ntdll export fix or establish anything about CS2 execution.

The previous capture probes cmd.exe as `aa64` and selects the native farm.
This capture probes it as zero and selects the hybrid farm by path heuristic.
The native-only command processor is cross-linked into that farm, leaving it
with an incompatible hybrid kernel32.dll. Wine's architecture rejection is
correct. The architecture probe runs before generated prefix symlinks refresh;
a dangling link after bundle relocation reproduces this exact routing failure.
The log does not record why the original file probe failed, so the dangling
link itself remains inferred, while the wrong farm selection is directly logged.

Generated system executable paths now probe the current bundle that the farm
refresh will install, using the same native-first preference as a bare name.
Explicit sysaa64, sysx64 and syswow64 paths retain their separate architectures.
Custom application paths and prefix files absent from the bundle still use
their original files. The probe only reads files; it does not repair, remove
or replace user data. No Wine loader validation or child startup logic changes.

The regression compiles the production probe and routing functions under ASan
and UBSan, with dangling old-bundle links, readable old-architecture links,
mixed-case paths, explicit farms, invalid PE files, custom files and nested
paths. It is included in the Actions host gate. Device acceptance still requires
the root command processor to start, the service to become ready, genuine Steam
to accept `-applaunch 730`, and CS2 to create its real process. The independent
Win64 Chromium address-space blocker remains unresolved.

## The 20:49 capture reaches the real service's update handoff

UUID `3556F6F5-C95F-3343-931F-F41BB8B1F899` matches the IPA built from
`a43e51a684553d76ca43efae992d2814c6c84d06` in Actions 41559954039. The root
probe is now `aa64`, kernel32 loads, and both service children publish valid
private native startup exports. The capture contains no unhandled native fault.
It does not reach steam.exe or cs2.exe.

The original SteamService.exe (PID 0048) reports an official service version
update from `000a0029001a0019` to `000b000f0046001b`, creates
`SteamServiceTmp.exe /Update` (PID 0054), then exits zero before connecting its
SCM dispatch pipe. Wine's `process_send_start_message` correctly fails that
initial start with error 1053 when the original process exits. This is not a
30-second elapsed timeout. Madeira's preparation helper immediately propagates
1053, so its batch exits and the session stops while the updater is still alive.

Service preparation now keeps the original process identity while the SCM start
is pending. An update handoff requires the configured service's exact image,
its held process handle, clean exit, and an actual new child at the expected
SteamServiceTmp.exe path with matching parent and creation generation. It waits
for that specific updater within a deadline, checks its real exit status,
reopens the service and retries startup once. Old service handles are closed
before waiting so Valve can legitimately replace its service registration.
Only a genuine queried SERVICE_RUNNING state permits the Steam launch to
continue. Other failures, foreign helpers, timeouts and a second failed start
remain failures. No service keys, Valve code, authentication or VAC checks are
modified, and unrelated children are not kept alive.

The helper emits `update-handoff-v1` once. Packaging requires that marker and
byte identity between staged, bundled and zipped helpers, since a resource-only
change need not change the native Mach-O UUID. Tests cover the update handoff
and failures with production policy code. Real on-device service readiness,
Steam's `-applaunch 730` result and CS2 process creation remain unverified. The
independent current Win64 Chromium address-space constraint is unchanged.

## The 21:27 capture exposes a null TEB during forced cleanup

UUID `B7B46B26-57D0-3CFE-8F62-B441ECEE5565` and helper marker
`update-handoff-v1=1` identify source `bd607b56620f439c9183bd31a45201b245fcf3fd`
from Actions 41563906131. The helper holds the correct SCM parent PID 004c.
This time no SteamServiceTmp.exe process is created. SCM fails its pending
connection near its ten-second deadline and terminates the original service,
which was still doing certificate/cache work. The failed updater witness is
correct and remains a failure. The old log does not contain the raw wait result;
the new bounded SCM diagnostic distinguishes timeout, process exit, event and
wait error and records elapsed time and the actual overlapped result.

Forced cancellation of WinINet worker 005c enters FEX retirement and faults in
`user_mode_callback_return`: x3 is null and the first load reads address 0x378.
The dispatcher had retained its TEB with `mov x19,x18`. iOS can clear reserved
x18 between instructions; copying zero does not cause the TEB memory-access
exception that normally recovers a load/store. Successful retirement can then
return through a null retained pointer. The dispatcher now loads the already
validated TEB from callback arguments that remain alive until return.

The ARM64 regression clears x18 before every instruction while modeling the
existing Mach handler's TEB load/store recovery. Restoring just the old MOV
reproduces the exact read at 0x378 after a successful callback. The corrected
instruction preserves return state across 256 callbacks, two owners, both trace
modes and nested frees. The new `fex-callback-v2` packaging marker rejects the
old native bridge.

The SCM producer separately uses Windows' documented 30,000 ms default instead
of Wine's 10,000 ms and accepts the documented DWORD ServicesPipeTimeout value.
Finite valid legacy decimal strings remain supported; malformed, zero and
infinite values leave the default intact. See Microsoft's [default-timeout
documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/windows-trace-session-manager-service-not-start-event-id-7000)
and [DWORD configuration documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error).
This does not prove that Valve's certificate/update work finishes within that
deadline, nor that cache/signature work is otherwise correct. The preparation
helper retains its separate 35-second call safeguard.

Only the existing native ARM64 services.exe is rebuilt, using a temporary
overlay with source restoration even after failed builds. Its existing native
crosslink in hybrid sessions is preserved. The package gate verifies native PE
architecture, the new SCM marker and staged/bundled/IPA byte identity. The helper
also stops querying SCM once the original process identity is pinned; it keeps
the same bounded child observation and genuine readiness checks. No installer,
authentication, game files, Wine prefix reset or security checks are changed.

Device acceptance remains: no 0x378 callback fault during forced cleanup, actual
SCM wait outcome, successful updater completion and SERVICE_RUNNING, followed
by genuine Steam and CS2 process creation. Library and CS2 remain unverified;
the independent Win64 Chromium address-space limitation is unchanged.

## The 22:24 device run confirms the service and callback fixes

The next capture has the expected native UUID
`B5BFDE63-90AD-377B-ACBB-BDB9E14E2B0A` from source
`285e988c894899c969038640aee844911374704a`, Actions 41568566518.
The original service exits during its genuine update at 12,429 ms, within the
corrected 30,000 ms SCM wait. The new trace explicitly reports `process-exit`,
not timeout. The updater witness is one, its real exit code is zero, the
replacement service connects in 280 ms, and the helper queries state four
(`SERVICE_RUNNING`) and returns zero. Both forced worker and main-thread FEX
retirement callbacks return successfully; no null-TEB read at 0x378 recurs.

The batch then really creates AMD64 steam.exe with `-applaunch 730`. These are
device-confirmed startup improvements, not just CI results. They do not establish
that the native client finishes authentication or launches the game: this
capture contains no cs2.exe creation or native authentication-success result.
Madeira's separate SwiftSteam signed-in/ownership records are not such proof.

Every browser attempt fails in chrome_elf.dll DLL initialization, before a CEF
page or Library store is observed. Thirteen helpers abort with `80000003` at
the same chrome_elf offset `dc104` after the large PA reservation fails. High
fixed 16 GiB hints exceed the actual task map; the roughly 32 GiB alignment
fallback (`0x7ffff0000`) also fails. Its first scan covers a 16 GiB band;
the existing high-side retry then searches above the WoW64 windows. Neither
can fit that request: the Wine ownership census's largest free contiguous
span is about 17 GiB. Other map
summaries omit logical reservations or are truncated; they cannot authorize
overwriting guest windows. The task still reports a 63 GiB map with both
increased-memory and extended-VA entitlements already active. No supported
signing change, guessed fixed-hint relocation, fake reservation or skipped
Chromium check is justified by this evidence.

Two apparent secondary faults are not established blockers. The exact official
current Win64 core package inspected in Actions 41552679648 includes x86
bin/SteamService.dll and SteamService.exe, without a SteamService64.dll. The
AMD64 SteamServiceConnect thread's architecture rejection is followed by normal
exit zero, so replacing that official DLL is unwarranted. The seven fdtrace
`CROSS!` warnings all refer to communication descriptors whose consumer threads
already exited; normal thread closes do not retire that diagnostic ledger, and
cached-file registrations do not populate it. They do not prove that retiring
helpers closed surviving Steam threads' descriptors. A close guard based on
that stale ledger would leak legitimate cached files.

The `Wine finished after 110.5s` line is also not a process-exit result: it follows
the existing first-present debugger-detach heuristic, and Steam continues
creating helpers afterward. That line and the generic dll-missing suffix must
not be used as proof of session termination or of a Chromium DLL dependency.

The current IPA remains the last built runtime candidate. There is no new
validated runtime fix or new IPA from this capture. A correct guest address-space
solution is still needed before the real Library and authenticated CS2 launch
can be accepted. No installed game, prefix or account data was reset.

## Correct native placement around separated WoW64 windows

The native allocator searched below and above the collection of WoW64 windows,
but omitted gaps between separated windows. This is a real false
`STATUS_NO_MEMORY` condition when a middle gap can satisfy a caller's request.
The new fallback searches every remaining segment within the original placement
bounds, while retaining live and retired reservations, unadopted placeholders
and owned 16 KiB guards. Existing Wine view and kernel mapping checks still
decide whether a candidate is available. Fixed-address requests are unchanged.

FEX reservation authority is captured from the original request, separately
from the derived segment bounds. A generic native request cannot acquire FEX
ownership merely because a middle gap happens to match the arena. Logging is
limited to the first 32 segmented searches, and final IPA validation requires
the compiled `wow-placement-v1` marker.

The source regression executes the production segment search with a real
32 GiB, `PROT_NONE` mapping in an owned virtual test arena, in both directions.
It also covers caller limits, guards, placeholders, reused slots, ordinary
reserved mappings and the FEX authority boundary. The captured map is a separate
negative case: WoW64 windows at 16–20 and 24–28 GiB, their 16 KiB guards, JIT
aliases at 12–14 GiB, and FEX at 45–53 GiB leave a largest gap of
17 GiB minus 16 KiB. The test requires the real Chromium-sized reservation to
fail there. This correction does **not** solve the captured browser failure.

Chromium 126's Windows fallback also requires a second, real 32 GiB temporary
reservation for its backup-reference-pointer pool. Even an otherwise nearly
empty 63 GiB task map cannot accommodate that fallback after retaining the
first aligned 16 GiB pool. Returning a shorter reservation, changing a fixed
hint, mapping the null page or removing the security check is not a valid fix.

Read-only inspection of the official browser packages additionally rules out
a blind DLL substitution: Valve's current Win64 libcef has a different API hash
and eight helper-required exports absent from stock CEF 126. The coherent
official I386 browser has a different private HTMLIPC schema from the current
AMD64 core, including renumbered browser-creation fields and new resource-routing
commands. A payload translation model is not evidence of a working transport or
compatible rendering/security semantics. No such substitution or protocol
workaround is enabled by this patch. Native Library and CS2 launch remain
unverified and blocked by browser initialization.

Read-only Actions inspection 41578716240 also checks the live official public
beta manifest (version `1793235415`). Its CEF archive differs from stable, but
the extracted chrome_elf still reports Chromium `126.0.6478.183` and the same
unconditional 16 GiB regular/backup-reference-pointer pool allocation sequence.
Switching the user's update branch is therefore not justified as a fix, and
no branch setting was changed. The same inspection extracts the real current
and I386 helper protobuf descriptors; they confirm the schema differences
rather than establishing a compatible transport adapter.

Inspection 41578816318 identifies the actual modern factory:
`bin/chromehtml.dll` exports `CreateInterface` and registers
`ChromeHTML_Controller_003`, which SteamUI requests. The caller then uses a
controller interface whose complete layout was not established by that first
inspection. A later full dump corrects the earlier interpretation of the large
SteamUI caller: its returned-object offset-eight access belongs to a different
factory, not ChromeHTML. The actual `003` acquisition is at RVA `0x596a6d`, and
CHTMLController has one primary interface. Its current 42 slots differ from the
January component's 43; IHTMLResponses also changes from 67 to 64. Neither the
public `Controller_001` declaration nor the shared `003` name proves compatible
method arguments or callbacks. No direct component swap or guessed vtable proxy
is enabled.

The live official Win32 stable and public-beta manifests were checked separately
in inspection 41580202903. Both return HTTP 200 and are byte-identical, version
`1769731672`, with the same verified I386 browser/helper pair. There is no newer
Win32-beta browser in those manifests to substitute without the unresolved
protocol work.

Actions 41578723650 builds the placement correction from source
`581758fee97eb8e5a43160012e069376fbfefb57` (tested merge
`477ec686a8d4f8a1a6df7bdc20401935960aaddc`). All 82 registered host commands,
native SCM compilation, actual ARM64 callback execution and final package/ABI
checks pass. The IPA artifact is 13205004492; its native UUID is
`E1BBFC97-C862-3D6D-92E4-DE11B0810733`. This build verifies the source correction,
not Steam readiness: it contains no demonstrated fix for the captured CEF
failure and must not be presented as a working Steam/CS2 build.

## The 05:11 capture proves the trap and a separate CEF backing leak

`madeira-log(20261103-051156).txt` has native UUID
`E1BBFC97-C862-3D6D-92E4-DE11B0810733`, matching source `581758f` and
Actions 41578723650. Fourteen browser attempts repeat the same failure before
any CEF page is ready. This supersedes the older black-dialog investigation.

Exact-image inspection [41584493073](https://github.com/letsdothisagainx/Madeira/actions/runs/41584493073)
checks the archive hash, the chrome_elf SHA-256 listed above and its captured
FEX module identity. The initializer at RVA `0x417f0` requests the first 16 GiB
pool. Three exact high-address attempts fail, followed by two unhinted
`0x7ffff0000` temporary reservations. The second unhinted attempt is Chromium's
normal retry after releasing its emergency reservation, not a Madeira-created
restart. No first pool succeeds and the BRP pool allocation is not reached.

The null result takes `0x41833 -> 0x418e0 -> 0xdc080`. The recorded allocation
error is Windows `ERROR_NOT_ENOUGH_MEMORY` (8); the instruction at `0xdc0df`
calls the distinct `HandlePoolAllocFailureOutOfVASpace` leaf at `0xdc0f0`.
Its trap is `INT3` at `0xdc104`; bytes there are `cc cc 0f 0b`. The following
UD2 is not executed. The stack value `0x2f` is the source line retained by
`PA_NO_CODE_FOLDING`, not Steam's unrelated AppError_47.

FEX's INT3 lowering records SIGTRAP/BP and the next guest RIP, then enters the
dispatcher ARM `BRK #0`. Wine's intermediate native `C000001D` is reconstructed
by the existing FEX exception converter as guest `80000003` at `RIP-1`, exactly
`chrome_elf+0xdc104`. Wine receives that guest exception, fails DLL initialization
and terminates the helper. This is not evidence of an unsupported x86 opcode.
Static initialization callers are traced, but their complete C++ constructor
names were not symbolicated. The allocation trace's `nrip=+0x4e0ca` follows a
lock-release helper and must not be presented as the allocation callsite.

The original images are a separate proven lifetime bug. For example, a private
libcef image at `0x3bdca0000` has size `0xd3ca000`; after its owner retires, the
physical map still shows 128 MiB and 48 MiB of dirty resident original backing.
FEX owner views all return to zero, and pool copies are reused, so neither fact
proves that the original image backing was freed. Footprint reaches 5,544 MiB.

The source patch tags only full, private AMD64 libcef/chrome_elf image views in
native steamwebhelper with their immutable owner lease. After CPU callbacks,
JIT copies and FEX data retire, it uses normal Wine view deletion while the
original generation is still registered. Live, shared, builtin, hybrid,
resource, foreign and referenced images are retained. A rounded 16 KiB host
span must also exclude other Wine views and anonymous aliases; real 4 KiB tail
canaries verify that the cleanup cannot erase a neighbour. Physical reduction on
the iPhone remains unmeasured; diagnostics report logical image bytes only.

Native process-group and identity slots also lacked the WoW teardown path that
recycles them. The patch releases quiescent native metadata after all memory
cleanup, validates generation during delayed thread exits and serializes
identity writers. Pending native reapers/TEB handoffs remain protected. Tests
reproduce the old 64-slot exhaustion and identity-publication race, then run
160 lifetimes, concurrent registrations and recycled-PEB cases.

AMD64 generated INT3 diagnostics now use the producer's CHPE CPU-area frame and
thread pointers, owned FEX code and the actual guest `cc` byte. Recognized
events still return failure to the Mach handler so the unchanged guest exception
chain runs; no trap is skipped or asserted initialization marked successful.
The actual FEX exception converter and ARM64EC RIP adjustment are regression
tested separately from this diagnostic observer. Native HLT, UD2, stale/foreign
state and genuine native faults retain their existing diagnostic path.

No CEF flags, security checks, DLL binaries, physical/JIT budgets, authentication
or installed files are changed. `--single-process` and `--jitless` are already
present in the capture; the failure occurs before V8. Windows PA pool sizes are
compiled constants, unlike Chromium's iOS build. No safe current-binary runtime
adaptation was established, and a smaller chrome_elf alone would leave libcef's
independent allocator unchanged. These teardown/diagnostic fixes do not establish
successful browser initialization, responsive Library or authenticated CS2 launch.
