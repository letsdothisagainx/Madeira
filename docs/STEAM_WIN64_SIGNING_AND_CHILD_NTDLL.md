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
