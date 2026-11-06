# CS2 prerequisites and native counter writes: November 6 capture

Installed source: `69aa48b43dc908500e293278d6d575bde455d753`.
Exact packaged images were inspected from IPA run42166957510 in read-only
Actions42174258413; the FEX callee was checked in42174861623.

## Device evidence

Service result0/SERVICE_RUNNING, all three SCM event completions, actual I386
and native64 SteamChrome sections and owned mutable debug-log routing are now
observed on the iPhone. No previous FEX/CallRetStack allocation failure or
BMainLoop stall assertion is present. These paths are preserved.

Steam runs the genuine AppID730 installscript. The x86 prerequisite graph is
0374 ->038c ->03a4 ->03bc ->03c8 ->03e4: script, CMD, start/w, original Burn,
cleanroom and elevated installer. The elevated/original/cleanroom processes
and wrappers propagate exit0, and the parent starts the x64 CMD. Minimum and
Additional runtime dependency records appear, but full MSI completion logs and
an independent registry/file audit are absent. The capture ends only about four
seconds into the x64 stage. No x64-installer, DirectX or CS2 outcome is established.

The cleanroom worker's fault is wcslen(NULL): ECX0 + EAXfffffffe +2 wraps to guest
zero. Exact I386 ntdll +5e650 is wcslen+10; kernelbase +58a71 returns from that call
inside KERNELBASE_lstrlenW; +68e90 is __wine_exception_handler_page_fault. Wine's
API deliberately catches this AV, returns0 and sets ERROR_INVALID_PARAMETER.
Context recovery and host-to-guest exception conversion preserve the correct
address. Worker and process later exit0. No NULL mapping or exception bypass is
appropriate. The native `UNHANDLED` label does not establish a fatal Windows AV.

## Verified address-path defects and corrections

The exact native EC ntdll SHA is
84482e7f68fbfe37812292042fbe038f03eaa7d452765956507946f4d11609dd.
RtlQueryPerformanceCounter +230/+238 (RVA73818/73820) executes indexed STR and
STP into its own exported diagnostic block's RX copy. The A64 image's equivalent
site is RVA76120. These are native diagnostic writes, not guest self-modifying code.
The source overlay keeps the 24,712-byte counter layout and sampler export,
introduces an explicit private writer contract, and routes the existing accesses
through its getter. Only an unpublished owned image binds the contract to the
same bytes through its retained RW alias. Child copies and unloaded-image rebuilds
bind independently after relocations; a parent's pointer is never adopted.
Later PE data synchronization preserves only this already-validated eight-byte
host-private slot instead of transiently copying its NULL file initializer.
All other bytes retain ordinary data-sync behavior, with no live rebinding.
No new allocation, Windows API result or mapping permission is introduced.

Exact WoW64 FEX SHA6a6e905dbd3adb251e9f8bdae44b21d52829226f2b6949aa1b0bde6545ebc20d
identifies the STXR at17fbc as LookupCache::UpdateDynamicL1Stats's IosL1Misses
increment. The existing planner refused its X8 address because a later call might
consume an implicit result pointer. The actual chrono callee overwrites X8 before
reading it. A bounded straight-line direct-target proof now establishes that kill;
indirect, external, unknown, branching or read-before-kill callees remain rejected.
Only the existing private-copy ADRP relocation changes; the LDXR/ADD/STXR retry,
values, branches and ordering remain native. No FEX submodule code is changed.

The 54 complete million-event epochs have no census overflow. Their top-two keys
per family are exact selected counts, not complete attribution of all54million.
Other FEX telemetry and IRTopoChecked sites remain; this correction does not
claim to eliminate every fault. Session totals cannot establish an improvement
against the shorter baseline, particularly with Low Power Mode enabled.

## Matched Apple ARM64 validation

Validation42176908549 uses the actual staged QPC source and actual production
Mach-store decoder, with clock/thread API and exported-address fixture adapters.
It does not execute the Windows COFF QPC image on macOS. The FEX fixture executes
the captured function bytes, with address relocation and a clock-backend shim
that retains the verified callee prologue; its atomic/retry/branch bytes are intact.

| Operation | Baseline faults | Corrected faults | Baseline wall | Corrected wall | Baseline handler CPU | Corrected handler CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| QPC, 4 workers / 3,000 calls | 6,000 | 0 | 72.647 ms | 0.203 ms | 50.439 ms | 0 ms |
| FEX counter, 2,000 increments | 5,111 | 0 | 56.785 ms | 0.184 ms | 54.642 ms | 0 ms |

Clock agreement, exact QPC histograms/calls, unchanged counter values, original
exclusive retry, RX nonwritability, RW nonexecutability and independent successor
binding pass. A second private QPC image also has zero faults without changing
its predecessor. Portable production tests cover1,069 full/partial/split source copies,72 binder,
44 staging/PE and27
direct-callee contracts. Actual A64/EC native producer compilation and packaged
contract/NULL-slot/no-DIR64 gates pass in42176177864. The old production X8 guard
rejects the captured FEX producer; the corrected guard accepts it and rejects
unknown, escaping, branching and read-before-kill cases.

## Acceptance still required

Matched production-path Apple ARM64 regressions measure the corrected operations;
they are not Steam-on-iPhone measurements. A new device run must verify genuine
x64 prerequisite completion, continued service/IPC operation, strict cache reuse,
lower comparable fault cost and real CreateProcess(cs2.exe). Only after that
should phonon, steamaudio and scenesystem be assessed. No installer statuses,
registry success, authentication or game launch are fabricated.
