# CS2 follow-up to source 4b41f1dd

This change preserves the working CS2 menu, Steam service, official Chromium
IPC, Wine prefix, game installation, input and DXMT configuration. It does not
establish VAC eligibility or a correctly rendered practice map.

## Evidence and security boundary

The attached `madeira-log(20261109-024842).txt` identifies source
`4b41f1dd7603612e1596ac885d0b883fa601cf26`. The screenshot itself was not
available in this workspace. The quoted signature warning and 27 FPS / 37 ms /
5456 MB screenshot measurements are user-provided evidence.

The effective game command is `cs2.exe -steam -condebug -joy`. No insecure-mode
flag was found. Steam API initialization and genuine Steam launch work. The
log does not expose a rejected filename, signature verifier HRESULT, or secure
connection result. No argument is removed merely because it appears in this
command. No official game or Steam binary is modified.

**Confirmed source defects, corrected:** Madeira's content downloader checked
fresh chunks by size and Adler-32 without their manifest SHA-1, and trusted
resume-journal entries without rechecking current bytes. The production
downloader now checks the chunk SHA-1 before writing/journaling and rehashes
journaled chunks against the requested manifest. The manifest parser retains
the actual whole-file hash field. See [content integrity](STEAM_CONTENT_INTEGRITY.md).

**Not established:** those defects caused this installation's VAC warning.
The existing phone installation was not remotely inspected or automatically
repaired. Cached content hashes and certificate-table presence do not prove a
trusted signature. The bounded read-only audit records those limits explicitly.
It runs off the UI thread, stops when Wine or a managed download becomes
active, and never delays or determines launch readiness.

An optional scoped Wine `WinVerifyTrust` observer calls the original verifier
unchanged and records its real return value, action GUID and safe basename.
It preserves LastError, verifier state and exceptions. It is enabled by default
only for native Steam AppID 730; it can reveal an ordinary trust-API failure
if Valve uses that API. It cannot observe a private verifier's internal reason.
It never changes a trust decision or marks a session secure.

The `SteamServiceConnect` load of I386 `steamservice.dll` into AMD64 Steam is a
real architecture mismatch. The service itself reaches running state, and no
official matching 64-bit DLL was established. Forcing that DLL into the process
would be incorrect. Its relationship to VAC remains an unproven hypothesis.
If Valve requires a secure environment Wine/FEX cannot provide, that remains a
compatibility limitation rather than a condition this patch can bypass.

## DirectX first-time setup

**Confirmed:** exact-IPA inspection found I386 `regsvr32.exe` and `rundll32.exe`
but neither native AArch64 nor ARM64EC counterpart. This is an incomplete Wine
system-program set. The build now compiles the genuine stock Wine utilities for
both native architectures, preserves the existing I386 utilities, and verifies
their architectures, imports, hybrid metadata, source provenance and exact
app/IPA copies. Their real DLL-registration calls and failures are preserved.

**Strong hypothesis, not yet a device result:** the missing native utility
explains DirectX's later `RegisterDllFromSection` / CreateProcess error 2. The
old log does not identify the exact failed executable. Failure-only image-search
diagnostics now record a bounded basename, path class, ABI and actual error
before the native process-creation boundary, without command lines/private paths.

The seven DirectX plugin children in this capture exit zero. The previous
unrelocatable 4 GiB image problem is not repeated here. DirectX still ends -9.
Of its 169.767 seconds, 138.212 elapse before the first plugin request, 28.197
between the first request and final plugin exit, and 3.358 in subsequent
registration/cleanup. Plugin child lifetimes total 16.619 seconds. These
overlapping intervals do not attribute every second to CPU execution.

The existing startup clock records process requests, entry, dispatch, exit and
quiescence for Steam, service, installscript, DirectX/plugin and CS2 stages.
No synthetic main-menu or practice-map readiness is emitted. The first-plugin
delay and final legitimate installer completion still require a device run.
Only a successful official installer may establish its persistent completion
state; no Steam registry/installscript result is fabricated or pre-marked.

## Exception overhead

**Confirmed and corrected:** exact IPA symbols/instructions identify native FEX
telemetry, IR diagnostic counters and CompileBlock counters writing their RX
copy. Explicit private, source-built writer contracts bind only those validated
spans to the same backing's RW alias before publication. Genuine atomic
operations and diagnostic payloads remain. The surrounding process leases,
generation ledger and RX protection remain in force. Unknown contracts use
existing recovery. No arbitrary guest stores are rewritten.

The CompileBlock candidate estimator also had a reproducible two-thread
decrement underflow and duplicate summary race. A nonblocking approximate
sampler and unique atomic report tickets fix these while preserving exact
dispatch/compile totals. See [producer evidence and measurements](FEX_NATIVE_DIAGNOSTICS.md).

Apple ARM64 run [42557493889](https://github.com/letsdothisagainx/Madeira/actions/runs/42557493889)
executes real Mach faults and the production recovery/getters. For eight threads
and 3,200 operations:

| Production operation fixture | Before faults | After faults | Before / after handler CPU |
| --- | ---: | ---: | ---: |
| Captured telemetry STSETL, source-selected addresses | 3,200 | 0 | 24.385 / 0 ms |
| Actual staged IR diagnostic increment | 22,500 including retries | 0 | 227.720 / 0 ms |

Results and adjacent bytes match, RX remains nonwritable, RW nonexecutable.
These are bounded fixture measurements, not a predicted phone FPS increase.
Other genuine locks, per-thread history and guest self-modification remain.

## Rendering and memory

No demonstrated BC7, sRGB, typeless-SRV or shader translation defect was found.
The inspected DXMT paths retain the correct linear/sRGB formats and view
capability. API/Metal counter success does not prove correct final pixels.
The sparse view diagnostics are not a census of every bound view.
The missing-resource warnings do not prove corrupted assets. The audit reads
fixed critical files and available exact installed-depot references without
inventing optional resources or modifying archives.

The sampled GPU work (1.8–2.3 ms) is much shorter than CPU inter-present gaps
(roughly 464–499 ms in those samples). The screenshot's 27 FPS is a different
moment. No speculative rendering-feature change or asset replacement is made.

The 1152 MiB shared-backing RX/RW pool, 240 MiB image-headroom policy, certified
retired-code recycler and explicit per-image FEX heaps remain unchanged. Alias
virtual sizes are not counted as two physical copies. Peak footprint near
5865 MiB remains close to the approximately 6144 MiB device budget. The existing
`vram-trim-mb=4096` is a safety margin below the kill line, not a 4 GiB VRAM cap;
raising it blindly would be unsafe. Current counters do not prove a reclaimable
resource leak, and no live textures, code generations or owners are discarded.

## Device comparison still required

| Metric | Tested 4b41 device evidence | New implementation on iPhone |
| --- | --- | --- |
| Steam process creation | t+10.6 s, app-monotonic clock | Unmeasured |
| CS2 process creation | t+413.0 s | Unmeasured |
| Interactive menu / practice-map time | Menu reached; exact readiness times unmeasured | Unmeasured |
| Menu FPS / frame time | User screenshot 27 FPS / 37 ms | Unmeasured |
| In-game FPS | Unmeasured | Unmeasured |
| Sampled CPU inter-present / GPU work | 464–499 ms / 1.8–2.3 ms; different workload from screenshot | Unmeasured |
| Whole-session emulated stores / handler time | 57,051,750 / 249,963 ms | Unmeasured |
| Comparable per-second fault rate | Not established by aggregate totals | Unmeasured |
| Peak footprint | Approximately 5865 MiB | Unmeasured |
| Missing graphics | Reported, precise pixel cause unresolved | Unverified |
| VAC signature warning / secure connection | Warning reported, no successful secure connection established | Unverified |

The earlier 9d44 run has a different duration, workload and clock origin;
aggregate totals are not a valid performance percentage comparison.

Update Madeira in place through SideStore, using the same signing account and
bundle identity (`com.willfaust.madeora`). Do not delete the installed app.
The produced IPA is ad-hoc signed for subsequent SideStore signing, not signed
with the user's Apple Developer credentials by CI. No prefix/data migration,
manual phone file edit or game reinstall is required. A rollback is an in-place
installation of the prior IPA with the same signing identity; it does not undo
Steam's own legitimate installer activity.
