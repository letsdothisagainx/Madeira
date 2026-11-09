# CS2 follow-up to 8bd3785c

This pass uses the November 9 `201100` Madeira capture. Its game launch and
menu are working; no successful VAC-secured server connection is recorded.
No newer standalone console or VAC diagnostic ZIP accompanied this capture.
The only user-marker record is `process-observed`: there is no `test-begin`
or `error-reported` timestamp to correlate with the reported popup.

## VAC: actual changes and evidence limits

The existing game arguments remain `-steam -condebug -joy`, with a complete
three-argument observation and neither insecure nor third-party flags. Eleven
selected files match cached references, including internally consistent signed
VPK directory files. These are not authenticated full Steam verification.
The VPK parser and signature/security decisions are unchanged.

Game details now offer **Steam → Verify files with Steam** while Wine/storage
work is inactive. This runs the existing genuine client preparation with
`steam.exe ... steam://validate/730`, without `-applaunch`, game arguments or
a profile save. Retained Valve UI source registers this URI to its own
`VerifyAppFiles`/`SteamClient.Apps.VerifyApp` flow. The action records only
`requested`, `result=unobserved`, `completion=steam-ui`. Steam owns any
authenticated manifest fetch, repair, progress and completion. The next phone
test must observe its actual result; a launch request is not verification.

The read-only module inventory expands fixed public candidate names and exact
paths. A future accepted mapping must match the complete known root/path;
old redacted paths cannot be reconstructed from a basename. The new header
observation records the loader's Wine-builtin flag and raw machine/hybrid
fields. Catalog roles identify layouts, not publishers or authentic signatures.
Private/unknown files remain explicitly unmeasured, not malicious or unsigned.

A fault-safe guest PEB snapshot runs after successful server process
initialization and before guest entry. It reports BeingDebugged and
NtGlobalFlag, or unmeasured on failed/partial reads. It changes neither field,
does not query or hide the host debugger, and is not a complete guest API
debug-state inventory. StikDebug or a PIX message alone cannot establish the
Windows guest Boolean.

The real service in this run is PID 004c (main TID 0050, worker 0064), with
SCM state 4 and genuine pipe events. Separate AMD64 Steam PID 0068/TID 00b0
fails its service-DLL load. The actual failed file's header/hash and call flags
remain missing; no architecture guard, service status or Valve DLL is changed.

The existing [Trusted Mode research](CS2_4711_VAC_EVIDENCE.md) remains relevant:
Valve does not document iOS/Wine/FEX support, and its trackers contain matching
Windows-CS2/Proton signature warnings. This is a compatibility lead, not proof
of an immutable platform ban or this session's rejected component. Networking
certificates, relay readiness, loopback play and a running service remain
separate from VAC approval. Secure matchmaking is unresolved.

## Display and rendering

The old 640×480 selection comes from the saved per-game request, which outranks
the global `desktop-size=800x450`. It is not evidence of a Metal capability
failure. Existing choices are preserved. **Use app default** explicitly opts
into the app/global resolution; **800×450** and **960×540** are selectable.
One validated resolver now supplies desktop arguments, monitor publication and
source logging. A separate proven bug blindly replaced a deliberate 1408×648
selection on an iPad; that destructive reset is removed.

An app default is not an instruction to stretch pixels. The game still owns
explicit swapchain sizes. Select 800×450, restart the session, and compare the
reported Wine monitor with the new bounded native layer/drawable/attachment/
viewport observations. A different game-chosen backbuffer remains observable
rather than silently rewritten. Higher modes are opt-in; no pool, VRAM or
jetsam limit is increased.

No texture, material or shader correctness defect was demonstrated by counters
or a sampled DXBC parser stack. Native BC support and sampled sRGB views work,
but do not prove final pixels. The bundled hardware-only D3D11 pixel probe
provides 113 real offscreen readbacks. Its host tests validate input vectors and
actual PE packaging; GPU results still require the phone. See
[rendering evidence and exact UI steps](CS2_RENDERING_20261109.md).

## Bounded native-write correction

Inspection of the exact installed 8bd CPU images proved that the leading GPR
sites update FEX's private four-slot call-return diagnostic history. The three
reported sites account for at least 6,936,355 exact observed events; overflow
and top-site limits prevent whole-run extrapolation. Genuine invalidation
synchronization and unrelated exclusive operations are excluded.

The owned downstream producer now exposes one additional 192-byte history
writer contract, bound to its own validated RW alias before publication. Every
history operation, volatile access, index/collision rule and initial value is
preserved. Four-span metadata survives DATA refreshes. No guest store is
rewritten, native synchronization disabled, RX protection weakened, live code
reclaimed or FEX/JIT pool enlarged. Packaging rejects stale CPUs and the old
three-span native binder.

Production tests compare original/unbound protected writes with the bound
writer, including all 192 payload bytes, neighbors and protections. A real
Apple Mach workload measures faults and elapsed time separately from actual
CS2 performance. Device FPS, total fault rate and peak memory remain unmeasured
for the new build. The previous 6049 MiB footprint remains a capacity concern.

## Phone acceptance and rollback

Update Madeira through SideStore with the same account/app identity; do not
uninstall it. Request genuine Steam verification and retain Steam's actual
result. Select the desired resolution through the game's Madeira details.
At the real game menu, use **Begin VAC Test**, press Play once, then **Mark VAC
Error** immediately if the popup appears. Export the compact ZIP. The user
marker timestamps a report, not an internal security decision.

Capture the Wine/native geometry records and, separately, the pixel probe's
actual result. Only a real VAC-secured connection and real CS2 frames satisfy
their respective acceptance criteria. Missing graphics, secure acceptance and
the legacy DirectX failure remain open until demonstrated otherwise.

Rollback is an in-place SideStore update to the previous 8bd IPA; keep app data.
There is no prefix migration. Older builds ignore the optional inheritance
field and retain the saved explicit resolution. Genuine Steam repairs, if
requested, are Steam's normal operation and are not undone by an app rollback.
