# CS2 marked follow-up to 4a70400

This pass uses the November 9 `225348` Madeira log and the supplied
`Madeira-Steam-CS2-Diagnostics.zip`. No VAC-secured connection or independently
authenticated full Steam verification result is present. The warning is still
unresolved; a successful build or a local game is not secure-play acceptance.

## Marked attempt and content trust

The app records a test at 22:51:46.317 UTC, touch dispatch at 22:51:49.722 and a
user error report at 22:51:55.489, with device offset -300 minutes. The console
has a generic-confirm localization warning at `11/09 17:51:50`. Under the stated
assumption that its unknown year/zone match the device's local wall clock, that
warning follows the touch and precedes the report. Neither the warning nor the
user report identifies the popup body, a rejected file or a security decision.
App DispatchTime and Wine POSIX monotonic counters remain distinct domains.

The real export contains 503 selected console events, 487 of them repeated
network performance warnings. Its byte snapshot is truncated, but its record
quota omitted zero rows. Both generic-confirm warnings survived. A regression
with more repeated rows demonstrates the old forward-selection starvation;
the corrected collector retains fixed high-priority events and assumed nearby
context, samples at most 32 performance warnings, and counts omissions. These
are selections within a bounded head/tail read, not a complete console copy.
Newest error anchors are chosen in their own app clock domain, independently
of source-consumption order. No arbitrary raw Steam-log grammar is invented.

Cached PE hashes and VPK consistency are unchanged. The capture contains no
genuine Steam verification completion or exposed trust-API rejection. The
existing **Verify files with Steam** action requests the real client workflow;
only its actual result can establish authenticated verification/repair. No
Valve binary, signature, trust response or launch-security flag is changed.

Valve documents Windows/Linux, rather than an iOS/Wine/FEX secure-launch
contract. Its Windows-CS2/Proton reports contain the same warning, including
verified-file cases; see [the earlier support research](CS2_4711_VAC_EVIDENCE.md).
This supports a compatibility hypothesis, not an identified immutable platform
ban. The exact rejected component/requirement remains unknown.

## Service architecture and truthful observations

Service PID 004c is I386 and successfully maps its DLL and observed dependencies.
Its real state 4 and result 0 are present as interleaved output fragments.
Separately, AMD64 Steam PID 0068, thread 00b0, rejects a service-DLL load with
`c000007b`; the fallback fails with `c0000135`. The export-time service DLL and
EXE header candidates are 014c. Rejecting a 32-bit DLL in a 64-bit process is a
valid loader check. Candidate headers are not proof of the exact failed binding,
complete imports, publisher trust or a connection to VAC.

Wine's unbuffered printf emits the old service record in five separate writes;
concurrent native diagnostics can split even `service-state=4`. The exporter
correctly refuses those torn lines. The owned launcher now emits one bounded
numeric stderr record, preserving LastError and genuine SCM results. Failure or
short writes do not invent a state. Summary false means not observed, rather
than stopped. No Wine architecture rejection or service protocol is weakened.

## Rendering lifecycle

The virtual monitor remains 800x450. SDL's initial visible client rectangle is
640x450, followed by the same DXMT layer request and acquired drawable size.
No native Metal downsize is demonstrated; the game/client request must remain
distinct from the monitor size. No resolution policy changes are made here.

The log contains actual `MTLCommandBufferErrorDomain` error 7, with explicit
`BackgroundExecutionNotPermitted`. DXMT directly committed GPU work while
UIKit was inactive. The owned native staging now gates submission by the real
UIKit lifecycle, preserving queued encoded work and FIFO ordering. Worker
threads condition-wait while inactive; UIKit itself never waits for activation.
Its setter may briefly serialize behind a native commit. Actual statuses,
errors, completion handlers and already-submitted buffers are unchanged. This
does not promise to drain all in-flight GPU work or retry failures.

Tests exercise the production queue, cancellation and 8,000 exact-once
submissions through 10,000 transitions. Actual phone suspension/resumption is
still required. The observed background failures do not prove the cause of all
missing scene content. No BC/shader semantic defect is established by the trace.

The 113-readback probe was not run in this capture. It is now reachable from
normal **Settings → Diagnostics → Run D3D11 pixel test**, using the ordinary
JIT/session flow and a transient profile. It stages only the owned bundled test
into a new private directory without overwriting prefix files or saving a
library entry. See [pixel coverage and limitations](CS2_RENDERING_20261109.md).

## CPU pressure and limits

All four previous native diagnostic spans bind successfully. Their former
history-store PCs do not appear in the bounded top-site reports. This does not
establish zero whole-run faults or a controlled FPS improvement. The remainder
includes genuine ARM64EC invalidation-tracker mutex/state writes inside an RX
image copy. Exact installed-image inspection and the separate producer tests
are documented in [native FEX diagnostics](FEX_NATIVE_DIAGNOSTICS.md).

The ARM64EC tracker now uses the existing checked native owner-heap factory,
with its complete construction/use/destruction at one writable address. Real
locks and interval checks remain intact. The pointer stays null throughout its
constructor; duplicate or CTX-initialized partial startup is refused, and real
allocation failure returns STATUS_NO_MEMORY. WoW64 storage remains unchanged.
Production-source tests cover 4,000 concurrent queries, two owners, failure
paths and teardown; final packaging requires a new EC-only capability to reject
stale CPUs. No controlled iPhone performance result exists for this correction.

The JIT pool, FEX arena, image/code budgets, GPU capabilities and asset settings
are unchanged. The reported peak of roughly 6057 MiB against a 6144 MiB limit
remains a material risk. New menu/gameplay FPS, memory, startup and secure-play
results require device measurement. The legacy DirectX -9 failure is separate
and remains unresolved; no failed prerequisite is marked installed.

## Phone test and rollback

Update through the same SideStore account/app identity without uninstalling.
Retain Steam's actual file-verification result. At the real menu, use Begin VAC
Test, press Play, then Mark VAC Error if the warning appears, and export the
compact ZIP promptly. Include a screenshot of the incorrect graphics. Run the
pixel test in a separate fresh app session and share its `[d3d11-pixels]` result.
Also test leaving and returning to the app; native lifecycle errors are real
errors until the device shows otherwise.

Rollback is an in-place update to the previous 4a704 IPA, preserving app data.
The new probe stage is owned test content; no prefix migration or game-file
replacement is performed by this build. Steam repairs explicitly requested
through its verification UI are Steam's own operation.
