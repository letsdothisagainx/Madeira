# Run9: code retirement, released classes and checked recovery writes

## Matched evidence and limits

Archive SHA-256: `c8bb42d5ac37d361500fc76b655416862dca862665faa6dda6b7a5497daef5f6`.
Export: `2026-11-19T02:48:39Z`. Tested app source:
`7ec4544e7d679216e9c703f8c629747a98a9b25b`; native UUID:
`0E0D0363-D494-3188-8151-3517ED504248`. Package and runtime provenance agree.
The subsequent `5f6fc749` change only published the same IPA.

The remote connection begins at 21:44:15 Eastern, Mirage activates at
21:45:29, the first full update is printed at 21:45:30 and the actual
`NETWORK_DISCONNECT_TIMEDOUT` is printed at 21:46:28. Setting the timeout
earlier is configuration, not that failure. A later loopback session does not
establish remote gameplay.

The 64-frame batch spans 97,241 ms, with a 47,255.4 ms maximum inter-Present
gap, only 53 ms GPU execution and 5.0 ms average time inside Present. Main-thread
CPU work continues, including Embree-associated execution and later engine and
network processing. This is not evidence of a 47-second GPU wait. No texture
E_OUTOFMEMORY appears in the checked native/console text. Existing store
recovery completions are present; recovery did not stop at its logging cap.

The source defects below are reproduced independently. The export does not
prove every retaining reference, the contribution of each defect to the full
97-second batch, or the cause of every app crash. No iPhone acceptance result
is claimed for the corrected candidate.

## Continuing safe generation maintenance

The pinned FEX source is unchanged at
`6fb1b5071febda1fca17b9284a074ffcc8a9e334`. The correction is applied through
the Madeira-owned `build/fex-compat/code-sweep-retry.patch` overlay.

The original IosMaybeSweepCodeBuffers exhausts 256 retries, selected every
16th trigger. A thread in simulation through those 4,096 triggers remains on
its old generation even after becoming eligible and receiving another 10,000
triggers. The actual-function replay reproduces that retained shared reference.

The corrected function has no lifetime attempt cap. Same-generation retries
use `std::chrono::steady_clock`, a 25,000-microsecond deadline and the existing
one-in-16 cheap trigger filter. A claimant rechecks generation, skipped state
and deadline after acquiring existing busy ownership, preventing concurrent
callers from multiplying the sweep rate. New generations remain immediately
eligible. Registry lifetime protection, entry gate, signal-frame checks,
in-simulation checks, map locks and migration locks remain intact.

CompileBlock also offers maintenance after a completed cache lookup and after
a raced compilation returns an existing translation. Lookup/emission locks
have been released, invalidation-shared ownership is retained and unpublished
delivery compilation is excluded. The sweeper excludes its caller; the
caller's code reference continues to pin the returned code.

The staged production-function fixture checks both WoW64 and ARM64EC: the old
late-migration failure, subsequent release of the final old reference, continued
simulation, signal-pinned buffers, 32 concurrent callers, deadline limits,
thread unregister racing a snapshotted migration and both cached-return paths.

## Reusing an eligible larger whole class

The observed reservation shape is 128 + 64 + 3*32 + 4*16 MiB plus seven 16 KiB
dispatcher carves: `0x1601c000`, or 352.109375 MiB. Within the existing 384 MiB
partition, fresh capacity is 112 KiB short of another 32 MiB class. Exact-class
matching can leave a released 128 MiB carve unusable for a 64 MiB request,
producing the observed smaller-class fallbacks and generation rotations.

The guarded producer now probes explicitly larger power-of-two classes only
after its ordinary request fails, bounded by the existing 128 MiB maximum.
The private versioned `MADEIRA_FEX_CODE_REUSE_ABI_V1` request may consume only
an eligible existing whole carve of that requested class. It fails before
tail growth, region-C growth, reclaimed image allocation or ordinary VM
fallback, including when those fresh routes have ample capacity. It cannot
weaken owner/lease, grace, thread-scan, mapping or quarantine checks.

On success CodeBuffer adopts the full class size before calculating usable
bounds, checking the terminal guard, naming it or freeing it. A 128 MiB grant
therefore keeps its terminal RX/RW guard; it is never treated as a 64 MiB
allocation with an interior guard. Ordinary smaller-class fallback remains.
The 1,152/768/384 MiB pool and partitions are unchanged.

The actual native allocator plus staged producer replay reproduces the old
352.109375 MiB failure shape and adopts the released 128 MiB class after a
64 MiB failure without changing reservation cursors. It verifies terminal
guards, full destructor size, ineligible buffers and every fresh-route refusal.

## Checked writes during concurrent mapping changes

ios_store_split_crossing previously validated both destination fragments,
then dereferenced them with memcpy. Another thread can revoke a page between
validation and writing it, faulting the recovery thread itself.

The helper retains its decoder, destination/alias eligibility and permissions
checks, then uses mach_vm_write for each bounded fragment. A failed write
returns failure without base-register writeback or PC advancement. A negative
partial result encodes the prefix confirmed written by successful fragments;
the failed fragment's byte effect is unknown and no whole-store atomicity is
claimed. The server caller logs this after balancing suspension and does not
publish instruction state for an unfinished store.

A synchronized separate thread revokes either fragment after validation by
making it read-only, inaccessible or unmapped. The frozen original helper
faults in all 12 baseline child cases. The corrected actual helper refuses all
36 cases, including indexed writeback forms, with unchanged PC/base state and
balanced resume calls. The 310 existing recovery cases continue passing.
macOS run `44489805124` executes the actual Mach operation on 16 KiB host pages
and passes these checks. Linux uses explicitly separate checked kernel pipe
delivery for status/byte coverage; it is not a Mach performance measurement.

## Existing summary export and package verification

The existing CB_SUMMARY replacement format now uses ASCII `candidate_rip=`.
RunDiagnostics privacy filtering is unchanged. The tests reproduce omission
of the old non-ASCII row, retain the new counters through the actual sanitizer
and ZIP collector when Swift is available, and still reject secret-bearing
variants. This is preservation of existing measurements, not a new profiler.

The new overlay and private ABI invalidate both FEX PE caches and the complete
IPA cache. Native Unix code is rebuilt by the app workflow. Package gates
require the new monotonic-maintenance, released-class reuse, ASCII summary and
checked-write producers in the compiled components. Tests reject stale images.

Final build/package validation is recorded in the delivery report. Actual
acceptance still requires an iPhone remote join, responsive T/CT selection,
playable gameplay through a round, and stable rendering/memory after leaving.
No Steam, game-content, networking-protocol, rendering-setting, bundle-ID,
prefix, authentication or installed-configuration change is part of this patch.
