# Run10 upload pressure and changelevel

## Matched evidence

Archive SHA-256:
`918de683c539690d8a92f5b0e1c642943f78d0c19e116483d8276ebbc9e6286a`.
Export `2026-11-19T19:11:42Z`, tested source
`a99940fb3384018fc6280efd7e0eae7eb08a819a`, native UUID
`B8CF6744-0556-321F-BD41-8EA95BA5A13D`. Runtime and package provenance agree.

Remote handle #3658517496 connects at 14:00:32 Eastern. Inferno activates at
14:03:17 (165 seconds), with the first full update at 14:03:30. The server
initiates changelevel at 14:04:29; Dust II activates at 14:06:29 (120 seconds),
with a full update at 14:06:30. The actual NETWORK_DISCONNECT_TIMEDOUT is
14:07:20. The later 14:07:40 loopback connection is a different local session.

The console contains 466 texture OOM rows: 464 CreateTexture2D and two
CreateTexture3D. Of these, 416 occur during 14:04:29–31, before the timeout.
The native failure reporter intentionally prints only eight detailed failures.
The first admission decision is arithmetically consistent with its charge and
the unchanged 201,326,592-byte floor. This patch does not ignore that floor.

The 89.839-second frame batch contains only 99 ms GPU execution and a maximum
59.026-second inter-Present gap; the later 60.113-second batch has 19 ms GPU
execution and a 42.816-second maximum gap. These are not long GPU execution
times. Detailed RIP samples end near 14:01:59, and detailed thread samples
near 14:02:27. They cannot identify the function executing during the later
stalls. Rounded counters show substantial main-thread CPU progress during both
problem intervals; no additional emulator or networking change is justified
by these measurements alone.

## Completed transient storage churn

Critical completion handling previously called trim_completed(..., false)
on staging, copy and argument rings. It destroyed every completed block;
following submissions then recreated natural 32/32/4 MiB backing. Keeping
only a final FIFO entry also failed to retain a completed reusable prefix
when another submission remained pending behind it.

The corrected ring owns at most one bounded completed spare outside the
pending FIFO. Only a genuine GPU-completed entry may move there. Allocation
and forecasts reuse it under the existing ring lock; pending entries remain
owned and unchanged. Explicit denial reclamation still drains the spare.

The queue shares a limited warm budget across its three rings. During critical
pressure the total is at most min(16 MiB, reserve/64, available/16). New pressure
blocks use bounded power-of-two classes, at most 4 MiB; the selected class only
shrinks during a latched pressure episode. Existing high/low-water state
separates pressure from recovery. Healthy allocation policy is unchanged.

The actual ring/queue fragment regression compares identical bytes: 312
allocations / 7,072 MiB cumulative traffic under the old critical disposal
policy versus eight allocations / 79 MiB with bounded reuse. Both cases have
an initial 68 MiB owned-capacity peak. Those figures do not establish lower
physical footprint. Separate native Metal validation measures actual copied
bytes, GPU completion, sampled process footprint and Metal capacity without
touching unused buffer pages to manufacture a result.

## Large texture forecast and real upload peak

The first refusal charges 60,813,696 destination bytes plus 124,112,112 temporary
bytes. The latter equals 2*(60,813,696 + 4,872*255): the natural-block path's
conservative whole-batch/padding allowance. Its 184,925,808-byte total exceeds
the 101,353,296 bytes available above the floor.

A valid 256x256, seven-mip, 116-cube array using 16-byte BC blocks reconstructs
these exact operands. It is a controlled matching layout, not proof that the
archive identifies that descriptor uniquely. Its largest subresource is only
64 KiB; a second whole-batch temporary allocation is unnecessary if uploads
wait for and reuse the same completed block.

Under measured pressure, batches larger than the natural block now select a
bounded mode when each subresource fits that block. The forecast conservatively
charges one full upload block even if existing backing might already suffice.
The producer enforces the same cap: a capacity miss submits complete commands,
waits at most 50 ms on the real private GPU event, then reuses completed backing
or returns a genuine failure. It cannot allocate a second newly grown block
after exhausting its charged cap. It never changes texture dimensions, formats,
mips, slices, SRVs or the copied bytes.

Preflight runs before partial command/retain state, on each retry. The actual
allocation method does not flush. Active upload ownership protects one
completed block between subresources; it starts only after genuine backing
exists. Scope exit restores previous policy, and native GPU intent retains
credit across intermediate submissions until the final real fence is published.

For the matching layout, a 32 MiB natural block changes the charge to
60,813,696 + 33,554,432 = 94,368,128 bytes, which fits the recorded available
headroom without changing the floor. The actual staged-method test transfers
all 4,872 subresources/60,813,696 bytes with one newly allocated block. It also
tests 4 MiB block policy, no-completion refusal, pending destination lifetime,
nested/unwind restoration and old/new map ownership. No missing mip, nil
resource or incomplete initialization is reported as success.

## What keeps the process near its limit

The archive establishes substantial transition overlap, rather than a
permanent-leak verdict: texture/buffer capacities fall from 569/680 MiB around
14:04:29 to 267/334 MiB around 14:04:59; Metal allocation falls from 1,352 to
717 MiB. Guest file-backed capacity falls from 3,551 to 2,806 MiB by 14:05:02,
and measured footprint falls to roughly 5,242–5,286 MiB. These capacities are
not additive with one another or with footprint.

At the earlier peak, staging is already drained. Therefore staging churn does
not explain all process memory. Native malloc relief returns zero throughout
the recorded episodes; only one incidental 32 KiB footprint drop appears.
Guest decommit/remap is active, JIT aliases share backing, and no CPU-placed
buffer duplication is shown. The evidence does not identify all remaining
guest/native allocations or justify forcing release of game-owned resources.

The implementation removes a demonstrated avoidable upload peak while those
owners overlap and reduces repeated transient allocation work. It does not
claim a measured decrease of the phone's entire near-6-GiB working set, nor
that every required future resource will fit.

## Validation and acceptance boundary

All changes use Madeira's owned build transforms; pinned DXMT remains pristine.
The recipes invalidate DXMT and IPA caches. Package gates require the new
transient-reuse and bounded-upload producers in their compiled components and
verify staged-source hashes and exact app/IPA copies. Existing generation
maintenance, larger-class adoption, checked writes, JIT partitions, renderer,
networking, prefix, installed files and configuration are preserved.

Native Metal and final build results are recorded in the delivery report.
Host tests and a compiled IPA cannot establish a faster iPhone map load,
responsive team selection, gameplay through a round, or intact graphics after
changelevel. Those acceptance outcomes remain to be measured on the device.
