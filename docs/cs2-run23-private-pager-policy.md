# Run23: private-data paging policy and independent first-stall capture

## Evidence and coverage

Input SHA-256 `a1d93ff1733043c7662a3156ee4b4ba7e89b09e9ca9e72bff35853706cece178`,
run `778BC5D8-7AD5-4D89-8198-1F6D29229589`, tested source
`949e7332e015d712f9408230ebb66dce4d3f12c0`, native UUID
`2CEE3A9D-A765-329B-8F7C-CF10DB6FDE94`. Starting head was
`e656ca6da69f27f72912b4f3bbfe81122eb4aaf1`, publication-only after that source;
no newer work was reset. Current/preceding evidence is kept separate.

The existing read-only analyzer, calibrated to 2026-11-24 22:11:31–22:12:37 UTC,
reproduces 56 complete main intervals: 64.826499 s elapsed, 1.376869 s user CPU,
35.239881 s kernel CPU, 96.2398% kernel share of **consumed CPU**. Only intervals
wholly contained in the calibrated console-time window are included; original
console precision/calibration uncertainty remain. Incident duplicates are removed
by run/sequence (1023 duplicates, no conflicting copies).

Closely matched operation boundaries give:

| Instrumented body | Begin-count delta | Inclusive elapsed delta |
|---|---:|---:|
| Server call, direct/IPC | 14663 | 0.317591 s |
| Uninterrupted mutex acquisition | 9566 | 0.004394 s |
| Server-select wait | 3901 | 0.115019 s |
| Map/protect/decommit wrappers | 2033 | 0.025073 s |

These totals neither sum to CPU nor subtract from it. Entry/exit pthread_sigmask,
other native callees, implicit faults and uninstrumented operations are outside
these body timers. Their small measured bodies do not explain the interval; that
is narrower than ruling out all synchronization/runtime work. The pacing hook
advances once across about 64.984 s with an approximately 59-s gap; it is not GPU
completion or a playable-gameplay result.

There are 54 retained access observations in the window, all matching backing
ledger entries; 47 are naturally aligned, noncrossing release stores. Others
include different access patterns and a crossing store. Current generated-block
lookups resolve repeated animationsystem.dll+0x38faa1/+0x38fab2. Writable external
page/region observations were taken after resume, not atomically with registers.
Changing effective addresses and source sites do not establish one stuck
invocation or identify a kernel stack.

The matched host I/O boundaries increase by 74710 page-ins, 549224448 read bytes
and 13757403136 accounted write bytes. These are whole-app counters, not
per-thread/per-file I/O or physical-storage writes. Eight retained explicit slow
VM operations are hole punches (maximum 338.542 ms); they do not account for all
implicit VM work or prove a main-thread dependency.

## Normal runtime change: fresh private-data paging advice

The private guest tier currently turns eligible anonymous/private Windows data
into MAP_FIXED|MAP_SHARED file mappings. It supplies no paging-reference hint,
so the external pager uses its default access behavior. Private heap/data access
has no sequential asset-file contract. Under the observed pressure, treating
those mappings as a speculative file-access stream can pull neighboring pages
into a constrained working set.

Apple's published XNU at `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` provides a
specific, conservative mechanism:

* [madvise](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_mman.c)
  maps MADV_RANDOM to VM_BEHAVIOR_RANDOM.
* [vm_map_behavior_set](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/vm/vm_map.c)
  records reference behavior in the map entries. This persistent hint is distinct
  from immediate WILLNEED/DONTNEED/FREE operations; it does not warm or discard data.
* [vm_object_cluster_size](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/vm/vm_object.c)
  can grow DEFAULT page-in preheating adaptively (published minimum 32 KiB), while
  RANDOM uses the requested cluster and exits when it is no larger than a page.
  Explicit larger requests remain possible. This published tree is not the
  device's exact private kernel or proof of its dominant expensive operation.

`ios_swap_private_pager_advice()` now requests MADV_RANDOM immediately after
successful fresh private backing maps in `ios_swap_map()`, and after successful
fresh-zero reservation replacement in `ios_swap_punch_resv()`.

Eligibility uses the current native thread's existing immutable registration
(owner/lease/PID/TID/TEB), the already validated CS2 process identity, the current
private valloc view and its matching creation-context tag. `thread_ios.c` exposes
only that thread-local identity; `server_ios.c` checks the existing published CS2
identity. No registry lock, guest stack walk, sampled identity, captured address
or module whitelist selects allocations. Missing/stale/cancelled/finishing
identity leaves the existing behavior. Worker allocations in that same validated
process qualify. Creation context is not asserted as general reclaim ownership.

Image/file sections, executable/ARM64EC, system, write-watch, placeholder and
other excluded views retain their existing policy. `ios_swap_image_map()` does
not call the hint. Other guests, including Steam/CEF, retain the prior path.
The hint is applied to fresh host-page interiors under the existing VM lifetime
lock, not retroactively by a sampler. It does not move, reclaim, touch, zero,
copy, pin, protect or publish guest contents. The mapping, extents, file offsets,
quarantine, zero-on-reuse, 4-KiB/16-KiB protection aggregation, CPU ordering and
GPU completion contracts remain unchanged. No anonymous-memory exception,
backing disablement, capacity increase or reserve reduction is introduced.

Advice failure preserves the successful allocation and original errno; it is
an optional policy receipt, not fabricated mapping success. Existing VM timing
now includes advice operation 7; the existing backing snapshot reports attempts,
accepted/failure counts, cumulative advised bytes and last error. Cumulative
replacement bytes are not live capacity. Acceptance by the syscall is not proof
of fewer faults or faster frames. No new sampler or journal is introduced.

This is a **normal-execution paging optimization candidate**, not a confirmed
kernel diagnosis. It targets potentially avoidable speculative page-in and
working-set pressure. It may reduce sequential prefetch throughput in portions
that actually benefit from it. A comparable device run must establish its effect
on main user/kernel time, paging, activation, frame gaps and a sustained round.
Nothing in the supplied export proves the number of speculative pages, a
per-file writeback cost, or a measured benefit from this new policy.

## Allocation shortage stays separate

This run has 884 direct admission/OOM results. The first retained example has
673400 usable bytes (201999992 minus the 201326592 reserve), below its 699048-byte
destination before adding the 65536-byte upload growth. Staging changes cannot
admit it. Prior Run22 stalled without an allocation burst. No safe large retained
owner or redundant representation was established for this destination-only
shortage. The hint does not release live capacity, and **no sufficient footprint
reduction or texture-allocation repair is claimed**. Reserve, uploads, fences,
real HRESULTs, resources and aliases retain their prior semantics.

## Required capture correction

`RunEvidenceStore.incident()` now attempts the independent first remote
post-activation stall lane before ordinary priority/cadence suppression.
Resource priority still protects the ordinary first/recent failure windows;
a later disconnect cannot replace the dedicated first-stall file.

Capture returns success only after nonempty complete writes and successful
close. Partial/failed output is removed, the saved flag remains false and a
later eligible observation can retry. Copy handles partial writes/EINTR and
reports open/read/write/close failures. Empty recording data is also an
unsuccessful capture, with a distinct first-capture failure counter. Successful
write/close is not an fsync/abrupt-termination guarantee. Existing pending-tail
and persistence coverage remain. No temporary double-sized incident copy is
introduced: the existing 256-KiB dedicated lane and <16-MiB run budget remain.

The frozen actual 949e7332 incident method reproduces the resource-before-
activation suppression in an ordinary data replay. The corrected store exports
the dedicated file for resource failure -> activation -> stall -> disconnect,
retains the first resource window unchanged, and retries after empty input.
No filesystem failure or application crash is induced for this validation.

## Controller stop point

Physical controllers are enabled in the native log. Retained input observations
still count zero physical samples, changes, translated actions and key calls.
The final retained snapshot has 17 mouse calls, cached source flags 25 and only
30 sampler invocations; the route is about 139 s old. Startup/lifecycle discovery
rows are absent from the retained rolling journal, so framework enumeration is
not established by their absence. Source still enumerates extended profiles on
startup/connection/foreground and runs the timer only for active cached profiles.
The keyboard/mouse branch remains observed independently of downstream returns.
This establishes neither physical input nor an independent input defect. Controller
validation is pending. No queue, mode, binding, routing or focus change is made.

## Verification boundary

Ordinary fixtures exercise the actual TLS identity, CS2 classification and policy
helper on an 8-MiB initialized, writable shared file map. Every byte is checked
before/after; aligned ordinary writes are preserved. Main/worker eligibility,
foreign/stale lease/PID/owner, cancellation, executable/image/system/write-watch
exclusions, bounds and errno are covered. Darwin additionally queries the actual
VM region's RANDOM behavior and unchanged read/write protection. Linux reports
that Darwin query unavailable. No eviction, protected access, forced fault,
page revocation, captured instruction execution or memory-pressure experiment
is performed. Warm small host mappings cannot demonstrate phone paging/FPS gains.

Native source provenance includes the new thread identity dependency and its
lifetime header. The package checker requires linked policy/identity symbols and
the policy consumer. Normal existing upload/credit/fence/reserve, input, export,
privacy, rotation and prior-run checks remain part of delivery. The existing IPA
workflow uses its normal-recovery profile; historical fault cases are compile-only.

Build success, policy selection and syscall acceptance establish implementation
and packaging only. Acceptance still requires responsive remote team selection,
movement/aim/buttons, sustained rendered play and correct visuals on the iPhone.
