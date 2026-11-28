# Run26: bounded private-allocation churn candidate

## Evidence and hypothesis

Input SHA-256 `1b1f04268cebd3e9e1bd40bc844d21fd078b3e6d3018f0c5063d1afd22ef1e82`,
run `EFC2E9BD-1D72-407A-89FB-F72344876F24`, source
`ae1a64988e3aca681a4988fd0ebe4ca8e299ac49`, native UUID
`CDD109BC-FB32-3616-8BEB-4B35169B00F9`. Starting HEAD `916216f9` is preserved.

The existing analyzer reproduces 66 complete main intervals wholly inside
09:00:50–09:02:08 UTC on November 28: elapsed 76.802161 s, user 3.602511 s,
kernel 39.165587 s (91.5766% of consumed CPU). Current-run journals and incidents
are deduplicated by run ID and sequence: 5,532 unique rows, 1,100 copies, no
conflicts. Nearest measured clock calibration and register capture times select
intervals; original console seconds and parser arrival remain distinct. Pacing
advances six times over 77.037273 s while foreground. Fifty-one of 57 decoded
accesses match file backing; 41 are aligned noncrossing release stores.

Backing census traffic reaches 6,068 maps and 6,286 releases, with zero learned
churn classes in wide mode. The existing adaptive filter is explicitly broad-only;
wide mode repeatedly sends every eligible allocation through external backing,
irrespective of how soon that size's allocations have been released. Counters
are cumulative traffic, not live physical memory or a controlled speed benchmark.
The observed hot accesses in large reservations do not prove that the smaller
whole allocations modified here dominate main-thread kernel CPU.

**Hypothesis:** avoiding external mapping, first-touch and retirement work for
demonstrably short-lived whole private allocations reduces competing pager and
writeback pressure. This is a bounded normal backing-policy change, not a claim
to have identified the exact kernel operation or repaired gameplay.

## Production change

`ios_swap_commit` now learns eligible whole-view lifetimes for the current,
validated CS2 owner/lease in wide mode. Only fresh writable private allocations
of 256 KiB–4 MiB, aligned to the device's 16-KiB host page, qualify. A size class
needs at least eight completed lifetimes shorter than three monotonic seconds,
and young deaths must be at least half its allocations. Only successful normal
file mappings or admitted bypasses contribute young-death evidence.

A qualifying fresh commit can keep its existing anonymous zero-filled mapping
instead of replacing it with a shared backing-file mapping. No live mapping is
migrated, no bytes are copied or skipped, and no extra mapping is allocated.
Steam, foreign/stale process lifetimes, image/section/system mappings, guarded,
watched, executable/ARM64EC/JIT/alias ranges, existing file backing, reservation
subcommits and large whole allocations retain the previous path.

The aggregate additional anonymous commitment is capped at **32 MiB across
all tracked lifetimes**, not per allocation. Every byte is charged, irrespective
of current residency. A fresh native budget query subtracts existing graphics
creation credits and supplies the unchanged admission floor. Admission requires
available capacity for twice that floor plus all outstanding churn commitment
and the new whole allocation. The native helper uses a try-lock: busy/unknown
budget takes the ordinary file path. Cold classes and a full cap make no native
budget query. The helper preserves errno and cancellation state and does not
schedule native malloc relief from the VM critical section.

The charge survives guest decommit, partial view splits, process quarantine and
thread exit. Whole host-page bitmap bits are cleared only after actual successful
`munmap` or the existing PROT_NONE replacement in `unmap_area`. Duplicate releases
cannot refund twice; failed operations cannot refund; a recycled pointer cannot
inherit a previous lifetime's allowance. Mapping contents, zero-on-reuse, old
file-offset retirement/quarantine, GPU ownership, recovery, TSO and JIT sizes do
not change. The existing payload-reading zero diagnostic is skipped for the
tracked anonymous commit/decommit just as for fresh file holes; the real zeroing
producer is unchanged and no diagnostic page warming is added to this path.

This is **not a proven footprint reduction**. Choosing anonymous backing can
increase charged footprint, bounded by the full commitment cap. The policy
stops new bypasses well above the existing floor and only reclaims its allowance
after actual native unmapping. It does not claim a large reservation is resident
or count shared JIT aliases twice. Fixed C metadata payload is 43,640 bytes, separate
from recorder storage. There is no dynamic metadata allocation or per-event
filesystem output under the VM lock. The existing slow census adds one bounded
`swap-churn-budget-v1` row with cap, outstanding/peak charge, exercised bypasses,
refusal counts and measured native-budget query count/time.

Uncharged old learning records rotate when the bounded table fills; their
authoritative backing ownership stays in the existing extent ledger. Charged
commitment records never rotate. Eviction is counted and never treated as a
young death, so old long-lived learning cannot exhaust the entire run's policy
capacity or refund memory still in use.

## Separate allocation and controller limitations

Request 26049 has 984,552 bytes above the reserve but requires a 4,194,304-byte
destination and 65,536 upload bytes. It remains a truthful pre-allocation refusal.
All 64 admission/OOM results and zero native allocation failures retain their
meaning. No sufficient, safely releasable live-resource owner has been proven;
this policy does not lower the floor or claim to fix destination-only shortages.
Physical-controller validation remains pending with zero upstream activity.
No controller, launch, exporter retention, graphics setting or networking timeout
is changed.

## Normal validation and package gates

`check-cs2-churn-backing.py` compiles the actual production decision and header
against ordinary lifecycle/budget adapters. Its immutable actual `ae1a6498`
baseline chooses file mapping for nine of nine repeated allocations. The new
decision keeps the ninth mapping anonymous after learning eight short lifetimes.
It covers aggregate exhaustion, fresh pressure thresholds, generation and
process isolation, partial splits, duplicate releases, quarantine retention,
long-lived classes, unavailable metadata and 4,000 overlapping lifetimes under
the existing VM-lock contract. No protected memory, fault, captured code or
deliberate crash is executed. A local Linux run measured roughly 0.5–0.9 us per
metadata decision plus retirement over 10,000 cycles; native queries are adapters
in that measurement, so iPhone kernel/query cost is **unmeasured**.

The real native budget-header fixture checks outstanding credits, the unchanged
floor, busy-lock refusal, errno/cancellation-state preservation and balanced
ordinary parallel receipts. The ten recorded Run14/25/26 refusals remain refused.
Existing safe retirement metadata, upload-byte/fence, source-provenance and
read-only package-inspector checks remain required. Normal CI includes the new
fixture, and the IPA gate requires the linked policy marker and the defined
native budget provider. The source digest now binds both policy and provider
headers, and selective component cache invalidation covers their consumers.

## Device comparison

Use the same remote map/connection sequence, play through a round and return or
change maps, then Export Run once. Expect nonzero bypass counts only if qualifying
turnover and headroom actually occur; outstanding charge must stay at most
33,554,432 bytes. Compare complete post-activation main user/kernel intervals,
page-in/I/O counters with their host scope, pacing/Present gaps, footprint,
allocation failures and visuals. Fewer maps alone is not gameplay acceptance.
If bypasses are absent, the candidate was not exercised; if they occur without
better pacing, this hypothesis has not repaired the stall. Real gameplay and
physical-controller movement/aim/buttons remain device acceptance work.
