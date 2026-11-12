# CS2 sign-on: bounded buffer reuse and unnecessary wakes

Evidence: `Madeira-Run-Diagnostics(4).zip`, runtime
`edd7b7e9d4ba6bd377d2a91f99fa17b8e72c7225`, iPhone18,3/iOS 27.0.1.
The user reports a peak footprint of 5,755 MiB versus 6,143 MiB previously.
DXMT logical capacity and Metal allocated size are separate, overlapping
accounting measures; neither is added to physical footprint.

The console establishes a remote connection, de_mirage server information,
`SIGNONSTATE_FULL`, and a full update at 14:52:34. The first unexpected closure
is 14:53:04, with formal disconnection at 14:53:12. The reason was redacted.
That interval is consistent with a timeout but does not prove one, CPU
starvation, or a VAC verdict. There is no gameplay acceptance claim here.

## Confirmed cache defects

The installed `DynamicBuffer::allocate()` ran its global pressure sweep before
checking the requesting buffer's completed FIFO. Actual production-method
tests reproduce destruction of that same eligible spare followed immediately
by a fresh allocation. This provides no memory saving for the satisfied
request and creates avoidable allocation, release and synchronization work.

The pressure sweep also treated an entry two completed submissions old as
cold. Submission IDs are not frames or measured reuse intervals. The archive
records FIFO maximum three; the legacy per-object reserve of 64 cannot explain
the repeated draining of these short queues. In a late approximately 87-second
window, 15,750 of 16,453 fresh misses followed trimming of the same instance.
The trim totals are cumulative detached capacity, not simultaneous physical
memory, and their shared counter does not attribute each trim path.

## Production correction

Reuse a requesting instance's completed spare first. Only a true miss can
initiate fresh-allocation reclamation; that sweep excludes the requesting
instance. Current, queued, deferred and executing GPU references stay owned.

Repeated demand earns a warm-cache lease. Observed request frequency, demand
within a submission epoch and gaps between uses determine retention. Cold
one-shot and oversized spares receive no warm-cache credit. Credits are capped
at 4 MiB per resource and `min(128 MiB, reserve / 8)` across queues within one
loaded DXMT image. A measured 6 GiB budget has a 768 MiB reserve and a 96 MiB
credit cap. Separate runtime images do not share that counter; it is not a
promise of a 96 MiB whole-iOS-process cache. Live/current/in-flight resources
are not part of the reclaimable-spare limit.

The caller-serialized controller enters soft reclamation at `available <=
reserve` and exits at `available >= 1.25 * reserve`. Emergency cache draining
enters at one-quarter reserve and exits at half reserve. At the example budget
these are 192/384 MiB; the gap exceeds the 96 MiB cache cap, so bounded refill
alone cannot immediately re-enter emergency pressure. A genuine upcoming
allocation that cannot fit also enters emergency mode. Measurements use the
actual native footprint/available-memory query; subtracting reported footprint
from a configured limit is not a substitute.

Every batch rechecks controller state under the existing registry lock.
Timestamped samples prevent another thread's stale cache from undoing a newer
emergency decision. Unknown readings grant no new credits. Empty, expired
owners return their credits. An atomic empty-cache hint avoids needless locks
on drained resources, while actual FIFO inspection and mutation retain their
instance lock. References are destroyed outside registry and instance locks.

GPU completion remains the sole permission to reuse or detach a spare. Heat
and age only determine retention; they never override lifetime proof. Existing
upload-ring pressure behavior, live textures and JIT protection are preserved.

## Confirmed synchronization inefficiency

Wine's final shared SRW owner woke the exclusive-waiter address even when
`exclusive_waiters == 0`. The source overlay now checks that count. Writers
publish their waiter count before checking ownership: a preceding publication
is observed by the release CAS; a later writer sees the unlocked state or a
subsequent owner whose release observes it. Public address-wait/wake behavior,
exclusive-release wakes, atomics and alias handling are unchanged.

This removes empty wake-queue work. It does not establish a reduction in every
x64/ARM64EC crossing or identify the remote disconnection cause. The sampled
main-heap contention supports reducing allocation churn; no heap correctness
defect justified changing heap spin counts or thread priorities. API wake
counts are not counts of threads actually awakened, and aggregate thread-wait
milliseconds are not elapsed wall time.

## Validation and remaining device checks

Actual production-method ASan/UBSan regressions compare the installed and new
policies. A periodic two-name workload changes from zero hits/32 misses to
32 hits/zero misses after warm-up. A separate synthetic 80-name burst changes
from 1,040 hits/240 misses to 1,280 hits/zero misses. These are bounded host
stress workloads, not an exact replay of every CS2 request or iPhone FPS.
Tests cover cache-credit limits, cold/oversized preference, expiry, emergency
hysteresis, stale samples, mid-batch emergency transitions, unknown readings,
current/GPU/deferred ownership, 6,000 cold resources and concurrent destruction.

Actual Wine SRW and address-wait queue tests remove 20,000 unnecessary wakes
and 40,000 queue atomic operations for 20,000 uncontented release pairs. Queued
writers, wake-before-park races, final-reader release and 48,000 mixed reader/
writer operations retain correctness. These counts are host tests, not phone
measurements of the total exception or synchronization cost.

One export blind spot is corrected without adding runtime logging: a finite
fault-site mapping status named `cookies` triggered the secret filter. Its
known suffix is normalized to `code-seal` before the existing filters; real
credentials and cookies remain excluded. The existing pressure marker is also
preserved rather than misclassified as an opaque token. Public uppercase
`NETWORK_DISCONNECT_*` enum codes are preserved only in the existing Netchan
closure context; arbitrary payloads and credentials remain excluded. This does
not recover the reason already removed from the supplied archive.

The next iPhone run must measure physical footprint, cache reuse/regret,
map-loading and warm gameplay FPS, and whether the legitimate remote connection
stays alive. Existing high store-fault service time and long producer gaps
remain unmeasured after this correction. No networking protocol, matchmaking,
JIT pool, prefix, game data or controls are changed.

Install over Madeira with the same bundle identifier and signing identity.
Do not uninstall or clear documents. Rollback uses the prior IPA with the same
identity; no prefix migration or game-content modification is required.
