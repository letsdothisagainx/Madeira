# Remote-loading recovery scheduling

## Evidence and phase boundaries

Input: `419a059c8bbda19cf6c557f536c13fc564c3477c`, export
`2026-11-17T20:08:31Z`, native UUID
`79EB77A5-F924-3BEC-8866-C587A88B7F06`. The input ZIP SHA-256 is
`b48bd347f06c04f18ae21c30b67b6479fdf507af68a93d6bf1671d00ed9b544f`.

The remote connection starts at 15:00:47; activation occurs at 15:02:32
(105 seconds). Full state and Dust II physics appear at 15:02:33. After a
30-second timeout is configured at 15:03:02, another full update is logged at
15:03:33 and `NETWORK_DISCONNECT_TIMEDOUT` at 15:03:42. Those timestamps describe
application logging, not independently measured packet-arrival times.

The exported native log now contains **400 successful crossing-store
recoveries**, including the exact Tier0 copy PCs selected by the report. These
are actual completed writes with accepted Mach PC publication. The final
400th message appears around 15:02:16; the existing logging cap means later
absence says nothing about continued recovery.

Within the remote connection-to-activation interval, 148 logged recoveries
report 19,198 ms of summed thread system CPU and 20,850 ms of summed observation
intervals. Across all 400 records, system CPU sums to 51,172 ms. Threads overlap;
these are **not wall-clock totals** and do not explain all 105 seconds.

The accesses advance across many distinct addresses. Worker 03cc and another
hot worker 03c8 were created by initial thread 0384 in process 0380, with entry
Tier0 + `0x1730d0`. Their names are redacted. Material-system addresses in stack
candidates do not establish a particular resource job. TEB reuse elsewhere in
the export prevents identifying a thread from its TEB alone.

The original x64 stores are ordinary `MOVDQU` operations. The emitted ARM64
stores and decoder agree. This evidence supports many stalled accesses during
progressing copy work, not a proven single infinite invocation. Some recovered
stores are scalar/pair stores as well as Q stores.

The 197,771 ms / 0.3 FPS window ends before the remote connection. The 60.3/60.5
FPS windows are also before it. Actual remote windows include 1.4, 2.4 and 2.6
FPS with little GPU work. Post-activation samples additionally include Embree
and animation execution, separate from the pre-activation Tier0 copies. Their
semantic purpose and contribution to the final timeout remain unresolved.

## Confirmed application dependency

Production crossing-store recovery used the diagnostic sampler's execution
thread. It ran between 100 ms sleeps and required two matching PC/address
observations. A successful completion cleared that comparison, so a subsequent
new boundary normally required another two observations. Diagnostic bursts
(four passes spaced 250 ms apart) and the subsequent RIP profiler did not run
recovery at all. The source therefore imposed long waits on an operation needed
to let a stopped guest access complete.

This is distinct from the underlying reason iOS retries those accesses in its
kernel. The 432 original native ARM64 cases and 120 additional untouched-sparse
and mixed-object mapping cases complete normally on macOS. They do not establish
a safe reason to replace FEX's store emitter or change guest backing policy.

## Production correction

`server_ios.c` moves recovery to one dedicated utility pthread, with the existing
sampler as a startup-failure fallback. One owner handles both discovery and
completion state. Recovery no longer depends on a diagnostic burst or profiler
returning. Existing opt-outs remain effective.

Whole-task discovery stays at 100 ms. Only a native thread whose store was
actually completed and whose updated PC was accepted can enter an eight-entry
fast-follow set. That set checks at 5 ms, retains its own Mach send rights,
revalidates native thread identity, and expires one second after the last
successful completion. Observation alone cannot renew it. There is no task-wide
5 ms scan and no unbounded work queue.

The running-thread requirement, actual 60 percent system-CPU gate, repeated
PC/address observations, decoder, protection validation and completed-write-only
PC advancement remain in force. Fast-follow CPU accounting uses microseconds
to avoid millisecond rounding dominating a 5 ms interval. Failed capture,
identity mismatch and expired ownership release the retained port and discard
the comparison. The fallback runs both discovery and follow-up so retained
candidates cannot become stranded when pthread creation fails.

`signal_arm64_ios.c` removes the helper's first-eight-call diagnostic formatting
while a writer can be held suspended. Formatting can acquire a libc lock owned
by that writer. The existing caller reports completion/refusal after balancing
its suspension; store bytes, validation, register writeback and return values
are unchanged.

No game binary, FEX emission, UDP transport, timeout, DXMT resource policy,
memory budget, JIT partition, input path or user data is changed.

## Validation boundaries

The scheduling regression executes production recovery functions with controlled
Mach counters and a monotonic test clock, while the actual store helper writes
real test-owned mappings. Work advances only after bytes and PC publication are
verified. Its modeled latency is not an iOS kernel reproduction or a remote-map
loading measurement.

For 20 advancing stores, the controlled replay results are:

| Schedule | Ordinary modeled time | With a two-second diagnostic pause |
| --- | ---: | ---: |
| Previous sampler-owned recovery | 4,000 ms | 6,000 ms |
| Dedicated bounded follow-up | 390 ms | 390 ms |

Initial discovery remains unchanged; subsequent qualifying stores need two
5 ms observations rather than two 100 ms observations. The candidate performs
four whole-task scans in this replay. It does not scan the task every 5 ms.
These results establish the scheduling change, not a predicted 105-second
map-loading reduction. Identity changes, rights expiry, protected neighbors,
failed PC publication, exact CPU thresholds and startup fallback are separate
correctness cases.

Native ARM64 instruction/protection tests and packaged-binary verification are
separate checks. The new build still requires iPhone measurements of remote
connection-to-activation, responsive team selection, gameplay, connection
stability, frame times and physical footprint. It is not established that all
remaining post-activation stalls share the corrected scheduling dependency.
