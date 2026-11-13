# CS2 run 7: native metadata writes and finite-wait accounting

**Recovery status after b832:** the DXMT corrections below remain enabled.
The finite-wait overlay is excluded from the production build, and WOW64
tracker storage has returned to the multiplayer-capable d73 implementation.
The descriptions of those two experiments below are historical, not the
current production policy. See [startup recovery](CS2_B832_STARTUP_RECOVERY.md).

Evidence: installed source `d73f2583a79f7c402edaec3646f2d0d1d89c0752`,
Madeira-Run-Diagnostics(7).zip. The remote connection reached full sign-on and
timed out at 23:14:45; the later 23:15:34 connection was local loopback.
No new VAC rejection was observed. No networking or security behavior changes
are part of this correction.

## What the CPU samples establish

The resourcesystem+0x231c0, meshsystem+0x39a40,
rendersystemdx11+0x35f40 and soundsystem+0x3d500 rows are saved guest-frame RIPs,
not instruction-by-instruction execution attribution. The quoted 202-sample
window is after the remote timeout; 104 samples were RUNNING. These rows cannot
identify proprietary function names, establish a spin loop, or represent
whole-process CPU shares. The corresponding game PEs/PDBs are not present in
the development workspace.

An actual running host-PC bucket maps to tier0+0x28fa2a/0x28fa33. Its dumped
code advances source/destination pointers and copies two vectors per iteration.
It is productive copying; neither skipping it nor removing its safepoint is
justified. Another scalar copy path uses FEX's unaligned TSO barriers. These
ordering barriers remain intact. materialsystem2+0x10eff0 is a stack candidate,
not a verified unwind or proprietary function identity.

## Independently resolved native fault sites

The exact shipped IPA was inspected, with source revision and binary hashes
checked: [inspection run](https://github.com/letsdothisagainx/Madeira/actions/runs/43365581877),
[proof artifact](https://github.com/letsdothisagainx/Madeira/actions/runs/43365581877/artifacts/14010580411).

| Image / code RVA | Actual function / target |
| --- | --- |
| D3D11 0x77a94 / 0x7d690 | `PreDraw<true/false>`, `g_perf.draws` |
| D3D11 0x118928 / 0x11892c | `DynamicBuffer::TrimCompletedForQueue`, `g_dyn_stats[3560].eligible_n/eligible_bytes` |
| D3D11 0x11895c | Same trim function, `g_dyn_stats[2024].wfa_min` |
| D3D11 0x9777c | `BCStreamReport()`, local static atomic tick |
| A64 ntdll 0x6dc60 / 0x6dbe8 | `RtlAcquireSRWLockExclusive`, WOW64 `ThreadCreationMutex` |
| A64 FEX 0x1a1aac / 0x1a1b44 | shared-mutex lock/unlock, WOW64 `InvalidationTracker` |

Across the bounded epoch reports, the identified CS2 draw counter accounts for
212,312 reported fault hits, dynamic statistics for 253,803 and BC report tick
for 3,081. The selected WOW64 mutex and tracker targets account for 367,221 and
85,914. These are reported hot-site counts, not a complete census of the
12,178,260 total faults, and must not be converted into a predicted FPS gain.

The executable image copies are protected. Recurring native writes to their
mutable bookkeeping trigger Mach exception recovery. Moving private metadata
to native RW storage avoids those exceptions without weakening RX protections.

## DXMT correction

The owned build overlay replaces image-resident census/performance state with
one native heap owner per loaded module. Every existing operation, counter,
atomic memory order and reporting cadence stays enabled. Header lifetime
anchors allocate before TU-local static consumers. PE owners are freed after
the last static consumer on legal module unload. The native archive is linked
statically into Madeira's app image: its single owner retains the former
process-long BSS lifetime so live queue workers remain safe during force-exit
CRT cleanup. It is not reallocated per guest session. Accessors only load the
stable pointer: no per-draw allocation, lazy guard or new lock. Census report
ranking scratch arrays are per-call stack variables rather than shared mutable
statics.

The census state is 1,051,816 bytes on the tested 64-bit host. It replaces the
existing arrays rather than adding texture, upload or executable backing. The
same source transaction builds AArch64, ARM64EC, i386 and native DXMT. Cache
keys, source manifests, compiled capability markers and final IPA checks reject
old binaries. Vendor source pins remain unchanged and are restored byte-for-byte.

The existing bounded-hot buffer cache, trim thresholds, GPU completion checks,
texture ownership, upload retirement and JIT partition are unchanged.

The detached BC-refill worker deliberately retains its original image-lifetime
timer sink. Its pending timers must outlive C++ static cleanup without referring
to a freed performance owner. This one sink keeps its existing lifetime and
atomic behavior; no worker shutdown or rendering policy is rewritten.

## WOW64 tracker correction

The existing ARM64EC owner-heap tracker pattern now also applies to WOW64.
`InvalidationTracker` and its shared mutex occupy one stable owner-heap address;
the tracker still borrows the same `Threads` map and `CTX`. Publication happens
only after successful construction, OOM follows the frontend's genuine fatal
initialization contract, and repeated process initialization is refused before
it can replace a live owner. Declaration/destruction ordering is preserved.
Both final PE gates require the source-built `IosInvalidationHeapABIV1` DATA
capability, with its initialized value and private non-executable bounds checked.

The separate WOW64 `ThreadCreationMutex` remains unchanged: an early-to-late
mutex switch cannot safely be introduced without proving every startup callback
is quiescent. Its observed fault count remains a known cost, not a claimed
improvement. Notification logic, thread retirement, code invalidation, memory
protections and the generated-code pool policy are unchanged.

## Finite wait correction

The native fastsync implementation started its elapsed-time clock after lookup
and initial/adaptive spinning, then debited only a capped parking interval from
the caller's relative timeout. Short waits could therefore consume their whole
deadline in spinning and still park or hand the original duration to the server.
The generated iOS sync translation unit now starts timing before lookup, bounds
adaptive spin and parking by the remaining deadline, and debits total elapsed
time on every fallback. An expired deadline becomes a real zero-time server
query; it does not fabricate timeout/success or bypass object, APC, abandoned or
error checks. Explicit zero, absolute and infinite waits retain their routes.
Signed-minimum relative timeout conversion is also made overflow-safe.

The actual production-function harness requires the old short-wait regression,
then checks the corrected code under address/undefined-behavior sanitizers,
including signaled/manual/semaphore objects, generation recycling, server/APC
results and public single/multiple-wait dispatch. The exported run does not
measure the whole-game cost of this timeout defect; it is not proof that this
defect alone caused the remote timeout or frozen frame.

## Verification and limits

Focused regressions compile production counter code: protected original-image
stores fault, while replacement heap writes preserve exact counts without
fault recovery. Concurrent producers, reporting cadence, static ctor/dtor users,
independent module instances and repeated unload/reload are exercised. These
are runtime storage/ownership tests, not simulated CS2 frame-rate results.

Actual iPhone measurements are still required for exception rate, CPU/frame
time, peak footprint, remote timeout behavior and responsive team selection.
No test here establishes playable gameplay or VAC-secured acceptance. The
unchanged input route still sends iOS touch/controller events through Wine;
there is no automatic team selection or input workaround.

Rollback consists of reinstalling the prior IPA in place with the same bundle
identity. No prefix, game, account, controller or display-settings migration is
introduced. Source rollback should revert the production correction commits
and rebuild the corresponding source/compiled provenance together.
