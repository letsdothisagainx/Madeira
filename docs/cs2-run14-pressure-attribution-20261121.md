# Run14: budget exhaustion, renderer termination, and the remaining owner gap

Evidence SHA-256:
`6ee7749a4b89a22d7fb989952c347b97f295993955cad78bda44b6f9e5b2df4e`.
Tested source `08c333bae081862256d73d0d4b388ceea9fa1db7`, native UUID
`AAABE9A1-D67E-3187-BE74-A1435A5E998A`. Runtime/package provenance agrees.
CS2 PID0378, initial TID037c, owner/PEB `0x10fe14000`, process lease34.
References below are decoded sanitized members. The attachment is not committed.

## Established sequence

- Remote connection02:44:17; activation02:46:32:135seconds, including
  resource work, scheduling and networking, not a disk-only measurement.
- Console02:47:32–33 contains408 CreateTexture2D and3 CreateTexture3D
  `E_OUTOFMEMORY` rows. Eight native reports are the bounded sample, not the
  complete count. No `NETWORK_DISCONNECT_TIMEDOUT` token appears.
- The renderer then reports `E_INVALIDARG`, an assertion and a minidump request.
  Worker0398 and039c null reads resolve to `rendersystemdx11.dll+0x7a2fe`.
- At native77398, worker0398 calls NtTerminateProcess on its process with
  `0xC0000005`. This is a terminated Windows guest, not a confirmed iOS jetsam.
  Native logging continues.

The terminal operand trace is internally consistent: the preceding generated
load takes eight bytes from `[x2+8]`; those bytes are zero and x0 is zero before
the dereference. That is an observed null producer/load, not the old alleged
high-half loss. No creation token/resource identity connects this object to a
particular rejected texture. The exact Valve renderer PE is not present in the
archive/local matching artifacts, so its higher-level producer is not claimed.

## Admission is reproduced, not bypassed

`md_resource_growth_acquire()` in `build/dxmt-ios/memory_pressure_native.h`
returns reason1 when `available <= floor` or
`charged > available - floor`. Pending receipts are independently accounted.
The first report has203,736,552 bytes available, floor201,326,592 and
charge2,798,672. Its above-floor2,409,960 bytes do not fit that charge.

The normal-only fixture executes the actual production function with all eight
logged footprint/available/charge/floor tuples. All eight reproduce ret3,
reason1 and pending0 without consuming a receipt. Healthy admission/release
then succeeds, including400 concurrent acquisitions/releases. This establishes
the predicate and recovery of metadata under controlled readings; it does not
measure reclamation, render pixels, or fix this working set.

The texture factory's estimate includes destination backing and simultaneous
initializer growth. The first request's1,398,096-byte destination plus
1,400,576 temporary bytes is consistent with aligned initial-subresource
uploads. No double-charge, latched OOM, or inaccurate estimate is established.
The already-low game profile and child `d3d11.mipClampAuto=0` are intentional.
The safety margin and truthful HRESULTs remain unchanged.

## Ownership audit: what is and is not measured

Near02:47:30, logical DXMT capacity is1,152MiB: private textures635MiB,
buffers492MiB, staging8MiB and initializer storage16MiB. Metal reports
1,248MiB allocated. These counters overlap and are not additive to process
footprint. The eligible dynamic cache is about1MiB. Two completed CPU-command
trims release4MiB capacity each; the second observes about1.05MiB lower task
footprint while other threads run. Neither establishes sufficient headroom or
exclusive physical attribution.

Source inspection retains the existing genuine completion requirements:

- ResourceInitializer uses its real event, submits pending work before bounded
  pressure waits, clears CPU references on reset, and only trims completed
  storage. Its observed8+16MiB is not an explanation for the whole shortage.
- Metal's local newBuffer path uses native storage (or provided no-copy memory).
  The remote-client shadow allocation branch is not this local path. Texture
  descriptors are released; owned texture/view wrappers retain actual resources.
- Creation receipts release only after their actual CPU/GPU lifetime. All eight
  refusals show pending0. No stranded receipt is established here.
- Earlier retired helper FEX owners in this capture report zero remaining
  tracked views. Current native malloc is about170MiB used/220MiB allocated;
  the actual public relief attempts report zero footprint reduction.

The last complete pre-failure VM walk (native75479 onward) reports dirty/resident
bands: JIT RX1,152/1,071MiB, JIT RW1,152/1,071MiB, guest1,341/561MiB,
FEX605/216MiB, host-low575/475MiB, PA362/448MiB. The two pool aliases share
backing and must be counted once. Even after excluding that alias, these
dirty/swapped/resident measures are not an additive task-footprint ledger.

One large guest region at `0x726eca0000` can be identified: native11208–11215
loads the32-bit `libcef.dll` image there. Its128MiB dirty region is part of the
live Steam browser window, not independently established obsolete storage.
The remaining broad bands do not identify which process/allocation sites own
all charged pages or which backing remains required.

**Attribution gap:** no measured reclaimable owner/lifetime defect explains the
remaining task footprint. Ordinary native guest VADs do not carry a general
process-lease ownership tag. Existing FEX/CEF tags cover specific native data
and private images; window ownership can identify32-bit namespaces, not
exclusive ownership of shared-section pages. Virtual reservation totals,
cumulative allocation traffic, compressed bytes and Metal capacity cannot fill
that gap. No live resource or quarantined range is newly released.

## Minimal pressure-boundary observation

This revision adds an observation, **not a claimed gameplay or memory fix**:

- On a physical reason1 refusal only, after unlocking the native receipt mutex,
  queue the opaque refusing owner/lease and exact operands. The request uses
  trylock, fixed storage, no payload reads/allocations and no VM/pool lock.
- At most one capture per owner/lease, four captures for the whole host session.
  Busy admission-side observation is best effort. Repeated411 failures cannot
  request411 walks. The existing pool-warmer consumes the request outside locks
  and cancels it if its process generation is stale or exiting.
- Reuse the existing VM census, once at that boundary instead of waiting up to
  the regular census period. The added walk has100,000-query and250ms soft
  between-query bounds. A single kernel call is not preemptible; truncation and
  elapsed time are explicit. It runs on the existing low-priority worker.
- Keep four dirty-region candidates from each non-pool band, at most16 rows.
  Copy only authoritative VAD/FEX/CEF/window metadata under separate trylocks;
  no lock nesting, guest payload read, Mach thread hold or resource mutation.
  Record owner/recorded lease/current lease, native-thread/exiting state,
  quarantine, view kind, busy/unknown results and window generation.
- The census and later registry snapshots are not atomic. Rows say
  `snapshot=post-walk`, `charged-physical=unknown`, `reclaim-permission=0`.
  Stale or unknown ownership never becomes permission to free memory. This is
  a selected sample, not a complete physical ownership census.

The expected information is whether dominant pressure-boundary regions still
belong to an active native CPU, a retained process generation, a browser window,
or remain unattributed. An unknown result may still require allocation-site
provenance; this observation does not promise an exact kernel ledger by owner.
No new broad profiler or per-allocation log is added.

## Cleanup and the displayed dead frame

Wine pseudo-processes share one native task. Windows process-object death and
its master socket EOF do not synchronously join every native worker. At77539,
`ios_thread_process_exit_ready()` reports four surviving native threads and
ready0/reclaimed0; later CPU records still include039c and03a0. The existing
quarantine therefore correctly retains their accessible memory until native
quiescence. Clearing a suspend count or forcibly freeing those ranges would
introduce a different defect.

`process_exit_wrapper()` retires the child identity while the genuine Steam
root/session can remain alive. The shared CAMetalLayer/MetalHostView does not
produce replacement game frames after the guest renderer dies. Its last image
can remain displayed. That persistence does not establish a runnable frozen
CS2 main thread. Cleanup and presentation behavior are not changed in this patch.

## Loading and recovery are separate

The135-second activation delay predates the terminal failures. Present#2048's
31,551.9ms maximum gap with8.6ms average inside Present is not a31-second GPU
wait. The scoped main-thread records now show actual varying host PCs and
measured user/kernel deltas, including substantial kernel time at some stores
and blocked native reads at others. The xprobe P/E columns are not used as
user/kernel time.

The main recovery record reaches106 completions, with zero recorded refused,
partial or publication-failed recoveries in its scoped cumulative counters.
The400-line historical output cap does not stop recovery. The previous
discovery-scheduling correction is preserved. Neither those completions nor a
current code PC attributes the whole loading interval to a single function.
The native read continuations are being resolved against the exact tested IPA;
a read syscall alone does not identify an asset file or a faulty socket path.

## Verification and delivery boundary

Normal checks execute production admission, request/take and selected-region
classification with ordinary valid metadata, normal lock contention and
concurrent requests. They do not run protection/revocation/crash experiments.
The observer test also runs the unchanged production Swift sanitizer on macOS,
preserving useful ownership fields and secret-row omission. The cache-key check
keeps native/DXMT source invalidation intact. Existing normal discovery replay
continues to protect the earlier recovery correction.

No physical saving, faster load, successful texture creation on the phone or
playable round is asserted. No memory-reclamation correction has been selected
without an established owner. This attribution patch is not presented as a
fixed-game IPA. A new installation is not requested as a substitute for the
remaining causal investigation.

Acceptance remains responsive remote team selection, sustained play through a
round and a clean return/changelevel with correct required textures. None has
been performed or verified here.
