# Run14: budget exhaustion, renderer termination, and the remaining owner gap

Evidence SHA-256:
`6ee7749a4b89a22d7fb989952c347b97f295993955cad78bda44b6f9e5b2df4e`.
Tested source `08c333bae081862256d73d0d4b388ceea9fa1db7`, native UUID
`AAABE9A1-D67E-3187-BE74-A1435A5E998A`. Runtime/package provenance agrees.
CS2 PID 0378, initial TID 037c, owner/PEB `0x10fe14000`, process lease 34.
References below are decoded sanitized members. The attachment is not committed.

## Established sequence

- Remote connection 02:44:17; activation 02:46:32: 135 seconds, including
  resource work, scheduling and networking, not a disk-only measurement.
- Console 02:47:32–33 contains 408 CreateTexture2D and 3 CreateTexture3D
  `E_OUTOFMEMORY` rows. Eight native reports are the bounded sample, not the
  complete count. No `NETWORK_DISCONNECT_TIMEDOUT` token appears.
- The renderer then reports `E_INVALIDARG`, an assertion and a minidump request.
  Workers 0398 and 039c null reads resolve to `rendersystemdx11.dll+0x7a2fe`.
- At native line 77398, worker 0398 calls NtTerminateProcess on its process with
  `0xC0000005`. This is a terminated Windows guest, not a confirmed iOS jetsam.
  Native logging continues.

The terminal operand trace is internally consistent: the preceding generated
load takes eight bytes from `[x2+8]`; those bytes are zero and x0 is zero before
the dereference. That is an observed null producer/load, not the old alleged
high-half loss. The exact guest bytes at `+0x7a2fe` are `48 8b 01 ff 50 08`:
a pointer/vtable read followed by an indirect call through offset8. The failing
null is the value from that object field; identifying it as a particular COM
resource or method would require additional type/producer evidence.
No creation token/resource identity connects this object to a
particular rejected texture. The exact Valve renderer PE is not present in the
archive/local matching artifacts, so its higher-level producer is not claimed.

## Admission is reproduced, not bypassed

`md_resource_growth_acquire()` in `build/dxmt-ios/memory_pressure_native.h`
returns reason1 when `available <= floor` or
`charged > available - floor`. Pending receipts are independently accounted.
The first report has 203,736,552 bytes available, floor 201,326,592 and
charge 2,798,672. Its above-floor 2,409,960 bytes do not fit that charge.

The normal-only fixture executes the actual production function with all eight
logged footprint/available/charge/floor tuples. All eight reproduce `ret=3`,
`reason=1` and `pending=0` without consuming a receipt. Healthy admission/release
then succeeds, including 400 concurrent acquisitions/releases. This establishes
the predicate and recovery of metadata under controlled readings; it does not
measure reclamation, render pixels, or fix this working set.

The texture factory's estimate includes destination backing and simultaneous
initializer growth. The first request's 1,398,096-byte destination plus
1,400,576 temporary bytes is consistent with aligned initial-subresource
uploads. No double-charge, latched OOM, or inaccurate estimate is established.
The already-low game profile and child `d3d11.mipClampAuto=0` are intentional.
The safety margin and truthful HRESULTs remain unchanged.

## Ownership audit: what is and is not measured

Near 02:47:30, logical DXMT capacity is 1,152 MiB: private textures 635 MiB,
buffers 492 MiB, staging 8 MiB and initializer storage 16 MiB. Metal reports
1,248 MiB allocated. These counters overlap and are not additive to process
footprint. The eligible dynamic cache is about 1 MiB. Two completed CPU-command
trims release 4 MiB capacity each; the second observes about 1.05 MiB lower task
footprint while other threads run. Neither establishes sufficient headroom or
exclusive physical attribution.

Source inspection retains the existing genuine completion requirements:

- ResourceInitializer uses its real event, submits pending work before bounded
  pressure waits, clears CPU references on reset, and only trims completed
  storage. Its observed 8+16 MiB is not an explanation for the whole shortage.
- Metal's local newBuffer path uses native storage (or provided no-copy memory).
  The remote-client shadow allocation branch is not this local path. Texture
  descriptors are released; owned texture/view wrappers retain actual resources.
- Creation receipts release only after their actual CPU/GPU lifetime. All eight
  refusals show `pending=0`. No stranded receipt is established here.
- Earlier retired helper FEX owners in this capture report zero remaining
  tracked views. Current native malloc is about 170 MiB used/220 MiB allocated;
  the actual public relief attempts report zero footprint reduction.

The last complete pre-failure VM walk (native lines 75479 onward) reports dirty/resident
bands: JIT RX 1,152/1,071 MiB, JIT RW 1,152/1,071 MiB, guest 1,341/561 MiB,
FEX 605/216 MiB, host-low 575/475 MiB, PA 362/448 MiB. The two pool aliases share
backing and must be counted once. Even after excluding that alias, these
dirty/swapped/resident measures are not an additive task-footprint ledger.

One large guest region at `0x726eca0000` can be identified: native lines 11208–11215
loads the 32-bit `libcef.dll` image there. Its 128 MiB dirty region is part of the
live Steam browser window, not independently established obsolete storage.
The remaining broad bands do not identify which process/allocation sites own
all charged pages or which backing remains required.

**Attribution gap:** no measured reclaimable owner/lifetime defect explains the
remaining task footprint. Ordinary native guest VADs do not carry a general
process-lease ownership tag. Existing FEX/CEF tags cover specific native data
and private images; window ownership can identify 32-bit namespaces, not
exclusive ownership of shared-section pages. Virtual reservation totals,
cumulative allocation traffic, compressed bytes and Metal capacity cannot fill
that gap. No live resource or quarantined range is newly released.

## Minimal pressure-boundary observation

This revision adds an observation, **not a claimed gameplay or memory fix**:

- On a physical reason 1 refusal only, after unlocking the native receipt mutex,
  queue the opaque refusing owner/lease and exact operands. The request uses
  trylock, fixed storage, no payload reads/allocations and no VM/pool lock.
- At most one capture per owner/lease, four captures for the whole host session.
  Busy admission-side observation is best effort. Repeated 411 failures cannot
  request 411 walks. The existing pool-warmer consumes the request outside locks
  and cancels it if its process generation is stale or exiting.
- Reuse the existing VM census, once at that boundary instead of waiting up to
  the regular census period. The added walk has 100,000-query and 250 ms soft
  between-query bounds. A single kernel call is not preemptible; truncation and
  elapsed time are explicit. It runs on the existing low-priority worker.
- Keep four dirty-region candidates from each non-pool band, at most 16 rows.
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
its master socket EOF do not synchronously join every native worker. At native line 77539,
`ios_thread_process_exit_ready()` reports four surviving native threads and
`ready=0`/`reclaimed=0`; later CPU records still include 039c and 03a0. The existing
quarantine therefore correctly retains their accessible memory until native
quiescence. Clearing a suspend count or forcibly freeing those ranges would
introduce a different defect.

`process_exit_wrapper()` retires the child identity while the genuine Steam
root/session can remain alive. The shared CAMetalLayer/MetalHostView does not
produce replacement game frames after the guest renderer dies. Its last image
can remain displayed. That persistence does not establish a runnable frozen
CS2 main thread. Cleanup and presentation behavior are not changed in this patch.

## Loading and recovery are separate

The 135-second activation delay predates the terminal failures. Present #2048's
31,551.9 ms maximum gap with 8.6 ms average inside Present is not a 31-second GPU
wait. The scoped main-thread records now show actual varying host PCs and
measured user/kernel deltas, including substantial kernel time at some stores
and blocked native reads at others. The xprobe P/E columns are not used as
user/kernel time.

The main recovery record reaches 106 completions, with zero recorded refused,
partial or publication-failed recoveries in its scoped cumulative counters.
The 400-line historical output cap does not stop recovery. The previous
discovery-scheduling correction is preserved. Neither those completions nor a
current code PC attributes the whole loading interval to a single function.
The native read continuations were resolved against the exact tested IPA:

| Runtime return address | Image offset | Matching native symbol | Call at LR-4 |
| --- | --- | --- | --- |
| `0x101a79018` | `0x1369018` | `wait_select_reply+0x38` | `_read` |
| `0x101a8ab70` | `0x137ab70` | `read_reply_data+0x30` | `_read` |

The native runtime image base is `0x100710000` (native line 252). The inspected
Mach-O UUID matches Run14; its SHA-256 is
`034e80cc92e4d6e1573cdcd1c58562c1d0969e28a886ead3c33839b9df1a2850`.
`wait_select_reply` reads `wait_fd[0]` for a Wine wake-up cookie, and
`read_reply_data` reads `reply_fd` for server replies. Thus these particular
read samples are Wine wait/RPC pipes, not identified VPK/swap/asset reads.
The waited object/request, reply latency and aggregate contribution to loading
remain unknown; a legitimate blocked wait is not itself a wait implementation
defect. No pipe/wakeup implementation is changed.

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

### Completed normal verification

Code/test revision: `f1bdb0ef13df14c83e911ec291f55d7517ea472f`.
[Read-only/normal-input workflow 44885207359](https://github.com/letsdothisagainx/Madeira/actions/runs/44885207359)
passed Linux and Xcode 27 jobs. Results include:

- All eight actual admission predicates reproduce; healthy admission/release
  and 400 parallel receipts balance. The callback is verified to run after
  releasing the receipt mutex.
- 80,000 concurrent observation requests coalesce. Four session slots, distinct
  generations, stale/exiting rejection, query/time bounds, busy trylocks and
  known/unknown owner classification pass with unchanged ownership metadata.
- The actual unchanged Swift sanitizer preserves the ownership fields and
  omits rows containing secrets.
- The previous successful-store discovery replay and compile-only legacy
  fixtures pass. No deliberate faults, protected-memory/page-revocation tests
  or background coding agents were used.
- 4,212 cache-key cases pass. Read-only DXMT staging validates 22 source
  records and the existing Metal shader recipe without modifying vendor files.
  The write-mode shader preflight requires the build's already-applied shader
  transform; it is not the appropriate check for this clean source-only tree.
- The exact prior artifact 14671470397 is retrieved and its archive digest
  `29f35aa4d2e06ef895f067dd602090d2cf504f2dea9a2a94106ad9995b08d72d`
  verified. Native symbols and compiled recovery call paths match the tested
  source/UUID. This verifies the existing IPA, not a new app build.

The complete iOS application has not been rebuilt/published for this observation
patch. These checks compile the extracted production functions and validate
the prior native package; they do not validate a new linked image or execute
the added census on an iPhone. No replacement IPA or on-device pass is claimed.
