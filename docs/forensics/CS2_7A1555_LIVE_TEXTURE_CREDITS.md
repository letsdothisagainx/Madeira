# CS2 7a1555: texture admission and upload reuse

Evidence: the run exported 2026-11-16 06:01:48 UTC, source
`7a1555a306d9283448e64a36d1c0d76c90926a02`. This is a new run;
older game-process records in the archive are not current-session outcomes.

CS2 launched at 00:47:27 local time, connected remotely at 00:53:41–42,
activated at 00:57:05, and received full updates at 00:57:06 and 00:58:40.
The remote channel timed out at 00:58:48. Later full updates belong to a
local loopback session. This change does not alter Steam, networking, VAC,
JIT placement, executable protections, game files, settings, or input.

## Confirmed failures

The old texture policy had a 384 MiB ordinary floor, a 256 MiB completion
floor, a 1 MiB per-request exception limit, and a cumulative 128 MiB
completion allowance. A 1,398,096-byte request with 313,657,240 bytes of
reported headroom exceeds that exception's size limit. An 8-byte request
at 260,605,704 bytes is below its hard floor. These gates can explain the
recorded rejections without assuming a corrupt Metal allocation. The old
log does not record outstanding credit or cumulative allowance at each
failure; it cannot identify which additional gate also applied. The
captured console contains 756 texture OOM reports. No observed native
Metal nil result proves that every rejected texture was physically impossible.

`available` is OS-reported process headroom, not a promise that all those
bytes are safely allocatable. DXMT capacity, Metal allocation, physical
footprint and compressed memory are overlapping accounting domains.

The upload census rose from 272 MiB / 28 allocations to 27,696 MiB / 940
allocations between 00:55:27 and 00:57:05, eventually 28,242 MiB / 1,056
allocations with 1,054 frees and only 0–32 MiB live. This is cumulative
allocation churn, not 28 GiB of physical residency. Normal trimming dropped
the reusable upload block below half-reserve even while texture admission
allowed work in that range. An explicit emergency-drain latch did not stop
these normal trims.

The five initializer methods also used `continue` inside `do/while(0)`:
a failed allocation could skip initialization and return a successful fence.
The zero-buffer path could link a fill before checking native backing.
These source defects are reproducible independently of this game's logs;
the archive does not prove how often they occurred in this run.

## Production corrections

- Replace historical completion spending and the 1 MiB cliff with fresh
  physical headroom minus concurrent prospective reservations. Keep an
  adaptive safety floor of one quarter of the normal reserve, clamped to
  128–256 MiB (192 MiB for the reported 6 GiB limit). Reclaim starts at the
  existing larger reserve. Genuine insufficiency still returns OOM.
- Charge destination backing plus genuinely new upload/zero-buffer growth,
  including conservative alignment, oversize and fallback-decode costs.
  Hold an initializer transaction across forecast/admission/enqueue so a
  concurrent creator or trimmer cannot invalidate the forecast. Reforecast
  after reclamation before replacing the CPU reservation.
- Transfer pending credit to the initializer's genuine native shared event
  before recording commands. Retire it only after the actual GPU frontier
  completes. CPU return, elapsed time, or process termination does not prove
  GPU completion. Owner/lease validation and bounded event loans prevent
  trusting arbitrary guest-supplied Objective-C pointers.
- Normal admission never waits for an unpublished private batch. A denied
  producer flushes its real pending batch before a bounded retry; native
  waits release the budget mutex and resample real memory. Darwin's relative
  condition wait is explicitly non-cancelable, so owned cleanup boundaries
  explicitly test deferred cancellation before/after each bounded sleep;
  cancellation cannot strand the waiter count or budget mutex. The first Mac
  regression run exposed this difference from Linux's cancelable wait.
  No successful allocation or completion is fabricated.
- Retain one completed natural-size upload block under soft pressure, use
  high/low-water hysteresis at critical pressure, and still release completed
  warm storage for genuine emergency reclamation. In-flight buffers and live
  textures/SRVs remain owned by their normal CPU/GPU lifetimes.
- Make initializer retries bounded and truthful, allocate backing before
  linking commands, preserve the previous zero buffer until replacement is
  valid, and propagate failure to the texture factory instead of publishing
  an incomplete resource.

## CPU and executable-fault interpretation

The saved guest RIP `0x71d50ea342` resolves to `tier0.dll+0x28A342`.
The supplied bytes show `mov rbp,rax` following a call. The actual sampled
host bin around `0x7c47d35540` contains a vector 32-byte copy loop with a
FEX cancellation check. A saved guest return address can be stale while
translated code runs. Matching proprietary PE/PDB files and a complete
caller/length are unavailable: an exact function name or an emulator spin
bug is not established. No Valve code or FEX implementation is patched.

The earlier host faults near `0x7c47598090`, writing `0x71d0460140`, were
followed by successful self-modifying-code handling during Steam Overlay
trampoline initialization. Wine's `NOT COMMITTED` diagnostic queried the
host JIT PC as a guest address; it does not prove the host mapping was
unmapped. These recovered events do not establish the later frame-stall
cause. No speculative SMC/cache/protection change is included.

## Validation boundaries

Host tests execute staged production methods against controlled memory,
resource and GPU-completion fixtures, with sanitizer coverage. At the
recorded headroom values, both 8-byte and 1,398,096-byte requests plus a
new 32 MiB upload block are admitted while preserving the 192 MiB floor.
They also test real insufficiency, concurrent credits, ownership, recovery,
GPU-pending lifetime, native allocation failure, and byte-identical data.

The repeated-upload fixture changes 1,000 allocations into one reusable
block with identical copied bytes and 1,000 fixture submissions. This is a
host result, not an iPhone FPS or physical-memory measurement. The native
registry has a separate Darwin Foundation/Metal test; package gates require
the new PE/native implementations and exact source provenance.

Real CS2 texture output, process peak, sustained frame pacing, team selection
and remote-session survival still require iPhone testing. Removing false
rejections cannot guarantee that all legitimately live game resources fit.
The observed allocation churn is a concrete avoidable CPU cost, not proof
that this change eliminates every 89-second present gap.

Rollback: install the earlier same-identity IPA over the app, or revert this
commit and rebuild through the existing workflow. Do not uninstall Madeira,
reset the prefix, remove game files, or clear account/settings data.
