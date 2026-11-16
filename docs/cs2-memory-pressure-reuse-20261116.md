# CS2 memory-pressure reuse — 2026-11-16

Baseline: `7e6ce444774a567a0ee634e8c5c629dde05d6cab`. This change addresses
source-confirmed allocation churn and temporary-memory growth. It does not
establish successful map loading, a lower iPhone footprint, improved thermals,
or sustained multiplayer gameplay.

The supplied native log identifies source `7e6ce444`, with matching packaged
and actual native UUID and matching virtual-memory/JIT producer provenance.
The request and log report approximately 6,113 MiB footprint against a
6,144 MiB limit, 99% trim regret, `warm-budget=0`, texture admission failures
and later 40–60 FPS windows. No independent jetsam report or complete
physical-memory ownership breakdown is available. DXMT capacities, Metal
allocated size, compressed memory, swap backing and process footprint must not
be summed. The raw attachment is not committed.

The late VM walk reports guest-band dirty/resident pages of 1,309/238 MiB,
FEX-band 748/132 MiB and host-low 571/596 MiB. Both JIT aliases show
1,152/1,058 MiB, but they share verified backing and must be counted once.
The final footprint sample includes 2,553 MiB compressed memory; that is a
task-accounting category, not an extra allocation to add to the bands. Native
malloc reports 293 MiB used out of 336 MiB allocated, so public free-heap
relief alone cannot be assumed to recover hundreds of MiB. These overlapping
observations do not supply a complete additive physical ownership ledger.

## Confirmed source defects and corrections

### Dynamic-buffer pressure handling

The existing critical-pressure state forced the completed warm-cache budget
to zero. Its hysteresis retained that state until headroom recovered, so a
frequently reused completed buffer could be destroyed on every frame even
when retaining a small existing working set would avoid another allocation.
The allocation-miss sweep stamp was thread-local, allowing different loading
threads to repeat the same full registry walk at the same GPU frontier.

`tools/build/stage-dxmt-dynamic-memory.py` now emits `bounded-hot-v3`:

- The existing normal pressure thresholds and hysteresis remain intact.
- Under critical pressure, a global allowance retains only existing,
  completion-proven, learned-hot spare names. It is bounded by the minimum of
  available headroom / 16, reserve / 256 and 4 MiB. It grants no allocation or
  refill permission. Unknown or zero headroom retains none; an explicit
  texture-admission failure still drains all eligible spares.
- Cold and oversized entries are considered before learned-hot entries.
  Current resource names and outstanding GPU references are preserved.
- Queue/frontier sweep stamps suppress duplicate allocation-miss registry
  walks across threads. Newly returned already-completed backing, a newer GPU
  frontier or stronger pressure invalidates suppression. Real completion and
  explicit-drain calls retain their reclamation pass.

### Guest-backing migration

`build/ntdll-unix/virtual_ios.c` previously copied an entire overlapping
file-backed extent into one temporary `malloc` allocation before replacing
the mapping with anonymous backing. The temporary allocation grew with the
extent, producing an avoidable loading-time burst.

Migration now uses at most 1 MiB of scratch, preserving bytes and restoring
the existing per-page protections after each chunk. A failed chunk leaves its
suffix file-backed and recorded in the ownership ledger. Protection changes
return a real failure if required migration did not finish; they do not claim
executable or guarded backing that was not established. This bounds temporary
duplication; it does not make still-live guest memory reclaimable.
This run reports zero swap copy-backs (`unbacks=0`), so the bounded conversion
fix is not presented as the cause or cure of this run's sustained footprint.

### Native free-heap relief

`build/dxmt-ios/native_heap_relief.h`, the native pressure-query producer and
the existing Wine pool-warmer coordinate public
`malloc_zone_pressure_relief(NULL, goal)` calls. Valid existing footprint
samples queue a coalesced hint; the background worker remeasures before doing
work, outside graphics and pool/VM locks. The goal is 16–64 MiB, with a
two-second minimum interval following an observed footprint drop and an
eight-second backoff when no drop is measured.

Only allocator-owned **free** malloc pages are eligible. Live guest heaps,
textures, pending uploads, executable pages and JIT aliases are not purged.
The allocator's returned-byte count is recorded separately from the actual
before/after physical-footprint readings. Neither that count nor detached
DXMT capacity guarantees a physical drop. Unknown measurements and absent
native backends remain inert; no extra worker thread is created.

### Upload reuse fast path

`tools/build/stage-dxmt-upload-memory.py` previously queried native pressure
and a Metal shared event before every initial mip/slice upload, even when the
ring already owned sufficient nonoverlapping backing. The fast path first
checks growth using the conservative cached GPU frontier. Reuse without growth
needs neither native query. A genuine capacity miss refreshes the real event,
rechecks reuse, then measures pressure before considering new backing.
Existing admission, bounded waits and real GPU completion remain mandatory.

## Verification and limits

The focused host checks execute the staged production allocator/initializer
and the actual swap migration helpers with controlled adapters. They validate
bytes, ownership, completion boundaries and failure paths; they do not replay
the complete iPhone execution schedule or measure CS2 FPS, thermal state or physical savings.

| Controlled host workload | Previous policy | Corrected policy |
| --- | ---: | ---: |
| Dynamic warm-frame reuse hits, 96 frames | 0 | 23,552 |
| Dynamic warm-frame allocation misses | 23,552 | 0 |
| Dynamic trim regret | 12,160 | 0 |
| Dynamic new backings | 24,576 | 256 |
| Dynamic peak owned capacity | 1.5 MiB | 1.5 MiB |
| Event reads for 49,066 uploads fitting owned backing | 49,066 | 0 |
| Pressure queries for the same uploads | 49,066 | 0 |
| Temporary scratch for a 32 MiB guest-backing conversion | 32 MiB | 1 MiB |

The upload checksum and 1 MiB owned backing were unchanged; the fast path
performed no extra allocation, wait or submission. A separate dynamic test
suppressed 128 redundant same-frontier scans, then proved a newly eligible
retirement invalidated suppression while a retained GPU reference stayed valid.
The swap fixture used real sparse-file/anonymous mappings: a 2 MiB scratch
ceiling blocked the old 32 MiB conversion but allowed the corrected conversion.
Injected mapping failure preserved the unmigrated suffix and its ledger offset;
retry succeeded, neighbours and guard protections remained intact, and failed
protection changes did not update guest protection bookkeeping.

Focused checks passed:

- `tests/host/check-dxmt-dynamic-memory.py` and
  `tests/host/check-dxmt-upload-memory.py`, including staged-code ASan/UBSan
  ownership/concurrency, bounded pressure, recovery and real-growth cases.
- `tests/host/check-swap-copyback-budget.py`, `check-swap-coverage.py`,
  `check-swap-images.py` and `check-swap-decommit-remap.py`.
- `tests/host/check-native-heap-relief.py`: controlled valid/invalid readings,
  concurrent request coalescing, no invented physical savings, background
  backoff and preserved `errno`. The real Darwin/libmalloc exercise is skipped
  on this Linux host and must run on the macOS build worker.

The game-owned texture profile was also traced and corroborated in this run.
`already-low` means the existing unambiguous CS2 video file contains
texture-detail scalar 0. `applied=0 deferred=1` deliberately keeps Steam/CEF
options unchanged. After the genuine `cs2.exe` creation request, the log
records `child-environment-prepared`; DXGI then logs
`Found config env: d3d11.mipClampAuto=0`, confirming the deferred option reached
the game's renderer. Balanced does not silently omit requested mips. No profile
defect was established and no new unsupported Source 2 command is introduced.

No FEX code, JIT pool size/partition, placement, Steam/CEF launch policy,
network transport, Valve binary or authentication mechanism is changed. The
full 1,152 MiB pool and existing 768/384 MiB partition are preserved. No prefix,
game files, account data or settings are deleted.

Device acceptance still requires correct required textures, meaningful
physical headroom, lower allocation churn, completed remote map loading,
responsive team selection and a sustained real match. The texture OOM floor
is preserved: if live memory still cannot fit, allocation must fail truthfully.
