# CS2 loading: remove APFS discard from the heap/VM lock chain

Installed baseline: `fd6b7c03564c2ca15ccb6cdba68083676928f318`.
Evidence: the supplied 16,660,044-byte `madeira-log.txt`. No separate IMG_1431
file was available; screenshot values are the user's report.

## Measured facts and limits

This main log contains 48 bounded game-log warning observations, not the full
connection/sign-on console. It cannot independently measure this run's remote
connection-to-activation interval. The historical 152-second and 92-second
intervals include transport and game initialization; neither is disk-only time.

The native trace establishes real multi-second filesystem calls:

| Operation | Observed duration | Execution context |
| --- | ---: | --- |
| `F_PUNCHHOLE (decommit)` | 4,844 ms | synchronous reservation decommit |
| `F_PUNCHHOLE (decommit)` | 8,412 ms | synchronous reservation decommit |
| `F_PUNCHHOLE (deferred)` | 8,662 ms | existing background release worker |

Eight printed slow decommit calls total 15,983 ms; eight printed worker calls
total 15,046 ms. These calls can overlap, so these totals must not be added or
treated as map-loading wall time. The final counters report 25 slow calls;
only 16 slow-call records were printed. The largest calls occur near existing
14:38–14:40 wall-time observations, without a calibrated full game timeline.

At approximately 14:39:08, three CS2 threads report 60-second waits on main heap
`0x7075e800d0`, owned by `03c4`, identified as `AsyncIOService/0`. Its samples
include resource work, buffer validation and native reads. They do not prove
which operation owned the heap throughout those waits.

Source supplies the relevant serialization mechanism: `RtlFreeHeap` holds the
heap lock while `heap_free_block()` releases empty subheaps or calls
`subheap_decommit()`. Reservation decommit then holds `virtual_mutex` while
calling the synchronous APFS hole punch. Thus a slow discard can block the heap
and other VM users, including buffer validation and fault handling. The trace
does not prove that this accounts for the entire connection-to-activation delay.

Other observations guide scope:

- The trace contains CPU-before-GPU gaps, including 64 frames in 70,922 ms with
  242 ms GPU time and 125,995 ms with 73 ms GPU time. Those windows cannot be
  independently labeled remote map loading.
- The shader cache directory is active. At 5,120 unique shaders the recorded IR
  recreation counter remains zero. Sampled early PSO calls reach about 2 ms;
  this does not bound every later compile. Full shader initialization already
  occurs outside the pipeline-cache lock. No shader-cache correction is
  demonstrated, so the working cache and renderer are preserved.
- Dynamic-buffer reuse reaches 99%, retired initial-upload capacity reaches
  zero, and peak process footprint is 5,903 MiB. Resource capacities and Metal
  allocation figures are not added together.
- CS2 records actual successful public UDP sends and receives, each 1,300 bytes,
  on different descriptors. These are unpaired checkpoints, not proof of relay
  identity or successful match acceptance. No transport settings are changed.
- Cumulative store-handler time is 260,892 ms across the roughly 28-minute run,
  not one continuous loading stall. No FEX or protection policy is changed.

## Production correction: zero-backed decommit with retired offsets

`build/ntdll-unix/virtual_ios.c` now handles decommits covered by a union of
reservation extents as follows:

1. Under the existing VM lock, validate complete backing coverage, bounded
   metadata capacity and room in the existing discard queue.
2. Take an already-zero free or fresh sparse-file offset within the existing
   cap. Pending or failed punches never qualify as free offsets.
3. Discard only the dead whole-host-page contents and replace their mapping
   with the new zero-backed shared mapping. No CPU copy or live neighbor is
   involved.
4. Update reservation extent metadata, preserving its ownership, churn key,
   birth time and file-backed lifetime. Coalesce compatible replacement pieces
   so repeated overlapping decommits do not preserve obsolete split boundaries.
5. Queue only the unmapped **old file offsets**. The worker punches them outside
   the VM lock and makes them reusable only after a successful punch.

The worker never receives the replacement VA. Recommitted writes cannot be
erased by an old punch. Live backing-byte accounting and the 6,144 MiB swap cap
do not increase. No full-size temporary buffer is allocated. Temporary offset
quarantine is bounded by the existing file cap and queue.

If queue/thread, zero-offset, discard, mapping or metadata capacity is unavailable, the
function retains honest synchronous zeroing. This fallback also handles unions
of previously split extents without silently making recommit anonymous.
Failed retired punches stay quarantined. `MS_KILLPAGES`, mapping and other
filesystem operations can still block; the change does not claim to eliminate
all storage latency. A failed dirty-page discard keeps the synchronous path;
even successful discard is not a guarantee about instant physical-footprint
reduction. Actual footprint under asynchronous reclamation needs device
validation. Existing `MADEIRA_SWAP_PUNCH_DEFER=0` behavior is retained.

The existing low-volume swap census adds remap/fallback counts. There is no new
profiler, background timer, active network probe or game instrumentation.

## Production correction: keep unrelated file reads out of a Steam observer lock

`build/ntdll-unix/js_read_trace.h` previously took a shared diagnostic mutex and
scanned 64 slots after every successful CS2 file read once any Steam UI JS file
had been observed. A fixed 32-byte atomic, monotonic owner filter now rejects
nonmatching owners before that mutex. Publication precedes enabling tracking;
there are no cached negative results. Hash collisions conservatively retain
the existing exact owner/handle check. Handle reuse and inode validation remain.

The recorded Steam owner and CS2 owner do not collide. The last JS record
precedes main loading, so actual observer-lock contention during loading is
unmeasured. This removes unnecessary read-path locking/scanning, without claiming
that it explains minutes of loading. It does not cache or alter game file data.

## Validation and remaining device test

The actual production swap core is compiled against real owned sparse files.
A verbatim pinned old function serves as the negative control. Controlled
native-call delays establish that the old decommit holds the VM lock during a
blocked punch; the new caller returns and another thread obtains the lock while
the retired-offset punch remains blocked. Tests verify zero contents, unchanged
neighbors, writes surviving late punches, overlapping decommits, unchanged live
capacity, and honest failures/fallbacks. Injected delays are not iPhone timings.

Actual-header read tests perform 10,000 real reads. The old observer guard takes
10,000 diagnostic locks; the recorded nonmatching CS2 owner takes zero with the
new guard and completes while the observer mutex is held. Publication, eviction,
collisions, handle/inode reuse, file bytes and errno are checked under sanitizers.

Linux and Darwin CI exercise these paths; final IPA provenance must match the
changed native source. Existing signal/JIT, socket, DXMT, input and export checks
remain required. The iPhone must still establish the new connection-to-activation
interval, full sign-on, responsive team selection, sustained gameplay, FPS and
peak footprint. Under 30 seconds is a target, not a measured result or guarantee.

Install over the existing app using the same signing identity and bundle ID.
There is no prefix or cache migration, game-file edit, timeout change, shader
quality change, or reinstall. Installing the baseline IPA with the same identity
provides rollback while retaining user data.
