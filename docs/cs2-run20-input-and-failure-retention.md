# Run20: bounded input delivery and durable resource failure evidence

The input archive SHA-256 is
`305f914a82d1f2d5ade25ec2930a8d2a20ef25532fd13a2fd095a6bc4c0c8440`.
It tests source `482ac26ffb81a2985310d64c697c61616f5134ed`, native UUID
`BE56EF9B-A68E-3BA6-9549-B06809C49E7D`. Analysis uses only the current
`05C2C4FC-604F-42B9-A2CF-BDB527CA0DC5` namespace. Preceding Run19 is separate.

## What the evidence establishes

The real remote session connected at 03:08:41 and activated at 03:10:03
Eastern on November 24 (82 seconds). The user reached a live player view,
with unusable 0–1 FPS and controller input. The early 67,889-ms / 64-frame
batch precedes the 03:12:05–27 allocation failures and controller connection.
Neither input congestion nor the later allocation burst explains that entire
interval. GPU execution and time inside Present are small compared with gaps
between calls; these are not measured GPU execution stalls.

Replaying the existing analysis against calibrated capture timestamps, with
both ends of each main interval wholly inside 03:10:12–03:12:00, reproduces
91 intervals: 107.260835 seconds elapsed, 3.733065 user and 38.491615 kernel
CPU, or 91.159% kernel share of **consumed CPU**. Console wall-second precision
and post-resume mapping observations remain uncertain. Forty naturally aligned,
non-crossing STLR samples have writable external mappings. This does not identify
the expensive kernel operation. The actual STLR fallback, code-buffer reuse and
recovery/QoS correction remain intact. No instruction toggle or backing-policy
change is included.

The nearby 107-second host-app I/O deltas reproduce 25,791,090,688 write bytes,
710,422,528 read bytes and 63,779 page-ins. These are not per-thread/per-file
statistics, physical-device write volume, or proof that every VM fault is I/O.
Main-sampler holds total only 6.045 ms in the early window. The later 249.070-ms
hold and 5.766-second recorder utility operation remain outliers, not a causal
explanation for the earlier stall. Thermal state is 2; maps/runs are not a
controlled performance benchmark.

There are 222 console OOM occurrences and 222 direct observer admission/OOM
results (separate scopes), no observed native-allocation/initialization failure
in that direct counter, and eight retained native text refusal rows. The example
1,048,576-byte destination + 65,536-byte temporary charge exceeds usable
869,912-byte headroom. The destination alone cannot fit. This is correct reserve
enforcement. Existing bounded uploads really ran. Altering their forecast or
removing the reserve would not fix this.

Review of live-owner pressure-boundary records, current view/backing lifetimes,
completed upload/CPU-command retirement and renderer capacity does not establish
sufficient safely reclaimable physical storage. The CS2 owner is still live;
its guest reservation sizes are not physical residency or reclamation permission.
Compressed memory is substantial. RX/RW aliases share backing; Metal/DXMT counters
overlap. The tiny eligible dynamic cache cannot cover these shortages. No live
mapping is force-freed, no resource initialization is skipped, and no sufficient
reduction for destination-only failures is claimed. The missing distinction is
which live guest allocations/representations account for charged resident and
compressed memory, and which kernel VM work dominates while they are accessed.
Current post-resume page metadata and whole-app I/O cannot establish that.

The actual terminal console reason is `NETWORK_DISCONNECT_KICKED_VOTEDOFF`
at 03:14:12. This run has no captured network-timeout token, E_INVALIDARG or
renderer assertion. Structured evidence ends about 03:14:04.898; raw logs extend
later and changed during export. Later records do not retroactively extend
structured coverage. Visual corruption is reported independently of counters.

## Production corrections

* `Winios/InputQueue.h` replaces the actual transport, keeping 255 usable slots.
  Adjacent compatible pure relative motion is summed; absolute motion keeps its
  latest position. No motion crosses a key/button/wheel/mode boundary. A motion
  batch retains at most 100 ms of history. Producers and consumer use try-locks;
  no allocation, formatting, filesystem or Wine call occurs under that queue lock.
* On overflow an edge displaces only queued pure motion, retaining remaining
  FIFO order. If no motion is available, or an edge producer cannot acquire the
  lock, an explicit epoch reset drops pending history and tells the consumer to
  release bridge-submitted holds. This is bounded, counted loss with safe
  neutralization, not a promise to preserve arbitrary unlimited input history.
  Text has edge headroom and retains its existing generation/pacing semantics.
* The consumer performs at most 64 event/neutralization steps per pump. Old
  motion and old completed press/release pulses are discarded rather than
  replayed after a long stall. A still-held press remains deliverable even
  below one drain per second; releases remain valid. Existing IPC can itself take time; the event
  budget is not an IPC-latency guarantee. Per-motion logging/flushes are removed.
* `PadKeyboardMouse` now gates buttons and key sticks as well as mouse motion
  on native UI focus. Old code posted keys/buttons with `focused=false`.
  Losing focus, library ownership, app inactivity and session transitions release
  bridge state and invalidate stale queued input. Held controls must return to
  neutral after focus/lifecycle loss. Overflow epochs resynchronize current valid
  controller and hardware state. Custom binding releases use the original action.
  No dialog protection is removed and no extra foreground-stealing call is added.
  Native focus publication includes the initial unfocused state, even when
  Swift's cached Boolean already began false; identical observations do not
  repeatedly reset the queue.
* The staged `TextureInitializationCredit` now exposes the fence already captured
  by its real credit handoff. The diagnostic factory previously invoked
  `initializationFence()` separately, triggering initializer maintenance twice.
  The corrected helper queries it once and hands off the same frontier. Completion
  ownership, upload bytes/layout/window, credits and reserve are unchanged.

These remove demonstrated overhead and input correctness defects. Queue saturation
and incorrect foreground delivery are not proved in Run20. None of these changes
establishes removal of the primary kernel-heavy stall.

## Input and failure evidence

The existing keyboard/mouse branch now records physical callback/sample counters,
closed effective bindings and signature, translation/enqueue/coalesce/drop counts,
queue depth/age/epoch, drain progress and injection results. App/library/focus state
has separate timestamps. It does not record typed text, button streams or passwords.
The actual wineserver routing decision supplies active/focus HWND and target PID/TID;
a try-only process-registry lookup supplies owner/lease when unambiguous. No extra
Windows query/IPC is added to input delivery. Existing successful input-window-
procedure return callbacks provide limited consumption evidence, including the
watched CS2 lifetime. These are not proof of raw-input polling, a game action or
responsive gameplay. Busy/recycled identities remain unavailable. Counters and
post-event snapshots are not an atomic end-to-end transaction.

Native recording reserves 48 KiB for the first 32 and rolling latest 96 failed
request records; ordinary traffic cannot displace this lane. Counts, try-lock drops
and detail overwrites remain explicit. Zero-capacity reclamation detail is sampled
one in 64 before formatting, while all reclamation counts remain exact. Swift
aggregates routine successes/reclamation, reserves a 1-MiB rolling failure journal,
and keeps a separate first-detail file capped at 256 KiB. Native sequence deduplication
suppresses only the same observed occurrence; identical descriptors from different
requests remain separate. First important and recent/terminal incident windows
have separate 1-MiB limits. Lower-priority frame stalls cannot overwrite resource
incidents; a new observed connection resets recent-window priority, preserving the
first important window. The exact vote-kick token is captured separately from cleanup.

The unchanged Export Run flow includes `resource-failures.jsonl`,
`resource-failures-first.jsonl`, `input-path.jsonl`, `incident-first.jsonl` and the
existing evidence, with previous runs under their own identity. Critical structured
files are packaged before ancillary logs. Existing streaming ZIP, privacy filtering,
owned-file checks, cancellation and share sheet remain. Structured cutoffs and live
raw-source changes remain explicit.

Journals total at most 10 MiB, incident copies 2 MiB, first failures 256 KiB,
received system diagnostics at most 1 MiB, and five 256-KiB metadata limits total
1.25 MiB: 14.5 MiB/run before small fixed identity files, below the enforced
16-MiB/run snapshot limit. The preceding run has its own bounded budget. Native
record payload is below 512 KiB; the input queue/hold payload is below 16 KiB.
The CPU interval history is now 192 fixed 48-byte entries instead of dictionaries.
Existing bounded read/batch/copy/serialization buffers remain. Payload bounds are
not a measurement of Foundation/allocator physical overhead; device overhead and
worst-case filesystem latency are unmeasured. No diagnostic disk I/O occurs on
VM/game critical paths. Persistence/incident work remains on the recorder utility
queue and retains measured cost, drop, rotation and persisted/fsynced coverage.

## Normal-input verification and acceptance boundary

Fixtures compile actual production queue/translator, process identity/routing,
native recorder, staged initializer-credit helper and Swift recorder functions.
The old queue demonstrably loses a key-up after 255 motion entries; the replacement
covers ordering, coalescing, releases, full-edge overflow, try-lock accounting, age,
lifecycle changes and fixed storage. The old pad translator demonstrably posts a
button while unfocused; corrected buttons/key sticks/motion are gated. Tests cover
custom bindings and epoch resynchronization. Actual server routing metadata is
checked for busy, ambiguous, exiting and changed identities without extra RPC.

The fence metadata fixture reproduces two baseline queries versus one corrected
query, with the same genuine handoff target. Existing actual staged upload tests
verify owned-byte contents for BC mips, sRGB cube faces, 3D slices, oversized rows,
arrays, bounded growth and completion-controlled reuse. This is not a GPU/device
benchmark. No captured instruction or fault scenario is executed.

Native recording retains first 32 + latest 96 details from 222 failures amid 6,216
routine records, counting 94 overwritten details. Swift retains 222 distinct request
details after 11,119 routine observations and later stalls/terminal incidents. The
6,119 reclamations plus 5,000 successes generate zero per-event logical writes
before their aggregate checkpoint. This measures recorder logical work in a host
fixture, not iPhone physical memory or game throughput. Run20 parsing keeps 222
console errors, eight native text rows and the seven old successful structured
results distinct. Existing serialization, rotation, incomplete prior-run, redaction,
streaming ZIP and cancellation checks remain part of normal CI.

Actual iPhone acceptance is still required: responsive controller movement, aiming
and buttons during a sustained remote round, intact textures and correct return or
changelevel. Neither a compiled IPA nor reaching the live player view proves that.
