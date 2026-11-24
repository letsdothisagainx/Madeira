# Run22: kernel-heavy remote stall; attribution candidate

## Reproduced evidence

Archive SHA-256 `ad3b677b0a54dcfe61dbb5e05676a6ed152ff32589956e03753fae4ae5351ef3`,
run `BE7063E9-010C-4415-ABD6-7C4B60B2771C`, source
`8a360afef38b82a3b84a1eaca73826d583b0d52e`, native UUID
`F816138C-82A2-3D2F-B9D6-75D26F5FE9A4`. The starting checkout was
`c7a8a61d3b9b8804a770705fe76576f103c8c7cc`, whose intervening change publishes
that source's IPA. It has not been reset. Current evidence and the preceding run
remain separate.

Steam's response wait cleared and CS2 started at 14:35:59 Eastern. Remote
connection was 14:40:42, activation 14:42:04, and the actual reason was
NETWORK_DISCONNECT_TIMEDOUT at 14:43:30. The host remained running at the
approximately 14:44:07 structured cutoff. Later changing raw logs are separate.
A newly rotated console with unknown byte relationship is corroborated by this
process lifetime, timestamps and typed events; it is not discarded as historical.

`tools/analyze-run22-evidence.py ARCHIVE` verifies the supplied archive hash and
replays the existing calibrated analysis for 19:42:07–19:43:25 UTC. It deduplicates
by current run/sequence and includes only complete main intervals whose start
and capture fall within those boundaries. Console whole-second precision and
calibration uncertainty still apply. The result is 65 intervals, 76.915693 s
elapsed, 2.961694 s user and 30.587423 s kernel CPU: 91.172% of consumed CPU,
not of elapsed time. The 46 pacing-hook advances over 76.599188 s are about
0.60/s, not GPU completions. The 116115-ms/64-frame batch with 53-ms GPU
execution crosses disconnect and is not a clean gameplay benchmark.

The selected 51 memory-access observations include 50 backing-ledger matches
and 38 aligned, noncrossing release stores to writable file-backed mappings.
Animation and other guest sites appear. Post-resume region/page observations
are not atomic with registers or a kernel stack. A reservation's virtual size
is not its resident size. No instruction or access is skipped or emulated here.

The host I/O boundaries report 58461 page-ins and 20659683328 accounted write
bytes over 76.524649 s. They are neither per-thread nor per-file measurements or
physical-device writes. The existing raw XP page-wait counter is already
available: 262 wholly contained native wall-time intervals total 77.504 s and
6.0008 s of host-wide page-wait deltas (rounded printed interval lengths). This
is not subtracted from main-thread CPU or treated as a complete explanation.
The retained 17 slow explicit VM completions are hole punches, maximum
529.048 ms; neither these completions nor global operation totals identify all
implicit faults, lock waits or main-thread kernel work.

Direct results reach 27996 non-failures without observed admission/OOM/native
allocation/initialization/invalid-argument failures. This failure therefore does
not require the earlier allocation burst. Footprint and compression still show
pressure. The older destination-only shortage remains unresolved: reducing
staging cannot make a 1-MiB destination fit 869912 usable bytes. There is no
source-backed basis here to reclaim live mappings or weaken the reserve.

## Source audit and exact remaining question

The current shared fixed-map path still limits eligibility to fresh commits,
checks old guest protections and overlaps, and preserves extent lifetime,
quarantine and zero-on-reuse. Decommit uses replacement zero backing before
retiring old extents. External retirement no longer depends on MS_KILLPAGES.
RX/RW JIT aliases are not independent backing. Existing temporary upload bounds
and GPU ownership remain. This audit did not establish a safe large retained
cache, abandoned owner, duplicate storage or a new lifetime defect sufficient
to explain the stall. No live backing policy, TSO choice, reserve, pool size,
network timeout or renderer setting is changed.

**The exact expensive kernel operation remains unresolved. No justified gameplay
production correction is claimed by this candidate.** The missing distinction
is how much of the validated main thread's elapsed progress is inside Wine
server calls/select waits, uninterrupted-mutex acquisition or explicit VM work,
versus work outside those instrumented paths (including implicit VM/pager work).
Existing aggregate counters cannot answer that distinction. Exact executing
PC-to-guest resolution was not retained continuously for this main lifetime.

## Bounded passive additions

* `runtime_progress.h`, `server_ios.c` and the existing VM wrappers maintain four
  cumulative operation classes only for the validated initial CS2 native thread.
  Registration binds owner, lease, PID/TID and native identity. Four fixed lifetime
  slots are never recycled; exhaustion leaves attribution unavailable. Other
  threads take the disabled TLS path. There is no lock, allocation, formatting,
  I/O, guest payload read or additional suspension in these counters. Existing
  server status/return paths, masks, locks, APC handling and errno are preserved.
* The existing once-per-second main observation emits operation totals, depth,
  advisory active start/detail, capture/query separation and snapshot-update
  status after resume. Inclusive/nested elapsed times are not CPU and must not
  be added across classes. Individual atomics are not a transactional snapshot;
  an active observation is advisory. It cannot attribute uninstrumented kernel
  operations or another thread's work.
* Slow/in-flight VM records retain the issuing known-main lifetime and native ID
  without a registry query under the VM lock. Issuer is not allocation owner.
* A new bounded entry point to the existing checked FEX metadata resolver visits
  at most 256 RIP entries; exhaustion returns unavailable, never a partial RIP.
  The existing resolver's 65536-entry limit is unchanged. Resolution follows the
  existing native block pointer and does not use a saved guest RIP as execution.
  All new lookup work is after resume: at most approximately 4.7 KiB and 12 checked
  metadata reads per main sample. Module/RVA uses only an already cached loader
  map with matching owner/lease, plus its observation age. A try-only guard
  serializes cache publication/reset with the bounded copied lookup; busy means
  unavailable, never waiting or reading a partial map. Legacy readers receive
  a fixed per-observer copy (four slots) so cache resets cannot mutate their
  borrowed view. Slot exhaustion is unavailable. No new loader/stack
  walk. Concurrent code/module changes remain possible and are labelled.
* Controller records at discovery/lifecycle transitions distinguish framework
  controller, extended/micro-profile counts, enumeration time, cached profiles,
  actual sampler-timer state, selected mode and app activity. No device name,
  serial, buttons, typed text or binding override is recorded/changed. Existing
  foreground rescan was already present; this is not described as a new repair.
  Run22's zero physical samples/callbacks/translations/key injections and nine
  mouse injections leave the first physical-input link unverified. Queue and
  focus policies are unchanged.
* Known missing-resource/shader/pipeline error rows can retain an opaque stable
  hash of a bounded resource-path token, error class, original console timestamp
  and last-observed parser phase. Original private paths are not disclosed; hash
  collision and parser timing limits remain. Required/optional status stays
  unknown. These messages are not relabelled allocation failures or proof of
  visual corruption's cause.

The same recorder, first/recent failures, preceding-run separation, sanitized
logs and one-button streaming ZIP remain. A separate 256-KiB first post-activation
stall excerpt survives later incidents without taking the resource-failure lane.
There is no new rolling journal; the excerpt brings allocated disk budgets to
15.5 MiB, still below the existing 16-MiB per-run cap. Added fixed native payload is below 40 KiB (four lifetime
slots, issuer fields in 64 in-flight slots and four fixed module-cache copies), inside existing <1-MiB payload
and <16-MiB-per-run persistence budgets; allocator overhead remains unmeasured.
Resolution uses bounded local stack buffers. Added observations share existing
rolling capacity, so overwritten detail remains counted. All persistence stays
on the utility recorder queue.

## Validation and acceptance boundary

Ordinary fixtures execute the actual counter header and resolver on synthetic
metadata, never captured instructions or protected mappings. They cover identity
and lease rejection, nesting/completion, concurrent observation, VM issuer,
unchanged errno, bounded lookup exhaustion and unavailable mappings. Existing
full resolver behavior is retained. Swift fixtures validate typed records,
opaque private-resource identifiers, privacy, input/launch freshness, failure
retention, prior-run separation, ZIP cancellation and share behavior. Existing
normal upload/credit/fence/reserve and input ordering/lifecycle tests are retained.
CI uses the normal-recovery profile; historical fault fixtures are compile-only.

A Linux microbenchmark of 500000 counter pairs measured approximately 3.7 ns
with no registered thread and 60.5 ns registered in one run. These are local
host observations, not an iPhone overhead guarantee. Metadata lookup latency
is recorded per sample. Device scheduling, persistence cost and total observer
impact remain unmeasured; no speedup is claimed.

Build/linked-source/component checks and a published IPA establish packaging.
They do not establish responsive team selection, controller movement/aim/buttons,
correct visuals, or a sustained remote round. The device comparison must test
those outcomes and inspect the new per-main wait/VM totals against kernel CPU,
without treating smaller printed counts or menu rendering as acceptance.
