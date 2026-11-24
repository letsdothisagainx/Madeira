# Run21: real Steam interaction and evidence freshness

The archive SHA-256 is
`ee7bee08131b54a5c511865df887622abd688918075af827e3cbb558f6dd8023`.
Current run `90520442-BFAF-4858-BB21-518A26B2029F` matches source
`06a93b3c81460e63c3da7d9b7b1e39b088318fec`, native UUID
`1E19AE26-0CEE-3E28-AF0F-35A1267D838B`. The inspected checkout starts at
`1c320db46a29f44806a9b06e3ce8eadaf363935c` (publication-only follow-up).
Preceding Run20 remains separately named; its counters are not Run21 counters.

## Established blocker and production handoff

Steam's current AppID 730 / ActionID 1 reaches UpdatingAppInfo at 09:00:12,
RunningInstallScript at 09:00:13, then SynchronizingCloud/Stats and
ShowInterstitials at 09:00:46 Eastern, November 24. It explicitly waits for a
user response. The prompt text is private/unknown. No subsequent current CS2
process, main-thread record or rendering batch is captured. The exported
03:01:47–03:17:53 CS2 console is historical. The same ActionID in the earlier
03:01 launch is not the current launch. Helper exit status did not prevent
Steam advancing beyond the install phase. CEF timeouts are observer failures,
not proof that all CEF or Steam stopped.

Native Steam launches previously passed a transient entry with no AppID to the
launch UI, which only displayed generic progress and could dismiss on a Steam
surface. Dock's Show desktop action was not available for that native path.
Library now retains the requested AppID separately, follows only newly appended,
matching, nonhistorical GameAction observations, and shows Steam's explicit
response wait. Open Steam is available during startup and in the session menu;
it dismisses the native cover/menu/keyboard, releases library input ownership,
and reveals the existing real compositor. It does not answer a prompt, issue a
CEF request, change Windows foreground focus, or bypass Steam's launch process.
A native reveal request is distinguished from an attached visible session.

The archive does not establish the specific prompt window at 09:00:46. New
pre-CS2 observations use a bounded passive census mode (64 windows, at most
eight Steam candidates, two-second UI sampling; transition/15-second persistence).
It records window serial, process lease, last Wine visibility observation,
GDI presentation timestamp, swapchain existence separately from presentation,
and currently attached host layer/compositor metadata. Busy/unknown is explicit.
No born-minimized restoration occurs in passive mode. The explicit reveal is
a user operation; observation does not restore windows or steal focus.

CEF remains optional. UI-evaluation requests have a global maximum of 24 per
observer lifetime, at most 16 before a relevant wait; four bounded attention
resets can use the remaining allowance. Existing ten-minute observer lifetime,
query timeout and privacy rules remain. A stopped/timed-out observer cannot
block Open Steam. Prompt subtype stays unknown.

## Structured export

* `launch-progress.jsonl` records request UUID, AppID/action, public stage,
  stage-begin source and receipt time, last observation/age, explicit wait,
  observer state/age, real view handoff, window evidence, observed CS2 lifetime
  and first matching presentation. These are observations, not playability.
* `source-freshness.json` records owned file identity, run-start byte boundary,
  latest boundary/mtime, observation clocks, truncation/rotation and unavailable
  sources. The ZIP manifest relates each exported raw file to those boundaries,
  including appends after the structured cutoff and selected source timestamp
  ranges. A preexisting prefix alone is not proof of historical content: early
  current startup can precede recorder initialization. Unknown identity/rotation
  does not become a known current range. Historical logs remain useful but do
  not populate current gameplay summaries. Console ingestion requires an
  observed current CS2 lifetime and rejects timestamped pre-run rows.
* No CS2 start means gameplay metrics unavailable/workload not reached, rather
  than zero FPS or zero errors. Empty failure files do not validate retention.
* Input snapshots distinguish sampler invocations and current sampler-observed
  state from physical changes, translated actions, bindings, route and accepted
  injection. Each timestamp has an age/unavailable status. Last-known routes
  are never proof of current focus or game consumption. The existing bounded
  queue, focus protection, ordering and neutralization policies are unchanged.

The existing single-button streaming ZIP, cancellation, privacy filtering,
previous incomplete run separation and first/recent failure lanes remain.
Launch history adds 512 KiB of rolling disk capacity, bringing journal allocation
to 10.5 MiB; total per-run limit remains 16 MiB. At most 64 fixed native window
records and bounded source metadata are added. Payload targets remain under
1 MiB recording RAM; allocator overhead is not measured. All file bookkeeping,
parsing and persistence run on the recorder utility queue, never VM/game locks.
Window inspection uses try-only registry/census reads on the existing UI loop.
Device overhead and Steam prompt usability require iPhone verification.

## Gameplay and memory limitations

Run20 remains the relevant failed gameplay baseline: 91 wholly contained main
intervals in 03:10:12–03:12:00 total 107.260835 seconds, with 3.733065 user and
38.491615 kernel CPU (91.159% of consumed CPU). The early slow batch precedes
controller connection and the later 222 refusals. Forty aligned STLR observations
have writable external mappings after resume. These are not kernel stacks or
per-thread/file I/O attribution. This run never reaches that workload.

Review of the unchanged live backing ledger, owner/lease checks, extent
retirement/quarantine, host-page protection aggregation and upload/command
completion paths provides no new demonstrated dependency identifying that
kernel work. Soft faults/page-in, external-object writeback and other kernel
VM work remain insufficiently distinguished. No instruction, backing, timeout,
JIT-size or recovery-policy experiment is included.

The bounded format-block upload producer remains active. Run20's representative
1 MiB destination plus 64 KiB temporary charge exceeds 869,912-byte usable
headroom; the destination alone fails. The small eligible completed caches do
not establish a sufficient physical reduction. Live guest mappings cannot be
freed from reservation size, sampled ownership or overlapping renderer capacity.
No new safe sufficient lifetime reduction was established. The reserve remains.
This candidate corrects the launch handoff and attribution gaps; it does not
claim to repair primary FPS, destination-only shortages or visual corruption.

## Validation boundary

The public Run21 fixture tests 09:00 ShowInterstitials versus historical reused
03:01 ActionID, typed privacy, stage continuation, identity/byte freshness,
truncation/rotation, snapshot ages and actual streaming ZIP inclusion. Existing
normal input, resource/fence, source/packaging, redaction, rotation and incomplete
run fixtures are retained. CI uses `normal_recovery_checks=true`; historical
fault suites are not executed. Build and published artifact identities are
reported separately at delivery. No iPhone session is performed here.

On-device acceptance remains: usable Steam response window, actual CS2 process,
responsive remote round with controller movement/aim/buttons, correct textures,
and comparable frame/CPU/memory evidence. Export Run remains the only collection
step, including preceding available evidence after a relaunch.
