# Run19: bounded real texture upload growth and resource/exit evidence

Evidence source `6367a1566aad52eb5ec23af973b93db402cd3885`, native UUID
`EA48680B-97E9-3102-A69D-CF790363851B`, run
`8ACF83DD-5795-47FB-A446-9093A938D6B9`, ZIP SHA256
`221af2242a8ef9aec416cb19a6cffa6d7f52272c7bae2bead45bdd7ad720400c`.
The later workflow-only head is preserved. Work and the explicitly selected
checks use no agents or deliberate fault experiments. Delivery exposed an old
automatic push workflow that executed captured-store/protection cases before
cancellation (run 45330388073). This violated the requested constraint; its
results are excluded from this candidate's validation. Both historical fault
workflows now require a separate explicit manual opt-in and cannot execute on
push or ordinary dispatch. The normal-input checks remain in the focused and
IPA workflows. No further legacy experiments are run.
The normal-input flag also selects ordinary/static final ABI checks rather than
the historical emulator matrix that deliberately clears x18 and faults.

## Established mechanism and production change

The native predicate correctly refuses destination plus simultaneous temporary
growth while preserving the physical reserve. For the first retained request,
22,543,008 destination bytes fit within 37,881,608 usable bytes; the total
45,546,656-byte creation does not. These are pre-allocation refusals, not
observations of Metal returning nil.

The old `forecastUploadGrowth` only bounded a compact batch if its payload
exceeded the natural 32-MiB block **and** its largest subresource fit that block.
A smaller pressure batch instead obtained storage for its entire payload.
Lowering only that forecast would let the producer exceed its credit.

The downstream `stage-dxmt-upload-window.py` pass changes both forecast and real
producer. A read-only versioned native budget query uses the same reserve and
pending credits as admission. It may exclude only this owner/lease's CPU-phase
receipt when refreshing that creator's forecast. It neither grants memory nor
retires GPU credit. The normal fresh admission decision still covers the whole
destination plus actual additional upload block capacity.

The pressure window is a power-of-two allocation class, at least 64 KiB and at
most the natural block and the batch's required class. It adapts to remaining
headroom after destination and other creators. It is not a fixed Run19 address,
size or a reduced safety floor. Existing reusable capacity is charged as zero
additional backing, while the execution window remains enforced independently.

Oversized subresources upload complete format blocks through that window.
The real initializer preserves every mip, array/cube face, row and depth slice,
the original CPU row/image pitches, BC block alignment, edge extents and texture
identity. Contiguous rows use one native update; padded rows retain their
individual source strides. A source row larger than the window splits across
whole format blocks. No complete extra subresource scratch is introduced.
Native BC remains native; the existing software-decode scratch allowance is
retained for devices that actually use that separate path.

Before reuse, the producer submits its existing private upload queue and waits
on its genuine GPU-signalled event. The creation scope keeps one completed warm
block, enforces its admitted additional-growth budget, and restores nested
state afterward. Waiting has an aggregate 50-ms budget starting at the first
required wait. An unavailable completion or real allocation failure returns
failure; it never publishes success with missing initialization. CPU command
retries remain bounded and a blit is linked only after real backing exists.

The pins and vendor trees remain unchanged. Both native/PE compilation use the
owned staged copies. The new recipe participates in component keys, manifests
and final package checks; no old cached DXMT can silently omit it.

## What this does not establish

For the later recorded requests, destination alone exceeds usable headroom:
22,020,096 > 11,225,304 bytes, and 16,777,216 > 2,065,680 bytes. Bounded uploads
cannot make those destinations fit. Census capacities (Metal 1252 MiB, tracked
live 1157 MiB, textures 659 MiB, buffers 489 MiB, staging 8 MiB) overlap; almost
all listed dynamic cache capacity is already in use or retired. Existing
reclamation and the genuine-completion retry remain. No evidence establishes a
large abandoned owner or a safe additional live-resource release. The same
reserve remains enforced, so these destination-only failures can recur.

Resource failures precede SRV invalid-argument errors, a render assertion, and
CS2's `0xc0000005` exit. The fault is a null read at
`rendersystemdx11.dll+0x7a2fe`; both the sampled register and subsequently observed
source pointer are zero. The old generic high-half heuristic does not establish
translator truncation. The exact failed creation that feeds this object remains
unidentified. No exception is bypassed. Madeira remains alive; later quarantine
with surviving native Wine threads cannot be force-freed and does not establish
the cause of the earlier pressure.

## Kernel-heavy interval

`tools/analyze-run18-evidence.py` also works on this archive. Deduplicate the
current namespace by `(runID, sequence)`, exclude preceding sessions and use
nearest measured wall/monotonic calibration. Include only intervals wholly
contained in 2026-11-24 04:00:40Z through 04:01:41Z (console whole-second
boundaries, not packet-exact times). The 51 main intervals total 59.620270 s,
user 3.041013 s, kernel 21.687596 s: 87.70245% of consumed CPU. There are 35
aligned non-crossing release-store ledger matches in that window; page queries
are post-resume observations, not kernel stacks or proof of the sampled page's
earlier state. The frame batch is 60,573 ms/64 frames, 32,620.6-ms gap,
16.7-ms maximum inside Present, 43-ms GPU execution. These are distinct.

Inspection of current shared mapping, allocation generations, host-page
protection aggregation, dead-range replacement, successful-punch-only offset
reuse and quarantine does not establish a new release/protection race explaining
this cost. `external-retire-no-killpages-v1` already ran. Explicit instrumented
VM times and whole-app read/write counters do not identify an in-kernel blocking
path or the write destination. The unanswered distinction is kernel work on
live external pages versus other main-thread kernel activity; observed writable
present pages after resume do not settle it. No new backing or instruction
policy is presented as a stall repair.

A single existing utility tick now also reads supported `TASK_EVENTS_INFO`
fault, page-in, COW-fault and Unix-syscall counters, including query times/result.
These are explicitly whole-host-task, may wrap, and cannot attribute a fault to
the CS2 main thread, a file, an instruction or a physical disk read. Collection
does not touch guest pages, change permissions, suspend threads or change
recovery. It complements, rather than replaces, the existing mapping/page data.

## Export corrections

* Direct texture/SRV request IDs are allocated by the shared native bridge.
  Records carry closed descriptor metadata, initial-data presence, policy/window,
  destination/temporary/total charge, the actual permit snapshot/result,
  GPU-event/frontier where available, returned HRESULT and local resource pointer
  identity. Admission, native nil, initialization, handoff and dependent-view
  stages remain distinct. Unavailable descriptors/budget results remain null.
  Pitches/payload and native errors not returned by the API remain unavailable.
* Reclamation observations carry released completed **capacity**, the existing
  pre-reclaim pressure sample and clock. They make no physical-saving claim.
  No additional post-reclaim query is added to the producer; later admission
  and utility memory samples preserve separately timed footprint evidence.
* Exact app-session request/result/stage counters continue after the first burst.
  Failed details roll through the fixed native ring; success detail is sampled
  one in 64. Try-lock drops, ring overwrite and persisted source coverage remain
  explicit. Direct requests, native text reports and console occurrences must
  not be summed as unique failures. The existing eight text messages stay for
  compatibility; they no longer determine direct observer lifetime coverage.
* A source occurrence uses file identity and byte offset. The parser emits one
  graphics observation per occurrence, enriches it with a nearby API if needed,
  and suppresses repeated observation of that same occurrence within a bounded
  128-ID history. Distinct identical failures are retained/count separately.
* Native guest exit emits PID/TID, owner/lease and exact status before cleanup.
  The parser handles `process-retire-v1`, quarantine `peb`, `exit_code`, abort
  status and signed wrapper status without publishing empty API-name events.
  Unqualified text does not acquire the current CS2 lifetime. Recorded module
  ranges may resolve existing exception PCs, with non-atomic association clearly
  labelled. Guest exit and surviving host/unknown host termination are separate.
* Matching loaded provenance is preserved from a bounded 64-KiB startup prefix
  if burst tail ingestion skips it; only matching source/UUID typed provenance
  is replayed. No historical console/process/failure events are replayed.
  Duplicate observed connection confirmations no longer advance attempt IDs.

One-button Export Run, streaming ZIP/cancellation/share, privacy filtering,
MetricKit delivery policy and separate preceding incomplete-run retention stay.
Journals (8.5 MiB), incident (3 MiB), system (1 MiB) and bounded metadata remain
under 16 MiB per retained run. No per-request retained map or new persistence
queue is added. New native counters are 128 bytes in the existing 393,216-byte
ring design; direct request metadata is 160 bytes, stack-owned during creation.
Main CPU history now retains only its six summary fields rather than full
decoded dictionaries. Input windows and prefix buffers are bounded and released
per tick. Foundation/allocation overhead and actual iPhone physical recording
RAM remain unmeasured; payload caps are not a demonstrated <=1-MiB physical
footprint guarantee.

The baseline's ~376.7-ms persistence operation is utility-queue elapsed time,
not a measured game-thread pause. Filesystem writes, checkpoint/fsync/rotation
work and their counters remain separate from host rusage. No uniform negligible
overhead or attribution of all residual writes to backing is claimed.

## Ordinary validation and acceptance boundary

`check-dxmt-upload-window.py` compiles actual staged forecast, ring and initializer
functions against normal owned byte arrays and an explicit completion adapter.
In its controlled BC7 witness the baseline forecasts 22,373,120 staging bytes,
making the 44,742,768-byte creation fail the selected budget. The correction
allocates/reuses one real 8,388,608-byte fixture block, making total growth
30,758,256 bytes. This is not a recovered Run19 texture descriptor, Metal
residency measurement or iPhone speedup. Tests compare every initialized byte
for BC7 mip chains, odd BC1 sRGB cube faces, padded RGBA 3D slices, a row larger
than a 64-KiB window, 1D arrays and reuse of existing completed 32-MiB capacity
with zero additional charge. Allocation lifetime balances at destruction.

Native receipt fixtures preserve the reserve and owner/lease exclusion, ordinary
parallel receipt/release balance and all recorded Run14 predicate decisions.
Actual C/Swift fixtures test direct request/result counters beyond eight records,
unknown/busy/recycled identities, serialization/nulls, redaction, source dedup,
guest-versus-host exit, rotation, incident/previous incomplete data and disk caps.
Run19 fixture preserves **81 console OOM occurrences, eight native reports,
299 prior structured rows** as separate facts. Existing ZIP/share/cancellation,
retirement, TSO and cache-key checks remain. The canceled automatic legacy run
above is not included as passing verification.

CI must compile the actual Metal/PE/native/iPhone paths and validate final IPA
source/component/native UUID and matching symbol artifact. A build is packaging
evidence. No remote join, responsive team selection, playable round, correct
textures/changelevel, kernel-time improvement or thermal benefit has been tested
on an iPhone here. Destination-only shortage and kernel mechanism remain open.
The workflow remains: run CS2, encounter the problem, tap Export Run, share one
ZIP; relaunch retains the preceding run's available evidence separately.
