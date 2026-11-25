# Run24: distinct loading and wait dependencies; final export correction

## Identity and analysis rules

Input SHA-256 `f866b3cfc7c2a76d73d77016054cf1fdfe4440416556e582764ddb079f885dbd`,
run `2B0B3608-DC92-41DC-92A4-781A20C03E03`, tested source
`e50f8dfdcacc68495db607028bb615d0435ec2bd`, native UUID
`A51B832E-AEDE-3C5E-A20B-B9AB964321D9`. Starting HEAD was
`d4ad26fbc6568cc4e6e0a8138c5485e16c7f4d15`; its change after the tested source
only publishes that package. No newer code was reset.

The existing `tools/analyze-run18-evidence.py` reproduces both windows using
`--process-lifetime 0x1053e8000-34`. Only current-run top-level evidence is read;
896 incident/journal copies are deduplicated by run ID and sequence, with no
conflicting duplicates. The preceding run is excluded. Complete main intervals
are included only when `[registerCaptureBeginNS - intervalUS*1000,
registerCaptureBeginNS]` falls wholly within the selected UTC window after the
nearest recorded clock calibration. Original console seconds retain their
precision/clock uncertainty; parser receipt time is not event time.

| Selected UTC window, November 25 | Complete intervals | Interval seconds | User CPU seconds | Kernel CPU seconds |
| --- | ---: | ---: | ---: | ---: |
| 19:50:02–19:50:50, loading | 40 | 46.517583 | 1.369894 | 27.682012 |
| 19:51:19–19:51:49, after activation | 25 | 28.606002 | 0.710752 | 3.041957 |

Loading has 34 retained decoded access records, all matching backing ledger
entries, including 29 aligned, noncrossing release stores and three crossing
ordinary stores. The later window has nine decoded accesses, seven backing
matches and three aligned, noncrossing release stores. This is not one continuous
animation-store spin. Post-resume metadata is not atomic with register capture.
Whole-app paging/I/O counters do not identify the main thread's fault cost or a
backing-file write destination.

The private paging advice ran: 4,721 accepted attempts, zero reported failures.
Neither acceptance nor comparisons between these different windows establish a
performance benefit. Remote connection to activation remains about 113 seconds;
the terminal reason is `Timeout; remote problem`. The later pacing observations
remain failed gameplay evidence, not GPU-completion measurements.

## Exact native attribution and normal wait paths

Read-only inspection of the tested published IPA verifies SHA-256
`0984735daaabf8ff6b2f2a2258f92a412424cd19b91d9a7f150c008e07bdc6da`.
Its `Madeira.debug.dylib` has the recorded UUID and SHA-256
`a56b5865c29018b12df41115cd827c736d6d105885348e80369be5fac2f35c13`.
The normal matching-symbol reference is `Madeira-native-symbols:45511231989`.
Using the recorded load base `0x105d78000`, the packaged native symbol table and
static disassembly confirm:

* LR `0x10716b8e0` is `wait_select_reply+0x38`, directly after `read` of the
  current thread's wait pipe. `server_wait -> server_select` submits the select
  operation, flags, handles and deadline. If not immediately signaled, this pipe
  blocks until `wine/server/thread.c`'s `wake_thread`/`check_wait`/`end_wait` and
  `send_thread_wakeup` publish the matching cookie. Object signaling, an APC or
  timeout can complete that protocol. A pipe wait alone does not identify which
  condition is outstanding.
* LR `0x10717e4c0` is `read_reply_data+0x30`, directly after `read` of the RPC
  reply pipe. It reads a reply header and any requested payload, handles short
  reads and retries EINTR. `build/wineserver/request_ios.c` supplies the response
  through `send_reply`/pending `POLLOUT` handling. The sampled function name does
  not identify the request or prove that a reply was lost.
* Native continuations `0x1071b6ee4` and `0x1071b6efc` are
  `NtWaitForAlertByThreadId+0x778/+0x790`. The packaged import stubs resolve to
  `os_sync_wait_on_address_with_timeout` and `os_sync_wait_on_address`,
  respectively. This explains the `__ulock_wait2` samples without guessing a
  C++ mutex from the kernel symbol. The untimed path parks on the current
  thread's alert word. A legitimate `NtAlertThreadByThreadId` atomically sets
  that word and wakes it. `RtlWaitOnAddress` uses this primitive for several
  guest synchronization operations; the continuation does not identify its
  guest caller, predicate or expected producer.

The main thread is sampled in the select wait with active ages growing from
approximately 0.366 to 2.650 seconds during 19:51:33–35. At 19:51:39–45 it is
sampled in the untimed alert path at the same native SP with zero interval user
and kernel CPU. It resumes other execution afterward. These are wait-heavy
portions, not evidence that every interval is CPU-saturated or that one wait is
permanent. Completed inclusive operation times cannot be added as independent
work or subtracted from CPU time. Entry signal-mask work and other uninstrumented
paths remain outside those body timers.

**Remaining dependency gap:** the retained main records do not contain the
select operation/handles/deadline/cookie, the corresponding server object state,
or the alert wait's guest address/caller and matching waker. The existing
server-side stuck-wait dump is gated by desktop diagnostics and its threshold;
it supplies no main-thread object record here. The alert registry only prints
long parks, so the several-second alert wait is not identified by those dumps.
Consequently these data cannot distinguish a legitimate dependency on slow work
from a missed signal, incorrect predicate or incorrect wake routing. For loading,
the separate missing distinction is implicit pager/fault cost versus other
uncovered native work; accepted advice and explicit VM timings do not resolve it.

No source-supported synchronization or backing correction was established in
this investigation. No waits, deadlines, scheduling, instructions, mappings,
protections, recovery eligibility or pool sizes change. The smallest useful next
observation would publish the already-known main thread's current wait descriptor
and its matching completion/waker identity through fixed-size bookkeeping,
without reading guest payloads or adding suspension. That observation is not
implemented or represented as a runtime repair here. No diagnostics-only IPA is
published as a gameplay resolution.

## Required final-archive correction

`RunEvidenceStore.incident()` already independently saved the first activation
stall. `snapshotRun()` already copied it. `RunDiagnostics.export()` maintained a
separate filename allowlist that silently excluded
`incident-post-activation-first.jsonl`. The file is now admitted for the current
run and the existing UUID-namespaced preceding run. Ownership, no-follow opens,
regular-file checks, permitted path shapes, byte budgets, privacy and streaming
ZIP behavior remain unchanged. No collection or per-frame cost is added; export
may include up to the existing 256-KiB dedicated capture per retained run.

`tests/host/check-run-diagnostics.py` now drives the actual recorder through
resource failure -> activation -> first stall -> later disconnect, snapshots
both run identities, calls the actual ZIP exporter, and reads the completed
archive with Python. It checks the file, record identities, preserved first
window and manifest byte counts in both namespaces. Before the allowlist change,
this regression fails at the final archive with `dedicated first stall omitted
by final ZIP exporter`; reaching the temporary snapshot is insufficient.

## Separate unresolved memory and controller outcomes

All seven direct admission failures remain retained. Request 25977 needs a
16,777,216-byte destination plus 65,536 temporary bytes, while only 9,553,744 bytes
remain above the 201,326,592-byte reserve. Destination-only shortage is 7,223,472
bytes. Pending credits are zero; reducing staging cannot repair this refusal.
These late failures follow the earlier stall. Review of the existing completed
upload/cache reclamation and creation-credit paths does not establish an
additional sufficiently large, safely releasable owner. No live resource,
quarantined mapping or alias is force-freed, and no HRESULT or reserve changes.

A bounded review of `GamepadInput.swift` confirms initial enumeration,
connect/disconnect and foreground rescans, extended-profile caching, lifecycle
neutralization, the active/profile-gated 4-ms timer, and observations before
keyboard/mouse translation and menu gating. No independent controller defect is
established by this run's zero upstream physical observations. The 93 mouse
injections do not validate physical controller input. Input behavior is unchanged;
movement, aim and buttons remain device validation pending.

No responsive remote round, visual repair or end-to-end controller action has
been verified. Host fixtures and CI checks establish only their stated code and
packaging contracts, not gameplay acceptance.
