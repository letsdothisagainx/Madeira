# CS2 remote activation: read validation and work-proportional task wakes

Installed source: `cbeffbf499513058905d492975b483e4993c4118`.
Evidence: the supplied Run Diagnostics ZIP exported at `2026-11-15T09:53:56Z`.
Console times below are EST (UTC−05:00); the Madeira sampler's wall-clock rows
agree with that session. Log line numbers refer to the extracted sanitized files.

## Confirmed timeline and limits

| CS2 console time | Event |
| --- | --- |
| 04:46:41 | SDR relay network ready |
| 04:47:03 | Remote reservation confirmed |
| 04:47:37 | Remote challenge, connect and connection established |
| 04:49:34 | Host activate: Remote Connect |
| 04:49:37 | Full game-state update received |
| 04:49:39 | Physics created for `de_dust2` |
| 04:50:05 | Network channel timeout set to 30 seconds |
| 04:50:48 | `NETWORK_DISCONNECT_TIMEDOUT` |
| 04:50:59 | Disconnection in `SIGNONSTATE_FULL` |

Connection to activation took 117 seconds. The user saw team selection. This is
a remote match, not the later local/background server. No new VAC warning is
observed. The later timeout is confirmed; client starvation, external packet
loss and their relative contributions are not independently established.

The sampled renderer reports 64 frames in 240,927, 54,480, 31,817, 150,207 and
6,902 ms. The 35–60 FPS historical observations were lighter rendering states,
not matched remote-map benchmarks. `e481cc04..cbeffbf4` has no FEX or DXMT vendor
source changes. Browser admission/recovery, networking, JS-read observation and
guest-memory decommit changed. The evidence does not justify reverting the
working browser, JIT, renderer or transport to explain a like-for-like FPS
regression that has not been measured.

## Actual running execution, not saved guest RIP

CS2 is process `0384`. Thread initialization records identify main thread `0388`
with TEB `0x70ab6b0000` and thread `03dc` with TEB `0x70ab610000`. Addresses are
session evidence only; no fix depends on those absolute values.

| Sampler time | Actual sampled work | Session-log lines |
| --- | --- | --- |
| 04:48:01.1–01.7 | Thread `03d4`, `tier0.dll+0x28fa2a`, stack candidates include `materialsystem2.dll+0x10eff0`; 97–99% thread CPU | 63882–63893 |
| 04:49:07.4–08.0 | Thread `03dc`, `tier0.dll+0x1f0b0c/+0x1f0b17`, through `rendersystemdx11.dll+0x70926/+0x70fa7`; 72–75% | 66454–66469 |
| 04:49:41.0–42.2 | Main thread `0388`, native `pread` through `virtual_locked_pread` and `NtReadFile+0x60c`; 99–100% | 67442–67468 |
| 04:50:23.3–23.6 | Main thread, `animationsystem.dll+0x44c405`, stack includes `animationsystem+0x390040` and `engine2+0x236b83`; 71–74% | 68541–68547 |

Generation 18 records 196 running samples, all native, with Darwin syscall 153
(`pread`) and return address `virtual_locked_pread` (67726–67753). One raw symbol
lookup calls the syscall stub `voucher_mach_msg_set`; the syscall number,
decoded native samples and native continuation identify the read path instead.
The context row explicitly says `current=false`, `in-simulation=0`. The saved
guest RIP `0x3200000000` is not an engine function or productive JIT execution.

Actual host-PC decoding in generations 15 and 17 shows vector load/store copy
loops and suspend checks in the tier0 paths. That supports resource-copy work,
not proof of a failed wait or spinlock. The available archive contains no
proprietary DLL bytes or matching symbols sufficient to assign Valve function
names. Stale local Wine/FEX binaries must not supply symbols for newer run RVAs.

The read burst has zero or small physical disk-read/page-in deltas and zero
sampled critical-section contention nearby. Cached I/O can still cost CPU;
these counters neither measure logical bytes read nor prove which asset,
descriptor, offset, destination backing or individual syscall caused the cost.
Main-heap contention is therefore not established as this interval's blocker.

## Production correction: work-proportional shader/task scheduling

Pinned `dxmt_tasks.hpp` broadcasts after every completed task, including when
the completed task has no dependent continuations. Its workers run at
`THREAD_PRIORITY_TIME_CRITICAL`; unnecessary broadcasts can make otherwise idle
workers compete for CPU and the queue mutex just to discover no work. The run
contains high wake-all rates, but does not attribute every wake to DXMT.

The staged build copy now publishes the ready continuation batch under the
existing mutex, then issues at most one wake per new ready task, bounded by
the existing worker limit. A zero-length batch takes no ready-queue lock and
issues no wake. Submission,
task execution, dependency ownership, priorities, queue contents and completion
semantics remain intact. No required shader or rendering work is discarded.

Shutdown also publishes its wait predicate while holding the wait mutex, then
broadcasts. This closes the interval in which a worker could observe the old
predicate, miss a notification and park before destruction joins it. It is a
separate correctness defect, not an established cause of the remote timeout.
The pinned DXMT source remains unchanged; staging is bounded and contract-checked.

These changes reduce unnecessary work that can compete with game, audio and
network threads. They do not change packet formats, acknowledgments, socket
transport, timeouts or Valve authentication. Actual improvement in network
service latency and match persistence still requires iPhone measurement.

## Preserve improvements; separate other evidence

Present #832 reports `gap_max=57850.7ms` but `inside_max=17.1ms` (71932). Most
of that measured gap precedes the measured Present call. It is not evidence of
a 58-second drawable acquisition or GPU completion wait inside Present.

The existing deferred decommit path completed 6,789 punches with zero queued;
its largest recorded punch was 635 ms. Prior baseline evidence included an
8,412 ms synchronous punch in a VM/heap lock chain. Preserve that correction.
The 4,207,365 store faults and 26,627 ms handler total are cumulative and do not
identify a single continuous loading stall. Peak footprint is about 5,799 MiB
against the reported 6,144 MiB limit; no new memory-limit termination is shown.

The secondary access violation occurs around 04:52:35, after timeout and local
fallback. Actual FEX mapping gives `tier0.dll+0x20415a`; host `LDUR X8,[X1]`
reads invalid `0x7f36400000004`, and guest-exact bytes begin `48 8b 02`.
The saved Overlay `+0xb8458` RIP is stale and does not attribute this crash to
Steam Overlay. Available evidence does not identify the pointer's origin or a
correct compatibility repair. It must not be described as the timeout's cause.

## Native read path: evaluated optimization excluded after measurement

The existing `virtual_check_buffer_for_write()` touches destination pages before
`NtReadFile()` performs its read. An evaluated metadata/Mach-validation path
avoided this dirtying for cold destinations, short reads and EOF. Its protection,
write-watch and alias checks passed, but real Darwin warm-buffer measurements
showed additional CPU cost:

| Request | Original probe | Evaluated Mach path |
| --- | ---: | ---: |
| 64 KiB | 0.36 us | 13.28 us |
| 256 KiB | 0.37 us | 15.91 us |
| 1 MiB | 0.77 us | 20.58 us |
| 16 MiB | 11.03 us | 26.86 us |

These are host microbenchmarks from focused CI run `43703210106`, not iPhone
measurements. The candidate is excluded from the delivered source and IPA.
`virtual_ios.c`, its existing read validation, decommit correction and JIT
implementation remain byte-identical to `cbeffbf4`. No slower path or new buffer
cache is introduced. The actual main-thread `pread` work remains an unresolved
part of loading; its descriptor, request size and asset identity are unavailable
in this export. A synchronous read sample alone does not prove a broken syscall
or justify replacing ordinary file I/O with an unvalidated asynchronous layer.

## Validation boundary

The native production-scheduler regressions establish operation counts:

- 512 independent completions: completion queue locks and broadcasts each
  decrease from 512 to zero.
- A 40-dependent fanout: completion queue locks decrease from 41 to one;
  41 broadcasts become eight bounded single-worker notifications in the
  eight-worker host fixture, and every task completes exactly once.
- The idle-pool workload decreases native wait/re-wait entries from 768 to 96.
- Sixty dependency-publication races pass. The original shutdown can lose its
  notification at the checked-predicate/park boundary; the corrected scheduler
  completes without the negative control's external rescue.

ASan/UBSan and the 17-file transactional build/package tests pass. Host elapsed
and CPU timings vary, so no CS2 loading-time or frame-rate improvement is
inferred from these tests.

Focused tests run the complete pinned/staged task scheduler with real host
threads, dependency completion, bounded wakes and deterministic shutdown races.
The production checks also verify composed source staging, immutable originals,
all three PE ABIs, compiled capability markers and exact packaged bytes. Host or
CI results are not iPhone performance measurements. The next device run must
establish connection-to-activation duration, continuous frame delivery,
responsive team selection, sustained remote networking and peak physical
footprint. Under 30 seconds and 35–60 FPS remain targets, not measured results.

There is no prefix or data migration. Install over the existing app with the
same signing identity and bundle ID; installing the prior IPA the same way
provides rollback while retaining Steam, CS2, account, controls and saved data.
