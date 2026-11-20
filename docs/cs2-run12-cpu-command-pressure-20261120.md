# Run 12: current failure and completed CPU command storage

## Exact run, rather than the older quoted events

Archive SHA-256:
`5d065d1a3b0d0ef1a81d97491f0653a19f7cf797d35c081158d22634ec06be69`.
Export `2026-11-20T03:19:56Z`; source
`0267de5f5c6dc91b13e38c2324e02fe77e930765`; native UUID
`19FCEF3E-3292-328D-9528-AC618ED50C61`. Runtime provenance agrees with the
package. The topology row reports four logical/visible cores, six host cores,
one package and mask 0xf. The larger-class and upload corrections remain active.

The request quotes Run 11's TID 03c4, 20:12:15 self-suspension and 1,065 OOMs.
Those are not the events in the attached Run 12. Current CS2 is PID 0378,
main TID 037c, TEB 0x70a9b70000 and PEB 0x11d4dc000.

The two recorded suspensions, around 22:11:48 and 22:12:19 Eastern, are by
worker 03a4 against main 037c. Both are followed by successful context capture,
and main-thread CPU execution continues. The second starts at count zero,
establishing that the first count was cleared in between. Generic resume logs
are sampled. No current self-suspend or dispatch-watch event appears, and the
main thread continues through native end 22:18:27.921.

Windows ResumeThread returns the previous suspend count: a final count 1 to 0
resume returns 1; a return of zero means the thread was already unsuspended.
See the [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread).
No suspension count, caller, callback or proprietary instruction is changed.

## Current remote failures and pressure

| Event | First join | Second join |
| --- | --- | --- |
| Remote connected | 22:08:48 | 22:15:19 |
| Map activation | 22:10:50 | 22:17:24 |
| Connection to activation | 122 s | 125 s |
| Full state/physics | 22:10:50 | 22:17:24 |
| Actual timeout | 22:12:59 | 22:18:10 |
| Disconnection state | 2 | 6, FULL |

Later loopback messages are separate. The first activation's frame batch spans
105.602 seconds with 44 ms of GPU execution, maximum present gap 27.067 seconds,
and about 5.5 ms average inside Present. These are CPU-side production stalls,
not a 27-second GPU wait. Main-thread samples progress through mesh, animation,
engine and network work. Other CS2 threads perform video/codec/scaling work;
this is not evidence of a codec or translation defect. Some global profiler
generations belong to Steam processes and must not be assigned to CS2.

Run 12 has 95 CreateTexture2D OOM rows and no CreateTexture3D OOM rows. Fifty-five
precede the second timeout and forty follow it. First refusals are about 22:17:49.
The detailed requests are 262,144 bytes, temporary growth zero, pending zero,
available 198,051,064 bytes, and floor 201,326,592 bytes: the denials are correct.
The highest captured physical footprint is 5,971 MiB. Native and console are
not byte-budget truncated; collection/privacy omissions are still recorded.

At second activation, staging/initializer capacities are about 8/32 MiB. After
the timeout both are zero, while reported Metal allocation is about 1,283 MiB.
These capacities overlap other accounting and cannot be subtracted from the
process footprint to label an unidentified leak. Guest decommit/release remains
active, including zero-backed remaps without fallback and backing/footprint
declines after cleanup. The texture-profile `deferred=1` flag is child transport,
not a deferred-texture counter; the intended mip policy is consumed by DXMT.

## Separate confirmed retention gap

The queue's CPU command-data ring uses HostBufferBlockAllocator with natural
4 MiB blocks. CommitCurrentChunk only applies free_blocks at the CPU completion
frontier; normal blocks have a 300-submission/call retention policy. A command
chunk can own multiple blocks, so the number of queued chunks does not cap bytes.
At a long frame/loading gap this completed high-water storage stays allocated.

Existing critical-pressure handling covers GPU staging/copy/argument rings and
the separate ArgumentEncodingContext scratch storage. It does not cover this
CPU command-data ring. This is a source-confirmed pressure-policy gap, not a
claim that Run 12 measured a particular number of gigabytes in that ring: there
is no such capacity census in this export.

The correction applies completed CPU-cache maintenance at its existing producer
safe point. The ring has null_mutex and is never trimmed by a finisher, denial
or background thread. The queue's real cpu_coherent frontier is published only
after GPU completion and chunk reset/destruction; current and pending closures
and data stay owned. A raw GPU sequence number is not substituted for that
established completion frontier.

Under pressure, completed storage has a bounded warm allowance of at most one
natural block; healthy maintenance retains its original policy. Explicit
reclamation publishes an atomic drain request, consumed by the next producer
safe point. It is not described as synchronous release during a texture retry.
The producer's pressure measurements use the existing cached native snapshot.

At most eight per-queue reports record actual released capacity and measured
before/after process footprint, with the before timestamp. Concurrent activity
means an observed process-footprint change is not an exact causal attribution.
No extra per-allocation/frame profiler or guest-memory eviction is introduced.

The first native replay demonstrated an additional limit: releasing the blocks
through malloc/free reduced ring ownership but did not reduce measured host
physical footprint. A bounded-malloc variant is retained in the comparison so
this is not hidden by capacity counters. The queue's private CPU blocks now own
their VM backing directly: VirtualAlloc/VirtualFree on Windows, mmap/munmap on
the native platform. Other host, reference-tracker and deferred allocators remain
unchanged. Sizes are checked and page-rounded, move ownership includes the exact
release length, and failed allocation cannot publish a nonexistent block. No
arbitrary malloc pages are advised or unmapped. Release errors are reported
honestly; they are not converted into a successful physical-reclamation claim.

## Controlled native physical result

The macOS replay at source `e21d249dc1437797b6ffc21f58a5a627a0ba2138`
uses fresh processes for each policy and identical 55,578,624 used payload bytes
(checksum 1,760,505,856). GPU completion is controlled; the real staged reset,
producer, allocator and task physical-footprint query execute.

| Policy | Completed owned capacity | Footprint before maintenance | After maintenance |
| --- | ---: | ---: | ---: |
| Original malloc retention | 64 MiB | 51,627,072 B | 51,627,072 B |
| Bounded malloc | 4 MiB | 51,594,240 B | 51,594,240 B |
| Bounded owned VM | 4 MiB | 51,364,928 B | 4,162,560 B |

The VM variant's within-process observed drop is 47,202,368 bytes, about 45 MiB.
A later zero-headroom drain measures 1,016,768 bytes. Initial command-burst
owned capacity is 64 MiB for every policy: this fixes retained completed pages,
not the unavoidable simultaneous peak of that workload. Separate-process
baselines include small runtime variation. These are host measurements, not
Run 12 owner attribution or an iPhone map-loading result.

## Validation boundary

Focused fixtures exercise the actual staged producer/ring and original host
allocator with controlled completion/pressure inputs, including pending data,
resource ownership, repeated pressure/reuse, explicit drains and recovery.
Darwin validation separately measures real process footprint with identical
used command payloads; unused allocation tails are not touched to inflate RSS.
Capacity, cumulative traffic, initial burst peaks and measured retained physical
memory are reported separately in the delivery results.

Package gates require the compiled CPU-command-cache and owned-VM producers in native and all
three Windows DXMT variants. Source hashes invalidate the affected component
caches. Existing topology, code-buffer reuse, checked stores, upload bounds,
texture admission, input, Steam, networking, installation and configuration are
preserved. A separate current-processor-number API range risk was reproduced,
but not linked to Run 12's stalls and is not patched here.

This correction does not establish that the whole working set fits or that the
122/125-second loading intervals are fixed. Responsive team selection, sustained
remote gameplay, correct map/menu textures, physical headroom and connection
stability still require the iPhone run. Host tests and a built IPA are not those
acceptance outcomes.
