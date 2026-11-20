# Run13: matched instruction analysis and the remaining attribution gap

This investigation does **not** establish a gameplay pass. The first commits
added only the bounded observations explicitly permitted by the request. The
subsequent production correction fixes self-starvation in the existing native
store-recovery scheduler, as reproduced below. Copy completion, memory
permissions, suspension semantics, rendering, socket transport, topology and
code-buffer allocation retain their existing implementations.

## Evidence identity

- Source: `48a4fef1f1a82a508597ce033d6ad740f1847f8b`.
- Native UUID: `ADAB4FE6-A5F5-3B52-8F07-4682B764F17F`.
- Uploaded ZIP SHA-256 (verified locally):
  `bd36945cf452facd545ba3c017bcba81cf62a7e85045eac7c4d71f1f2200eac1`.
- Export metadata: `2026-11-20T08:00:06Z`.
- CS2 PID `0374`, main TID `0378`, main TEB `0x70aef10000`, PEB `0x10791c000`.
- Runtime/package/virtual/JIT provenance matches at native line 251.

Times below are November 20, Eastern. The remote connection establishes at
02:54:49, Mirage activates at 02:56:32, and the first full update is logged at
02:56:33. The 02:57:02 timeout row configures the timeout. The actual
`NETWORK_DISCONNECT_TIMEDOUT` is at 02:57:33; disconnection in
`SIGNONSTATE_FULL` is logged at 02:57:47. Later loopback activity is separate.
Connection to activation is 103 seconds, including loading, synchronization,
and networking.

Batch 1024 (native lines 70169–70171) takes 90,712 ms for 64 frames. Its maximum
inter-Present gap is 30,672.5 ms, inside-Present average is 9.6 ms, and reported
GPU work is 26 ms. These are not a 30-second GPU execution or Present wait.
Readback Map waits and game-thread BC decode time are zero in this batch.

Captured footprint peaks at 5,779 MiB. No observed texture-admission/OOM or
self-suspend rows establish a repeat of those older failures. These absences
do not prove every allocation, texture or thread is correct. Logical topology
4/host 6/mask `0xf` and CS2's adoption of the existing 128-MiB code carve are
active. The nearby 4,279 real compilations in 458,752 lookups do not measure
compilation duration or explain the frame gap.

## Official images inspected without executing game code

The earlier public depot manifest is no longer anonymously retrievable (401).
The currently available public depot was retrieved in CI; each of the four
files matches the FEX identity recorded in this run. The inspection script
also pins the SHA-256 of the bytes actually inspected. FEX's identity is
name/PE-timestamp/SizeOfImage based; it is not itself a cryptographic checksum
of the device's installed file. No private Steam credentials were used.

| Image | Runtime FEX identity | SHA-256 of inspected bytes |
| --- | --- | --- |
| tier0.dll | `8f2d32d37c93635a` | `0bcd160dfa72d9f97fbf85095d59baad18fca61f20d840e83a5bd9f7635d5c32` |
| embree3.dll | `bfdf794d989662f5` | `903b3c680ffbf2965d7988f0a42d902c5e198cab15c435ddea79852573be3620` |
| networksystem.dll | `942d2ad34c245d8a` | `00e7ec56f9ef163f6c5e19329b8dae24d60610308ee84780320775f7d7fff984` |
| soundsystem.dll | `d33a17eb78d1efeb` | `645260089eb32075efdd18e4217e7f71a1df5f79396c89a06431cb5b247a1851` |

Read-only inspection run: <https://github.com/letsdothisagainx/Madeira/actions/runs/44701591155>.
No Valve DLL was executed, patched, committed, or included in a new app.
Internal C++ function names are not exported for the following ranges. The
names below describe the verified instructions, not recovered private symbols.

## Time-ordered attribution

### Copy workers and the serial main-thread interval

At native lines 66841–66873, workers 0394 and 038c execute host
`0x7c34c3fc38`, `STR Q0,[X8,#16]`. The actual store addresses are respectively
`0x7a5aeb3ff1` and `0x7a58cf3ff5`. They cross the 16-KiB boundaries by 1 and
5 bytes. The matching x64 operation is `tier0.dll+0x28fa33`,
`movdqu [rax+16],xmm0`, inside the unwind range `0x28f1f0..0x28fc7c`:

```text
28fa22  movdqu xmm0,[rcx]
28fa26  lea rcx,[rcx+32]
28fa2a  movdqu [rax],xmm0
28fa2e  movdqu xmm0,[rcx-16]
28fa33  movdqu [rax+16],xmm0
28fa38  add rax,32
28fa3c  cmp rax,rdx
28fa3f  jb 28fa22
```

The unchanged pointers in two bounded observations are real snapshot values.
They do not establish invocation identity, the original requested length, or
whether intervening recoveries and subsequent calls revisited the same span.
The stack candidates include material/resource work, but are not a verified
unwind or an independently established worker job name.

During the serial interval around 02:55:10–26, the main thread's actual host
PC/block metadata resolves two different operations:

- `tier0+0xc4973`, range `0xc41b0..0xc4edc`: x64
  `mov [rax+rcx*8],rsi`, emitted as `stlur x25,[x7]`. Nearby branches and strings
  concern blob-count/value parsing. This is not the saved SDL caller.
- `tier0+0x215faa`, unwind fragment `0x215f9e..0x215ffc`: x64
  `mov [rcx],rax`, emitted as `stlur x8,[x0]`, after constructing a relative
  pointer and before initializing more header/node fields. The fragment does
  not establish an internal function name.

The export does not contain effective addresses or invocation counts for these
scalar stores. Opcode selection alone does not establish a fault/retry loop.

### After activation

At 02:56:56, the actual Embree worker PCs map into
`embree3+0x2aa1e/+0x2aa54`, range `0x2a7d0..0x2aa6d`. They store vector
records (`str q4,[x2]`, `str q11,[x3]`) among SIMD bounds/min/max operations and
two-sided pointer updates. This is bounds/partition work, not a demonstrated
wait loop. Its cost and number of invocations remain unmeasured.

At native 68968/69000, main TID 0378 executes
`networksystem+0x1c5429/+0x1c5430`, range `0x1c52c2..0x1c54c6`.
The emitted operations are `stlur w1,[x6]` and `stlur w6,[x27,#16]`.
The x64 body imports `tier0!g_BitBuf_BitWriteMasks`, merges bits into 32-bit
words, increments an index/bit position, and decrements its loop counter.
This is bit-buffer writing, not an OS socket wait. It does not prove a
malformed count, repeated packet, or one nonterminating call.

Concurrent sound worker 0470 executes:

- `soundsystem+0x33c9fe`, range `0x33c760..0x33ca70`: scalar filter arithmetic,
  circular-buffer indexing and sample stores, with a 512-frame loop.
- `soundsystem+0x33dd16/+0x33dd44`, range `0x33dbf0..0x33ddd2`: vector
  accumulation and circular-buffer updates, including scalar indexed stores.

These are actual DSP instructions. Sampled worker CPU is not whole-process
audio cost and does not establish a WASAPI scheduling defect.

### Quiet interval and networking

Around 02:57:10–19 the main thread contributes little CPU and other work also
subsides before later busy processing resumes. A uniformly saturated-CPU
explanation is unsupported. The top-CPU table can omit an idle main thread;
its P/E columns describe performance/efficiency cores, not user/kernel CPU.

SteamNetworkingSockets logs receive-service activity during this interval,
including `RecvUDPPacket` batches at 02:57:13, :18, :19, :22, :24 and :26.
That prevents claiming all receiving stopped. These rows do not supply the
native last-receive/last-delivery time for the selected remote connection.
The timestamp of the full-update message does not independently timestamp
the underlying UDP arrival. No transport correction is established here.

## Recovery and backing audit

The dedicated recovery owner, monotonic consumed-CPU kernel-fraction gate,
complete-task history, retained native identities and eight bounded hot slots
are present. The 400-record limit caps output only. All 400 printed completion
rows in this run report completion, but the cap is reached before the remote
loading interval; they cannot describe later eligibility/failures/latency.

`ios_store_split_crossing` decodes the sampled STR Q immediate form, checks
both fragments and uses checked Mach writes. It changes PC/writeback only
after the existing success checks. The normal exception handler also has
scalar/release-store handling. Adding a blanket memcpy, splitting all stores,
removing interrupt checks, or reapplying the old wall-time gate correction is
not justified by this export.

No measured hot-slot exhaustion, checked-write failure, or release-store
boundary crossing has been established for the current critical interval.
Do not turn those hypotheses into a production policy change.

Deferred hole-punch code releases its queue lock before `F_PUNCHHOLE` and
takes the VM lock afterward for extent publication. Slow maintenance is not
proof that the game thread held/waited on that lock for the same duration.
No new file cache, protection-lock removal or backing policy is introduced.

## Exact remaining measurement and scoped implementation

The missing measurements are the native main-thread PC/wait state during its
low-CPU intervals, real user/system CPU deltas, and the existing recovery
owner's eligibility/result/current-address timeline for the observed copy
workers. No available source or matched image supplies runtime values for
those facts retroactively.

`cs2_stall_watch.h` and `cs2_stall_watch_native.h` provide only that scope:

- Register the main native identity at accepted cs2.exe initial-thread startup,
  with the existing PID/PEB lifetime lease; no guessed PID+4/thread-name rule.
- Reuse xprobe's existing enumeration for one main-thread snapshot per second,
  even when it is waiting or absent from the top-CPU list. Log pre-capture
  native run state/suspend count, true user/system CPU deltas, actual host
  PC/LR/SP/x16, capture duration, and API results.
- The held window contains only Mach register capture and its balanced resume.
  All code reads, decoding, symbol lookup, lease lookup and output follow
  resume. Post-resume instruction reads are labeled explicitly.
- Enroll at most two workers from already validated CS2 copy-loop observations.
  Reuse their existing recovery captures; do not suspend them again. Record
  eligibility, current address/instruction, completion/refusal/publication
  counters, held time and sample age independently of the old 400-row cap.
- Four process lifetimes maximum; 1,200 records per target; fixed storage;
  immutable identities; no retained Mach rights or new observer thread.

This does not provide a private GNS-connection-handle-to-native-socket mapping.
Per-connection last-packet processing remains a separate explicit gap.

## Verification boundary

Local normal-input checks passed for identity selection, two-worker capacity,
one-second/1,200-sample bounds, idle-main inclusion, matching store-address
decode, balanced normal capture, and passive recovery-result recording.
The 4,212 component-cache invalidation checks passed. The new headers invalidate
the IPA inputs without rebuilding unrelated FEX/DXMT components.

Local Swift execution was unavailable. The dedicated read-only CI run
<https://github.com/letsdothisagainx/Madeira/actions/runs/44706349406> passed
Linux and macOS normal-snapshot checks, the actual Swift sanitizer with both
emitted rows/privacy filtering, and reinspection of all four SHA-pinned images.
The existing touched native-observation and recovery fixtures also compiled
locally with `--compile-only`; none of their executables was run. This checks
fixture integration, not an iOS app build. No crash, page-revocation or protected-memory experiment was
run. Existing fault-injection workflows are intentionally not dispatched for
this request. The commit uses `[skip ci]` to prevent their automatic push runs;
only the explicitly selected normal-input/read-only workflow is dispatched.

## Subsequent production correction: discovery starves follow-up

Further source inspection established a separate scheduling defect in this
same copy-recovery path. `ios_stuck_store_recovery_tick` sampled `now` before
the full task scan, then assigned `discovery_due = now + 100`. When discovery
took at least 100 ms, discovery was overdue again on return. The worker then
repeated expensive full scans, and already-enrolled store writers could be
inspected only between whole scans despite their 5-ms follow-up policy.
`ios_stuck_store_check` also offered no hot-thread service inside a long scan.

The correction is restricted to the recovery owner's schedule:

1. `ios_stuck_store_discovery_checkpoint` services existing hot targets between
   native discovery queries after the follow-up interval has elapsed. No target
   is suspended at that checkpoint. Hot state is separate from discovery's
   active history table, and their existing retained native rights are reused.
2. The next full discovery is due 100 ms after scan completion, measured with
   a fresh monotonic clock. A slow scan cannot immediately make itself due
   again and monopolize its worker.

The checkpoint cannot preempt a single in-flight native API call. This is a
bounded interleaving correction, not a guarantee of 5-ms wall-clock service on
iOS. The existing two-observation PC/EA check, consumed-kernel-CPU gate, checked
fragment writes, PC publication, hot-slot cap, TTL, and balanced suspension are
unchanged. There is no priority boost, forced resume, or new recovery thread.

### Focused normal-success replay

`check-stuck-store-scheduling.py --discovery-normal-only` compiles the actual
production function bodies. The before variant substitutes the two exact
pre-correction bodies from source `f0fb85f7`; the fixture is SHA-256 pinned.
All destinations are ordinary writable mappings. Every native query/write
succeeds. No protected neighbor, revocation, API failure, deliberate crash or
fault-injection case is executed.

After normal enrollment, one active writer has 19 remaining 16-byte stores;
seven idle threads require successful metadata queries. Each ordinary query
accounts for 20 ms in the deterministic scheduler adapter, yielding 140 ms of
discovery work. The real helper writes are checked byte-for-byte, including
unchanged neighboring bytes, and all native rights/suspensions are balanced.

| Actual scheduler bodies | Final store completed at modeled ms | Largest target capture gap | Full scans |
| --- | ---: | ---: | ---: |
| Before | 2,910 | 145 ms | 22 |
| Corrected | 500 | 25 ms | 4 |

The candidate gap includes one non-preemptible 20-ms metadata operation plus
the normal 5-ms polling sleep. Additional normal-only checks pass for advancing
EA/PC, zero consumed CPU, the exact earlier scalar-store opcodes, the inclusive
60% eligibility boundary, eight-slot overflow, and native ownership. The old
wall-time eligibility bug is not reintroduced or re-fixed.

These values measure the controlled adapter workload, not an iPhone speedup.
The correction removes a source-proven obstruction to timely copy recovery.
Run13 does not measure full-scan durations after the old 400-row output cap,
so its exact contribution to the 103-second load and later timeout remains
unproven. The scoped records in this candidate retain that attribution gap
instead of claiming every sampled store was stalled.

The candidate is to be built and published through the established IPA
workflow. A successful build will establish packaging only. Responsive remote
team selection, gameplay through a round and a correct return/changelevel
still require a real iPhone session.

The IPA dispatch explicitly selects `normal_recovery_checks=true` to honor the
request not to run deliberate crash/fault-injection experiments. The default
full historical test profile remains available and unchanged. This dispatch
runs the normal-success recovery replay and observation/decoder checks, and
compiles the touched legacy fixtures without executing their fault cases.
The normal IPA native/source/ABI/topology/packaging validation remains active.
Complete IPA cache keys include the validation profile, so a normal-only build
cannot be reused as though the full historical suite had passed.
