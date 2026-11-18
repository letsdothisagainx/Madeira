# Texture admission and self-suspension in a1ab80c2

## Exact evidence

Input source: `a1ab80c2350a02a73994cacefdfff4613591c7f1`.
Export: `2026-11-18T09:05:24Z`.
ZIP SHA-256: `c2920e3f1107f3ee62ebf9f772b12960b7efc3cef7ab2ff7328489741f2f7c61`.
Runtime and packaged native UUID agree:
`A579BB67-859F-3966-9AEF-214BC03A77B4`.

The remote connection starts at 03:56:49 Eastern. Dust II activates at 03:58:30
(101 seconds) while texture creation is failing. Full state and physics follow
at 03:58:32. At 03:58:42 further allocation failures precede a successful
self-suspension of main thread 0510 in process 050c. Native logging continues
afterward. This export contains no recorded `NETWORK_DISCONNECT_TIMEDOUT`.
The timeout-setting message is configuration, not a disconnect event.

The dedicated store-recovery policy is recorded at native line 466. Four
hundred successful recoveries are logged, including the exact copy instruction
observed at lines 69057/69059. That implementation was active and is preserved.

## Admission arithmetic and missing charge

The native predicate tests the complete prospective request against freshly
measured available memory minus the safety floor and outstanding credits. Its
reason 1 is a physical-budget rejection. It does not use the pressure hysteresis
flag to reject an otherwise fitting request.

The old rejection logger prints destination texture capacity, while the actual
permit covers destination **plus forecast initializer growth**. An empty
64-bit initializer normally needs a 32 MiB upload block. Therefore a tiny
initial-data texture can require much more than its printed destination size.

| Native line | Destination bytes | Available above 192 MiB floor | Destination alone |
| --- | ---: | ---: | --- |
| 82561 | 22,543,008 | 20,481,680 | Does not fit |
| 82608 | 10,485,760 | 7,800,488 | Does not fit |
| 82609 | 10,485,760 | 7,751,336 | Does not fit |
| 82610 | 10,485,760 | 6,997,672 | Does not fit |
| 82611 | 22,020,096 | 6,882,984 | Does not fit |
| 83072 | 15,360 | 3,573,272 | Fits |
| 83076 | 16,384 | 5,637,656 | Fits |
| 83077 | 65,536 | 5,211,672 | Fits |

Replaying the real native predicate with these operands reproduces the first
five denials using destination capacity alone. Adding an empty 32 MiB upload
ring reproduces all eight. Existing zero initialization for the final three
would need at most 1 MiB and would fit. The archive lacks initial-data, ring
cursor and full-charge fields, so this does not prove each missing upload state
on the phone. It does establish why the printed operands were insufficient.

The configured 6,144 MiB policy budget is not treated as an independently
verified exact kernel termination threshold. Its 192 MiB safety floor remains
unchanged.

## Production corrections

### Pressure-sized upload batches

Under measured pressure, an initial-data texture batch within the existing
32 MiB upload capacity uses its complete payload rounded to the existing
256-byte alignment as the block minimum. Forecast and actual allocation use
the same value. Healthy batching and larger batches retain the prior policy.
Completed compact blocks remain reusable; pending blocks retain their genuine
GPU ownership. No mip, slice, row, texture format or SRV is omitted.

A per-creation scope restores the prior allocation policy before the existing
creation transaction unlocks, including nested creation and exception unwinding.
The transaction excludes competing creators between forecast and enqueue.
Because the whole compact batch fits a fresh block, its forecast does not add
the previous second whole-payload surcharge intended for chunked batches.

The rejection record now includes the permit's final `charged-bytes` and
`temporary-growth`, preserving the eight-record bound. The package verifier
requires the compiled compact-upload marker, preventing a source-only or stale
binary claim.

### Reclaim newly completed transient storage

The previous one-time recovery latch conflated draining dynamic-buffer warm
names with reclaiming transient buffers. After an early drain, new GPU
completions could make transient backing reclaimable, but a later denial could
not request another forced transient trim until the entire pressure episode
became healthy.

Actual denial now independently permits transient reclamation. A queue-wide
completion-frontier claim prevents repeated trims at an unchanged frontier.
Dynamic warm-name draining remains latched once per episode, preserving the
bounded hot-buffer reuse policy. Only real completion permits release; no live
texture or executing GPU buffer is evicted, and no freed-capacity counter is
substituted for a fresh native footprint query.

The adjacent device census's 96 MiB warm budget is a maximum allowance, not
96 MiB of available reclamation. Approximately 2 MiB of dynamic capacity was
eligible there. The log does not prove that its other transient capacity was
already GPU-complete.

## Texture profile lifecycle

`cs2-video-profile-v1 result=already-low` means the existing, unambiguous CS2
video file already contained `setting.videocfg_texture_detail=0` before Steam
launch. The `applied=0 deferred=1` row describes child transport rather than
failure to select Low. The child-environment preparation row exists at line
57909, and DXMT reports consuming `d3d11.mipClampAuto=0` at lines
61986/62905/63063. This deliberately preserves requested physical mip identity;
it is not an automatic mip-dropping quality shortcut. No profile change is made.

## Exact suspension caller and remaining question

Read-only GitHub Actions inspection downloaded the actual a1ab IPA artifact
(run `44172963516`, artifact `14370284511`) and verified its UUID.

* KernelBase SHA-256:
  `d0903a84f03eafc2daf5c065161cda4090150d3db4e53e9844dea133373f2684`.
* Ntdll SHA-256:
  `e2f1efbbe0627c92210d23e989b965aac40b8c6cd354aa996869405402560eb5`.

KernelBase's native `SuspendThread` spans RVA `0x6de64..0x6df18`.
At `0x6dedc` it loads auxiliary IAT slot `0xc4490`, independently resolved to
`ntdll!NtSuspendThread`; `0x6dee0` calls it, and the recorded `0x6dee4` is the
return continuation. The matched Ntdll native stub spans `0x5a684..0x5a69c`,
uses syscall `0xf5`, and contains the recorded PC `0x5a698`.

Native CHPE/ExtraRFETable unwind metadata and disassembly validate both saved
return slots. SuspendThread allocates `0x40` bytes and saves LR at `SP+0x38`;
thus index 56 is the return into the entry thunk at `0x78f4c`. That thunk spans
`0x78f2c..0x78f74`, allocates `0xb0`, saves FP/LR at `+0xa0/+0xa8`, and sets FP
accordingly. Recorded syscall SP `0x70db3faf10` yields thunk SP
`0x70db3faf50`, recorded FP `0x70db3faff0`, and saved LR at
`0x70db3faff8` = original `SP+232`, containing `client.dll+0x457b`.
This validates a return chain rather than merely labeling scanned addresses.

Handle `0x3ea0` resolves atomically to actual current thread 0510, with matching
requester/target TEB and process. Wine correctly increments its suspension count
and waits for a genuine final resume. `held=0` and `MADEIRA_REAL_SUSPEND=0` do
not clear that count. The adjacent context record is part of stopping the
thread, not proof of an orphaned independent context operation. Protocol tests
exercise actual pthread continuation, early resume races, nested counts,
process scope and handle variants. No suspension-semantics change is justified.

An isolated, read-only Actions job obtained the official Windows game file
anonymously from depot `2347771`, exact manifest `6054210037651104742`, path
`game/csgo/bin/win64/client.dll`. The actual post-update file is **39,141,528
bytes**, SHA-256
`39de4a6d1881ebf9726a43ffcb1e05ce12d007750053afc52eed5a97b7d21c7d`.
Its `SizeOfImage=0x298d000`, timestamp `0x6afd14c1`, and computed FEX mapping
identity `eb5eed5d42f84131` match the loaded module. The export's 39,120,536-byte
cached audit precedes Steam's update; requiring that stale size would reject
the matching current image. The analysis does not execute or modify the game.

Exact disassembly resolves `client.dll+0x457b` to a context/register capture
routine spanning `0x4520..0x4a10`. It opens its input thread ID, calls
`SuspendThread` at `0x4575`, then `GetThreadContext` at `0x4588`,
`ResumeThread` at `0x4597`, and `CloseHandle` at `0x45a0`. The recorded return
address is exactly the end of that suspension call. Thus its intended resume
is in the same caller, after context capture; a self-target stops before that
resume can be reached. This establishes the stopping mechanism independently
of generic sampled resume logs.

The validated direct caller at `0x432c`, in `0x3140..0x4516`, passes its own
input thread ID unchanged. That routine processes request records and serializes
results. It contains no current-thread query or thread enumeration establishing
where that ID originates. A real leaf tail thunk at `0x14a7c0`, which correctly
has no unwind entry because it does not change the stack, adds `0x50` to its
object pointer and loads the thread ID from the adjusted pointer's `+0x60`
(original object `+0xb0`) before jumping to `0x3140`. This establishes a stored
callback argument, not a thread ID invented by the suspend wrapper. Wine's
inspected current-ID, OpenThread, server-ID and Toolhelp paths show no
demonstrated mismatch.

The writer is also resolved: `client+0x5281` calls the genuine
`GetCurrentThreadId`, and `0x53aa` stores that result at the callback object's
`+0xb0`. The object is submitted through `g_pThreadPool` virtual slot `+0x80`
at `0x53d6`. Its matched vtable's `+0x28` entry is the leaf capture thunk.
The job therefore saves its creator's ID and ultimately executes its capture
on that same thread in the failing run. Matched client RTTI identifies its
wrapper as the lambda job for
`ReceiveRequestDiagnostic(CUserMessageRequestDiagnostic_t const&)` using
`IThreadPool::QueueJobWithFlags`. This is a received diagnostic-message path,
not an established fatal-OOM handler. An earlier nonself suspension also appears
in the export.

The same exact official manifest also supplies matching `tier0.dll`, mapping
identity `8f2d32d37c93635a`, SHA-256
`0bcd160dfa72d9f97fbf85095d59baad18fca61f20d840e83a5bd9f7635d5c32`,
3,979,416 bytes. Exact RTTI and chained x64 unwind ranges resolve the actual
`CGlobalThreadPool`/`CThreadPool` slot `+0x80` to `tier0+0xa5500`.
Its branch at `+0xa558b` really invokes the submitted job's callback inline at
`+0xa55a7`; the other path queues it through `+0xa5780`. The inline gates read
pool dword `+0x130` and pool byte `+0x159` together with job byte `+0x15`.
The supplied job's latter byte is 2. The export does not record those pool
fields or the outer return chain distinguishing submission-time inline dispatch
from later job helping. Therefore the exact gate/dispatch taken, and why that
state occurs, remain unestablished. No unsupported flag meaning is inferred
from an older SDK layout. Texture failures precede this request, but the evidence
does not establish that they caused its dispatch.

The matching image inspections succeeded in Actions runs `44280845850`,
`44281373288`, `44282794106`, `44283105934` and `44284128882`, on a separate analysis ref.
No forced resume, count clearing,
proprietary binary patch or fabricated success is introduced.

## Validation limits

The focused tests compile the actual staged allocator/factory methods rather
than replacing admission with an equivalent model. The eight-row replay keeps
the recorded floor and available-memory operands unchanged. In the controlled
initial-data cases, the final three compact charges are 31,488, 33,536 and
131,840 bytes and are admitted. The first five remain denied at their original
headroom; the test admits their complete charges only after supplying a fresh
measurement with 68 MiB more available memory.

The transient-lifetime reproducer leaves 68 MiB of newly completed test-owned
storage retained under the previous recovery latch. The corrected path releases
that storage, while preserving a separate pending 32 MiB buffer and its bytes.
No completion means no release. Eight concurrent denials claim the same
completion frontier once; repeated soft-pressure calls retain warm dynamic
buffers. These byte counts describe controlled owned buffers, not measured
iPhone RSS. Actual initializer transfer tests cover six texture shapes and 142
subresources, including native BC, row/depth padding, mip chains and cube arrays.

The operand replay, real owned-buffer transfer, completion-frontier, native
predicate and full staged-factory tests establish code behavior with explicit
allocator, GPU-event and footprint inputs. Reclaiming test-owned bytes does not
establish an equal iPhone physical-footprint reduction. Successful creation of
required map textures, responsive team selection, continued main-thread frames
and actual gameplay remain unverified on device. The game capture routine and
its own intended resume are resolved; the upstream self-targeting request still
requires further evidence before a suspension-related compatibility patch is
justified.
