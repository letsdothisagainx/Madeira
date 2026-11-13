# CS2 run 8: CPU work before GPU submission

Evidence is the exported run from source
`87feb2aa256f7bcb0e8b9db1c61733c80862caba`. The export shows remote
connection and full sign-on, followed by stalled gameplay and timeout. It does
not establish playable 60 FPS or independent VAC-secured gameplay acceptance.

## Phase and clock limits

The 49–60 FPS intervals end around the runtime wall-clock sample at 03:15:17.
The console records the remote handshake at 03:13:47, game-loop activation at
03:15:19, a full update at 03:15:20, Dust II physics creation at 03:15:28 and
timeout at 03:16:35.
There is no completed 64-frame performance window after full sign-on.
Runtime timestamps attached to aggregate frame reports are nearby observations,
not exact start/end times or a cross-thread causal trace. The exported console
time zone is unmeasured; these wall-clock labels support phase ordering, not
calibrated cross-domain latency. The high-FPS intervals
therefore cannot be presented as a gameplay benchmark.

| 64-frame window | Average Present gap | Maximum gap | Average time inside Present | GPU execution/frame | Drawable wait/frame |
| --- | ---: | ---: | ---: | ---: | ---: |
| #128 | 502.4 ms | 14,217.6 ms | 2.9 ms | 2.0 ms | 0.07 ms |
| #192 | 934.6 ms | 23,578.3 ms | 61.6 ms | 3.7 ms | 0.06 ms |
| #256 | 537.7 ms | 5,860.8 ms | 3.3 ms | 1.0 ms | 0.53 ms |

The #192 window also has a 3,583.5 ms maximum inside Present and 35.95 ms
average encoding preparation. These are real CPU-side outliers; they do not
show a busy GPU or slow drawable acquisition. The queue-ring commit wait,
explicit synchronization count and event-stall counters are zero in these
windows. Two Metal command buffers per frame were submitted. Existing
commit-before-present behavior and separate encoding/completion workers are
already active. Increasing frames in flight or adding GPU work is unsupported
by this evidence.

## Attribution from the exact installed binaries

Saved guest RIPs in the overlay, tier0 and animation DLLs identify guest-frame
context; they are not necessarily the instruction executing in native code.
The captured actual FEX block at native `0x7c47a9a540` maps to
`animationsystem.dll+0x44c400`. Its captured instructions initialize an object
with vector/scalar stores and a vtable pointer. No backward branch or repeated
write fault at that block was demonstrated. No proprietary function name is
available, and the object initialization is preserved.

A separate repeatedly sampled native path resolves to `fex_ios_rpm_lock`:
ARM64EC FEX RVAs `0x15684c`, `0x156854` and `0x156858` are the recursive
owner-lock retry loop, including `YIELD` and `LDAXR`. Main and worker threads
appear there during substantial CPU activity. This establishes active polling,
not the exact total process time attributable to the lock.

These symbols come from the actual shipped IPA, not a stale bundled DLL:

- IPA SHA-256: `39d459f2ea91ff4b1b75e5656df96f8330fc407a4ffd1afeb2cefd57927feed9`
- ARM64EC `xtajit64.dll`: `4225f60465a067194fc402890e2fc82294fa8f5047668abfe55a241302b2ff60`
- [Read-only binary inspection artifact](https://github.com/letsdothisagainx/Madeira/actions/runs/43395182222/artifacts/14022073194)

## Production corrections

### Stop active polling during prolonged FEX allocator contention

The owned CMake overlay preserves rpmalloc's recursive owner/depth protocol and
acquire/release CAS. After 64 unsuccessful polls, a ready allocator uses a
nonalertable, relative 100-microsecond `NtDelayExecution`, then retries the
actual CAS. A delay never grants ownership or fabricates allocation success.
Short/uncontended calls do not enter the delay path. Readiness is published only
after the image's explicit heap was successfully acquired through the existing
NT mapping path. Initial constructor-time locks retain the original no-CRT
polling behavior. No address of the owner word escapes to a wait API, avoiding
an unsupported writable-alias contract or lost-wakeup dependency.

Actual old/new lock-body tests cover recursive entry, exclusive counter updates,
initialization without NT calls, failed delays and cancellation before ownership.
The host NT-delay shim sleeps for real but is not iOS timing. In a controlled
sequential Linux run of the final implementation, four-thread contention with
500-microsecond held sections used **707.163 versus 23.078 ms process CPU**,
and 100-microsecond held sections used **163.858 versus 7.823 ms**.
Uncontended 50,000-entry elapsed times were **2.886 versus 2.947 ms**: the
leaf calls add a small short-path cost. The 500-microsecond stress case's maximum
wait increased from **85.741 to 172.649 ms**. Other loaded-host runs also showed
variable/increased tail waits; finite parking and this existing unfair lock do
not guarantee individual wait latency. These are host contention measurements,
not game FPS or a guarantee of iPhone scheduling improvement.

The CAS and depth-publication leaf helpers keep mutable addresses local to a
provable native writable-alias sequence. A first nonleaf layout failed the
strong compiled-code check and was rejected. Both whole production PE ABIs now
pass checks for every known write producer: owner (2), depth (3), enabled (1),
readiness (1). Read-only loads may use the coherent RX mapping. The CI gate
repeats this check on the actual final FEX DLLs before publishing the IPA.

The heap, 16 MiB span geometry, retirement policy, native TEB identity read,
executable protection and live-code ownership remain unchanged. Wine's existing
NT wait state handles sleeping/cancellation without calling the FEX allocator.
Both PE backends are rebuilt; the final package requires the compiled
`lock=bounded-spin-park-v1` capability.

### Bounded memory trimming with a continuing cursor

`DynamicBuffer::TrimCompletedForQueue` previously restarted at the registry head
after each batch of 64 retired allocations. A large resource set therefore
repeatedly scanned earlier nodes under the registry mutex. The replacement
registers a stack cursor, continues from the next owner and redirects active
cursors before an owner can be removed. It resumes an owner with more eligible
FIFO entries and revisits skipped hot owners if pressure becomes critical.
Persistently busy or newly inserted owners can defer to a later sweep; one
useful-progress retry remains bounded. Native releases still occur outside
both registry and instance locks.

The test executes the old captured production method and new method on the same
8,000 owners. Registry visits fall from **489,744 to 16,000**, with identical
**1,536,000 bytes detached, 1,024,000 bytes retained and 1,024,000 cache credit**.
ASan/UBSan cases include concurrent unregister/delete, nested trims, a large
FIFO, a held instance, pending reuse and a final-batch emergency transition.
Warm-cache limits, pressure thresholds, queue ownership and completed-GPU
eligibility are unchanged. The registry adds one pointer, not a resource cache.

### Avoid redundant D3D11 command creation

`SetVertexBuffers` already detects unchanged buffer identity, but still emitted
an encoder command when offset and stride were also unchanged. It now emits
that command only when metadata changes. Buffer objects, references, DISCARD
renames, dirty flags and full state restoration remain active. An actual-method
repeat-binding check goes from **20,000 extra encoder commands to zero** while
preserving the resulting draw state and resource references. This is a bounded
test, not a claim about the frequency of redundant bindings in CS2.

Release HUD methods were already no-ops, but callers formatted strings before
calling them. Only debug builds now perform that formatting. The real
`UpdateStatistics` test goes from **378 format calls/378 allocations/11,718
allocated bytes over 63 frames to zero**. Debug HUD output and the existing
64-frame statistics remain byte-identical.

### Batch native residency declarations

Adjacent native Metal `useResource` commands with identical usage and stages
can use `useResources`, with at most 64 pointers/512 stack bytes per batch.
The stage preserves duplicates, order and every draw/binding/fence/encoder
boundary, with scalar fallback for unsupported selectors or invalid inputs.
No drawing, upload, submission or completion operation is skipped. A homogeneous
2,048-declaration replay goes from **2,048 to 32 native calls**; 440 mixed cases
verify identical ordered declarations. Remote replay is unchanged.

The native release path also avoids retain-count/class/ring diagnostics when
the existing stale-object probe is disabled. Actual retains/releases and
completion lifetimes are unchanged. No persistent Metal resources are added.

## Build and acceptance

Owned staging overlays compile the same corrected sources for AArch64,
ARM64EC, i386 and native DXMT. Cache keys and packaged binary markers reject
stale implementations. Vendor sources are restored byte-for-byte. The native
build recipe is unchanged, preserving shader-converter identity and existing
shader cache keys.

The source-controlled macOS tests execute real Objective-C ownership and
Metal compute/render readbacks where a Metal device is available; Linux
portable replay is not a substitute for those checks or iPhone gameplay.

New iPhone FPS, GPU busy, present latency, peak footprint, team selection and
connection lifetime are **unmeasured** until this build is installed. The prior
5,706 MiB footprint is a baseline, not an after result. No new queue depth,
texture backing, JIT capacity, security behavior or game configuration is
introduced. Install over the existing app using the same signing identity and
bundle identifier; retain the app data. Rolling back the source changes and
rebuilding restores the previous implementation without a data migration.
