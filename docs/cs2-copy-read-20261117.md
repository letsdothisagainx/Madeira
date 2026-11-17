# CS2 copying and positional reads — 2026-11-17

Evidence: export `2026-11-17T04:39:18Z`, source
`daf3dcecde4e14d46a5b8e49cf20fd56934a99fb`. Remote connection to
activation took 115 seconds; full sign-on was followed by a timeout. The later
loopback session and preceding 47–50 FPS windows are separate workloads.

## Established paths

The exact archived IPA was inspected in Actions runs `44020577006` and
`44020785831`, with native UUID `869F6713-CC33-3353-9A82-BC36A7EB553B`
verified before resolving its PE symbols and ARM64 branch references.

* UCRT SHA256: `f43f7110434978853c83ba4d66a6d8d718b8ecd544eae2b4063767675eb83e59`.
  `ucrtbase.dll+0x62b68` is `memmove+0x36c`, a vector store in a
  32-byte forward-copy loop. It is already vectorized.
* D3D11 SHA256: `f1dc5b4d90c0d96c224afead563ccbb2daff79fc4e886b8ad9848d574163e7f2`.
  `d3d11.dll+0x63484` follows the copy in `vector<uint8_t>::assign`.
  Direct branch references establish `PipelineCache::CreateShader` →
  `CachedSM50Shader` constructor → vector assignment → `memmove`.
  This sample precedes remote matchmaking.
* The later generated loop is ordinary translated guest vector-copy code,
  associated with Tier0 block entries `+0x28fa2a/+0x28fa33`. Its instructions
  advance both pointers by 32 bytes. The saved `+0x2cf5d8` context is not its
  current instruction pointer. Original copy arguments, invocation identity,
  and pointer progress over time cannot be recovered from this export.
* `virtual_locked_pread` first tries native `pread` without `virtual_mutex`.
  Only a software write-watch `EFAULT` retry takes that lock. The export
  lacks the descriptor, request, return value and original errno needed to
  identify the sampled read or a retry defect.
* Both long hole punches are deferred. Their worker drops its queue lock
  before `fcntl`, then acquires the VM lock to publish the zeroed free extent.
  Captured counters show no synchronous reservation-punch fallback and no
  swap copy-back (`unbacks=0`). Their durations do not establish game-thread
  blocking or APFS contention with the sampled descriptor.

## Production corrections

Shader cache misses previously prepared outside the insertion lock and only
checked for a winner afterward. Concurrent identical misses could each parse,
allocate, and copy the same bytecode, then destroy every losing shader.
The owned DXMT overlay adds 64 fixed preparation-lock stripes and rechecks
the cache after acquiring one. Ordinary cache hits remain on the original
shared-lock path. Distinct stripes prepare concurrently; a stripe collision
serializes preparation without conflating cache identities. Parsing runs
without the cache-map lock. Failures remain failures, release the preparation
lock, and can be retried. No additional bytecode cache is introduced.

The owned Wine file overlay corrects two reproducible `NtReadFileScatter`
defects: remaining length already excludes completed bytes, so subtracting
the current page position again caused premature completion after a partial
read; and a first-read error was overwritten by EOF. Positioned/current
offsets, short reads, EINTR, actual EOF, and IOSB/APC/event/IOCP publication
remain exercised. The export does **not** establish that CS2 called this API.

## Bounded capture of missing arguments

The existing sampler recognizes the observed generated copy-loop instruction
pattern, including its `x28+0x5e8` suspend doorbell and backward branch. While
the existing sampling suspension is held, it only snapshots registers and
84 bytes of generated instructions. Resolution, identity checks and logging
run after resume. Only CS2 owners can consume the 32-record budget. Output
reports current iteration source/destination/end, remaining span, associated
guest block entry and observed deltas; it explicitly leaves original length
and invocation identity unmeasured. No copied payload is read and no guest
operation or FEX interrupt check is replaced.

CS2 positional-read observations retain original native return values and
errno, offset/request/completed bytes, direct/write-watch/alias routing,
elapsed time and VM-lock wait/hold time. File names are classified locally;
raw paths and data are not exported. The capture is bounded and preserves
normal read results and completion semantics. It does not remove VM locking.

## Verification and limits

The production shader-cache bodies, constructor/destructor, and SHA1 code
run with eight host threads and an explicitly substituted SM50 API fixture.
For eight simultaneous identical 16,387-byte inputs:

| Work | Before | After |
| --- | ---: | ---: |
| Preparations | 8 | 1 |
| Bytecode-preserving constructor copies | 8 | 1 |
| Preparation input bytes | 131,096 | 16,387 |
| Retained bytecode bytes | 16,387 | 16,387 |

Tests also cover concurrent distinct inputs, stripe collisions, normal cache
hits while the miss stripe is held, validation failure/retry, and both shader
ownership modes. These counts prove duplicate-work elimination in that
reproducer, not its frequency in the iPhone run or a CS2 FPS improvement.

The original scatter function returns 6,144 of 8,192 requested bytes in the
half-page short-read reproduction; the corrected production body returns all
8,192 with matching contents. Actual read tests cover offset, EOF, original
errno, write-watch handling and concurrent protection. Copy capture tests
exercise 779 valid register snapshots, malformed instructions, boundaries,
ownership and output limits.

JIT layout, suspension/resume semantics, memory admission/trimming, texture
ownership, Steam/browser launch, UDP, input and the prefix are unchanged.
No Valve code or security decision is altered. No remote loading duration,
team-picker response, gameplay FPS, texture correctness or physical-footprint
improvement has yet been measured on an iPhone for these changes. The later
Tier0 copy/read stall is not claimed resolved by the shader/scatter tests.
