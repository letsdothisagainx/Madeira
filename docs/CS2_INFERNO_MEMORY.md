# Inferno loading: completed resource ownership

Evidence: installed `ada983bf1d288a16a6995fe72e29c91cdfc9a7ce`,
`madeira-log.prev(3).txt`, iPhone18,3/iOS 27.0.1. The user reports an online
Casual Inferno loading screen. The recording reaches 6,142 MiB footprint,
6,143 MiB peak, against an approximately 6,144 MiB process limit and then ends.
Memory-pressure termination is a strong hypothesis; no jetsam report or fatal
exception establishes the termination reason independently.

## Confirmed ownership defects

`DynamicBuffer::allocate()` sampled its rename FIFO before
`updateImmediateName()` queued the old backing. After a one-time update the
old backing stayed cached until another allocation on that same resource.
The depth census could still say zero. Roughly 5,958 live dynamic resources
and 11,898 live backing allocations are consistent with that pattern. Their
593 MiB initial and 402 MiB replacement capacities are logical allocation
accounting, not a measurement of independently reclaimable physical pages.

The correction registers dynamic buffers by a monotonic queue domain and
detaches only cached names behind that queue's completed submission frontier.
Current names, deferred command lists, queued renames and GPU reference
trackers retain their own ownership. Soft pressure preserves two submissions
of hot reuse; critical pressure can remove any completed cached name. Registry
removal precedes destruction, busy instance locks are skipped, and native
releases happen outside registry/instance locks. Queue addresses cannot be
reused as lifetime proofs.

CPU-placed buffer destruction also released host backing before native buffer
objects/views. The correction releases those objects before host pages. The
original destructor's order reproduces an ASan use-after-free with a native
release callback that accesses its backing.

The upload ring used strict `< completed` for reuse although retirement
already allowed equality. It also kept completed blocks for 300 submissions,
which can mean minutes at low frame rates or indefinite retention while idle.
Idle cleanup consulted a stale cached completion value. The correction uses
the actual completion event, inclusive reuse and completed-only pressure
trimming. Soft pressure retains one normal ring block; critical pressure
releases all completed blocks. Zero-fill backing is released only when no CPU
upload commands remain and every submitted upload has completed.

## Process budget and texture uploads

Native `MadeiraCtl` operation 40 returns actual process footprint and available
process memory. Operation 7 and its established compatibility behavior remain
unchanged. Unknown/sentinel readings do not create a fictitious budget; valid
zero available memory is critical pressure. A thread-local 100 ms cache bounds
query overhead.

The safety reserve is one eighth of measured footprint plus available memory,
bounded to 128–1,024 MiB. A measured 6,144 MiB process budget therefore starts
reclaiming caches with approximately 768 MiB left. This is a reclamation trigger,
not permission to allocate beyond the OS limit. It does not change JIT, swap,
texture formats, game settings or the device's memory limit.

Before upload-ring expansion under pressure, the initializer submits its own
pending upload commands and waits at most 50 ms for its private GPU completion
event. It rereads actual completion before reclamation. A timeout does not
invent completion or allocation success. The main command queue is never
committed or drained from an arbitrary resource-loading callback.

Native BC texture uploads do not retain a second software-decoded texture
on the observed A19 path. Live private textures have no guaranteed reload
source and cannot safely be evicted just because memory is high. This change
reclaims completed transient upload storage and redundant cached buffer
ownership; it does not discard live textures, mip levels or shader bindings.

## Evidence and validation limits

In the final 13.7 seconds, logical private-texture capacity grew by about
655 MiB and buffer capacity by about 145 MiB. Metal allocated size grew by
about 311 MiB. Final DXMT live capacity was 3,440 MiB and Metal's allocation
counter 1,929 MiB. These figures overlap and must not be added together.
Likewise compressed guest pages and file-backed swap accounting are not
additional independent physical allocations. The recorded retired helper
owners already reached zero remaining FEX views; no guest-memory leak fix is
asserted here.

Host regressions execute the actual staged production methods with controlled
Metal/resource-completion boundaries. They reproduce the original stale
census/retention and CPU-backing destructor defects; test 6,000 one-shot
resources, 10,000 concurrent destruction cycles, queue isolation, pending and
deferred owners, byte preservation, bounded waits, and real backing failure.
They do not execute an iOS GPU or load Inferno.

The build compiles corrected D3D11/DXGI/Winemetal/D3D10Core PE binaries for
AArch64, ARM64EC and I386, as well as the native DXMT substrate. A temporary
source transaction restores the pinned submodule bytes. Packaging verifies
PE architecture/exports, original/staged source hashes, recipe hashes, native
contract markers and exact IPA copies, rejecting stale tracked DLLs.

On-device results still required: peak physical footprint and reclaimed
capacity during the same Inferno load, completed map entry, sustained online
connection, correct textures/models, and separately measured warm gameplay
FPS. No new FPS, physical-memory reduction, successful VAC-secured gameplay
or completed map load is claimed from CI.

## Installation and rollback

Install over Madeira using the same bundle identifier and existing signing
identity. Do not uninstall it or remove its documents. No prefix migration,
game-file repair or settings reset is performed. Roll back by installing the
previous build with the same identity, preserving application data. The
production change is confined to the DXMT memory overlays/build integration;
the established Steam, UDP, JIT and input paths are unchanged.
