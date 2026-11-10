# CS2 executable-pool startup budget

The current November 10 architecture uses a **768 MiB image arena and a
384 MiB code arena within the existing 1152 MiB pool**, with guarded geometric
FEX code-buffer growth. See [the latest implementation and evidence](CS2_POOL_20261110_051624.md).
The dated policies and captures below are historical controls, including the
240 MiB soft headroom / 512 MiB code-growth policy which failed on-device.
They are not guarantees made by the current allocator.

The `86a0a17` device capture reaches the genuine `cs2.exe -steam -joy` process,
loads engine2 and initializes DXMT/Metal. It then fails to load the existing
`phonon.dll` because a contiguous executable copy cannot be allocated. The
resulting steamaudio import failure and tier0 breakpoint are downstream events;
the breakpoint is not patched or skipped.

## Confirmed capacity failure

The 1024 MiB pool has image head `0x1dcd0000`, code tail `0x20014000`, and only
`0x231c000` (35.109 MiB) between them. Phonon requires `0x3310000` (51.063 MiB).
Its 226 aged free extents total `0x33e4000`, but the largest is `0xf0000`.
Existing best-fit reuse and coalescing cannot join separated live allocations.
The capture does not establish that live owners' retained code generations can
be reclaimed safely, so their buffers and retirement rules remain unchanged.

The two capacity consumers interact: increasing the pool by 128 MiB alone lets
the next FEX generation request a fresh 128 MiB code buffer instead of reusing
the available 16 MiB buffer. This consumes the entire increase and reproduces
the image failure. Pool growth without replaying that decision is insufficient.

## Source correction

Only a fresh launch whose original Steam app ID is 730 selects the automatic
1152 MiB pool and 176 MiB image-headroom target. This keeps
`1152 - 176 == 1024 - 48`, preserving the measured pre-phonon code-cap decision.
The existing minimum code-buffer size, halving, reuse, reference guards and
executable ownership are unchanged. The extra capacity remains available to
image copies. The headroom target is the existing soft code-growth policy,
not a new hard partition or a guarantee of future image capacity.

The private launch reserve is cleared at a fresh launch, imported independently
of later user environment settings, and combined with any larger explicit
user reserve. No configuration file or installed game data is rewritten.
An existing pool is never resized. A reduced result is rejected before the
debugger request; unsuccessful alias creation is cleaned up, and refused
cleanup requires a restart rather than repeated retained allocations.

## Physical and virtual bounds

The full 1152 MiB is treated as charged memory. RX and RW share one physical
backing but require two separate virtual ranges. There is no assumption of a
no-footprint exemption.

The policy uses measured footprint plus `os_proc_available_memory`, rejects
unknown/sentinel/overflow values and inconsistent hardware totals, and caps the
effective budget at 6144 MiB. At selection time it requires the earlier observed 3818 MiB peak plus the
128 MiB increase and a further 2048 MiB reserve to fit that budget. This is
a startup eligibility check, not a continuing measurement of game residency. Available
memory must also cover the complete 1152 MiB pool plus 2048 MiB. This does not
raise the iOS memory limit or guarantee later game-asset residency.

Actual task-map bounds and successful mappings remain authoritative. The
automatic single-pool path validates 16 KiB alignment, nonoverflowing bounds,
separate RX/RW spans and executable-window/guest exclusions. Existing mapping
and protection operations retain W^X. The allocator still refuses an executable
image load when a real capacity or executable-copy failure occurs.

## Regression and device acceptance

`check-pool-cs2-budget.py` compiles the production budget/range helpers, reserve
import, complete EC_CODE allocation branch, image allocation/failure chain,
reclaim, and release paths. Synthetic separated extents reproduce the logged
count, sum and maximum; their original offsets were not recorded. Real shared
file mappings verify alias visibility.

The 1024 MiB control fails; 1152 MiB growth without the paired reserve also
fails after allocating a fresh 128 MiB code buffer. The paired policy reuses
16 MiB, allocates phonon, and allocates a further 48 MiB of images without
reclaiming the three foreign 128 MiB buffers. Ownership, retirement grace,
foreign releases, true-capacity failure and rollback are checked. The existing
meter, failure census, split, startup-budget and code-exit regressions run in
the IPA gate too.

CI proves the source behavior and build, not game startup on this iPhone.
Device acceptance requires an executable phonon copy, steamaudio loading,
progress beyond the previous breakpoint, continued authenticated Steam launch,
and no regression to CallRetStack allocation or DXMT initialization. New
graphics/audio/game errors must be reported separately. CS2 is not claimed
playable without on-device evidence.


## November 6 server.dll capture and correction

The `81f0428` capture verifies the earlier milestones on the phone: genuine
Steam launches CS2, phonon, steamaudio and scenesystem load, and DXMT reaches
`nextDrawable #1`. It does not establish a presented game frame or a usable
menu. Loading server.dll then fails honestly with STATUS_NO_MEMORY:

| Measurement | Captured value |
| --- | ---: |
| Shared pool | `0x48000000` (1152 MiB) |
| Image head | `0x244dc000` (580.859375 MiB) |
| Reserved code tail | `0x22018000` (544.09375 MiB) |
| Contiguous virgin gap | `0x1b0c000` (27.046875 MiB) |
| server.dll executable copy | `0x2580000` (37.5 MiB) |
| Free image extents | 5, totaling `0xa8000`; largest `0x38000` |
| Poisoned free capacity | 0 |

Coalescing cannot recover separated live allocations or provide the missing
10.453125 MiB. Three 128 MiB code buffers remain referenced or lack a verified
release; sampled execution and generation references prohibit treating their
unused-looking suffixes as reclaimable. Their full reservations, ownership,
reference checks and grace periods remain intact. Used-byte telemetry is not
sufficient to prove that future producer writes or returns cannot reach them.

The actual avoidable allocation is smaller: with region C disabled, four
16 KiB requests received whole reusable 16 MiB code carves. The existing
preserve-large-carve preference only applied when region C could serve the
tiny request. Each stolen carve could force a later real code generation to
reserve another 16 MiB. The preference now also uses a genuinely fitting small
main-tail reservation, limited to the existing 64 KiB tiny-request threshold.
No live carve is split, moved, freed or shortened.

The fresh path rechecks head/tail bounds and metadata capacity while holding
existing carve-then-pool locks through publication. If room disappears, it
rolls back and retries the original reuse policy once. Image head allocation
also clamps stale caller ceilings under the pool lock, including after grace
waits. It never enlarges an explicit caller limit or changes freelist-only
allocation. Existing holes, ownership, executable protection and true failure
paths remain authoritative.

`tests/host/fixtures/pool-cs2-200111-tail.json` records the complete observed
tail allocation, release and quiescent-owner retirement history through this
failure. The regression compiles the real EC_CODE, image allocation, reuse,
retirement and rollback paths. Release events follow the handles returned by
the counterfactual allocator; they are not forced to the old addresses. The
old production source reproduces all 19 carves, four oversized tiny results,
and the final `0x22018000` tail before rejecting server.dll. The corrected
replay ends at `0x1f024000` (496.140625 MiB), saving **47.953125 MiB**, rather
than assuming four times 16 MiB survives all subsequent lifecycle events.
With the same head, this leaves exactly **75 MiB** of contiguous image room.

The corrected replay allocates server.dll, two observed later diagnostic DLL
sizes (schannel/rsaenh), and another 32 MiB across multiple synthetic image
loads, leaving 4.15625 MiB. Those synthetic loads are capacity stress, not an
assertion that the remaining actual game modules are known. A subsequent
8 MiB image genuinely fails. A new 128 MiB code request cannot consume the
saved room: the unchanged 176 MiB headroom policy still requires degraded
16 MiB reuse. All three retained 128 MiB buffers are preserved byte-for-byte.
Real file-backed RX/RW aliases, executable host test code, RX write rejection,
owner/PC/grace guards and deterministic concurrent metadata/head races are
covered by the production-path fixture.

There is **no pool-size or physical-memory-budget increase** in this correction.
The capture's peak footprint is approximately 4290 MiB (periodic samples reach
4275 MiB), leaving about 1854 MiB below the 6144 MiB effective cap. Thus the
older startup estimate does not guarantee 2 GiB of remaining game residency.
Future assets, live code and iOS jetsam pressure still require device testing;
shared RX/RW backing is charged once, not twice or assumed free.

The current DirectX prerequisite separately fails to relocate an infinst.exe
image with stripped relocations at an unavailable fixed base (STATUS_CONFLICTING_ADDRESSES).
Steam nevertheless creates CS2. That error is preserved as a separate issue;
this patch neither fabricates installer success nor modifies the installer.

Device acceptance now extends beyond phonon and scenesystem: server.dll must
receive a valid executable copy, subsequent real modules must load, and Metal
must present an actual game frame toward the menu while memory remains safe.
Passing this bounded replay or the IPA build does not prove that acceptance.


## November 7 client.dll capture and retired main-code capacity

The `3c06c5c` phone capture confirms server.dll now loads, as do phonon,
steamaudio and scenesystem. Steam service, authentication, Chromium IPC and
D3D11 atomic recovery survive. DXMT reaches `nextDrawable #1`; that still does
not establish an actual presented frame or the game menu.

The next image, client.dll, requires `0x29a8000` (41.65625 MiB). At failure the
same 1152 MiB pool has head `0x269d4000` (617.828125 MiB), tail `0x2101c000`
(528.109375 MiB), and virgin gap `0x610000` (6.0625 MiB). Two small image
free extents total only `0x20000`; none is poisoned. The original production
image path genuinely returns STATUS_NO_MEMORY.

A 32 MiB FEX generation at RX `0x326fe4000` is released just before the
failure. Its generation sweep finishes all 21 migrations, but ordinary FREE
metadata does not carry an owner-quiescence receipt, and the three-second
image-reuse grace has not elapsed. A PC snapshot alone cannot exclude dormant
returns or later entry through linked code. This correction **does not shrink
the tail cursor or transfer that buffer**. Even returning all 32 MiB would
leave only 38.0625 MiB contiguous, 3.59375 MiB short of client.dll. The next
carve is a live 128 MiB generation, not reclaimable frontier space.

The missed capacity is instead three adjacent 16 MiB code buffers from
terminated hardware-query helpers:

| RX range start | Original owner | Allocation lease | Retirement evidence |
| --- | --- | ---: | --- |
| `0x340fe4000` | `0x1043fc000` | 11 | zero native threads, retired |
| `0x341fe4000` | `0x600310000` | 13 | zero native threads, retired |
| `0x342fe4000` | `0x700310000` | 14 | zero native threads, retired |

Together they provide 48 MiB. A separate 16 MiB buffer at `0x345ff8000`,
reused by owner `0x700310000` under lease 22 and subsequently retired, provides
later image capacity. These retired ranges have been idle well beyond the
reuse grace. Ordinary released buffers from still-running owners are excluded.
The old image recycler only handled the separate opt-in region C, so these
main-pool code reservations were invisible to the image allocator.

The production correction records the process lease at every code-buffer
handout and clears any previous retirement receipt on reuse. Retirement
certifies a buffer only when its recorded allocation lease matches the
runtime's quiescent lease. Native thread retirement completes owner-dependent
FEX callbacks before decrementing the group count; the remaining noreturn
native tail cannot reenter generated code. An exiting group cannot add new
Wine threads. Unknown or mismatched identities never produce a receipt.

Only after ordinary image allocation fails, the main recycler can transfer an
exactly adjacent run of whole certified buffers, bounded to 64 MiB. It requires
elapsed grace, full RX read/execute and RW read/write coverage, no writable RX
or executable RW pages, a successful empty strict thread-PC scan, and no
conflicting code carve, image mapping, live ledger entry or image freelist
entry. It removes the selected code records and publishes the image extent
atomically under the existing carve-then-pool lock order. The normal image
allocator retains alias invalidation, owner publication and capacity checks.
No live buffer moves, shrinks or loses protection. The existing explicit
recycling override still disables transfer; region C remains opt-in.

The pool stays **1152 MiB**, and the paired **176 MiB** code-growth headroom
is unchanged. Head and tail cursors remain unchanged when ownership transfers:
the tail watermark includes already-reserved bytes now owned by executable
images. It is not a new reservation or a claim that all those bytes remain
live FEX code. This avoids both unsafe frontier reclamation and pool growth.
Growing the pool without the paired policy would let FEX take another large
generation and consume the intended image gain.

The new `pool-cs2-083837-tail.json` fixture records 31 observed code allocation
results, five tiny-carve preservations, generation releases, process leases,
retirement and image-head checkpoints through client.dll. The production
regression checks the baseline allocation addresses/sizes and exact failing
geometry, then exercises the corrected transfer, client image ownership,
executable alias visibility and additional 8+8+4+4 MiB synthetic image loads.
Those later loads are capacity stress, not fabricated evidence of actual
post-client game modules. A further request must still fail when no eligible
contiguous capacity remains. Busy, recent, unproved, foreign-generation,
nonexecutable, improperly aliased and conflicting ranges remain unavailable.

The capture's approximately 4366 MiB peak leaves 1778 MiB below the measured
6144 MiB effective cap. The older startup planner's historical 3946 MiB estimate
therefore does not establish its nominal 2048 MiB of later asset headroom.
This patch adds no reservation or budget: both aliases continue sharing one
charged backing. Later assets, FEX arena pressure and jetsam remain device
acceptance concerns, not reasons to falsify an allocation or discard live code.

DirectX also fails in this current capture: relocation-stripped x64 infinst.exe
requires `0x100000000`, below task floor `0x104044000`, and has no relocation
table. Its moved load at `0x13e6d0000` fails STATUS_CONFLICTING_ADDRESSES.
Steam nevertheless starts CS2. That separate compatibility issue remains
unfixed; this allocator patch does not manufacture installer success.

The next phone run must confirm client.dll's executable copy, subsequent real
modules and an actual presented CS2 frame while Steam, JIT and memory remain
stable. CI and a successful bounded replay do not prove a rendered menu.


## November 7 evening embree3.dll dependency budget

The `f4403001` phone capture confirms the certified main-pool transfer works:
48 MiB at offset `0x40fe4000` is transferred, and client.dll receives its
`0x29a8000` executable copy. The first failure moves to client.dll's real
embree3.dll dependency, which needs `0x1524000` (21.140625 MiB).

At that instant, image head is `0x269c8000` (617.78125 MiB), reserved tail is
`0x2101c000` (528.109375 MiB), and virgin space is `0x61c000` (6.109375 MiB).
The image freelist has three entries totaling `0x678000` (6.46875 MiB); the
largest is `0x658000` (6.34375 MiB). No range fits embree. Remaining certified
retired code storage is one 16 MiB range plus two 16 KiB ranges. Active
dispatcher pages separate it from an ordinary released generation, so those
ranges cannot be joined. The zero page/PC/conflict counters do not prove an
eligible transfer: the size test rejects these small candidates first.

The 32 MiB generation at RX `0x326fe4000` is still live during both the embree
failure and client retry. Its FREE event occurs afterward. That future release
is never included in the failing request's available capacity, and this patch
adds no authorization to transfer an ordinary release into image storage.

The avoidable earlier reservation occurs when head is `0x1a7e8000` and tail
is `0x1f01c000`. The 176 MiB soft headroom policy permits a fresh 32 MiB FEX
generation despite available reusable 16 MiB generations. Raising automatic
CS2 headroom to **208 MiB** makes the existing honest allocation-failure/halving
ladder reach 16 MiB reuse instead. The three earlier 128 MiB generations still
fit their original decisions. The pool remains **1152 MiB**; alias addresses,
physical-budget guards, guard pages and minimum code-buffer sizes are unchanged.
This is a code-growth policy adjustment, not a hard image partition.

Code best-fit reuse now also preserves the more valuable image retirement
receipts: among equally sized eligible main-pool buffers, it prefers an ordinary
FEX release to a certified process-retired buffer. Smaller-fit selection,
existing eligibility checks, retirement grace, strict retired-buffer PC checks,
and region-C ties remain unchanged. A normal release remains usable only as
code under the existing contract; it does not become certified image storage.
The change applies throughout the counterfactual session, not just at one
hardcoded DLL or instruction address.

With both changes, the replay avoids 32 MiB of fresh tail growth. Earlier tie
choices also change ownership of later-retired buffers: the client transfer
now uses six certified carves at offset `0x41fe4000`, totaling `0x300c000`
(48.046875 MiB). The same protected transfer mechanism remains in use; no live
buffer is moved. Embree then fits in the 38.109375 MiB virgin range. After embree, projected head is `0x27eec000`
(638.921875 MiB), tail is `0x1f01c000` (496.109375 MiB), and virgin space is
`0x10f8000` (16.96875 MiB). Image-free extents plus preserved certified code
provide further separate capacity. The replay records image-free bytes
`0x684000` and a still-certified 16 MiB range at offset `0x40fe4000` (lease 10),
for `0x277c000` (39.484375 MiB) aggregate eligible space, with a largest range
of 16.96875 MiB. Their sum is not a promise of one contiguous allocation.
Two synthetic generation rotations preserve the certified buffer; 32 MiB of
additional synthetic images fit, leaving 7.484375 MiB aggregate before a real
8 MiB request fails. The headroom-only control reaches embree but supports only
16 MiB of this later stress. Subsequent real imports and asset residency remain
device tests.
A 16 MiB generation may rotate sooner than the captured 32 MiB generation;
additional reuse/rotation tests check safety, not a claim of improved FPS.

### Failed import and retry ownership

Wine deliberately retains the first client.dll image after dependency failure.
Its production `build_module()` removes public loader discovery metadata but
keeps the mapped image because dependencies may retain references, then sets
`module` to NULL. `load_native_dll()` consequently skips the unmap. The VAD,
JIT generation and allocating owner's ledger remain live. A later retry maps
at a different PE base, so neither same-base reload nor freed-layout-tag reuse
can adopt the retained copy. This is live-owned failure residue, not an unowned
allocation leak. No native rollback or premature reclamation is added.

`check-loader-import-failure-retention.py` executes the real Wine loader
functions with controlled boundary APIs and real list removal, then the native
reload/ledger/reclaim functions. It verifies retention and status, distinct
retry, ordinary error cleanup, owner retirement, sibling isolation, alias
invalidation, layout tags and reuse grace. It does not fabricate a dependency
success or execute Valve code on a host fixture.

The new `pool-cs2-200636-tail.json` records the complete observed code/image
sequence through embree and the failed parent retry. The baseline is replayed
with its captured 176 MiB setting and original ranking. The corrected replay
uses the actual 208 MiB plan and production comparator, follows returned handles
when earlier placements change, preserves five tiny-carve decisions and all
three live 128 MiB generations, and tests additional generation rotations and
synthetic image pressure. Later error-path actxprxy failures are not described
as normal post-embree game imports; none are demonstrated by this capture.

No pool growth or physical-memory exemption is used. Approximately 4.4 GiB of
observed footprint below the effective 6 GiB cap does not make all remaining
RAM available to JIT: later assets still need it. The DirectX fixed-address
installer failure and high emulated-write-fault cost remain separate issues.
Device acceptance requires a real embree executable copy and resolved client
imports, subsequent real modules, and an actual presented game frame/menu.

## November 8 earlier rotation and embree3.dll

The `5b22a6e` device log verifies the separate FEX data-arena correction:
8192 MiB total, approximately 2258 MiB used and 5933 MiB free, with no FEXAlloc
fatal abort. Real Steam launches CS2, and audio, scene and server modules load.
Client's first executable copy succeeds, then embree's `0x1524000` request fails
in the 1152 MiB executable pool. The per-image FEX heaps and startup guards are
unchanged by this correction.

The new fixture `pool-cs2-095621-tail.json` records all 29 successful code grants,
owner leases, releases, retirements, image endpoints and the two failed imports.
Five tiny-carve preservations and three retained 128 MiB generations occur
before CS2's late rotation. The crucial ordering differs from November 7:

| Captured state/event | Value |
| --- | --- |
| Head when fresh code growth is requested | `0x1825c000` (386.359375 MiB) |
| Tail before that request | `0x1f01c000` (496.109375 MiB) |
| Gap before growth | 269.53125 MiB |
| New fresh generation under 208 MiB policy | 32 MiB |
| Gap after growth | 237.53125 MiB |
| Subsequent release | Ordinary code-only FREE, before client/embree |
| Certified transfer for client | Six receipts, `off=0x41fe4000`, `bytes=0x300c000` |
| Final image head / tail | `0x269e4000` / `0x2101c000` |
| Embree request / virgin room | 21.140625 MiB / 6 MiB |

The ordinary 32 MiB release still lacks process-retirement proof. The correct
recycler rejection is preserved. The two remaining certified 16 MiB ranges
are separated by live mappings; their sum cannot satisfy one embree allocation.
Wine's failed-import retention keeps the first client image live, so a failed
retry does not authorize reclaiming it.

### Selected policy and timing control

The automatic CS2 plan now selects 240 MiB soft headroom. That blocks the
captured fresh 32 MiB request, but has only 2.46875 MiB of timing cushion:
a slightly earlier image head would admit it again. The regression therefore
also moves the rotation to the earlier captured CS2 initialization head,
`0x15cdc000`. The 240-only control then admits a 64 MiB generation, server
consumes the certified range and client genuinely fails. A larger soft reserve
alone is not treated as an order-independent repair.

A second startup-pool policy limits **fresh large MAIN-tail growth** against
512 MiB of retained tail reservations. It counts the actual successful cursor,
including any hole skips, instead of subtracting the current image head. All
three observed 128 MiB generations still fit: their combined tail ends at
496.109375 MiB. Adding another 32 MiB would exceed 512 MiB regardless of when
DLL copying happens. FEX uses its existing real allocation-failure/halving path
and takes an eligible 16 MiB code buffer.

Existing reusable code, verified region C and the existing <=16 MiB minimum
fallback retain their contracts. This is a limit on optional large growth,
not a promise that every future generation or image will fit. New concurrent
large requests check the limit inside the cursor CAS before reserving anything;
a failed request does not consume space or rely on a racy budget rollback.
Normal head collisions, live-code overlap checks and truthful OOM remain.
There is no change to image certification, owner leases, grace, poison checks,
RX/RW permissions or process/thread retirement.

The limit is selected only with the automatic CS2 pool plan and imported through
`WINE_IOS_JIT_CODE_TAIL_LIMIT_MB`. The app clears the private value for a fresh
launch and failed pool preparation. Other startup plans retain the previous
unlimited large-growth policy unless this CS2 pool policy was selected.

### Replay results and finite capacity

The 208 control reproduces every observed code address/size/lease, the six-
receipt client transfer, four image-free extents totaling `0x690000`, largest
`0x664000`, and the actual embree failure plus retained-client retry.
With 240/512, both the recorded and earlier-rotation replays load client and
embree through the production image allocator and executable aliases:

| Corrected replay result | Value |
| --- | --- |
| Client offset / allocation | `0x41fe4000` / `0x29a8000` |
| Embree offset / allocation | `0x269e4000` / `0x1524000` |
| Image head | `0x27f08000` (639.03125 MiB) |
| Retained code tail | `0x1f01c000` (496.109375 MiB) |
| Virgin gap | `0x10dc000` (16.859375 MiB) |
| Tail capacity avoided | 32 MiB |

Six further synthetic rotations reuse two distinct eligible 16 MiB buffers
without fresh tail growth. Active code, return/PC guards and all three 128 MiB
generations remain intact. Another 32 MiB across explicitly synthetic 8 MiB
images fits, followed by further legitimate code allocation. True exhaustion
still fails. Those extra requests are stress, not game modules observed after
embree: the device log contains no successful subsequent game imports.

A single subsequent **20 MiB image still fails** with the selected policy:
16.859375 MiB virgin space, 6.5625 MiB image-free space and one isolated certified
16 MiB range are not one contiguous extent. This limit is tested explicitly.
The test also evaluates a 448 MiB growth budget, which would shrink the third
fresh 128 MiB generation to 64 MiB and fit synthetic 20+40 MiB images. It is not
selected: it changes a working browser code-cache size, with unverified CEF
working-set and recompilation costs. Historical flat small-buffer limits caused
severe cache churn. No live 128 MiB buffer is reclaimed to make either test pass.

The backing stays 1152 MiB, charged once for both aliases. There is no pool
increase, address-map enlargement, RAM-limit change or physical-memory exemption.
The capture's roughly 4235 MiB peak leaves about 1909 MiB below the 6144 MiB
cap, not a guaranteed 2 GiB for future assets. Startup budget eligibility does
not guarantee later shader, texture or game-asset residency.

CI must pass the new production replay, timing adversary, atomic reservation
and real FEX constructor/retirement tests as well as the older pool fixtures.
Actual iPhone acceptance still requires a genuine client/embree dependency
chain, continued FEX compilation and a presented game frame. If a later actual
module exceeds the remaining contiguous capacity, its name and allocator state
must be reported; these tests do not establish a menu or playability.

## November 8 fbb4 device acceptance and a separate DEP sweep

The next supplied attachment identifies its installed source as
`fbb4a56f4e6959aef2f71651f281d844a451614f` at line 11, despite the accompanying
request repeating the older `5b22a6e` metadata. The 84,688-line attachment starts
at local time 16:49:30.932 and has SHA-256
`bb8e30fa82eb3b55cb961d1411ca5496b9ee3e68743743d6d7ce906c19135c7a`.
Its 1152 MiB pool, 240 MiB soft headroom and 512 MiB large-growth limit are active.

This capture supplies the previously missing client/embree device evidence:

* The certified six-carve transfer at lines 45789–45795 provides `0x300c000`
  bytes at offset `0x41fe4000`; the real client.dll executable copy loads.
* Embree's real executable copy then loads at pool address `0x326a28000`
  (lines 45799–45803), advancing the image head to `0x27f4c000`.
* The three earlier 128 MiB generations remain reserved. Later CS2 rotations
  reject fresh 128, 64 and 32 MiB growth and reuse eligible 16 MiB buffers;
  the recorded migration sweeps complete 15/15, 15/15 and 21/21 threads
  (lines 44516–44527, 45171–45182 and 45734–45745). No fresh 32 MiB carve
  appears, and the tail remains `0x1f01c000` (496.109375 MiB).

The next exhaustion is therefore not embree. After libmpg123-0.dll loads,
four `[force-exec]` operations outside a guest window precede a burst of
42 additional image copies (lines 45976–46128), including previously loaded
steamsysinfo.exe, opengl-program.exe and multiple processes' system DLLs.
Their image bytes and recorded trampolines total approximately 37.6 MiB before
alignment overhead. No new process creation accompanies this burst. The first
failed copy is kernelbase.dll at PE base `0x3ea6f0000`, already successfully
copied earlier at line 28086:

| First failure, line 46131 | Captured value |
| --- | ---: |
| Requested executable allocation | `0x180000` (1.5 MiB) |
| Image head | `0x28fd4000` (655.828125 MiB) |
| Reserved tail | `0x1f01c000` (496.109375 MiB) |
| Contiguous virgin room | `0x10000` (0.0625 MiB) |
| Image free extents | 7, totaling `0x88000`; largest `0x4c000` |
| Poison-marked free bytes | 0 |

The source establishes a concrete scope defect: `is_wow64()` can fall back to
session-global `wow_peb` for a native64 thread; `ProcessExecuteFlags` then admits
that thread as WoW64. With no owned guest window,
`ios_wow_force_exec_set_current()` returns the same fallback result as the
legacy session-wide mode, and `virtual_set_force_exec()` re-protects every
process's views. Its existing per-window DEP comments document how such a
sweep duplicates executable copies under the wrong process context. Native64
Windows execution flags must instead retain their fixed DEP semantics, and
an absent guest-window identity must not authorize a global sweep.

The erroneous source scope is directly visible. The device capture strongly
matches that path, but contains no direct
`NtSetInformationProcess(ProcessExecuteFlags)` entry trace or caller address;
the exact initiating API call in this capture remains inferred, not observed.
The first unhandled access violation appears only later at line 46477, after
pool exhaustion has started; the 290 total allocation failures in this burst must not
be described as independent normal game-module demand.

Peak physical footprint is 4261 MiB, below the effective 6144 MiB cap. This
capture supplies no evidence of renewed FEXAlloc fatal exhaustion or iOS
jetsam. DXMT again reaches `nextDrawable #1`, but neither drawable acquisition
nor successful client/embree copying proves a presented game frame, completed
client initialization, or a usable menu. Those remain on-device acceptance
requirements after correcting the separate DEP scope defect. No larger pool
or weaker code-retirement proof is justified by this new failure.

The correction keeps DEP query/set architecture checks local to the caller's
companion WoW TEB and live PEB-owned guest window. Native64 queries retain
permanent DEP and setters return `STATUS_INVALID_PARAMETER`. Independently,
the internal force-exec entry refuses a missing window in per-process mode;
only the explicit historical opt-out can select a global sweep. Neither the
pool budget nor image/code retirement certification changes.

`check-dep-process-isolation.py` compiles these production dispatch cases,
window ownership functions and sweep. The saved pre-fix source fails 14
isolation assertions; the corrected source passes under ASan/UBSan, including
concurrent independent I386 transitions, missing/dead/recycled owners, an
unbound bootstrap token, a native TEB matching a window without a companion
TEB, and a genuine I386 caller whose session-global `wow_peb` is NULL. Its
protection callbacks count boundary calls; they do not execute Wine or replace
the real pool/RX/RW allocator regressions or the next iPhone run.

## iOS 27 full-size placement and debugger handoff

The November 10 `14:04:01` capture is a pre-Wine placement failure. Its
reported 512 GiB task map does not establish a usable 512 GiB CPU allocation
range. The old constructor only tried up to 1024 MiB immediately above the
fixed Windows image window. The observed 626 MiB gap provided a rounded
624 MiB placeholder; the later first-fit census could not provide CS2's
1152 MiB RX allocation. No executable-pool capacity or VAC conclusion follows
from this run, because Wine never started.

The required-pool path now reserves two complete virtual destinations at
image load, with runtime Mach region discovery and fixed, non-overwriting
allocation. It first searches CPU ranges below 16 GiB, leaving the remaining
low CPU band available for guest/FEX fallback and CoreAnimation growth. On a
full extended map its final
fallback is the existing host-only [496,512) GiB band, excluding the guest
and Chromium [448,496) GiB bands and the GPU [64,448) GiB range. A high pair
also holds a separate contiguous 8 GiB FEX reservation in the same early
transaction. Wine adopts that exact held mapping without releasing it first.
Small-map low guest/FEX windows remain excluded from pool placement.

Large anonymous reservations can contain independent 128 MiB VM objects.
Ownership records cover every constituent region, including backing offsets;
they do not require one object to span the complete allocation. Early holds
touch only one 16 KiB ownership-witness page per region. The FEX handoff uses
a bounded versioned receipt containing the complete region records, checked
against the kernel before adoption rather than a scalar object identifier.

Both final destinations stay owned while the debugger supplies a temporary
RX allocation. Shared remapping replaces only verified owned placeholders.
The final RX address is prepared before its RW alias is established, allowing
debugger preparation to change backing without leaving the writable view on
an old copy. The transaction verifies protections, page preparation markers,
shared writes and actual execution on every 16 KiB page before publishing.
Temporary mappings are released afterwards. Failure cleanup checks mapping
identity and bounded alternate attempts exclude failed locations. This does
not move or reclaim live game code.

The bundled debugger script has a capability handshake and an allocation-only
command. StikJIT's older preparation helper formats only nine hex address
digits and ignores individual write-error replies. Low-address preparation
retains its native batching, followed by the app's complete marker and
execution checks. High-address preparation uses full-width debugger writes
and checks each reply. Its serial network cost is measured at runtime; it is
not assumed equivalent to the low-address batched path. The supplied script
travels with Madeira's normal StikDebug and built-in JIT requests.

The pool remains **1152 MiB**, with **768 MiB for images** and **384 MiB for
generated code**. RX and RW share backing; the FEX reservation is virtual
capacity rather than an additional 8 GiB physical allocation. Neither user
data nor the existing Wine prefix needs migration. The old 624 MiB shrink
path is bypassed for the required CS2 pool.

Regression fixtures reproduce the captured old low-gap failure. Positive
pressure layouts beyond those recorded in the device log are explicitly
synthetic. Production-function tests and native Mach smoke tests validate
the implementation at their stated boundaries; they do not establish iOS
TXM acceptance or successful Steam/CS2 startup. The next iPhone run must
confirm the full aliases, executable-page checks, healthy FEX arena and
genuine CS2 launch. VAC and Export Run acceptance remain separate issues.
