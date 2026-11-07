# CS2 executable-pool startup budget

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
