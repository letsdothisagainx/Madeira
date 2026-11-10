# CS2 executable-pool retirement and placement correction

## Captured failure

The `fce3739` phone capture (`madeira-log(20261110-011804)`, SHA-256
`cf444df0a723ad0bf2b0d93aac1147afd9e74f286ebccb35af1f302370c8b5de`)
passes browser preparation, starts the genuine Steam service and launches CS2
at approximately t+95.2 seconds. The first client.dll copy succeeds. Its
embree3.dll dependency then fails executable-copy allocation; the retained
client import receives DLL_NOT_FOUND, and a later client-copy retry also runs
out of executable space. Retaining that first failed-import image is Wine's
existing lifetime contract, not a newly established leak.

| Captured logical measurement | Value |
| --- | ---: |
| Shared pool | `0x48000000` / 1152 MiB |
| Image-head high-water mark | `0x29d70000` / 669.4375 MiB |
| Tail reservation watermark | `0x1e018000` / 480.09375 MiB |
| Contiguous virgin gap | `0x278000` / 2.46875 MiB |
| Image free extents | 10, `0xf0000` total, largest `0x28000` |
| Certified aged code receipts | 5, `0x3008000` total, largest run `0x1008000` |
| embree3.dll request | `0x1524000` / 21.140625 MiB |
| client.dll request | `0x29a8000` / 41.65625 MiB |

The receipts are separated. They cannot be added together into a contiguous
allocation. The additional unproved ordinary-FREE buffer belongs to the still
running game and must remain unavailable to executable images.

## Confirmed production defects and correction

`ios_tail_carves_retire_owner()` skipped every already-free carve. An ordinary
FEX release preserves its PEB and allocation lease, but if the owner later
became fully quiescent, the carve never gained that legitimate retirement
receipt. The correction certifies an ordinary release only at a matching,
nonzero quiescent lease. It restarts the three-second grace at that boundary.
Active owners, unknown identities, stale leases and reassigned buffers remain
unproved. The registry query remains outside the allocator locks; matching and
publication remain under the carve lock.

Certification alone is insufficient in this capture. At the game's tiny
dispatcher request, an interior tiny carve is old enough for reuse, while the
endpoint tiny alternatives are only two seconds into their three-second grace.
A tiny reuse at that interior address separates two retired 16 MiB code buffers.
The previous preservation preference considered only the individual carve's
size, so it did not recognize this small but valuable connecting extent.

The new bounded metadata helper evaluates the certified contiguous main-pool
span containing a candidate. For a request of at most 64 KiB, normal fresh-fit
and metadata-capacity checks can preserve that span by placing the tiny request
in fresh storage. No live code moves or shrinks. A failed fresh reservation
falls back to the existing guarded reuse path. The helper never supplies proof
or age to an unproved neighbour: preservation is a placement preference, while
actual reuse and image transfer retain their original lease, grace, PC, page,
alias and overlap checks.

The pool stays **1152 MiB**, soft image headroom **240 MiB**, fresh large-code
budget **512 MiB**, with region C disabled in this capture. All three live
128 MiB generations remain intact. No new memory-size setting is required.

## Production replay and limits

The fixture records 45 allocation results and 77 allocation/release/retirement
events. Integer allocator-clock seconds are constrained by adjacent log clocks;
one boundary-crossing event uses the later second required by its observed
retired-buffer reuse. Unrecorded image-free addresses are explicitly synthetic
separated extents matching the logged count, sum and maximum.

The pinned prior retirement function and prior preservation decision reproduce
all 45 old addresses, the exact recycler refusal, embree failure and retained
client retry failure. A promotion-only control still fails. The combined policy
loads client and embree through the real allocation/recycling functions and
shared RX/RW backing. It also checks nearby grace-boundary timing variants,
owner isolation, failed-import retention, executable payloads, protection
rejection and subsequent FEX rotations. Five older captured lifecycles run
against the current production decisions with returned handles and known image
requirements; separate old-policy executions retain exact-address controls.

The recorded-order corrected replay transfers `0x2004000` (32 MiB + 16 KiB)
from three certified receipts at offset `0x42fe8000`. embree receives its
`0x1524000` executable allocation there. Fresh tiny reservations add 80 KiB,
leaving the main head unchanged and tail `0x1e02c000`. The remaining virgin gap
is `0x264000` / 2.390625 MiB. Immediately after embree, the image freelist plus
virgin gap totals 14.203125 MiB; its largest reusable image extent is 10.875 MiB.
Further certified code totals 16.09375 MiB, with a largest run of 16 MiB. These
figures are logical capacity, not physical residency or guaranteed availability.
The corrected replay also allocates three further synthetic 8 MiB images
(24 MiB total), followed by four more FEX rotations after those images, eight
post-dependency rotations in total. It then retains 6.203125 MiB in image
freelists plus virgin space, largest reusable image extent 2.875 MiB.
A later single 20 or 40 MiB request can still genuinely fail: this correction
does not promise arbitrary future modules fit. Additional bounded image and
rotation tests are explicitly synthetic, not evidence of a rendered CS2 menu.

## Accounting, configuration and separate VA probes

Failure-only accounting reports bounded owner/lease groups, allocated code,
ordinary frees, certified retirement, unproved receipts, image freelists and
poison, separately for main and region C. Image records do not carry generations;
those are marked unknown. Cleared retired PEBs are not reconstructed from a
lease. Overlapping records are an unattributed union, never counted twice.
The snapshot takes carve then pool locks after the capacity census unlocks,
and explicitly identifies this later serialized snapshot. It grants no memory
and changes no mapping, protection or allocator metadata.

The former `overridden to1024` message described an intermediate request.
The final startup-plan record now states configured versus effective selection
and its source. CS2's budgeted1152 selection remains unchanged. The2048 MiB
startup eligibility reserve is not a continuous reservation or a guarantee of
later game-asset residency.

The low-address `errno=17` probes are no-clobber host-VA collisions, distinct
from this pool's logical capacity. Wine-view gaps do not describe all native
Mach mappings. The failed16 GiB FEX hold successfully falls back to the healthy
8 GiB arena. No mapping change or FEX allocation-trap suppression is justified.

## Rendering and remaining device acceptance

The game window is already `{80,0,720,450}` before swapchain registration:
640x450 centered in the800x450 monitor. DXMT's layer, render attachment and
drawable retain that size. The capture lacks the original CreateWindow request
and original DXGI description, so it does not prove a downstream resize bug.
A bounded native Wine observer now records original request/default/computed/
final window geometry without changing it. The184-case pixel probe is unchanged;
this capture does not execute it.

Peak sampled footprint is approximately4264 MiB against the measured6144 MiB
budget; the game failed before normal asset residency. Thermal state was serious
at launch. No new FPS, physical-memory or startup-time improvement is inferred
from the host replay. The pool is not enlarged; successful later game loading
still needs physical-memory monitoring.

On the iPhone, require both dependency copies, continued compilation, later real
module loading, a complete rendered frame/menu and safe memory use. Only then
retest matchmaking with the existing error marker/export. The current capture
cannot retest VAC; its running service and separate in-process DLL architecture
failure do not identify the rejected VAC component. No security or trust policy
is changed. Browser preparation, data, controls and authenticated launch remain
untouched. Install in place using the same app/signing identity; rollback is an
in-place installation of the previous IPA, without uninstalling Madeira.
