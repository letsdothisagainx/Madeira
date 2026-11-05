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
effective budget at 6144 MiB. It requires the observed 3818 MiB peak plus the
128 MiB increase and a further 2048 MiB reserve to fit that budget. Available
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
