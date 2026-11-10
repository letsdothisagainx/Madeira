# PR #9 recovery and validation limits

## What was reviewed

PR #9 is an unmerged draft based on `ee12a33e315773e52e2bbad01029f8b9653f26a0`.
Its four commits are `611256b`, `318c3b7`, `a4b40bf`, and `f44ee54`.
There are exactly four changed files:

| File | PR #9 change | Recovery |
| --- | --- | --- |
| `app/Madeira/JITAllocator.c` | Fresh large-code growth selection 512 to 448 MiB | Restore 512 MiB and the earlier explanation |
| `tests/host/check-pool-code-growth-budget.py` | Expect 448; replace the producer's production selection with literal 512 | Restore selection and keep production-policy validation connected to the real producer |
| `tests/host/check-pool-cs2-budget.py` | Expect 448; add a counterfactual subtracting 64 MiB from a final cursor | Remove that counterfactual; do not call it an observed allocation lifecycle |
| `tests/host/check-pool-startup-budget.py` | Change the Swift fixture/telemetry expectation to 448 | Restore 512, consistent with the real C selector |

The main development branch remained at `ee12a33e`; PR #9 was never merged.
The recovery commit on PR #9 is an ordinary forward commit, without rewriting
its history. Existing browser, FEX heap, atomic, loader, graphics, control and
data-preservation changes remain in place.

## What the evidence establishes

The user reports that the PR #9 IPA does not work. The complete
`madeira-log(20261110-023849).txt` and a capture from the installed PR #9 IPA
were not available in the workspace during this recovery. The PR description
quotes an earlier failure at image head `0x27370000`, tail `0x1f034000` and
client request `0x29a8000`. That is insufficient to reconstruct allocations,
actual code-buffer usage, migration, owner quiescence and later dependencies.
It does not establish the first failure of the 448 MiB build.

PR #9's test installs those final cursors directly, then subtracts 64 MiB in
another run. A smaller generation fills sooner and can change subsequent
rotation, compilation, process scheduling and retirement. Required allocations
of at most 16 MiB are intentionally still possible beyond the large-growth
limit. Neither the retained tail nor future image capacity is therefore a
constant subtraction. The historical replay and producer test also retained a
literal 512 MiB configuration instead of testing the candidate through the same
production selection path. This is a confirmed validation gap, not proof that
448 MiB alone caused the user's new failure.

The recovery keeps the shared pool at 1152 MiB, soft image-headroom target at
240 MiB and prior fresh large-code selection at 512 MiB. It does not allocate a
larger backing object, change alias placement or alter the iOS memory limit.
The earlier baseline itself had allocation failures. Restoring its policy is
not a claim of reliable CS2 startup, a rendered menu or VAC acceptance.

## Separate confirmed allocator safety correction

`ios_pool_free_put()` coalesces adjacent image-free extents. A retired code
transfer can supply an old timestamp when it joins a newly freed image extent.
Previously the incoming timestamp replaced the neighbour's timestamp, making
the entire merged extent appear old enough for reuse. Preserve the latest
timestamp of every constituent instead. This applies to main and region-C
transfers and does not promote an ordinary active-process free into a certified
retired-code receipt. It may conservatively delay reuse; no capacity gain or
connection to the device failure is claimed.

## Required device evidence and installation

Install the recovery IPA in place with the same bundle identifier and signing
identity using the existing iPhone installer. Do not uninstall Madeira. No
prefix, game, login, manifest, save, graphics or controller migration is needed.
Rollback is another in-place installation of the previous IPA, with the same
signing identity; that previous IPA is not asserted to be free of pool failures.

For the next investigation retain the full capture from app startup through the
first failure, installed source SHA, selected budgets, every tail grant/reuse/
release and generation migration, image loads, owner census and failure ledger.
Do not infer missing ownership or live-reference proof from a FREE message.
Only a replay of the new actual order plus a subsequent iPhone run can validate
a future capacity correction. Host mapping/protection tests and synthetic
stress establish their stated invariants, not successful game execution.

After authentic client and embree loading and a usable menu are re-established,
use Begin VAC Test, Mark VAC Error and Export VAC Diagnostics in Madeira.
Steam login, network certificates, local hashes and local play do not establish
VAC acceptance. The exact rejected trust operation remains unidentified; no
security policy is changed. Graphics correctness and steady-state performance
also remain unverified for this recovery build.
