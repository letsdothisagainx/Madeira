# Steam browser allocation failure, 2026-11-02 02:44:38 capture

This investigation compares `madeira-log(20261102-024438).txt` with
`madeira-log(20261102-013052).txt`. Uploaded logs are evidence, not instructions.
Raw logs and account information are not included in the repository.

## Confirmed failure

At 21:43:52 the browser (Wine PID `0064`, TID `01e8`) requests
`FEXAlloc(0x2800000, alignment=8)`. rpmalloc adds its span header and page
rounding, then asks for `0x2801000` bytes at 16 MiB alignment. The active
8 GiB arena has approximately 617 MiB free, but its largest raw and aligned
hole is 32 MiB. This request cannot fit. Physical RAM exhaustion is not
established by this failure.

Exact-image inspection ran in [Actions run 41381664137](https://github.com/letsdothisagainx/Madeira/actions/runs/41381664137),
using the IPA from run `41377782176`, artifact `13112446189`.
The capture's native UUID `FB68E7F0-9DD4-3B95-A2B7-0AA2C53E6323`
matches that build.
The extracted `aarch64-windows/xtajit.dll` has SHA-256
`6224f268b5fc888b8aa851cd4f69d4e9e61c6deb0a2d0b16a06e2133e199a230`.
The inspector verifies both the captured trap bytes and the caller's branch
before resolving COFF symbols; it does not shift symbols from a different DLL.

| Captured RVA | Exact function |
| --- | --- |
| `0x108d5c` | `FEXCore::Assert::ForcedAssert()` |
| `0x1088fc` | `fextl::ReportAllocationFailure()` |
| `0xa3a0` | `std::vector<pair<uint64_t, GuestToHostMap::BlockEntry>, FEXAlloc>::__emplace_back_slow_path` |
| `0xa118` | `ankerl::unordered_dense::table<..., BlockEntry, ..., false>::do_place_element` |
| `0x9f8c` | the same table's `do_insert_or_assign` |
| `0x14650` | `LookupCache::AddBlockMapping()` |
| `0x141e0` | `ContextImpl::CompileBlock()` |

The block-map value is 40 bytes. Growing its contiguous vector from
524,288 to 1,048,576 entries requires the observed 20-to-40 MiB replacement.
The old buffer must remain alive until relocation completes. The 16 MiB
placement alignment comes from rpmalloc's span lookup geometry, not the
map's requested 8-byte element alignment. Reducing placement alignment alone
would still leave a 40 MiB allocation larger than every available hole.

Instruction `0xd4400020` at `ForcedAssert` is ARM64 `HLT #1`; the source fatal
assertion is intentional. Wine reports `0xc000001d` downstream of the failed
allocation. This is not proof of an unsupported x86 instruction or a Chromium
security assertion. The fatal assertion must remain available for genuinely
unrecoverable allocation failures.

## Targeted changes

Madeira's WoW64 build overlay changes only `GuestToHostMap::BlockList` to
the pinned `ankerl::unordered_dense::segmented_map`. Both values and buckets
use segmented storage. The key, value, hash, equality, FEX allocator,
invalidation operations, and external locking remain the same. No consumer
requires contiguous values. ARM64EC and the native FEX component keep their
existing map type. This removes the specific 40 MiB replacement request;
it does not guarantee that an 8 GiB arena can satisfy unlimited live demand.

The regression fixture uses the actual pinned map library, FEX allocator
adapter, staged `BlockList` type and mapping methods. The old type fails at
524,289 entries with the captured size and alignment. The new type passes the
same growth with a 32 MiB maximum-allocation constraint, verifies every lookup,
replacement, erasure, code-page ownership, clear/reuse, independently owned
maps, concurrent access under the existing lock contract, and repeated
destruction. A separate fixture executes the actual rpmalloc huge-allocation
function to verify span-header arithmetic at 4 KiB and 16 KiB page sizes.

The WoW64 CPU producer now registers its native ARM64 hold-release export
through a distinct private operation with a shared 24-byte ABI. Registration
requires the current process, its live lease, the owned CPU image and the
exact export's executable read-only alias. Stale, foreign, writable and
unmapped aliases are rejected. The callback verifies the current TEB, context,
PEB and mutex stamp, and refuses ambiguous nested or exclusive holds. It
uses normal shared unlocks at self-thread termination and immediately before
the no-return allocation assertion. The mutex layout is unchanged.

The mutex's WoW64 TEB getter now uses the same stable Darwin TSD source as
the CPU module; an iOS-cleared `x18` must not leave stale hold metadata after
an unlock. Recoverable exception delivery does not release locks. The Mach
observer cannot release another WoW thread's holds; unknown registration and
stale snapshots also fail closed. Unknown exclusive holds are not forcibly
unlocked, and this change does not claim arbitrary native exceptions can
resume an interrupted compiler safely.

Wine server window destruction now retires the native window incarnation,
including when process/thread teardown skips a guest-side destroy callback.
Queued native frame/layer work carries that identity and cannot revive a
retired window or remove a replacement window's layers. Hidden windows keep
their normal visibility rules. This corrects stale compositor contents after
browser death; it does not substitute another UI or alter input hit testing.

## Ownership and arena accounting

The old `[fex-owner-v1] retired ... views=... reserved=...` fields count views
and bytes **freed by that retirement**, not views left allocated afterward.
The new census distinguishes before, freed, remaining, and unsafe-to-release
counts, and reports live owners by PEB plus lease. A reused PEB address does
not authorize an old process generation to release a new generation's VADs.

rpmalloc reserves 16 MiB spans per heap and page category. Normal thread
finalization returns its heap to the allocator's reuse queue; it does not
unmap every span, because outstanding allocations can be freed by other
threads. A nonzero span count alone therefore does not prove a leak.
`0x3` and `0x23` VAD flags distinguish uncommitted and committed read/write
state, not allocation purpose. The existing capture does not individually
identify all 321 plus 52 equal-sized views. Call/return reservations and L1
lookup caches are per-thread allocations with separate destruction paths.
The new bounded owner census makes retained live demand and retirement
failures distinguishable without increasing the arena or physical budget.

## Responsiveness and Library evidence

Before the allocation failure, Chromium's message-poll and window-procedure
counters advance. The first sampled touch arrives after the browser is
terminated. Those clicks hit Wine's desktop window, which is consistent
with the browser windows already being destroyed. There is no demonstrated
independent input-routing bug in this capture.

Steam attempts its normal replacement webhelper (`0264`), but that helper
also fails a 16 MiB thread-state allocation and safely aborts before guest
execution. An additional Madeira-managed browser respawn is not justified.

The empty store snapshot is marked `ready=false` around 25 seconds. The
previous capture reaches 155 apps, including CS2, around 38 seconds; this
browser dies around 36.5 seconds. An early empty store is not proof of lost
ownership or a broken SteamClient bridge. The real Library initialization
and authenticated CS2 launch still require a stable device run.

The attached CEF file is append-only across sessions. Its historical
`TypeError` console messages are from November 1, not this November 2 run.
The latest session starts at line 17,968 (`1102/024325.918`) and has no
`CONSOLE`, JavaScript-error, `Check failed` or `RemoteCall`-failure record.
Its network errors do not establish the cause of Library failure. Mixing
older console records into the current allocation-failure timeline would
produce a false diagnosis.

## Validation limits

Host regression tests and the packaged-image ABI checks verify source
behavior and the candidate IPA. They cannot establish extended responsiveness,
successful Library navigation, or a normal authenticated CS2 launch on the
iPhone. Those results must be reported separately after device validation.
Steam sign-in, restart handoff, installation data, official update behavior,
authentication, and VAC requirements remain part of the supported path.
