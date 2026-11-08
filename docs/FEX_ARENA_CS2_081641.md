# November 8 CS2 FEX arena exhaustion

The installed `477f8d4` capture reaches real authenticated CS2 and creates its
window. Its first fatal allocation failure is in the separate 8 GiB FEX data
arena, not the 1152 MiB executable pool. The executable pool and its 208 MiB
image-headroom policy are unchanged by this correction.

## Source and ownership evidence

The captured ARM64 instruction bytes match the packaged ARM64EC backend,
including the register-allocation call chain. `ConstrainedRAPass::Run()` grows
`PreferredReg`, a vector of one-byte physical-register entries. Its requested
capacity is 7184 bytes (`0x1c10`); vector capacity does not establish the number
of live SSA nodes. FEXAlloc calls the serialized rpmalloc allocation boundary.
The request uses an 8192-byte medium size class. An unavailable medium page in
that thread's heap requires a new 16 MiB span, aligned to 16 MiB. The arena
cannot supply it. Separate 9 MiB failures belong to frontend backing requests.
The matching backend SHA-256 is
`cc887fcc717be62d83e835e2b982651a74b2061d0fbddd1a2b828ac89b256ef9`;
all 65 distinct captured instruction words match. The native return addresses
identify the first resize in `ConstrainedRAPass::Run`, not its subsequent
SSA-to-register vector resize.

The census records the following simultaneously active owners. Reserved bytes
include unused address capacity and must not be presented as physical memory.

| Owner | Native threads | Reserved MiB | Committed MiB |
| --- | ---: | ---: | ---: |
| Official I386 browser, lease 7 | 64 | 4805.09375 | 2858.4765625 |
| Steam, lease 5 | 36 | 2135.53125 | 1184.515625 |
| Steam service, lease 4 | 4 | 257.66015625 | 163.7734375 |
| CS2, lease 23 | 15 | 913.14453125 | 514.07421875 |

The fixture preserves exact byte counts, size classes and log-line provenance.
Fifteen earlier owners were already reclaimed with zero remaining views. The
remaining four are active, so whole-process retirement cannot fix this case.
There are 383 reserve-first 16 MiB regions (flags `0x3`), 28 initially
committed 16 MiB regions (flags `0x23`), and 119 guarded CallRetStacks.
The former match rpmalloc's decommit-enabled span geometry; direct IR-pool
allocations use the latter flags, with matching named examples in the log.
Size and flags alone do not prove every individual region's caller.
The final census has 1043 views,
`0x5092000` free bytes and a largest gap of only 6 MiB.

## Allocation contract

FEX already serializes its rpmalloc calls under a recursive lock. The old
boundary nevertheless selects a separate thread-local heap for every caller.
Each heap can retain its own partially populated small, medium and large
spans. Thread finalization cannot free spans containing allocations still
referenced by other threads, and `rpmalloc_thread_collect()` does nothing.
Free capacity in one active heap cannot satisfy another active heap's request.

The downstream allocation boundary instead uses rpmalloc's explicit heap API
under the same lock. Each private backend image owns its own heap; the heap is
never installed in multiple TLS slots. Calls retain the existing alignment,
zeroing, failure, free-watch and mapping semantics. No individual thread exit
releases the process heap or its live allocations. Mapping ownership, owner
leases, process quiescence and arena bounds remain authoritative. The change
does not trim spans, change their 16 MiB geometry, move live objects, shorten
CallRetStacks or increase the selected arena.

Explicit heap acquisition also needs to return allocation failure safely when
its own metadata mapping fails. The checked build copy adds null checks before
metadata initialization and before publishing the acquired heap. The pinned
vendor checkout is restored after staging; no vendor gitlink is changed.

## Separate null-derived pointer failure

The later Steam-thread access to `0x800010` is native FEX IR reset code, rather
than the saved guest `steamclient64.dll` instruction. The actual writer first
stores a null failed buffer as Data, then derives List by adding its 8 MiB
offset. `IREmitter::ResetWorkingList()` clears the first node at List+16.
This establishes the immediate pointer provenance. The log does not identify
the owner of every preceding failed backing request.

Madeira already maintains checked IR-buffer startup handling for the WoW64
backend, but its ARM64EC package was built without that overlay. Both packaged
PE backends must be rebuilt with the common checked startup paths. The
ARM64EC-specific blocklist exclusion remains intact. The allocation failure
still aborts initialization honestly; no low page or synthetic object is mapped.

## Regression limits and device acceptance

The pressure replay uses the pinned production rpmalloc implementation with
its iOS 16 MiB span geometry, real allocation calls, separate private owner
images and the captured fixed-arena limit. Its allocation order and individual
VAD offsets are a deterministic calibration: the log does not contain the
complete original allocation history. Modeled savings are not on-device
measurements. All retained payloads, owner isolation, thread-exit survival,
cross-thread frees, zero initialization and real exhaustion must remain valid.

The old replay has exactly 1043 views, `0x1faf6e000` covered bytes,
`0x5092000` free bytes and a `0x600000` maximum gap. Both 16 MiB and 9 MiB
backing requests fail, followed by the captured aligned `(1, 7184)` request.
The new replay retains every payload and its guard/external reservations:

| Modeled owner | Old 16 MiB spans | Explicit-heap spans |
| --- | ---: | ---: |
| Browser, 64 threads | 227 | 101 |
| Steam, 36 threads | 107 | 38 |
| Service, 4 threads | 12 | 6 |
| CS2, 15 threads | 37 | 17 |
| Total | 383 | 162 |

This saves 3536 MiB in span reservations, offset by four additional 4 KiB heap
metadata views. Default CRT thread heaps are still initialized in both modes;
their metadata is not incorrectly counted as a saving. The new global free
space is `0xe208e000` (3616.5546875 MiB), with a `0xdd600000` contiguous gap.
The final small request and real 16/9 MiB reservations succeed. These are
controlled-workload results, not predictions of exact device allocation counts.
External views preserve captured aggregate sizes; their modeled assignment to
owners does not reproduce the device's per-owner reserved-byte totals above.

The ARM64EC startup regression executes the staged buffer allocation and IR
reset paths for null, MAP_FAILED and metadata failure. Neither failed buffer
publication nor List=0x800000 is permitted. Existing allocator, retirement,
executable-pool and atomic regressions remain required.

CI does not prove CS2 works on this iPhone. Device acceptance requires no
captured FEXAlloc failure or deliberate fatal trap, continued service/browser
operation, and real loading of phonon, steamaudio, scenesystem, server, client
and embree3. The 208 MiB executable headroom and code recycling still require
that complete module-chain test. A selected D3D feature level or created window
does not prove a presented game frame or a usable menu.
