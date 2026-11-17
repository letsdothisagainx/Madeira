# CS2 crossing-store investigation and recovery coverage correction

## Exact device evidence

The input is source `596f4b5d73075642ed1c7f5df811129825b97435`, export
`2026-11-17T07:29:37Z`, archive SHA-256
`a110f8fc08659b07897b5c6e4f875c099fbb91d1f153fc6e31cd382da0d69f2a`.
The native image UUID is `B5E20C35-AF46-3B01-9683-39BD1F8F192B`.

Worker `03e4`, rather than initial thread `039c`, supplies the two copy samples.
Its thread entry is recorded at Tier0 + `0x1730d0`; its actual name and job are
redacted. A material-system stack candidate does not establish job ownership.
The generated instruction at both sampled PCs is `0x3d800500`,
`STR Q0, [X8, #16]`, translated from an ordinary guest vector store. It is not
the FEX IR bulk-copy helper. The snapshot decoder correctly accounts for the
source increment preceding the store and the destination increment following it.

| Case | Actual store start | Host-page split | Generated host PC |
| --- | --- | --- | --- |
| A | `0x710d6afffa` | 6 bytes / 10 bytes | `0x7c32b9eea0` |
| B | `0x71721e7ffc` | 4 bytes / 12 bytes | `0x7c320539c8` |

These are fresh register captures from separate suspend/read/resume operations.
They do not identify the original requested copy size or invocation identity.
The same saved user PC can also be reported while the kernel handles its access.
The `xp-t` per-thread columns measure P-core/E-core time, **not user/system
time**. They cannot establish that the worker met the recovery path's kernel-time
eligibility gate. The archive does not capture enough instantaneous backing and
protection information to prove why either specific store repeated.

Remote connection to activation took 148 seconds. The actual close reason was
`Timeout; remote problem. Rx age client 10.6s relay 0.2s`. The subsequent stale
connection-ID packet occurred after removal. Neither a VAC rejection nor the
older `NETWORK_DISCONNECT_TIMEDOUT` token is inferred for this run.

## Reproducer and limits

`check-cross-page-vector-store.py` executes the actual ARM64 instruction and
observed generated copy loop, including the interrupt doorbell check. It tests
the two source/destination alignments, ordinary anonymous memory, shared-file
memory, and adjacent virtual pages backed by nonadjacent file extents. Warm,
cold, high-address, protected-neighbor and genuine fault/restart cases run in
bounded child processes. It also compares alternative stores as controls.

The native ARM64 macOS run completed all 432 cases with a 16 KiB host page.
It did **not** reproduce the iOS hang. The original vector store observed no
prefix writes in the protected-neighbor cases; the byte-store control wrote
the accessible prefix before faulting. That is an observation, not a claim of
architectural atomicity. Consequently no byte-splitting FEX emitter replacement
is shipped. No blanket native memcpy substitution or interrupt-check removal
is made.

## Established production defect

Madeira already has a narrowly gated crossing-store recovery path in
`ios_stuck_store_check`. It requires a running thread, at least 60 percent
system CPU over the interval, and repeated matching PC/effective address. The
existing helper validates the whole store before writing its page fragments;
only a completed store permits publishing PC + 4. This mechanism predates this
change. Other crossing stores were recovered in this export, but that does not
prove the two selected STR Q samples had the same cause.

The check's history held only 64 entries. It used one timestamp for an entire
task enumeration and evicted an entry during that enumeration. Once the table
filled, equal timestamps repeatedly selected slot zero. With 100 or 200 stable
threads, only 63 retained identities reached repeated observations; the later
threads never qualified. This is reproduced by executing the actual old
function with controlled Mach API adapters, not by assuming its behavior from
an unrelated allocator model.

`stuck_store_history.h` replaces this with two bounded hash tables. The previous
complete snapshot remains immutable while the next is built. Each current
native `THREAD_IDENTIFIER_INFO.thread_id` is retained, and absent identities
expire when the snapshots switch. Port names, Windows TIDs and TEBs are not
identity keys. The tables cover at most 4,096 threads and together remain below
1 MiB. Allocation, clock or enumeration failure invalidates history and declines
the check. Allocations happen before suspending any target. Counter regression
or a zero interval cannot qualify a store.
Failed suspend/context/frame reads clear the saved PC/address, requiring fresh
valid observations rather than comparing across an unobserved interval.

The system-CPU threshold, repeated-address requirement, store-completion helper,
protection checks, interrupt handling and PC publication rules are preserved.
The change repairs existing recovery coverage; it does **not** identify or fix
the underlying iOS kernel retry mechanism, and it does not prove that worker
03e4 was eligible in the recorded run.

The same decoder tests exposed signed-shift undefined behavior for negative
offsets and out-of-bounds indexing of Darwin's 29-element `__x` array for FP/LR
registers. Both effective-address decoders now use defined sign extension and
the dedicated FP/LR fields. Neither issue is asserted to explain the unsigned
X8-based STR Q samples.

## Correctness and preservation

The recovery fixture extracts the production helper, alias/protection routines
and caller's state-publication branch. It checks the observed byte splits,
noncontiguous shared-file extents, byte guards, real mapping protections,
read-only guest/writable aliases, missing NEON state, negative/indexed offsets,
FP/LR, and refusal before writes or register changes. PC advances only after
completed writes; a failed state publication leaves the target's original PC.
ASan and UBSan halt on errors. The fixture owns its mappings throughout each
call; it does not claim to prove safety against concurrent unmapping.

The native macOS results do not substitute for an iPhone run. Faster remote
loading, responsive team selection, sustained gameplay, correct graphics and
safe footprint remain device acceptance requirements. No I/O cache, UDP,
Steam, DXMT resource-budget, suspension or JIT-size change is included. The
existing 1,152 MiB pool and 768/384 MiB partition remain intact.
