# Steam runtime follow-up: 2026-11-06 02:18:00 capture

Baseline: `ace7051d1f4e611f0796bf17b29b3288a268b959` (the installed IPA,
not an assumed branch head). Exact packaged CPU images were inspected in Actions
run `42151724111`, using the IPA from `42145983788`.

## Confirmed performance defect

The full-image native PE copies preserve PC-relative data references into the
RX pool view. Native FEX therefore faults when updating its own mutable globals,
even though the same allocation has an RW alias. The read/execute view must stay
RX; changing its protection previously destroyed executable capacity.

Exact image evidence:

| Packaged image | SHA-256 | Captured instruction RVA | Data RVA / symbol |
| --- | --- | --- | --- |
| ARM64EC `xtajit64.dll` | `cc887fcc717be62d83e835e2b982651a74b2061d0fbddd1a2b828ac89b256ef9` | `fb3b8`, `ffb1c` (LDADD) | `3ced20`, `FEXCore::IR::IRTopoChecked` |
| ARM64 `xtajit.dll` | `2347b80aeaeb9e6cbf5c19bc249da3b1904ec913e377886d6090f78abd704f82` | `eed8c`, `f3348` (STXR) | `389cd8`, same symbol |

These are real IR topology-check accounting updates. The check, counter, logging
thresholds and atomic operations remain enabled. The small historical PC table
is lossy: its entries do **not** establish what fraction of all 57,761,686 faults
these sites explain. The recorded 285,030 ms is handler elapsed time, not a
measurement of total exception round-trip cost or pure CPU time.

The correction lowers proven transient native atomic addresses to the matching
RW view while building a private image copy. It changes the ADRP address producer,
not the LSE or exclusive instructions. Instruction decoding and bounded dataflow
must prove the address cannot escape; unknown instructions/control flow reject
the transformation. Targets must be aligned, wholly inside writable,
non-executable data in the same image. ARM64EC CodeMap excludes x64 thunks.
Guest Steam/CEF code, anonymous guest SMC, image pointers passed to APIs,
exports, wait keys and published copies are not rewritten. In-place reloads
retain the existing fault path. Fresh process copies use their own alias delta;
the existing allocation ledger, leases and quiescent retirement remain unchanged.

The portable tests compile the actual planner and PE adapter. The required Apple
ARM64 gate executes original and lowered code against real RX/RW shared mappings,
using production emulation for the original faults. It measures exception count,
wall time and worker/handler CPU separately, under competing native atomics.
Zero exceptions for the covered lowered cases is required; an overall device
speedup is not inferred from that microbenchmark. Family totals accompany the
existing bounded cost report to avoid extrapolating from the lossy PC sample.

## Service: established facts and open cause

The genuine I386 SteamService remains alive before the SCM control-pipe connection
and hits three real 30-second deadlines. About 2.18 million emulated stores and
18.9 seconds of handler elapsed time have accumulated by the first deadline.
The valid SCM RPC calls establish that RPC is not universally broken. All eleven
`POOL STALE` warnings are explicitly at intermediate import bind time, before
protection restoration/data synchronization; there is no proven call-time stale
NdrClientCall2 target in this capture. No rpcrt4 pointer patch is justified.

The SCM timeout, authentic registration requirements, service-managed launch
policy and status reporting are unchanged. Real-Wine integration holds a live
I386 service before its genuine dispatcher, verifies START_PENDING, then releases
it and requires actual control-pipe RUNNING/STOP transitions. This tests Wine's
protocol, not Valve's uninstrumented startup path. The native write correction
may remove a cause of slow initialization; it does not prove the service timeout
is resolved on this iPhone.

## IPC and assertion: facts, not fabricated readiness

The missing master section is expected to be created by the authentic I386
helper, then opened by 64-bit Steam. The old ARM64EC-only diagnostic misses the
creator. The new bounded observer covers actual common native create/open
syscalls for both ABIs, records the real result and safely snapshots only the
SteamChrome object name. It creates no objects and changes no result or lifetime.

The real-Wine integration uses the authentic, pointer-free 76/72-byte bootstrap
layout derived from the pinned, SHA-verified helper. I386 creates the section,
AMD64 opens/maps/exchanges it, the open handle survives creator exit, and the
last close removes the object across repeated rounds. This is transport coverage,
not proof of actual Steam/CEF browser readiness.

Exact-build CEF diagnostic context identifies LazyInstance completion attempting
AtExit registration with a null top-level manager. The private matching PDB is not
available from attempted public symbol endpoints. The originating singleton and
why the manager is absent are unresolved. The read-only probe runs after the
assertion and does not execute guest code or mutate its state. Browser window
activity continues later, so the assertion is not proven to terminate the entire
browser. Missing master opens precede it; a shared cause is not established.

## Device acceptance still required

The IPA must be tested on iPhone18,3 without changing the prefix, credentials,
game files or configuration. Require genuine service status, a successful master
section creator/opener pair, continued Chromium frames and input, five minutes
of main-loop progress, lower measured fault rate, and a real authenticated
`cs2.exe` process. The existing 1152 MiB pool, 8 GiB FEX arena and AppID 730 data
are unchanged. Only after CS2 starts should phonon/steamaudio/scenesystem be
retested. CI alone proves neither Steam responsiveness nor CS2 playability.
