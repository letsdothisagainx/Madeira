# Run16: CS2-only non-LRCPC2 candidate

Input ZIP SHA256: `809285669876a949e67832d67bd9316246d5781d279a027a139946743f44e776`.
Tested source: `58b0001e4a03f3ef9e2402188659c6a6eadc73e3`.
Native UUID: `8EA1D7F2-C3BC-3B4F-925E-6CFA074C0A03`.
Metadata export UTC: `2026-11-23T01:40:15Z`.

The recovery correction remains justified: all 485 captured main-progress samples
have suspend-count-before=0. Maximum recorded recovery holds are 214 us for the
main thread and 1,159 us across watched threads. Successful QoS scope changes
17 -> 33 -> restoration are observed. These samples do not establish an
exhaustive latency bound.

Remote Mirage connection at 20:35:25 activates at 20:36:50, followed by an actual
NETWORK_DISCONNECT_TIMEDOUT at 20:37:45. A completed 64-frame window spans 85,545
ms with 133 ms of GPU execution; its maximum Present gap is 45,867.3 ms and maximum
inside-Present duration is 45.3 ms. The recorded post-activation main-thread CPU
is predominantly kernel time (31.500619 s kernel, 0.901436 s user over roughly
55.6 s). Sampled aligned, single-page STLUR accesses change addresses over time;
this is not evidence for extending crossing-store recovery or skipping stores.
No E_OUTOFMEMORY/E_INVALIDARG is logged in the captured console. No texture-memory
repair is inferred from that absence.

## Focused change

`build/fex-compat/cs2-tso-profile.patch` is applied by the existing downstream
stager only to ARM64EC Module.cpp. The FEX submodule stays pinned and untouched.
`ProcessInit` already obtains the executable basename, loads configuration and
reloads its meta layer. The new function runs after that initialization and
before `CPUFeatures::FetchHostFeatures`, `CreateNewContext` and any JIT creation.

For exactly `cs2.exe` (case insensitive), it merges DISABLELRCPC2 into the current
HOSTFEATURES value and removes only the conflicting ENABLELRCPC2 bit. Other
feature bits are preserved. TSO and half-barrier options are not changed. Steam,
Steamwebhelper, WoW64 and other executables retain their existing selection.
No host-wide environment mutation or child-inherited environment override occurs.
The code directly uses the initialized FEX configuration API, not AppConfig JSON:
the current Windows GetFileAttributesA intentionally makes those files absent.

The existing Windows iOS selector honors DISABLELRCPC2 and therefore selects
SupportsTSOImm9=false. The existing frontend folds addresses appropriately and
the existing GPR StoreMemTSO backend selects STLR instead of STLUR. No backend
instruction algorithm, guest code, atomic operation, recovery eligibility or
memory protection is rewritten.

Each process starts a fresh context and lookup cache after the override. CS2's
experimental persistent-code-cache option is explicitly disabled before context
creation, preventing old feature-dependent translations from being imported or
reused by that path. The current Windows loader's compiled-section activation
is still TODO; the explicit gate also avoids depending on that incompleteness.
No cache, game, prefix or account file is deleted. Existing safe reuse of code
buffer storage remains enabled; unused bytes in a reused carve are not lookup
entries in a new context.

A single startup record reports the actual selected feature and unchanged TSO
options before context creation:
`[cs2-tso-profile-v1] exe=cs2.exe LRCPC2=false tso=true halfbar=true ...`.
This is not a new sampling system.

## Ordinary validation and its boundary

`check-cs2-tso-profile.py` executes the actual staged profile function and pinned
CPUFeatures selector in a host fixture with adapted configuration/IR/logging
services. It tests CS2, uppercase CS2, Steam, Steamwebhelper and near-match names;
merging preserves unrelated overrides, clears conflicting enable, retains TSO
and halfbar, leaves the parent environment unchanged and gates only CS2's code
cache. The actual StoreMemTSO scalar body and actual pinned CodeEmitter headers
then generate fresh ARM64 instruction bytes into ordinary writable storage.
The bytes are inspected, not executed; no protected/executable mappings or
fault experiments are introduced.

For captured register combinations the baseline generates `99000356` and
`d90000d3`; the candidate generates `889fff56` and `c89ffcd3` (STLR). The existing
NOP slots and all four scalar widths are checked. Other guests retain their
baseline STLUR emission when their existing settings enable LRCPC2. Runtime
selection records printed by this fixture are host validation, not observations
from a new CS2 iPhone session.

The overlay is part of the existing FEX PE cache key. Cache regression checks
verify that the patch invalidates FEX PE and IPA outputs, leaving native FEX,
LLVM, DXMT and unrelated dependencies reusable. Packaging verification requires
the new marker/policy in the actual ARM64EC xtajit64.dll and records its SHA256,
as well as normal native provenance, bundle identity and recovery linkage.

The recovery/QoS correction, allocation reserve, memory policy, graphics,
networking timeouts, complete 1,152-MiB JIT pool and 768/384 partition are unchanged.

This is an instruction-path hypothesis, not a demonstrated kernel diagnosis;
the export contains no kernel stacks. The on-device feature record and generated
code in the actual game still require the new iPhone session. Acceptance remains
a same-Mirage remote sequence with activation timing, post-activation user/kernel
CPU, Present gaps, texture errors, responsive team selection and a sustained
playable round without disconnecting. If kernel-heavy stalls remain with the
confirmed STLR fallback, investigate backing/mapping next, not recovery polling.
