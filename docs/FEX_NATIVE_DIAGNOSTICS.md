# Native FEX diagnostic writes

The November 9 follow-up capture from source `4b41f1dd7603612e1596ac885d0b883fa601cf26`
reaches the real CS2 menu. It still completes 57,051,750 emulated stores with
249,963 ms of cumulative handler time. These totals are not directly comparable
with a different-duration startup capture.

All 57 completed million-event fault epochs have exact family counts and zero
overflow. The family census is complete; the top-two-per-family site reports
are lower bounds for individual sites, rather than a complete attribution.

The installed IPA was inspected through Actions run `42554570119`, using the
artifact from build run `42548204854`. The matching native CPUs are:

- WoW64 `xtajit.dll`, SHA-256
  `0d94c4b1c193bf18e4ad1e466914e91e47f8d5fac247a4830bdf04b9ec5e8bc5`.
- ARM64EC `xtajit64.dll`, SHA-256
  `c75580ac74425c9a9dfe781a9e6c6c62f0d4059f01d40454926847d3a41aa46c`.

COFF symbols and native instruction bytes establish these producers:

| Observed operation | Verified source object | Reported-site lower bound |
| --- | --- | ---: |
| Generated `STSETL X0,[X1]`, opcode `f860303f`, to WoW64 DATA RVAs `386d48` and `386d60` | `TelemetryValues` at `386ce8`, indices 12 and 15: 32-bit segment-use telemetry | 8,713,652 |
| WoW64 `STXR W9,X8,[X14]` at RVA `f335c`, target `38ad18` | `IRTopoChecked.fetch_add`, a diagnostic count, not the allocator lock | 4,583,919 in PID `0090` |
| ARM64EC `LDADDAL X10,X8,[X8]` at RVA `14610`, target `3bd298` | `g_cb_total`, CompileBlock diagnostic dispatch count | 1,500,644 in PID `0334` |
| ARM64EC GPR stores at `14830` and `14840` | Per-thread call-return history | Unchanged by this correction |

The previous native SRW history binding is active. Its former hot PCs
`6a4f4`, `6a514`, and `6a520` do not recur in the new site reports. Other ntdll
critical-section instructions targeting FEX data are separate operations.

## Correction

`native-diagnostics.patch` is an owned downstream overlay. It is applied only
during the two Windows CPU builds and restored afterward. The vendor checkout
is not edited by the implementation.

Three explicit private contracts name only the telemetry array, four IR
diagnostic counters, and CompileBlock counters/estimator state. Each 32-byte
descriptor contains a versioned tag, exact payload size/alignment, canonical
payload pointer, and initially NULL writer. The native loader checks the full
source-built PE, native/hybrid identity, export name, disjoint private RW DATA
spans, payload bounds, and absence of writer relocations. Only an unpublished
owned copy is bound to its existing RW alias. No mapping or pool size changes.

The getters select this physical alias before a producer writes or installs a
generated-code telemetry pointer. The genuine atomic instructions, telemetry
bits, IR checks, and exact dispatch/compile counts remain enabled. Unknown
contracts retain canonical addressing and existing exception recovery.

After binding, source synchronization preserves the complete validated private
descriptor, preventing a partial metadata refresh from resetting a writer or
adopting a parent's pointer. Diagnostic payload bytes retain ordinary source
synchronization. The pure contract helper does not replace the surrounding
mapping owner/lease/generation ledger or establish VM lifetime by itself.

The old CompileBlock estimator also has a proven independent race: two threads
can both observe a balance of one, decrement it twice, and print
`18446744073709551615`. Its summary marker can regress and issue duplicate
reports. The corrected estimator uses a nonblocking sampling attempt; a
contending observer skips only that approximate sample and increments an
explicit skip count. Exact counters still increment. Unique atomic dispatch
tickets select each 16K report. The log calls the result a candidate balance,
which is what the Boyer-Moore estimate represents.

## Validation boundaries

Production-source tests reproduce both old estimator races before checking
the corrected staged block, concurrent exact counts, nonblocking behavior,
private alias selection, metadata synchronization, and malformed/foreign
contract rejection. Final-package tests require initialized descriptors in
both actual CPU binaries; legitimate zero-fill payload DATA remains allowed.

The Apple ARM64 benchmark executes real protected-alias faults and production
recovery. It distinguishes actual staged getter/IR producer execution from
execution of the exact captured generated `STSETL` instruction. Fixture CPU
costs and zero-fault alias writes are not an iPhone FPS or startup-time claim.

Apple ARM64 validation run `42557493889`, job `128966369056`, passed the new
contracts, package negatives, estimator races/concurrency, historical atomic
recoveries, and actual Mach tests. For eight threads and 3,200 operations:

| Producer fixture | Original Mach faults | Bound Mach faults | Original / bound handler CPU |
| --- | ---: | ---: | ---: |
| Captured `STSETL` with production-selected telemetry addresses | 3,200 | 0 | 24.385 / 0 ms |
| Actual staged `IRTopoNoteChecked` | 22,500, including genuine exclusive retries | 0 | 227.720 / 0 ms |

Both phases preserve exact flags/counts and neighboring bytes; RX stays
nonwritable and RW stays nonexecutable. Wall time includes thread startup and
the fixture, so it is not a pure instruction-throughput comparison. The
separate unsanitized sampler test performs 524,288 native RW dispatches in
3.929 ms with one thread and 24.243 ms with eight threads. Its contending
estimator skips samples instead of waiting; authoritative counts remain exact.

The production two-CPU PE build also passed in Actions run
[42561473875](https://github.com/letsdothisagainx/Madeira/actions/runs/42561473875).
Both actual DLLs linked and passed the full package parser: all three contracts
occupy private RW DATA, payloads are exactly 136/32/48 bytes, and each writer
starts NULL without a relocation. The overlay was restored afterward. This
proves the compiled producer contract, not its eventual iPhone execution.

On-device validation must show both FEX modules binding their contracts, lower
rates for these exact producers under a comparable workload, preserved Steam
IPC/service/game launch, and continued CS2 menu/frame progress. Per-thread
history stores, real allocator synchronization, memory pressure, and Valve's
secure-session result remain separate concerns.

## Four-slot call-return history follow-up

The capture from source `8bd3785c7f4a422ffdb20033510db46ea0fdcd52` ends with
37,209,939 timed store faults and 178,906 ms of cumulative handler time. Its
independent family census classifies 37,209,941 events: 23,411,472 GPR,
12,257,104 exclusive, 1,515,781 LSE, 6,400 release, 19,179 pair, and 5 swap.
The timing sample explicitly reports two dropped events. These cumulative
costs do not establish the application's elapsed time or frame-rate cost.

The 37 complete million-event epochs contain 1,724,144 overflow events across
epochs 1, 5, 8, 11, and 12. Every family total remains exact. Only two tracked
keys per family are printed, so individual site sums are lower bounds even
when an epoch has no overflow. A key contains the target page; the target byte
address and its RVA are first-event metadata.

[Inspection run 42692961205](https://github.com/letsdothisagainx/Madeira/actions/runs/42692961205)
reads the actual IPA from build run `42591313733`, checks its embedded source,
and proves all captured hot instructions against the packaged CPU bytes.
The native SHA-256 values are
`598846e092516fce6bfc089326db30efccc1b92b199c31e5b4987ecfc9ba86d6`
for ARM64EC and
`89813f94c8e697a3e725d6a451535fcd8dee75f055436747f586785a9fd264ad`
for WoW64.

In PID `034c`, ARM64EC image `0x3dd270000`, generation 477, maps through PEB
`0x10a1e8000`; its owner-lease record is 31. The reported generation cookies
remain unchanged for the following sites. COFF symbols and instruction bytes
identify their first targets as element 1 of the existing diagnostic arrays:

| Native PC RVA / instruction | First target RVA / object | Reported-site lower bound |
| --- | --- | ---: |
| `147fc` / `STR X25,[X11,#0xb8]` | `3bd348` / `g_madeira_thr_key[1]` | 3,117,351 |
| `14808` / `STR X20,[X11,#0xf8]` | `3bd388` / `g_madeira_thr_last_rip[1]` | 2,465,577 |
| `14814` / `STR X12,[X11,#0x118]` | `3bd3a8` / `g_madeira_thr_count[1]` | 1,353,427 |

These are native 64-bit diagnostic DATA stores on every block dispatch, not
guest self-modifying code. The native-data planner rejects their dynamic
array-address calculation. A fourth explicit private contract now contains
only the six four-entry call-return-history arrays, exactly 192 bytes. The
producer and summary reader select its retained RW alias once per block;
the original volatile accesses, operation order, hash, collision behavior,
zero-SP handling, and minimum initialization are preserved. The descriptor
is bound before publication and survives the existing DATA-refresh path.
No allocator, mapping owner, process lease, protection, or pool changes.

The hot ntdll exclusive target at ARM64EC DATA RVA `3ccf88` is instead
`InvalidationTracker+0x30`, genuine synchronization, and is excluded. WoW64
RVA `102e20` targets `IosWowSyscallC::Declined`, a different diagnostic atomic
path, and is also outside this history correction. Peak footprint of 6049 MB
remains an independent issue. Apple Mach validation and a comparable device
capture are required before claiming a measured runtime improvement.
