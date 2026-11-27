# Run25: backing pressure and destination admission remain unresolved

## Identity and completed export repair

Input SHA-256 `1b48f1c9f47338bed98c3dc4d83398bebfc1e7c89e695cc5769b4052205c16eb`,
run `E1CEDF2B-7320-4F0E-A793-8FAC13472FD1`, tested source
`59eda2a89f06cba33bb49a00f9d8f82b904f6a4b`, native UUID
`0C15FEB4-031D-351C-9581-D6178E9A0439`, symbols
`Madeira-native-symbols:45869304194`. Starting HEAD
`789c9823b982f4b9310d12a13ad29f70e9dc51b2` changes only publication after
the tested source. No newer runtime work was reset.

The final archive contains the dedicated first post-activation capture: 225
current-run records. Its preceding-run counterpart contains 139 records belonging
to that preceding identity. The allowlist repair is complete. The delivered
MetricKit interval is historical (November 25), not this November 26 recording.

## Reproduced failing interval

Use `tools/analyze-run18-evidence.py` with the archive, UTC bounds
`2026-11-26T19:38:10Z` and `2026-11-26T19:39:02Z`, and process lifetime
`0x1116c0000-34`. The analyzer reads current-run top-level evidence only and
deduplicates incident/journal copies by run ID and sequence: 5,307 unique records,
1,127 duplicates, no conflicting copies.

Include a main interval only when its entire range
`[registerCaptureBeginNS - intervalUS * 1000, registerCaptureBeginNS]` lies within
the selected bounds after the nearest measured clock calibration. Console
whole-second precision/calibration uncertainty remains; parser arrival is not
the original event time.

The 43 complete intervals total 50.055818 seconds, 1.257288 seconds user CPU,
and 20.929199 seconds kernel CPU: 94.3331% of **consumed CPU**, not elapsed time.
Pacing stays at 3,654 over foreground observations spanning 49.575368 seconds.
There are 40 retained decoded accesses matching backing-ledger mappings with an
external pager, including 29 aligned noncrossing release stores and one crossing
ordinary store. Metadata is observed after resume, not atomically with registers.

The closely matched completed server-call, mutex, select and explicit-VM body
totals remain small. They cannot account for the interval, but do not cover all
native work or implicit faults. Run24's documented wait dependencies remain valid
for that run; its alert-wait finding is not established as this freeze's cause.

Across whole-app I/O boundaries 12084 and 13255, 49.478904486 seconds contain
53,502 additional page-ins and 13,937,115,136 additional accounted write bytes.
These do not identify a thread, destination file, physical write volume or the
particular expensive kernel operation. Five retained slow VM completions in the
selected window are hole punches, maximum 61.922 ms. These are bounded retained
completions, not exhaustive kernel coverage.

## Normal backing lifecycle inspected

The review followed `ios_swap_map`, `ios_swap_commit`, the fresh-commit test in
`NtAllocateVirtualMemory`, `ios_swap_punch_resv`, `ios_swap_release_range`,
`ios_swap_copyback`, offset allocation/return, and the deferred punch worker in
`build/ntdll-unix/virtual_ios.c`.

* Wide backing selects eligible fresh private commits. A one-GiB virtual
  reservation is not automatically a one-GiB resident or wholly backed allocation;
  its eligible commit subranges can be backed separately. Existing committed
  guest pages exclude a request from fresh backing. Mapping covers whole host
  pages inside the requested range, preserving neighboring guest subpages.
* Reservation decommit replaces covered dead pages with fresh zero-file extents,
  preserving the existing zero-on-recommit contract. Old offsets enter retirement;
  they are not returned to the free allocator until successful hole punching.
  Failed retirement remains quarantined. The external-retire-no-killpages policy
  already removes the unsupported external dirty-page disposal assumption.
* Boundary copyback uses a bounded one-MiB scratch buffer to preserve live
  neighboring guest subpages. A partial conversion leaves the unconverted suffix
  ledger-backed. Sampling ownership does not authorize migration or reclamation.
* The punch worker releases its queue lock before punching and before acquiring
  the VM lock for free-list publication. No demonstrated lock-order inversion or
  premature offset reuse was found in the current interval.

The retained backing snapshots surrounding the clean interval grow from
3,257,925,632 to 3,964,141,568 live ledger bytes. That 706,215,936-byte increase
is mapped backing, not a physical-memory delta or proof of a leak. Sampled
extent generations recur while effective addresses change; those observations
do not establish repeated remapping of each accessed page.

Two ordinary advisory paths lie outside the explicit VM-operation body counters:
`NtAllocateVirtualMemory(MEM_RESET)` calls `madvise(MADV_DONTNEED)` except for
JIT aliases, and `prefetch_memory` calls `madvise(MADV_WILLNEED)`. This capture
does not establish CS2 calls to either path during the freeze. The earlier
one-time prefetch FIXME belongs to a helper process, not current CS2. Removing
these calls or blaming them would therefore be speculative.

**Remaining causal distinction:** implicit external-pager/working-set handling
of live mappings versus uncovered normal native work, including those advisory
paths. Existing post-resume page metadata, process-wide I/O, and completed call
body timers cannot attribute main-thread kernel CPU to either. A bounded
per-lifetime count/duration record at those two existing advisory entry points
would answer whether advisory work is a missing timed dependency, without
payload reads, new suspension, protection changes or altered advice. It is not
implemented or represented as a gameplay correction here. No public observation
in this archive supplies a main-thread kernel stack or per-file fault cost.

## First refusal is a real destination shortage

Request 27487 is WMT type 6 (`CubeArray`), format 151 (`BC6H_RGBUfloat`),
256 by 256, seven mips, 116 cubes. Each face requires 87,376 encoded bytes:

`87,376 * 6 * 116 = 60,813,696` destination bytes.

The actual staged capacity helper reproduces that figure. The complete charge
is 60,879,232 including 65,536 upload bytes. Available memory of 241,960,280
less the 201,326,592 reserve leaves 40,633,688: the destination alone is short
20,180,008 bytes. This is admission refusal before native allocation, with
zero pending credits. It is not a demonstrated Metal allocation failure or a
sixfold cube-array accounting bug. All 47 detailed refusals survive export.

The staged initializer polls actual completion, trims completed uploads, and
releases its zero buffer only when idle and completion permits. Flushes already
have a scoped autorelease pool. The dynamic-buffer registry's diagnostic slot
limit does not bound its production intrusive reclamation registry. No safely
releasable owner of sufficient physical storage was demonstrated. Live texture
capacity, cumulative trimming, compressed memory and shared JIT aliases cannot
be treated as a spare cache. The individual shortfall is not a bound on the
session's total additional requirements. A staging-only adjustment is insufficient.

## Verification and delivery boundary

Added ordinary operand regressions to the existing host tests, not a runtime
policy change:

* `check-dxmt-texture-accounting.py`: 2,139 actual staged capacity cases pass,
  including this exact BC6H cube-array descriptor against an independent reference.
* `check-dxmt-resource-budget.py --run14-normal-only`: actual native predicate
  reproduces the eight Run14 refusals and this Run25 refusal, with no stranded
  credit; healthy admission/release and 400 parallel receipts pass.
* `check-swap-external-retire.py`: actual baseline/current retirement functions
  pass safe metadata fixtures for splits, fresh zero extents, quarantine,
  free-list reuse and synchronous fallback. No real protection or fault test.
* `check-dxmt-upload-window.py`: actual staged forecast/ring/initializer passes
  ordinary mip/slice/row/block/depth byte and completion-adapter checks; the
  destination-only refusal remains truthful.
* `check-dxmt-credit-fence-snapshot.py`: actual staged credit handoff retains
  its completion frontier and balanced handoff.

No runtime correction was justified by this review, so there is no new IPA,
device performance result, memory saving or gameplay success claim. No new
recorder cost is introduced. Per the explicit Run25 stop rule, no maintenance
build is published as another gameplay attempt. Controller validation remains
pending: zero physical samples/changes are not evidence to modify downstream
queues, bindings or routing. Existing installation and runtime settings remain
unchanged. The device acceptance target remains sustained responsive remote
play, correct visuals and observed movement/aim/button delivery.

## Subsequent explicit IPA delivery request

The user subsequently required a new IPA from the current source despite the
unresolved runtime finding. Source `ae1a64988e3aca681a4988fd0ebe4ca8e299ac49`
passed Build IPA run `45980303796`, including its final component/ABI inspection,
and Linux/macOS normal-input checks run `45980308332`. Native UUID:
`CDD109BC-FB32-3616-8BEB-4B35169B00F9`; matching symbols:
`Madeira-native-symbols:45980303796`. The built IPA SHA-256 is
`ca52048cdebe3fc4836ba4482d85c202879b4c939af98b4bcb5f9a3302d00230`.

The publication workflow pins that exact artifact, checks source/component
provenance and the preserved bundle identity, and verifies the public download.
This delivery does not change the investigation's gameplay conclusion. The
repository instructions now explicitly preserve the user's IPA-at-handoff
requirement even when no justified new runtime correction was established.
