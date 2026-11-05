# FEX arena fragmentation: November 5 device capture

The failing IPA identifies source `4d482915`. Its CallRetStack failure is real:
the shared 8 GB arena has 899 live views, `0x232ff000` free bytes, and an 8 MB
largest gap. A guarded `0x802000` reservation cannot fit. Physical footprint is
not the reservation failure's cause.

## Source defect and correction

The pinned rpmalloc implementation reserves exact 16 MB spans aligned to 16 MB.
These are the census's 325 reservations with protection flags `0x3`, distinct
from the fully committed `0x23` dispatcher mappings. The original Wine reserved
area search placed every FEX allocation from the low end. Mixing aligned spans
with ordinary 64 KB-aligned Frontend, cache and guarded stack allocations
strands alignment tails. An 8 MB Frontend followed by an aligned span can leave
exactly the observed 8 MB hole, insufficient for the stack and its guard pages.

Only an authorized `FEX_ONLY` area's requests aligned above 64 KB now search
from its high end. Ordinary requests continue from the low end. Both use the
same free-range tree, full arena and owner/lease tagging. There is no fixed
partition, larger reservation, smaller stack, removed guard or fake allocation.
Explicit top-down requests, ordinary reserved areas, fixed placements and caller
bounds keep their existing handling. The startup line identifies the compiled
policy as `placement=alignment-ends-v1`.

## Lifetime evidence

The census contains three active owners, totaling 114 native threads and 113
CallRetStack reservations; the failing initializer accounts for the missing
stack. Webhelper's 61 threads hold 183 rpmalloc spans; the four-thread helper
holds 12. Steam holds 130 spans across 49 native threads. This is not evidence
that exited threads stranded those reservations. The capture does not reveal
which individual allocations inside each span are live or reusable.

Unmodified pinned rpmalloc is tested separately: a shared allocation survives
its originating thread, 100 successors adopt the same queued heap without new
mappings, and a remote free remains valid. Final unmapping is tested only after
all workers, heap owners and payloads quiesce. This host test uses native POSIX
256 MB span geometry; it does not pretend to execute Windows TLS or iOS spans.
No blanket span release or production retirement change is introduced.

## Renderer and main-loop evidence

The exact official libcef image is checked against its pinned digest, PE
metadata and PDB identifier `4D133C5B4FBE41474C4C44205044422E`, age 1, in
[the read-only inspection run](https://github.com/letsdothisagainx/Madeira/actions/runs/41976031070).
RVA `0x2ffac0e` is `REP MOVSB` in an overlap-aware copy routine. The captured
host PC is FEX's bulk-copy loop. That sampled operation is copying memory;
it is not an allocation syscall or evidence of an allocation retry loop.
The matching FEX loop checks zero and decrements its count; its inspected
control flow contains no allocation retry. Separate captured libcef return
sites immediately follow calls through the exact image's `VirtualAlloc` IAT.

Exact GUID/age PDB and `file.ptr` requests returned 404 from the tested candidate
CEF/Chromium symbol paths in
[the symbol lookup run](https://github.com/letsdothisagainx/Madeira/actions/runs/41976509870).
No matching PDB was obtained. Candidate URL failures do not establish absence
from an authoritative symbol service; upstream CEF also publishes symbol
archives, and Valve uses a custom build. The operation above is established by
verified instruction bytes, not an invented internal Chromium function name.

The sampler labels raw host x23 as `rsp`, but this emitted copy block uses x23
as its original source operand. Its printed `0x7c004000` is not validated guest
ESP. Destination x22 and count x7 were not logged, so the copy lacks a validated
length and caller stack. Separate `alloc-sustained` captures describe allocation collisions
and must not be treated as the same execution point. No Chromium throttling,
instruction skipping or copy-loop change is justified by this capture.

Steam's thread initialization fails before its engine warning, but timing alone
does not prove that the failed thread is the engine's blocked dependency. The
allocator defect is corrected independently; engine progress and copy-loop
behavior still require on-device validation.

## Regression and acceptance

`check-fex-arena-placement.py` executes production reserved-area search, free
ranges, Wine's RB tree, VAD construction/deletion and owner reaping against
controlled native mapping edges. A synthetic allocation order reconstructs the
exact live size census and totals: 899 views covering `0x1dcd01000` bytes, with
`0x232ff000` raw free bytes. Wine's granularity-adjusted free-range total is
smaller because it excludes partial allocation granules. The
legacy search leaves an 8 MB maximum gap and fails the next `0x802000` request;
the corrected search leaves 537 MB contiguous and succeeds. It also tests failed
mapping/initialization reuse, guarded reservation release, stale leases, live
owner rejection, quiescent reclamation, sibling preservation and recovery of
the entire unchanged 8 GB range. Existing native callback/thread lifecycle tests
remain in the gate.

CI does not establish device acceptance. Require at least five minutes with no
CallRetStack failure, no unintended sustained hot renderer loop, responsive
Steam and Library, and an authentic result from the existing CS2 launch request.
Service startup, browser-cache preparation, bridge installation, graphics,
authentication and installed game data are not modified.
