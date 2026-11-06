# Steam runtime correction — 2026-11-06 03:45:46 capture

Installed baseline: `6059b3507943f4505a63be9be020224e87e34d71`.
The previous atomic-only lowering was active but did not remove the session's
57,757,980 emulated writes. The exact family census is the evidence: 32,660,066
GPR, 14,891,593 exclusive, 8,880,358 release, 833,244 SIMD/pair, 492,714 LSE,
and seven swaps. The old 24-PC table does not cover those totals.

## Confirmed native allocator defect

The installed CPU images, not an assumed source build, identify the sampled
native allocator guard:

| CPU | Exact packaged SHA-256 | Guard functions | Mutable globals |
| --- | --- | --- | --- |
| ARM64EC | `cc887fcc717be62d83e835e2b982651a74b2061d0fbddd1a2b828ac89b256ef9` | `fex_ios_rpm_lock` RVA154110; unlock154194 | enabled3cca80, depth3cca90, owner3ccac0 |
| WoW64 ARM64 | `67cd454381328356abb91e669e8db2a115e74c2f16a4d408b57ea944dc585d98` | lock1400a8; unlock140128 | enabled387a40, depth387a50, owner387a80 |

The actual WoW64 image was inspected from installed-build IPA42154793768 in
read-only Actions42160149050. The repository's prebuilt WoW64 image and older
IPA images have different hashes and are not substitutes for that evidence.
Service native samples resolve to the guard's STXR/depth STR/STLR; the caller
RVA13f134 is FEX allocator `aligned_free`. The service continues genuine loader,
TLS and compilation work before SCM's control-pipe deadline. Rounded profiler
buckets and exact fault PCs are distinguished: the former do not establish a
particular instruction or a percentage of all faults.

A normal guard writes an enabled byte, recursive depth, exclusive owner and
release owner. Its native addresses still pointed into the executable RX copy.
Each store took a Mach round trip; contenders could spin while its owner was
suspended. Removing the allocator lock, changing its owner identity or allowing
RX writes would be incorrect.

The new native-data planner proves address-only use of an ADRP across the
complete control-flow graph. It handles the actual STRB post-index update,
ordinary depth loads/stores, LDAR/STLR and stable LDAXR/STXR retry loops.
Every candidate-address access must fit writable non-executable data in the
same owned image. Pointer escapes, comparisons of the pointer, unknown forms,
conflicting-address joins, unsafe calls and unbounded proofs reject lowering.
It changes only the ADRP in an unpublished private FEX CPU image. Atomics,
exclusive monitors, CLREX/YIELD, branch conditions, writeback, code metadata,
exports and arbitrary guest memory operations remain unchanged. Existing
publication generations and quiescent retirement still own the allocation.

All five write-bearing guard producers qualify. The old atomic-only planner
rejects all five. The production PE adapter lowers 227 proven producers in the
exact ARM64EC image, preserves all non-ADRP bytes and remains idempotent.
No FEX source code, memory budget, pool permission or guard allocation changes.

## Measured regression, not an iPhone success claim

The Apple ARM64 test uses the actual captured guard instruction bodies, with
only fixture relocation and the Windows TEB thread-ID reads adapted to a test
argument. The baseline compiles the actual production Mach store emulation;
the corrected path applies the production planner. Five competing workers
include an independent RW-alias contender and recursive acquisition.

Validation run42160887478 measured 2,000 critical sections and 500 recursive
entries on 16 KiB host pages, with RX/RW separated by the real 1152 MiB delta:

| Measurement | Original RX operand path | Lowered RW operand path |
| --- | ---: | ---: |
| Mach store faults | 11,366 | 0 |
| GPR / exclusive / release faults | 6,000 / 3,766 / 1,600 | 0 / 0 / 0 |
| Wall time | 611.047 ms | 12.405 ms |
| Worker CPU total | 1,376.604 ms | 0.143 ms |
| Handler CPU | 64.772 ms | 0 ms |

Mutual exclusion, recursive depth, publication ordering, neighboring bytes,
code integrity and RX-nonwritable/RW-nonexecutable protections pass. These are
measurements for the captured operation, not a projection of total Steam FPS or
proof that every fault in the device census came from this guard.

The new bounded site census replaces the lossy classifier, including its
per-store Mach read of an unvalidated x28 pointer. Each million-event epoch
uses a fixed non-evicting hash table with exact tracked/overflow totals and
at most two records per instruction family. First-event PID/TID/PEB and live
image-publication generations are captured only when inserting a new key.
Hits perform no Mach query or allocation. Unknown/recycled attribution is
explicit; overflow is never represented as an estimated PC count.

## Genuine service and browser controls

The service control downloads and verifies the production-pinned official
packages, runs Valve's unmodified `/install`, then the real Madeira preparation
helper and Wine SCM. It requires SERVICE_RUNNING plus a running process whose
image hashes to the genuine source. No fixture registers the service or supplies
status. Initial validation passed in 231 ms and repeated start/reuse passed.
The pinned service is a different build from the device's October21 service;
the script reports that mismatch rather than claiming exact-build equivalence.
Thus stock-Wine protocol compatibility is established for the pinned control;
the actual iOS service deadline still needs device evidence after this correction.
The existing 30-second deadline and truthful status policy are unchanged.

The browser control uses verified official I386 helper/CEF/SDL files and a
read-only AMD64 witness. Only the genuine helper may create the master section;
the witness never manufactures it or announces browser readiness. A transport
fixture passing does not substitute for this control or the real Steam client. The genuine-helper control passed: the AMD64 witness
opened the helper-created master section in 680 ms and verified its real
8 KiB ring header while the helper remained alive. This proves authentic
bootstrap mapping creation, not completed CEF rendering, login or Library.

The old section observer missed native early returns (including malformed
security-descriptor revision and invalid protection). Its new wrapper observes
all returned statuses while retaining the byte-identical native implementation.
The regression executes actual native guards, serialization and WoW64 pointer
conversion in a nonidentity guest window. The old stage fails the early-SD
observation regression; the corrected stage passes. This closes a diagnostic
blind spot; it does not prove the device has that security error.

## Immutable cache versus executable logging

The exact pinned helper executable has its own statically linked logger:
GetModuleFileNameW atRVA47a9e, a `debug.log` suffix, and CreateFileW atRVA47be9.
Its LOG_TO_FILE global is initialized independently of libcef's CLI logger.
Therefore the existing explicit CEF log switch did not prevent cache mutation.

The scoped native file hook recognizes only that exact default path of the
host-selected verified cached helper. Normal Wine resolution/disposition/IOSB
behavior creates the log in a separate app-owned mutable directory. Unowned,
linked or unavailable destinations produce a real I/O error. Log preparation
is optional and cannot introduce a new pre-Wine launch gate. The immutable
binary tree and strict cache verification are unchanged. Tests reproduce the
old unexpected-file failure, route real log writes, revalidate the same cache,
and still reject a changed DLL.

## Remaining device acceptance

Require genuine service status, successful actual helper section creation and
Steam open, continued browser frames/input, a five-minute responsive main loop,
a substantially lower comparable fault rate, and authenticated `cs2.exe`
creation. The AtExit/LazyInstance assertion's originating singleton and missing
manager cause remain unproven. Only after CS2 starts should audio and later
scenesystem module loading be retested. Prefix, credentials, game files,
controllers, graphics, 1152 MiB JIT pool and 8 GiB FEX arena remain intact.
