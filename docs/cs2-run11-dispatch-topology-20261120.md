# Run 11: diagnostic-job dispatch and Apple processor topology

## Matched evidence and separate failures

Archive SHA-256: `68a73ff256fe6f289b64a4f80691707fdc7b63bb87bdb7236c032607a510b275`.
Export: `2026-11-20T01:17:43Z`. Package and runtime source:
`9214ad22806eb689790107d4fd7a610ef67373f5`; native UUID:
`3AA9E976-6707-34D3-90B1-06E8A6E5425B`. The full image/code partitions remain
768/384 MiB. Larger-class adoption and generation maintenance execute.

The remote connection begins at 20:07:17 Eastern, Inferno activates at 20:10:44
(207 seconds), and full state arrives at 20:10:45. The last completed 64-frame
batch ends at 20:10:44.940. Before the later stop, the main thread executes
animation and particle work. Those samples do not establish defects in those
game modules. There is no recorded NETWORK_DISCONNECT_TIMEDOUT in this export.

At about 20:12:15, PID 03c0/TID 03c4 successfully suspends itself through handle
0x5a94, count 0 to 1. Server identity matches the current TEB and PEB. No watched
server-resume, wait-return or resume-api-failure appears before native logging
ends at 20:16:17.627. Subsequent interval-tail accounting and historical fault
metadata are not evidence of resumed main-thread execution. Generic resume
logging remains sampled. The late suspension cannot explain all earlier loading.

## Matching current binaries

Steam commits BuildID 26798866, Windows depot 2347771, manifest
`4200138934793327916`. Read-only inspection of the exact IPA and official depot
succeeds in Actions runs 44654107127, 44654554113 and 44654917590.

* Current client.dll: 39,143,064 bytes; SHA-256
  `07103341bc9e0ae2c596b2929075c5094cb397d7e370ea00986c720ed72414e1`;
  timestamp 0x6aff8722, image size 0x298e000, mapping identity eb5edd5d42fad2d2.
* Current tier0.dll: SHA-256
  `0bcd160dfa72d9f97fbf85095d59baad18fca61f20d840e83a5bd9f7635d5c32`;
  timestamp 0x6af4a3e4, image size 0x401000, identity 8f2d32d37c93635a.

The capture helper remains client+0x4520..0x4a10. Its SuspendThread call returns
to +0x457b, then it intends to call GetThreadContext, ResumeThread and CloseHandle.
The diagnostic lambda saves its creator's genuine thread ID and submits through
IThreadPool::QueueJobWithFlags. Its callback opens that saved ID. Executing this
callback on its creator blocks before its own intended resume. This is the
received diagnostic-request path; OOM is not established as its trigger.

## Confirmed Wine topology defect and production correction

The Apple builder combines PEB NumberOfProcessors with unfiltered host physical
cores. In the actual old-function replay, four exposed CPUs and six physical
cores yield `lcpu_per_core = 4 / 6 = 0`. Core, package, NUMA and group masks are
zero while active processor count is four and get_system_affinity_mask returns
0xf. This violates the Windows topology contract. Run 11 logs exposed four and
host-online six; the raw hw.physicalcpu response and returned topology were not
logged. The reproduction establishes the source defect, not a measured pool value.

The owned stage-apple-cpu-topology.py transform clips core/package relationships
to the visible CPU set and partitions nonmultiple counts into complete, disjoint
masks. Cache masks cover the same visible set, including partial final groups;
cache capacities/types/line sizes are preserved. Zero/short host sharing answers
get a nonzero fallback. Allocation failures return honest errors. Native build.sh
compiles this staged system.c and fails closed. Pinned Wine and the configured
CPU count remain unchanged. The native marker reports the actual host and visible
counts, rather than assuming the response on the phone.

The actual old/new builder, Wine relationship helpers, CPU-set derivation and
affinity getter are compiled in the regression. The old four/six case returns
mask zero; the corrected case returns 0xf. Coverage includes 3,600 variants,
12 real allocation-failure edges and 33 already-valid default topologies with
identical normalized relationship records. Normal and ASan/UBSan runs pass.

## Current binary connection to job dispatch, and its remaining gap

This connection is derived from the current binary, not an older SDK layout:

1. Tier0+0x65430 increments a core-record count and sums each core mask's
   population count. Vtable 0x30d5c0 slot +0x18 returns the former; +0x28 returns
   the latter. Its success methods return true even for zero masks.
2. GetCPUInformation clamps logical count to at least one and caps physical
   count by logical count. Thus six zero-mask core records become logical/core
   counts one/one. Tier0+0x63610 initializes performance-core count to one and
   exits early on the one-logical-CPU case.
3. On GenuineIntel, +0xa5b40 returns that performance count. The default worker
   selection at +0xa5f34 subtracts one, yielding zero workers. Coherent four-core
   masks instead yield four CPUs and three default workers.
4. Queue submission at +0xa5500 has a real inline callback branch when the pool
   has no workers. A creator-context capture executed there would self-suspend.

Explicit startup worker counts bypass the default selection. The current export
does not record the pool's startup parameters, fields or outer call chain.
Therefore the source defect can produce this exact failure mechanism, but the
actual dispatch taken in Run 11 is not independently proven.

## Minimum bounded observation at the unresolved boundary

The existing one-shot observer now reads a few fixed stack slots only on an
already successful self-suspend. It does not scan the whole stack or add a
system profiler. Current PE headers, code signatures, callback/vtable identities,
stack bounds and JIT-to-PE normalization are checked before object fields are read.
Unknown versions, short reads, unmapped/revoked storage or inconsistent objects
skip observation only. errno and all guest state remain unchanged.

The exact packaged KernelBase frames total 0xf0 bytes. Current client capture
allocates 0x4f8 and its caller 0xa18. Pinned FEX's ARM64EC entry bridge pops the
x64 call return on this alignment, giving these derived offsets from syscall SP:

| Offset | Validated use |
| --- | --- |
| 0xe8 | client+0x457b continuation through native thunks |
| 0x5e8 | client+0x4331 capture caller |
| 0x728 | saved callback argument, job+0x50 |
| 0x1008 | actual outer dispatch continuation |
| 0x1018 | caller's saved input thread ID |
| 0x1038 | client+0x53dc submission continuation on inline path |
| 0xfd8 / 0xff0 | saved R14/RDI, pool/job on that inline path |

Only the complete matching chain is labeled inline-submit-validated.
Other paths retain their module-relative outer return for further analysis.
Job byte +0x15 and pool +0x130/+0x159/+0x15a/+0x138/+0x140 are reported with raw
offset labels. These are post-suspend observations, not historical atomic pool
state. The previous resourcesystem+0x8bed0 stack candidate remains unproven as a
caller. No suspend count, thread identity, register, callback or resume is changed.

## Memory and acceptance limits

The console has 1,062 CreateTexture2D and three CreateTexture3D OOMs. The eight
native refusals are consistent with full charges and the unchanged 192 MiB
floor. Peak captured footprint is 6,023 MiB. Small allocations fail because
headroom is exhausted; this is not a demonstrated admission arithmetic error.

Staging is about 4 MiB and initializer uploads zero in the cited pressure census.
Their cumulative traffic is not live memory. Dynamic reuse remains bounded.
Malloc relief returns zero. Guest decommit/release, helper-process reclamation
and thread lookup-cache destruction are active. About 140,289 KiB of retained
shader bytecode is identifiable live cache ownership, not an established leak
or independently measured reclaimable physical memory. JIT aliases are shared
views and cannot be added as separate physical owners.

The remaining near-limit working set lacks per-PEB heap/VAD ownership correlated
with unique VM backing objects and physical footprint. No safe missed-release
correction was established. This candidate does not lower the admission floor,
force-release game-owned textures or claim that texture pressure is fixed.

Dedicated package gates require the compiled topology producer and bounded
dispatch observer, with exact app/IPA copies. Cache keys and native source
provenance preserve the earlier upload, generation-maintenance, larger-class
reuse and checked-write corrections. A successful build and host regressions
are not device acceptance: responsive T/CT selection, continuing frames, a
playable remote round and intact textures/changelevel still require an iPhone run.
