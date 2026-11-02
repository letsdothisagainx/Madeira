# Steam restart: FEX virtual address ownership and allocation failures

Device evidence: `madeira-log(20261102-002244).txt` and accompanying CEF log,
compared with `madeira-log(20261101-225828).txt`. Logs and account data are not
committed. Native image UUID is `CB76FF6D-4D34-34D3-A430-091C1FEB425C`.

## What the device run establishes

The Steam handoff fix works in this run: root PID 0020 exits with 42, successor
0294 remains active for about 23 seconds. Keep that behavior. The subsequent
failure is a virtual-address allocation failure, not a recurrence of IOSB v2,
the old ThreadState-null loop, or an authentication failure.

| Range (exclusive upper bound) | Size | Meaning in this run |
| --- | ---: | --- |
| `0xb40000000..0xd40000000` | 8 GB | Native Wine-owned FEX reservation |
| `0xc00000000..0xf00000000` | 12 GB | Legacy WoW64 FEX allocator's selected requirements |
| `0xc00000000..0xd40000000` | 5 GB | Intersection of those ranges |
| `0xb40000000..0xc00000000` | 3 GB | Reserved arena capacity inaccessible to the legacy scan |
| `0xd40000000..0xf00000000` | 7 GB | Legacy allocations also occur outside the native reservation |

The five-GB intersection is **not** the total usable space of the old allocator:
named allocations demonstrably extend into `D4..F`. Its twelve-GB scan eventually
fills, while the separately reported native arena still has a roughly 2.84-GB
gap below `C`. This is a publication/ownership mismatch, not evidence that every
large gap in the task was ignored despite satisfying the same constraints.

The failing scan reports `tries=0`, `errno=0` and gaps exhausted, before an OS
mapping attempt. The largest gap is `0x7f0000` (7.9375 MB), smaller than either
the `0x802000` call/return stack reservation or a 16-MB pool block. The later
`0x810000` gap is also smaller than a 16-MB aligned rpmalloc chunk. The footprint
near 3.7 GB does not establish physical memory exhaustion. Logical MEM_COMMIT,
reserved VA, and resident physical pages are different measurements.

## Proven failure paths

1. TID 038c cannot reserve its call/return stack. Existing checked initialization
   returns `STATUS_NO_MEMORY` with unpublished state, and Wine retires the thread
   before execution. Preserve this containment.
2. TID 0388 later fails a lazy 16-MB OpDispatcher pool reservation. The old pool
   records a null data buffer as owned, derives its list pointer by adding eight
   MB, and `ResetWorkingList` writes to `0x800000`. That value was already stored
   in the emitter object; it was not fabricated by the faulting ARM64 store.
   The captured `ldr x10,[x0,#0x320]` reads `DualListData.List`; the adjacent
   data pointer at `+0x318` is zero and its derived list pointer is eight MB.
   This matches `IREmitter::ResetWorkingList` and its invalid-node store.
3. TID 0390 is already published and running when a required rpmalloc chunk fails.
   `FEXAlloc` cannot report a recoverable STL allocation error in a build using
   `-fno-exceptions`, so its allocation-free fatal report deliberately stops.
   The resulting `0xC000001D` is downstream of allocation failure. Patching BRK
   would leave an invalid allocator result and is not a compatibility fix.

## Lifetime and safe reclamation

Normal WoW64 thread termination frees frontend state, GDT, call/return stack,
ThreadState and lookup resources. Process termination and native abort paths
can bypass that callback. `BTCpuProcessTerm` supplies no replacement teardown.
The old native process cleanup reclaims JIT code and the guest window, but
neither covers FEX's separate host-data VADs.

FEX caches typed rpmalloc spans and pooled IR buffers for cross-thread reuse.
Freeing these at an individual thread exit would corrupt surviving threads.
CPU module contexts, heap queues and pools reside in process-private DLL data;
the source and run show distinct per-process CPU DLL images. Native
`FEXBridge.mm` has a separate Mach-O context. Unknown or foreign-owner allocations
must not be guessed into a reclamation set.

One additional boundary matters: the old thread retirement counter drops before
`pthread_exit_wrapper` releases leaked FEX holds through an owner-specific CPU
callback. A count of zero alone therefore does not prove all FEX access ended.
Owner-dependent callbacks must finish while the thread still counts as live;
only the following native, non-returning cleanup tail can permit reclamation.
Preserve generation/lease checks, live siblings, images, section mappings,
placeholders and the native arena reservation.

## Implemented compatibility changes

- Native image loading publishes the reserved arena into validated, private,
  writable CPU-module DATA exports before CRT/rpmalloc initialization. Both
  the native ARM64 WoW64 DLL and the validated AMD64-header ARM64EC hybrid are
  supported. Ordinary AMD64 images do not acquire CPU-module privileges.
- Anonymous FEX host VADs carry a process owner and lifetime lease. Split views
  inherit that identity. Reclamation requires the known exiting owner's final
  callback to have finished, zero live native Wine threads, and the same lease
  under the VM lock. Native reservation placeholders remain held for reuse.
- The initial Steam process's handoff exit reclaims only its quiescent FEX data.
  It keeps the bridge TEB/window/JIT/session resources needed by the successor.
  Other process cleanup uses the existing guarded memory-retirement path.
- Required compiler objects and lookup mappings reject failed allocations.
  The first actual guest dispatch checks its lazy OpDispatcher and frontend
  buffers before execution, then retires failed state outside FEX locks with
  `STATUS_NO_MEMORY`. Inactive threads receive no extra eager pool reservations.
- Checked pools do not publish failed buffers or derive pointers from NULL.
  Failed resizing retains the original usable allocation and ownership. Pool
  migration/unclaim uses existing list nodes. On allocation failure, an adequate
  disowned buffer can be claimed with CAS without waiting for the usual idle
  timeout; live owned buffers remain protected.

These are maintained Madeira build overlays. The pinned FEX source checkout is
restored exactly after the build. No JIT/physical memory limit is increased.
Fresh STL-node allocations and nested container/runtime allocation failure
retain the explicit fatal boundary of the `-fno-exceptions` build; this is not a
claim that every possible OOM can become a recoverable Windows thread error.

Focused production-source harnesses cover allocation failure, fragmented VA,
recent-disowned-buffer reuse and CAS races, transactional resize, quiescent
root/child teardown, sibling preservation, generation/address reuse, real CPU
image headers, and the callback-versus-retirement race. macOS CI also runs the
Swift/CDP fixtures. Packaging gates require the new native lifecycle code,
first-use checks, and actual private writable arena DATA exports in the rebuilt
CPU DLL, alongside the unchanged IOSB v2 producer/consumer checks. On-device
stability and available headroom after real restarts still require verification.

## Guest placement churn and Library evidence

The old `[laa]` counter describes successful low-half placements, not failures.
The conflict counter reaches at least 83,968; the log samples do not reveal the
exact final unsampled total. Sampled failures are `STATUS_CONFLICTING_ADDRESSES`
for explicit reserve hints. Their trace attribution can contain stale errno,
address and size because only the previous stage field was reset. The low-half
placement path checks the incoming range; FEX's native `C..F` requirements are
ineligible. There is no proof these retries cumulatively consume FEX space.
Changing Windows retries or caching failures without address-space invalidation
would be speculative. Capture bounded, accurate first failures and aggregates.
Detailed VM failure records have fixed per-thread/global budgets in addition
to logarithmic aggregate summaries; cycling through more than eight signatures
cannot reset the output budget. Allocation attempts and their statuses remain
unchanged.

CEF confirms `library.js` HTTP 200, WebSocket 101, and an initialized AppStore
containing CS2. No exact Library error or update condition is captured. The
existing `OnGameActionShowError` console event loses its useful primitive error
token under privacy filtering; retain only the allowlisted `AppError_<number>`
form and a strict AppID-730 shape match. Do not log account details, IPC bodies,
arbitrary error strings, or claim an AppStore member proves ownership.

The inventory delta now explains AppID 228980's shared-depot-only filtering;
CS2's manifest, expected executable and installed state remain recognized.
No reinstall, data reset, version forgery or authentication/VAC bypass is part
of this work. Successful Library navigation and authenticated CS2 launch still
require a stable on-device run after the allocation/lifetime changes.
