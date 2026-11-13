# CS2 CPU/audio capture: f7fec80d

Evidence is the November 13 run export with source
`f7fec80dc40e5d389f5ac5bb1f8ff206bbf65e1c`. Raw account-bearing logs are not
committed. Remote Vertigo activation/full state is recorded at 21:05:04;
the idle-kick token is at 21:06:33. This is no new VAC rejection.

## Attribution limits

The late saved frame buckets map to tier0+15d580 and phonon+a65500. The saved
frame RIP is a caller, not the executing instruction. Late actual JIT buckets
are diffuse. Captured tier0 bytes show bounded integer-range work and owner
checks; a proprietary function name or a polling defect is not established.

A captured actual JIT block maps to phonon+39e0330. Its SIMD DSP code includes
two identical lane broadcasts followed by ZIP1. The source-owned fixture retains
the exact header/tail/code words. Bucket samples refer to the block prologue;
they are not measured time in the individual broadcast.

During loaded Vertigo before the kick, the main thread consumes 73.638 CPU
seconds across 88.235 seconds of sampled intervals. Nine resolved main-thread
samples are in animation/particles. The later single-thread audio profiles
must not be described as the main-thread profile. The recorded GPU windows end
before the full update. Main self-suspension coincides with the kick and does
not explain the preceding slow frames.

All 27 touch down/up pairs drain into Wine. The server lookup trace is capped
and contains repeated peeks; there is no proof of team-picker dequeue/UI
consumption. No focus, coordinate, or automatic-team override is introduced.

## Production changes

* FEX SHUFPS lowering: only same-SSA-source 128-bit/i32 masks 55/AA/FF become
  one lane DUP instead of two DUPs and ZIP1. Distinct inputs, other element
  sizes and 256-bit lane handling retain their original path. Raw bits,
  including NaN payloads and signed zero, are preserved. The pinned FEX tree
  stays unchanged; both PE recipes compile the owned staging patch.
* WASAPI queue: acquire the consumed position before the produced position.
  The old reverse snapshot can combine an old write with a new play value,
  underflow and falsely report a full ring. Buffer availability and padding
  now share the same bounded snapshot. Publish copied audio immediately;
  unconditional sample-by-sample diagnostic analysis no longer precedes the
  release store. Existing host pacing telemetry remains outside that path.
* Native Wine LFH size reads: retain handle/pointer validation and all checking,
  standard/large/free paths. A live USED LFH block's size reads only its own
  stable header and does not mutate heap/group/bin state. Other LFH operations
  already bypass this heap lock, and a live block pins its backing group.
  The caller must keep the heap/block alive and exclude concurrent resize/free.
  The ordinary size read avoids an unrelated global critical section; debug
  and shared-backend locking remain intact.

The heap trace is sampled, not exact per-API counting. Its 1088 ms/s of waiting
is cumulative across threads, not one 1.088-second stall. No caller or
allocation-size distribution is available to attribute all contention.

## Verification

Tests execute pinned/staged frontend bodies, use a native x86 SHUFPS oracle,
and compare the old/new ARM64 operations on Apple hardware in CI. Audio tests
interleave the real mixer with queue queries and include a failing old-order
mutation, wrapped/silent content, downmix and WOW64 regressions. Heap tests
execute production validation/size/LFH routines, preserve status/last-error
behavior, exercise 72000 concurrent allocation/size/free cycles, and require
the original serialized size function to fail the regression. Rebuilt heap.o
is compared with the actual stripped A64/ARM64EC ntdll native entry before
packaging; stale compiler output is rejected.

No JIT pool/partition, networking, Steam, cache policy, texture quality or
user-data migration changes are included. Audio source starvation is not the
same as host underrun: this capture has 15.14 seconds of game-reported missing
samples versus 3.07 seconds of host shortage over 880 seconds, with native timer
lateness at most 0.1 ms. Neither audio fixes nor instruction counts establish
new iPhone FPS. Team selection, sustained gameplay, audio behavior and the
5936/6144 MiB footprint require a real-device retest. Reverting the source
change requires no prefix or game-data reset.
