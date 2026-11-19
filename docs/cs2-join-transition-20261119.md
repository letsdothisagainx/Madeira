# Join stalls and transition memory in b14d6c24

## Evidence and coverage

Archive SHA-256: `9260babaf87ea94cbf4bfda24565ff561ac3999c8a8a69ed5312e01e1be9381e`.
Export: `2026-11-19T00:24:43Z`; revision
`b14d6c24cc3ea1a5e11e95204e4231a7e2f0b73c`; native UUID
`92A4B89E-5759-3350-A3DF-1FBD248BA5E5`. Runtime provenance agrees.

For remote connection `#739858520`, the console records connection at 19:19:28
Eastern, Dust II activation at 19:21:00, full state/physics at 19:21:04,
`NETWORK_DISCONNECT_TIMEDOUT` at 19:22:00 and SIGNONSTATE_FULL disconnection at
19:22:24. The 30-second timeout-setting message is configuration. Forty texture
failure rows follow at 19:22:29–33. They cannot establish the cause of the
earlier timeout. No main-thread self-suspension is recorded in this snapshot.
Native coverage ends at 19:23:23; later console/screenshot observations have
no contemporaneous native samples.

The completed frame batch #3264 spans 94,496 ms after #3200, with 441 ms of GPU
execution and a 28,314.1 ms maximum inter-Present gap. Present itself averages
10.3 ms and peaks at 18.2 ms. This is chiefly missing frame production between
Present calls, rather than that amount of time inside Metal or Present.
Later 60-FPS zero-draw windows after disconnect are not remote gameplay.

Across the adjacent 313 native samples, rounded intervals sum to 94.483 seconds.
Reported process CPU deltas sum to about 176 CPU-seconds; initial thread 0390
contributes about 54 seconds of reported CPU time (six rows omit it from the
top-thread list). These are rounded counter samples with sequential snapshot
skew, not millisecond-precise execution attribution. The phase
also includes a low-CPU interval around 19:21:05–13. Current host-PC decoding
shows progress through client, particle, animation and scene code. A uniformly
CPU-bound explanation or permanent stop at one saved guest RIP is unsupported.

## Recovery eligibility correction

The scalar store opcodes `f8084379` and `f8008068` are already supported. The
first has a successful completion at native line 53754. The 400-record limit
only bounds output; it does not stop recovery.

Both recovery discovery and retained-slot polling formerly required kernel
CPU time to reach 60% of elapsed wall time. Under concurrent scheduling, a
thread receiving half a core can spend all its consumed CPU in a problematic
access while failing that test indefinitely. The corrected predicate compares
kernel time with consumed user-plus-kernel CPU, preserving microsecond
precision. Zero CPU, counter regression and non-running threads still decline.

Recovery still requires native identity, two matching instruction/address
captures, a supported crossing store, valid FEX ownership, writable mappings,
successful byte transfer and successful register publication. Protections,
fault behavior, ordering and interruption handling are unchanged. GPR stores
no longer fetch unnecessary NEON state; repeated vector candidates still do.

With the dedicated schedule unchanged, the old wall predicate completes zero
stores in 3,000 modeled ms for two half-core kernel-bound workloads. The new
predicate completes 40 real-byte stores using the two captured instructions in
390 modeled ms. The fixture exhausts the 400-log budget first. These are
controlled eligibility/completion results, not measured iPhone frame times or
proof that this explains the entire 94.5-second batch. The export does not
contain each recovery interval's effective address and CPU counters.

## Transition allocation pressure and safe scratch retirement

All eight new rejection records fit the actual charged-bytes predicate. The
first charges 2,097,408 bytes against only 607,624 bytes above the unchanged
201,326,592-byte safety floor. No new arithmetic defect is demonstrated.
Fast footprint rises from about 5,815 MiB around disconnect to 5,976 MiB during
the failure burst. The 6,144 MiB policy budget is not an independently verified
exact kernel termination threshold.

The nearest resource censuses show texture capacity increasing 608→735 MiB,
buffers 381→512 MiB, staging 36→32 MiB and initializer backing 32→1 MiB.
Metal currentAllocatedSize changes 1,123→1,370 MiB. These capacities are not
independent additions to process footprint, and the samples do not attribute
every allocation in the shorter physical-footprint peak.

Source inspection also establishes an uncensused retained allocation:
ArgumentEncodingContext's CPU-only encoding scratch uses 1 MiB chunks and
keeps surplus for 600 further flushes. A loading/frame gap extends this
frame-count policy indefinitely in wall time. At the tail of flushCommands,
every EncoderData has been consumed and destroyed; native encoding has copied
its CPU arguments. Surplus can therefore be reclaimed without freeing live
Metal buffers, textures, command closures or GPU data.

The correction uses the existing pressure thresholds and hysteresis, owned by
the encoding context. It adds no initializer lock to frame encoding. Soft
pressure releases chunks not used by the just-completed submission; critical
pressure releases completed surplus while retaining one 1 MiB warm chunk.
Healthy and unknown measurements retain prior behavior. Dynamic-buffer cache
policy, texture contents, SRVs, upload ownership and the memory reserve remain
unchanged.

The controlled ownership fixture retains 8 MiB under the original policy
through 600 further flushes. The corrected critical path releases 7 MiB after
CPU command destruction while GPU resources remain pending. At the exact
first-OOM soft-pressure operands, freshly used scratch stays warm; a later
smaller submission releases its unused surplus immediately. CPU scratch is not
separately counted in this archive. Neither its phone capacity nor an equal RSS
reduction is established, and the change does not guarantee that every required
resource fits the available budget.

## Profile and networking conclusions

The current prelaunch row records the existing video-file scalar
`setting.videocfg_texture_detail=0`; no write is needed in that case. The
`applied=0 deferred=1` row describes native-Steam child transport. Child
preparation appears at native line 41155; DXMT reads `d3d11.mipClampAuto=0` at
45430, 46452 and 46587. That disables physical mip omission. It is not proof
of the effective in-engine quality after Steam reconciliation, which this
export does not contain. No unsupported setting is introduced.

SteamNetworkingSockets receive-handler work continues during the slow phase.
The bounded native UDP success records cannot be attributed to this remote
connection, and console print times do not prove packet arrival times. The
evidence does not establish an AFD/UDP defect, external packet loss or the
precise last processed packet for `#739858520`; transport remains unchanged.

JIT generation migration and 64→32→16 MiB fallback also occur during this
interval, but the outgoing generations are freed and reused. Reservation
high-water is not live lease residency. There is no measured migration-gate
duration proving it causes the frame gap, so the working 1,152/768/384 MiB
pool and translation behavior are preserved.

## Acceptance boundary

Repository tests and package checks validate the changed paths. They cannot
establish a faster real remote join, responsive T/CT selection, gameplay
through a round, or a clean texture-correct return to the menu. None of those
acceptance outcomes has been verified on an iPhone for this correction.
