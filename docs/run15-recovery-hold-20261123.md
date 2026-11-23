# Run15: remove unnecessary recovery-owned suspension and priority dependency

Evidence: source 9ba172ee9ff3d093b0681ea3867ffcb237e0b55e, native UUID
F127024B-2636-3693-8C53-F6CDE97574AC. Uploaded ZIP SHA256:
cc1b2a27d59299890229b670e1f655d59f253cd3fe796870f26c291939690b84.
The archive metadata reports exportUTC 2026-11-22T23:47:30Z.

The main native thread 320176 is explicitly held by production recovery for
7,083,212 microseconds at f8024373, EA 0x7a538f7ffc. Main-progress observations
independently show suspend count one, zero CPU progress, then count zero and
renewed progress. This behavior also occurred in Run14. It is not evidence that
the entire hold was in mach_vm_write or that all preceding loading time has the
same cause.

## Established source defects and correction

The utility-QoS recovery worker formerly suspended every qualifying target
before reading its frame/code, including first observations and instructions
that would never be repaired. A Mach suspend does not provide pthread lock-owner
QoS donation. Thus a foreground game could depend on a utility worker across
potentially paging VM reads, validation and synchronous checked writes.

* `server_ios.c:ios_stuck_store_inspect` now captures a read-only advisory state
  and inspects the candidate with no explicit target suspension. Only a repeated
  crossing candidate enters the repair scope. Preparation is not a permission
  receipt: after suspension it captures fresh GPR state and rereads the frame
  and instruction; frame, PC, opcode, effective address and width must agree.
  Sources/writeback are derived from the fresh state, and destination aliases,
  guest protections and native writable mappings are checked anew in the helper.
* `ios_stuck_store_qos_begin/end` request user-interactive QoS before acquiring
  the Mach hold, then restore the worker's prior QoS and relative priority after
  the matching resume. Discovery remains utility. API results and effective
  classes are recorded, not assumed successful. Guest thread priorities do not
  change.
* `signal_arm64_ios.c:ios_store_split_crossing_timed` retains checked Mach writes,
  bounds and permissions, per-fragment status and partial-prefix reporting.
  Register writeback occurs only after complete writes. The old untimed entry
  point is preserved for exception recovery; it takes no phase clocks.
* The existing bounded three-thread store-progress record gains fixed-size
  wall-time phases: advisory capture/read, suspend, held capture/read, validation,
  each checked write, alias accounting, state publication and resume; plus worker
  ID, QoS and API results. Publication/logging happen after the resume attempt.
  No payload capture, new sampler, allocation, timeout or cancellation is added.

No timer can cancel an outstanding write. A repair still owns its suspension
until synchronous writes and state publication finish. Its worst-case hold is
not bounded by this patch. The measured seven seconds cannot be apportioned
between phases from Run15; the next device record can make that distinction.

## Ordinary validation

`check-recovery-hold.py` extracts both the exact pinned pre-change inspector and
the changed production inspector/helper. On the same successful API workload,
the predecessor owns a suspension across two first-observation reads. The new
path owns zero suspensions during those reads. It completes 1,000 repeated
scalar/vector stores into writable pages, checking bytes, PC, fresh operands,
concurrent ordinary PC progress, nested count ownership and QoS restoration.
Linux uses an explicit successful QoS adapter and checked kernel-delivery adapter;
this does not benchmark Mach or iOS. On Darwin the check additionally captures a
real running worker without a suspension count and uses real pthread QoS and
real Mach writes into ordinary writable memory.

Normal scheduling, scoped observation/sanitization, pressure-budget predicate,
copy formatter, cache invalidation and package-inspector checks remain in the
selected CI profile. Historical fault fixtures are compiled only. No deliberate
crash, protected-memory, page-revocation or fault-injection case is executed.

## Memory and device acceptance remain open

The first texture refusal is consistent with headroom below the unchanged
192-MiB reserve. Two 4-MiB trims measured zero physical drop. Existing jumbo
reservations belong to live CS2; their virtual size is not reclaimable physical
memory, and RX/RW aliases share backing. Source inspection and sampled owner
records do not establish an abandoned allocation or safe reclamation target.
No memory policy, resource ownership, JIT pool, topology, graphics, networking,
Steam, installed data or user configuration is changed here. The physical owner
of the remaining headroom consumption is still unattributed; no memory saving
or texture repair is claimed.

Run15's 205-second activation, 59,763.2-ms Present gap, 286 texture failures and
server timeout are device baseline observations, not predicted corrected results.
Passing ordinary tests and IPA provenance establish implementation/packaging.
A responsive remote team picker, sustained playable round and clean transition
with correct textures still require an iPhone run. Different maps are not a
controlled performance comparison.
