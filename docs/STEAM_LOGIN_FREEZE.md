# Steam after-login freeze: evidence and changes

Evidence: `madeira-log(20261102-013052).txt` and its CEF log, compared with
`madeira-log(20261102-002244).txt`. The latest native UUID is
`A3C46560-F1B8-3912-9964-6FFA6EA6090A`. Device/account logs remain local.

## Established facts

- The reserved eight-GB FEX arena is used by all eight CPU instances. Five
  retired CPU contexts released 89 native VADs (521.61 MiB reserved, 335.05 MiB
  logically committed). Steam, browser and Crashpad contexts remain active.
  The last arena sample has 901 MiB free and a 420-MiB aligned gap. No FEX
  allocation failure or previous `0xC000001D` path occurs in this capture.
- UI detail logs stop at eight records per window. Window `500bc` has a raw
  present number nine after its `steam-frame seq=8`; another browser window
  continues raw presents after the IOThread fault. Neither counter alone
  establishes the last visible frame or an acknowledged user click.
- The read-only AppStore reply still contains 155 apps, including 730, at
  20:30:08.961. CEF main-thread and resource activity continues after that.
  No JavaScript exception, exact game-action error or observer timeout was
  captured. AppStore membership does not establish successful Library display.
- Around 20:30:09.139–09.416, browser IOThread 0124 faults at native PC
  `0x32643d8f8`. Its native instruction is `LDAPR w4,[x24]`. The preceding
  instructions load zero from guest object `0x6abb4000 + 4`, then form a new
  address from that zero plus four. With window base `0x500000000`, native
  `x24=0x500000004` is the correct translation of guest NULL+4. The guest null
  region is protected and must stay protected.
- Saved block-boundary RIP `0x6d84b6ed` and later FEX instruction-level RIP
  `0x6b143382` describe different points. Old probes also used incompatible
  ARM64EC CPU/SRA assumptions for this WoW32 thread. That diagnostic disagreement
  does not itself prove register corruption or an incorrect translation.
- Crashpad starts collecting/suspending browser threads, including main thread
  0068, after the fault. This supports an exception-recovery investigation, but
  the capture cannot prove exactly when input stopped working or whether it
  was already stalled before the fault. Missing resume detail lines are also
  inconclusive because those logs have their own cap.
- The reported 1,090 poll users are array high-water slots, not 1,090 live or
  armed FDs. The request histogram is dominated by selection, events and
  completion traffic. This does not establish a readiness spin or descriptor
  leak. The log's zero repeated partial-request rearms supplies no evidence of
  that particular storm.

The local `libcef.dll` differs in image size/checksum from the device DLL. Its
code and offsets cannot supply the missing exact guest instruction. Why the
object field becomes zero, and the actual Library failure, remain unresolved.

## Source fixes and observation boundaries

The iOS wineserver poll dispatcher now validates a readiness snapshot against
its registration generation, FD and current interest mask. An earlier callback
can close and reuse a later slot and the same numeric FD; that later readiness
belongs to the old registration and must not be delivered to the replacement.
Zero-interest descriptors retain terminal event watches, while disabled
descriptors remain disabled.

The sandbox fallback no longer treats an array-index threshold as evidence
that an FD is a process/thread protocol channel. Freelist reuse can put such
channels below that threshold and unrelated queues above it. Only validated
thread/process protocol objects receive nonblocking read probes. Queues,
devices and unknown objects require actual readiness. These are demonstrated
source defects; their causal role in this device freeze is not established.
No arbitrary communication throttling or request-result change is introduced.

Bounded ownership/request summaries distinguish high-water slots, live
objects, enabled descriptors, data interests, stale readiness, empty reads
and named request types. They record creation provenance rather than asserting
exclusive ownership of a shared descriptor.

First-fault capture validates the target TEB, TLS14 frame and guest-window
identity, then safely reads the actual JIT header/tail and instruction-to-RIP
table. It labels saved versus exact RIP and captures correct WoW32 live
registers, rebased guest opcode bytes, a four-byte pointer field and bounded
module/callsite candidates. Failed validation is reported as unavailable.
It does not change registers, exception handling, mappings or protections.

UI counters continue beyond verbose caps. A bounded five-second heartbeat
separates frame submission, surface state, native UI polling, flushes, hardware
message removal, WinProc entry and valid callback return. Input acknowledgements
include HWND/message ID only, not keys, text, coordinates or payloads. Passive
CEF progress counts already-received packets/replies, unchanged Store snapshots,
resource completions and WebSocket traffic without adding browser queries or
Steam API calls. Successful input injection is not labelled as UI processing.

Production-source sanitizer fixtures cover poll ABA/mask changes, typed probe
routing, pinned JIT metadata encoding/layout and malformed readers, logging
caps, and actual callback-return boundaries. Swift/CDP fixtures run in macOS
CI. The final IPA must contain the new native markers alongside the existing
FEX arena, handoff and IOSB v2 producer checks.

No Steam/CS2 reinstall, authentication reset, memory-budget increase, forced
helper visibility, null-page mapping or security bypass is part of this change.
The next device run must establish actual input and frame progress, the exact
guest failure, and Library/CS2 behavior; this build is not runtime proof that
the freeze is resolved.
