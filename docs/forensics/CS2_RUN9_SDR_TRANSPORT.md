# Run 9: official SDR reachability and native socket compatibility

Baseline: `e481cc04e1317b52bac68e63477ec8530ec17535`.
Evidence: the supplied Run Diagnostics (9) ZIP, extracted read-only. A separate
screenshot file was not available here; its dialog text is the user's report.
Console wall labels below are not calibrated to the native monotonic clock.

## What this run establishes

The game loads SDR configuration revision **1794268433** at console **09:11:36**.
The initial ping measurement fails by **09:11:46**, with no reachable cluster
among **45**. Retries beginning **09:14:19** and **09:14:48** also yield zero
measured POPs. The recorded connection at **09:12:32** is local loopback, and
there is no remote challenge/connection handshake in this export.

The native log has 62 generic socket-error records, all sends with Darwin
`EHOSTUNREACH` (65), and 25 richer UDP-failure records. All richer records
belong to Steam processes **0068/008c**, not CS2 **038c**: 22 IPv4 multicast,
one IPv4 broadcast and two public IPv6 destinations. These are not evidence of
failed CS2 relay sends. The generic error limit was not exhausted before CS2.
No observed `EMSGSIZE` establishes an MTU failure. Conversely, the previous
instrumentation did not establish successful CS2 kernel sends or receives.

Both the successful earlier run and this run show the debugger reachable over
**utun4**, 34 interfaces, four IPv4 addresses, 19 IPv4 routes and zero enumerated
IPv6 routes. Run 9 has 26 rather than 28 IPv6 addresses. Current Steam IPv6
HTTP/UDP tests time out while primary HTTP succeeds. That is evidence of a
changed or unhealthy IPv6 path, not proof that the VPN blocks SDR or that IPv4
UDP is filtered. The debugger probe only describes its own tunnel route.

The comparison from the remote-capable builds through e481 shows no networking
source change in the send/receive, NSI routing or JIT-network selection paths.
The prior FEX backoff uses the same native NT delay implementation already used
by FEX's Sleep. Poll/rearm and TEB audits found no demonstrated new regression.
**The precise reason for all 45 relay failures remains unestablished.**

## Confirmed compatibility corrections

### Preserve receive errors before observers

`tools/build/stage-ios-socket-errors.py` now fixes `try_recv` as well as the
previously corrected send path. It captures native errno immediately after a
failed receive, applies the existing OOB `EINVAL` normalization, and derives
NTSTATUS before logging or introspection can replace errno. The original retry,
async pending, completion, cancellation and byte-count behavior is preserved.
Hard receive failures gain bounded, sanitized context in
`build/ntdll-unix/socket_error_context.h`.

The original production body can convert `EWOULDBLOCK` into `ENOTCONN` when an
observer queries the peer of an unconnected datagram socket. This incorrectly
completes an overlapped receive instead of leaving it pending. Actual old/new
function tests reproduce this and then complete the corrected request using a
real IPv4/IPv6 UDP nonce. Hard errors retain their real identities, including
message-size and unreachable errors.

Causality limit: the legacy wire observer defaults off, and ordinary would-block
callbacks mostly return without work in this archive. The exporter does not
prove this corruption happened during Run 9. Upstream GameNetworkingSockets
also normally uses a synchronous receive/drain path; an error ends that drain
cycle. This fix must not be advertised as a proven explanation of the blackout.

### Correct ancillary metadata conversion

`tools/build/stage-ios-socket-control.py` stages two bounded corrections:

- The WoW64 converter computes the 32-bit header/padding from the **payload**
  length, validates both buffers, and copies only payload bytes. The old body
  rejected a correctly sized 20-byte 32-bit packet-info record, while a larger
  target could receive 16 bytes beyond the declared source payload.
- Native Darwin `IP_RECVTOS` and IPv6 receive-traffic-class aliases are recognized
  as the corresponding Windows control-message types. Native packet bytes and
  outgoing markings are unchanged. Unsupported metadata is not invented.

156 exact-size, multi-record, odd-payload, unaligned and short-buffer cases run
against the actual production converter, including exact physical allocations
and ASan/UBSan guards. Real owned IPv4/IPv6 UDP exchanges carry packet-info and
traffic-class data through both conversion functions. Real Darwin execution is
required in CI; Linux results do not establish behavior on the iPhone.

Causality limit: CS2's 64-bit calls do not use the WoW64 length converter, though
other genuine Steam processes do. Missing traffic-class metadata is an ordinary
compatibility defect but is not proof that all relay replies were discarded.

### Return independent, bounded BSD route rows

`tools/build/stage-ios-route-table.py` stages only the BSD IPv4 provider in an
immutable copy of Wine's `nsiproxy.sys/ip.c`. The owned `nsi_ip_ios.c` wrapper
requires that provider, with nsiproxy's quoted private-header namespace ahead
of ntdll's same-named header. The build fails if staging or compilation fails.

The previous parser reused an uninitialized row. Host routes without a netmask
could inherit the previous prefix length and missing gateways, while the
Windows Loopback field was undefined. The correction initializes each row,
assigns host `/32`, derives loopback from the interface, represents on-link
next hops as zero, and validates message/address bounds and alignment.

Actual old/new parser fixtures reproduce inherited `/10` and gateway fields and
poisoned loopback, then verify default/compact masks, loopback, host and tunnel
routes, count/short buffers, malformed snapshots and honest failures. The tests
include a real Darwin routing-snapshot query when run on macOS.

Causality limit: this corrects information returned through Windows
`GetIpForwardTable2`/`GetBestRoute2`; it does not rewrite kernel routes. No
exported route row proves that Steam selected an incorrect route in Run 9.
IPv6 enumeration and notification gaps predate the successful remote builds
and are not expanded into an unrelated rewrite.

## Small native/AFD checkpoint for the unresolved boundary

After actual successful native I/O, the existing socket overlay records at most
one public, non-DNS datagram send and one receive per logical PEB/PID, up to 64
owners (128 records). It reports native byte count, actual AFD status, family,
FD, process/thread IDs and an explicitly labeled monotonic observation time.
The first send and receive are **not a matched packet pair**. A marker does not
authenticate a relay, prove server acceptance, or count all packets.

There are no added packets, endpoint queries, payload reads, destination logs,
credential collection, route changes or destructive `SO_ERROR` queries. The
shared table is about 1 KiB, with a small native thread-local cache per
participating thread. The helper performs no explicit or per-packet allocation
and creates no timer; Darwin may initialize its normal TLV backing on first
access. The thread/owner cache removes subsequent locks and introspection after
sampling.
Tests cover concurrent sampling, the lifetime cap, error preservation, clock
failure and 200,000 warm calls with no further syscalls/locks. Synthetic public
metadata in those tests is explicitly labeled; actual traffic stays on owned
loopback sockets.

The checkpoint answers the narrow next-device question: did the iOS syscall
accept/send data and return public datagrams, and what did AFD return? Lack of a
record is not an independently established firewall or MTU diagnosis.

## Preservation, packaging and remaining acceptance

No renderer, FEX allocator/backoff, JIT partition/placement, launch argument,
Steam authentication, game binary, prefix, input mapping or export implementation
is changed. In the baseline export, 39 of 66 frame windows reach at least 50 FPS;
38 also exceed 30% GPU busy. Representative windows are 59.9 FPS/48% busy/8.1 ms
GPU and 53.2 FPS/38%/7.1 ms. Peak footprint is 5572 MiB and latest buffer reuse
is 95%. These are local/background rendering observations, not a remote-gameplay
benchmark. New-build FPS, footprint and official matchmaking are unmeasured.

The native packaging gate checks the compiled receive/progress/control/route
capabilities in ARM64 Mach-O and verifies the exact same native bytes inside
the IPA. Existing FEX/DXMT provenance and ABI gates remain active. No old native
object is accepted after a failed required socket/provider compilation.

The iPhone acceptance test remains: successful official SDR pings, matchmaking,
remote handshake, map loading, responsive T/CT selection and sustained gameplay.
A loopback test or accepted native send cannot substitute for that sequence.
Install over the existing app using the same signing identity and bundle ID;
retain all data. Reinstalling the previous IPA with the same identity provides
rollback without a prefix migration or game reinstall.
