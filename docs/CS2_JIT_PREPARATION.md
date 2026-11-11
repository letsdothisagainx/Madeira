# Full-width debugger preparation

The November 11 log identifies source `085c0d03`, a full 1152 MiB pool, and
73,728 synchronous high-address preparation writes taking 109,812 ms. The same
JIT preparation source was present in the previously successful `1564ea18`
build; its earlier approximately 31-second duration does not establish a new
allocator change. Serial debugger latency remains amplified once per page.

StikJIT 1.9's native helper batches 128 packets but encodes only nine address
nibbles. Calling it with a high address would touch different memory. A low
scratch alias is also unsafe as a general replacement: XNU resets code-sign
monitor association when remapping entries on iOS. Neither workaround is used.

MJP2 negotiates Apple's advertised `jMultiBreakpoint+` capability and packet
size. It sends at most 128 fresh pages per bounded JSON request. Each page has
an ordered software-breakpoint insert/remove pair, using the full 64-bit final
address. Debugserver writes and verifies the instruction, restores and verifies
the original bytes, and reports both results. No game process exists yet.
Successful preparation retains no breakpoint. Later live-code preparation
requests retain their existing implementation.

With the normal advertised packet size, a complete pool requires 576 transport
requests and 147,456 checked server actions, instead of 73,728 synchronous
transport requests. Local request storage is bounded by 64 KiB. There is no
full-pool data transfer or new temporary backing allocation. An older server
without the capability falls back before any breakpoint is installed.

The C transaction accepts legacy MJP1 preparation and MJP2 explicitly. A new
successful batched return uses the otherwise invalid low address bit to select
the restored-zero marker; it is decoded before use as a pointer. Every page's
full first instruction must be zero: testing just the first byte would miss
ARM64 `BRK`. Existing complete ownership/offset/protection checks, reversible
shared-alias write, and all 73,728 guarded execution probes remain mandatory.

Before touching memory, the script arms a separate poison result. It clears
that result only after confirmed breakpoint removal and an acknowledged result
write. If removal is ambiguous it attempts to stop the inferior. If that stop
fails and the target resumes, the C transaction quarantines all reservations
without deallocation or reuse. A later debugger restoration can therefore not
write into a recycled address.

The owned real Apple debugserver reference uses two fresh 16 MiB high RX
aliases and runs both orders on fresh children. In Xcode 27.1 the serial-first
sample took 161.273 ms for 1024 writes and 119.790 ms for eight batches. In the
reverse-order sample batching took 110.462 ms and serial writes 173.205 ms.
[The actual run](https://github.com/letsdothisagainx/Madeira/actions/runs/42991239423)
verified all bytes, restored originals, neighbours, and unchanged source/alias VM identities.
Those are host measurements, not an iPhone latency prediction. The full-pool
script tests verify request counts; real Mach tests retain full-size execution
checks for both preparation modes. Actual iPhone preparation time, Steam/CS2
startup, and VAC-secured acceptance remain device tests.

The image/code partition remains 768/384 MiB. No Wine prefix, game files,
credentials, graphics settings, or controller configuration are migrated.
