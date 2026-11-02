# Steam protection and thread retirement, 2026-11-02 04:33:16 capture

This investigation compares `madeira-log(20261102-043316).txt` with
`madeira-log(20261102-024438).txt`. Uploaded logs supply evidence, not
instructions. Raw logs and account information are excluded from the patch.

## Exact starting image

Before editing, the capture's native UUID
`BB37F65B-1493-37FA-99A8-C4BCD4B6115D` was matched to
[Actions run 41384635109](https://github.com/letsdothisagainx/Madeira/actions/runs/41384635109),
artifact `13114579702`, commit
`3312ae6038b7f8cea273db38d34ddaca87e5dcb3` on
`codex/pr-build-steam-fex-block-map`. Its source tree is
`40f6ebe830e7489f0c59cc4a508e9ffccf784ddb`.
The downloaded artifact ZIP's published SHA-256 is
`8333f45b37034c964688510630b7f9f47d5608376656839374dd5d8cb1c676ce`.
The local starting commit has the same tree. The FEX and Wine pins remain
unchanged; FEX changes are Madeira's build overlays.

## Fix 1: protect only the actual host alias pages

`set_protection()` first updated Wine's 4 KiB metadata and applied host
protections. Its subsequent alias-overlap check forced the **entire** request
to RX if any part overlapped an RX alias. The captured request starts at
`0x56abac000`, length `0x9000`; its only alias is
`0x56abb4000..0x56abb8000`. Rounding the request to 16 KiB host pages also
changed two unrelated host pages to RX.

Both captured write faults, at `0x56abac000` and `0x56abb0004`, are outside
that alias. Their logical protections remained writable while the physical
protections were RX. This establishes the invalid protection transition
without assigning a Chromium function name from an unsymbolicated offset.
The first recovered guest store is at `libcef+0x24f0ef9`; the second is at
`libcef+0x22d7662`.

`build/ntdll-unix/alias_protection.h` partitions each writable host protection
request into complete alias pages and ordinary pages. `virtual_ios.c` applies
RX only to live aliases and the requested protections to ordinary pages.
This happens inside the original protection operation, eliminating both the
RX spill and the intermediate writable permission on the RX alias. The
existing RW sibling, Wine metadata and FEX invalidation path are preserved.
The ordinary nonoverlapping path still makes its original protection call.

The subsequent load at `libcef+0x22d35a3` is genuinely `mov eax,[ecx+4]` with
ECX zero, producing host address `0x500000004`. The capture does **not** prove
whether earlier alias incoherence caused that null value. Darwin COW
detachment and an independent Chromium compatibility failure remain possible.
This patch neither maps the null page nor changes exception delivery.

`tests/host/check-alias-protection.py` reproduces the old spill as a failing
child process using real mappings. It then exercises the production splitting
helper and alias lookup, four concurrent neighboring writers, 3,000
transitions, shared RX/RW coherence, read/no-access cycles, 4 KiB metadata,
protection errors, and alias retirement followed by reuse of the same address.
No tested mapping combines writable and executable permissions. The host
fixture models shared backing; it does not reproduce Darwin's exact
`vm_remap` implementation or prove the later null read is resolved.

## Fix 2: retire private CPU state on abnormal native exits

For browser owner `0x500310000`, lease 5, the capture records 68 initialized
FEX threads and 57 native exits, leaving 11 native threads. Only four CPU
states completed guest-side teardown: this accounts for 64 retained
CallRetStacks and lookup caches, including 53 belonging to exited threads.

The native abort/pipe-EOF tail released verified shared holds but did not
invoke `MadeiraRetireThread`. Foreign `BTCpuThreadTerm` deliberately avoids
freeing a victim's state on iOS while that victim might still run. The new
native terminal callback invokes the normal destruction path on the **same**
thread, before its native lifetime count is decremented. It unregisters the
sweeper, deletes frontend/GDT/private CPU state, releases the CallRetStack and
lookup cache, and finalizes the thread's CRT heap.

`build/fex-compat/thread-retire.patch` adds the native ARM64 export and
registration. `virtual_ios.c`, `process_ios.c` and
`fex_hold_release_abi.h` validate the exact executable, nonwritable export,
owner PEB, current thread and live lease. A recycled PEB cannot authorize an
old callback. Busy registry locks and ambiguous/exclusive FEX holds refuse
cleanup; they are never forcibly unlocked.

CallRetStack and L1 lookup-cache mappings are private per-thread resources.
Compiler pools, shared code buffers and rpmalloc spans can contain live
cross-thread allocations. CRT finalization queues a heap for reuse; it does
not unmap all its spans. Whole-owner reclamation continues to require the
same lease, process exit, zero native threads and completed CPU callbacks.
This patch preserves the 8 GiB arena and physical/JIT budgets.

### Complete the native process lifetime

The remaining 11 native threads are ten address-alert waiters and one
nonalertable infinite `NtDelayExecution`. These waits have no Wine server
socket to observe closing. Wineserver's signal-based termination does not
terminate these same-task iOS threads. Also, server-side process death had
only notified Steam handoff, leaving the native owner marked active.

`build/wineserver/stage-steam-lifecycle.py` now stages thread-death and
process-death notifications. Native TLS records in
`native_thread_lifetime.h` and `thread_ios.c` match TEB, PID, TID, owner and
lease. A server kill sets the matching cancellation flag and sends the normal
native thread alert. Process death marks the matching group exiting; it does
not reclaim anything itself.

`tools/build/stage-native-thread-exit.py` stages cancellation checks at native
wait boundaries. Nonalertable sleeps use the existing alert wait while
preserving their deadline and ignoring ordinary alerts. There is no periodic
polling or extra timeout. Before aborting, the current thread removes its own
abandoned PE64 stack waiter entries from the shared futex table under its
existing queue locks. Other waiters remain intact. The original termination
status is preserved. No foreign CPU cleanup or Mach thread termination is
introduced.

This is cooperative cleanup at the observed wait boundaries. A thread stuck
in unrelated native code or an unknown exclusive lock still requires
diagnosis and remains quarantined. The patch does not claim arbitrary
asynchronous native termination is safe.

### Regression coverage

* `check-fex-thread-retirement.py` executes the staged retirement function,
  exported callback, actual CallRetStack destruction and CRT finalization
  against an 8 GiB ownership model. Counts go from 64 to 11 to zero while a
  shared payload remains valid. Twenty-five failed-browser/successor cycles
  allocate 128 aligned 16 MiB successor blocks per cycle alongside a live
  2 GiB parent baseline, without stale-owner growth. Foreign, busy and held
  states refuse cleanup. Allocator/backend stubs model their ownership;
  this is not a full FEX or Steam runtime.
* `check-native-thread-cancel.py` uses 64 real pthreads, the production native
  kill/lease functions and staged cancellation/delay functions. It covers
  killed address waits, infinite sleeps, removal of abandoned stack nodes,
  survival of a sibling node, ordinary alerts during a finite nonalertable
  sleep, stale identities and ambiguous PID rejection.
* Existing FEX view-lifetime tests cover an in-flight callback preventing
  reclamation, lease reuse, sibling owners and root-exit-42 Steam handoff.
  Registration, startup failure, process isolation, packaging and production
  export checks include the new callback. All three new tests run in the
  GitHub Actions embedded host-check gate.

Diagnostics are bounded: `[alias-prot-v2]`, `[fex-thread-retire-v1]`,
`[fex-exit-v1]` enter/return and `[native-thread-cancel-v1]` identify the
changed paths. Existing owner/arena census and compact exception diagnostics
remain enabled.

## Device acceptance remains pending

Compilation and host regressions cannot establish native Steam success.
There is no attached iPhone execution environment for this work. Install the
candidate as an update using the existing iPhone signing workflow; preserve
the bundle identifier, prefix, saved login and installed games.

Run Steam for **at least five minutes after login**, exercise clicks and
actual Library navigation, and capture the same bounded diagnostics. Acceptance
requires no unhandled Chromium faults or `0x500000004` read; no FEX
`STATUS_NO_MEMORY`; per-thread private reservations returning to their live
baseline; no abandoned webhelper owner with stranded native threads; and
responsive, correctly rendered Library content. Only a real device run can
confirm these conditions. Library and authenticated CS2 launch remain
unverified. No Steam JavaScript, account data, CS2 files, controller behavior,
authentication or VAC requirements are changed.
