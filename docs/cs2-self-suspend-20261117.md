# CS2 self-suspend correction and remaining evidence gap

Evidence: Run Diagnostics exported `2026-11-17T02:53:24Z`, package source
`bf0f0a0a2b682c59658d318e8491dd4d5a27b0c3`, native UUID
`2993B2AF-ED95-3CF1-B1C3-45198FBEE883`. The attachment is not committed.

## Established facts

The CS2 process is 032c and its initial thread is 0330, TEB 0x70ad050000.
The server resolved a real self-suspend, incremented the count 0 to 1, and
the client entered its cooperative suspend wait around 21:49:10. Logging
continues through 21:52:13 with the initial thread no longer consuming CPU.
Sampled resume logs cannot establish that no resume was attempted.

`MADEIRA_REAL_SUSPEND=0` disables a persistent Mach hold, not the Wine count
or self-wait. `held=0` does not mean the guest is runnable. The preceding
`srv-getctx-v2` record comes from suspend_thread -> stop_thread -> synchronous
Mach snapshot; it does not establish a separate GetThreadContext request.

The saved PC is a valid executable-copy alias mapping to
`ntdll.dll+0x89050`. The same saved value appears during startup. It is not
the suspension caller, an invalid address, or proof of a current x64 loop.
No contemporaneous caller stack, fatal exception or failed-resume target is
captured. Caller purpose and intended resumer remain **unidentified**.

The core wait checks suspension before timeout. A final legitimate resume
decrements the count and wakes the thread; a resume arriving before wait
publication is also handled. No lost-wakeup or count defect was established
for the observed stop. These paths did not change from 7e6ce444 to bf0f0a0a.

## Production correction

The same client path contains a reproducible identity defect: it tries to
recognize a real/duplicated self handle using ThreadBasicInformation, which
requires query rights. A handle with the documented THREAD_SUSPEND_RESUME
right can therefore suspend itself successfully and then incorrectly return
running because that query fails. This is the opposite of the captured stop;
it is **not** claimed as its cause.

The server now places an authoritative self tag in four existing reserved
reply bytes after resolving the actual target and performing the operation.
The fixed packet remains 16 bytes and count stays at offset 8. The tag has
no allocation, additional access requirement, second handle lookup, or count
change. A close/reuse after the operation cannot change which object the tag
describes. Older clients ignore it; older zero-tag servers use the existing
object-comparison operation without requiring query rights.

The owned stager preserves pinned Wine sources and composes after the async
APC correction and before lifecycle staging. Suspension nesting, physical
holds, ordinary access errors, status values and wake rules are preserved.

## Bounded capture authorized for the unidentified caller

The observer watches at most 16 self-suspending target identities, keyed by
process, thread and TEB. It records one API-entry frame/caller-candidate set
per target from the active native syscall frame, not GetThreadContext(self)
or a stale CPUArea guest snapshot. It reads at most 64 stack words and emits
at most eight code-map address candidates; arbitrary stack data and strings
are not exported. These candidates are not represented as a verified unwind.

Actual server resumes, including internal ones, are observed after count,
Mach release and wake operations. Each watch reports the first eight and
its first final decrement independently; process suspension is separate.
Failed resume APIs are capped after a watch exists. Publication and paths
with a persistent Mach hold perform no logging, mapping or heap work. The
observer never suspends, resumes, changes context, clears counts or invokes
a game callback. Read failure only reduces diagnostic detail.

`self-suspend-identity-v1` and `self-suspend-flow-v1` must both survive native
linking and exact app/IPA packaging. This is compiled-artifact validation,
not a successful iPhone execution result.

## Verification and limits

The source-extracted tests run real cooperating pthreads, with controlled
handle/RPC and wait-transport adapters. They reproduce the old restricted
self-handle failure and verify actual continuation after legitimate resumes,
early-resume races, nested counts, duplicate/pseudo/reused handles, process
scope, startup-created suspension and genuine failure returns. Observer
tests cover bounds, failed reads, aliases, concurrent process identities,
held-path safety and unchanged context bytes. Apple Mach suspension and
ARM64EC execution are not emulated by these tests.

No self-context handback rewrite was shipped. Replacing an existing cached
context could discard legitimate peer edits; this separate limitation needs
ownership-aware work and evidence of use in the failing path.

The captured 150-second connection-to-activation interval precedes the stop
and remains a separate loading problem. This export has no new timeout,
idle-kick or VAC rejection. Memory reached about 5753 MiB, buffer reuse was
90%, and no texture OOM was observed. No memory, DXMT, JIT pool, Steam, input,
network protocol or user-data changes are included here.

This build does **not** establish that the team-picker freeze is resolved.
Device acceptance still requires a legitimate remote match, responsive team
selection, continuous frames and actual gameplay.
