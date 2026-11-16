# Steam initialization stall after 6068cf7a

## Evidence boundary

The November 15 20:52 EST session used source
`6068cf7a6af164601eb3066a12267d5478b2c24d` and Steam client 1794536281.
That client version also launched CS2 earlier at 17:24:49. The current native
session successfully prepares the browser, starts genuine Steam and initializes
Chromium IPC, but does not record a new CS2 process or an App ID 730 GameAction.
Historical CS2 console and game-process records are not current-run results.

The successful earlier segment records connection-manager LogOn at 17:24:03,
Logged On at 17:24:05, GameAction at 17:24:09 and CS2 creation at 17:24:49.
The current captured connection log records connectivity tests at 20:52:50,
but no subsequent CM login/discovery or game launch. Sanitization can omit
secret-bearing rows; this absence does not establish an authentication failure.

CEF's observer receives one `apps:true, store:false` result, then a UI-text
evaluation times out. Its counters remain at seven packets and five replies,
without observed WebSocket traffic. CEF thread 0090 waits for over 130 seconds
at `libcef.dll+0xAC84102`, consistent with an SRW owners-halfword wait. The
export does not identify the lock's holders or prove why they did not release.
Observer timeouts are not a launch gate and are not themselves a proven cause.

No D3D11 texture allocator initialization or texture-admission failure appears
in this session. The 3,367 MiB peak occurred without CS2 and does not validate
the previous map-loading memory fix.

## Confirmed source defects corrected

### Address-wait stack lifetime

Wine's `RtlWaitOnAddress` registers an intrusive queue entry on the waiting
thread's stack. Both address wakers publish `entry.addr = NULL` while holding
the queue lock, before their final accesses to that entry. The waiter previously
read that field without the queue lock after its native wait returned. An
independent thread alert, timeout or allowed spurious return could let it skip
cleanup and return while the waker still unlinked/read its stack entry.

The waiter now always acquires the queue lock before conditional cleanup. Its
stack therefore remains alive until waker access has finished. The native wait
result, timeout conversion, comparison/size validation, FIFO selection and wake
operations are preserved. Immediate comparison-mismatch returns are unchanged.
The source overlay rebuilds native ARM64, ARM64EC and i386 ntdll implementations.
It does not change Valve binaries, force wakes, release held SRW locks, or
fabricate successful completion.

This is a reproducible compatibility defect in a primitive used by CEF. The
available export does not prove that this particular race caused the current
held-lock state or that correcting it restores Steam login on the iPhone.

### CS2 profile isolation

The CS2-only Automatic/Balanced profile had been appended to `DXMT_CONFIG`
before starting Steam. The log shows Steam consuming that option itself.
The genuine Steam bootstrap must retain the preceding baseline environment;
only the actual CS2 game child should receive its additional texture policy.

The profile is now carried as an app-owned private launch control. The native
process-creation path applies the optional rendering setting only to a validated
CS2 child with genuine Steam App ID 730 context, before loader imports. Other
environment entries and Steam's identity remain unchanged. Custom mip settings
retain precedence; unrelated launches clear the private control. No per-child
global Unix environment mutation is used.

The existing physical-memory admission, GPU-completed retirement, high-reuse
buffer policy, native BC accounting and visible quality choices remain intact.
The setting's involvement in the observed startup stall is unproven.

## Validation and remaining acceptance

Regression checks execute actual Wine wait/wake functions, including a paused
waker and independently completed native wait, and verify corrected lifetime,
timeout/status and wake behavior. Environment checks exercise the production
child merge, original Steam configuration, unrelated/probe launches, custom
settings and actual Swift preference persistence. Package checks require rebuilt
code for all three ntdll ABIs and exact app/IPA provenance.

Host and package results do not establish on-device startup, logged-on state,
map completion, memory headroom, frame rate or sustained multiplayer. Those
remain iPhone acceptance tests. The 1,152 MiB JIT pool, its 768/384 MiB partition,
Steam/browser integration, Wine prefix, installed game files, controls, UDP
transport, and run exporter are preserved.

Install over the current application with the same bundle ID and signing
identity; do not uninstall or reset application data. The source corrections
are independent and reversible without migrating the Wine prefix or game data.
