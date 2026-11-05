# Steam worker stall: native address floor

The November 5 capture identifies source revision `3914bed`. Its genuine Steam
service reaches state 4/result 0, then the authentic client starts with
`-applaunch 730`. Chromium eventually reports 155 applications including CS2.
Those working paths are not changed by this patch.

## Confirmed defect

`virtual_set_large_address_space()` lowered the iOS host allocation start from
above its 4 GB PAGEZERO region to `0x10000`. This is appropriate for other
platforms, but not for this iOS task. The existing query code already measured
`TASK_VM_INFO.min_address` as `0x104998000` in the same capture.

Later unhinted native allocations begin below that floor. The first WoW64
window clips the native search to 16 GB, so the separate high-address furniture
policy cannot raise its start. `try_map_free_area()` advances by 64 KB after
each kernel rejection in the unmapped prefix. Ten logged completed scans total
669,269 failed placement attempts; nine occur after worker 019c is created.
Each scan runs under `virtual_mutex` and reaches `mach_vm_map()` through
`anon_mmap_tryfixed()`. These are failed address placements, not proof of
physical-memory exhaustion.

The correction preserves the measured host floor during native large-address
initialization. It does not loosen allocation bounds, map the null page,
overwrite reservations, fake allocation success, or change fixed-address and
translated WoW64 requests.

## Worker context and evidence limits

Worker 019c uses TEB `0xfbfe20000` and ARM64EC CPU area `0x12f7c0000`; its logged
FEX ThreadState is `0xc2c001000`. A previous thread used the same TEB, so a TEB
address alone cannot establish identity. The sampler must distinguish sampled
host PC/continuation from saved guest state and check the target PID/TID/PEB.
Saved guest RIP is not automatically the currently executing instruction when
the thread is in native code.

The captured start address corresponds to tier0's exported `CThread::ThreadProc`
RVA `0x119e0`; filename, PE timestamp, image/text sizes and FEX module identifier
agree with the available official image. This is metadata correspondence, not
a full-content hash verification or identification of a particular queued job.

The existing capture does not contain a coherent guest stack for the hot worker
or the mutex address on which Steam's IPC thread later blocks. It therefore
does not prove that all observed CPU usage or the 15-second engine warning is
caused by these scans. The bounded additional context exists to resolve that
remaining question without large dumps or speculative timeout changes.

## Validation

The host regression executes the production floor query, large-address
initialization and native placement scanner against controlled Mach edges.
It reproduces the old below-floor retry prefix, verifies real placement after
the correction, and checks failure, caller-bound and WoW64 cases. The worker
context regression covers stale/reused TEBs, unreadable state and saved-versus-
sampled PC handling. Existing service and browser tests remain in the IPA gate.

The browser comparison uses the production observer expressions in a real host
Chromium with observation disabled and enabled, checking heartbeat progress,
read-only results and rejection of accessor side effects. It is not a causal
A/B test of Steam's CEF on this iPhone. The existing observer-off control remains
available; this patch does not change its default or claim that DevTools
timeouts establish a dead browser.

Device acceptance remains required: service running, responsive Steam/CEF and
Library/CS2 recognition, no sustained unintended hot-worker loop, engine
progress for at least five minutes, and a genuine result from Steam's CS2
launch request. A green build alone does not satisfy these criteria.
