# FEX code-buffer guard: confirmed unsupported protection

This guard is **not fixed**. The current Wine bridge honestly rejects its
protection request. An allocator build or a passing host test does not prove
that the iPhone has an effective code-buffer guard.

## Device evidence

The supplied `e02e86b85c034d0a43f64cf78a5876ad9733e7d6` capture contains 26
`Failed to mprotect last page of code buffer.` warnings. Its bounded protection
observer records eight failed guard requests, all with `STATUS_INVALID_PARAMETER`
(`0xc000000d`), no Wine view, and no kernel protection call. It also records
eight successful ordinary-view protection requests. The latter do not establish
that a direct JIT-pool carve has a working physical guard.

The first failed request, at log line 1203, is:

| Property | Captured value |
| --- | --- |
| Direct code carve | `0x346ffc000`, size `0x1000000` |
| Requested guard | `0x347ffb000`, size `0x1000` |
| Containing host page | `0x347ff8000`, size `0x4000` |
| Current / maximum host permissions | RX / RWX (`5` / `7`) |
| Wine view | absent |
| Protection status | `0xc000000d` |
| Kernel operation | `not-called:no-wine-view` |

Maximum RWX is a permission ceiling, not a current writable/executable mapping.
The observed current RX page has not lost execute permission in this event.
There is no kernel `mprotect` return or `errno` to diagnose for this request:
Wine rejects it first.

## Source contract

`FEXCore::Utils::FEX_PAGE_SIZE` is 4096. The pinned FEX `CodeBuffer`
constructor requests `ProtectOptions::None` for its final 4 KiB;
`CodeBuffer::UsableSize()` subtracts only those 4 KiB.
`CPUBackend::IsAddressInCodeBuffer()` similarly excludes only the final 4 KiB.
These three bounds agree with each other, but leave 12 KiB of usable code in
the same 16 KiB iOS host page as the requested guard.

The owned `thread-init.patch` already corrects the pinned Windows allocator
wrapper's reversed BOOL interpretation and supplies a valid old-protection
output. Reapplying that correction would not resolve this failure.

Wine's `NtProtectVirtualMemory` normalizes the request to Windows 4 KiB pages,
then searches for a covering Wine view. The direct `EC_CODE` carve path returns
pool addresses without creating such a view. Consequently the local decision
takes `STATUS_INVALID_PARAMETER` before `set_protection` or a kernel call.

Rounding this request down to 16 KiB would revoke access to 12 KiB that FEX
still considers usable. Returning success without changing protection would
also be incorrect. The host regression intentionally rejects both conclusions.

## What the regression executes

Run:

```sh
python3 tests/host/check-fex-code-guard-contract.py
```

The test compiles the actual pinned FEX constructor, destructor, usable-size
and address bounds; stages the real owned Win32 wrapper correction; and compiles
the literal normalization/view/commit/protection decision from Wine's production
`NtProtectVirtualMemory`. View lookup, commit lookup and protection callbacks
are explicit fixture boundaries. It does not compile the whole Wine syscall
dispatcher or claim to implement an iOS kernel.

Shared file mappings supply real RX and RW aliases. The direct-carve request
reproduces `0xc000000d` with zero protection-callback calls. The test executes
code immediately before the intended guard, proves the 12 KiB usable prefix,
and verifies that the failed guard remains readable, writable through its RW
alias and executable through RX. Those last observations are the known
limitation, not a successful guard test.

An ordinary committed-view fixture reaches the existing protection callback;
an uncommitted view and an injected protection failure retain their real status.
That callback test makes no claim about physical protection of ordinary 4 KiB
pages on a 16 KiB host.

## Requirements before implementing a physical guard

A safe implementation would need an agreed full-host-page red zone, matching
FEX usable/address bounds, real protection of both aliases, and unconditional
exclusion from Mach write emulation and stripped-execute recovery. Writes emitted
through the RW mirror must fault too. Normal reuse, oversized-carve reuse with
an interior old guard, owner retirement, NOP prefill and code-to-image transfer
must restore or safely retain every guard without handing out inaccessible code.

The existing `preserve-pool-rx-v1` policy deliberately keeps debugger-blessed
original RX pages executable throughout their lifetime. Historical execute
recovery code also records that restoring RX can fail on iOS. Neither the
current capture nor a Linux/macOS host test proves that disabling execute on a
guard and restoring it later is safe on this device. Physical RX guard changes
remain deferred pending that capability and lifecycle proof.

This finding does not establish that a guard overflow caused the Steam/CS2
failure. It establishes why these protection requests fail and what cannot
safely be inferred from their warnings.
