# 64-bit Steam: signing limit and reverse mixed-mode child loader

The next uploaded capture (Wine launch at 15:52:13 on 2026-11-02) matches
IPA UUID `3DF3028A-A24D-3CE5-9C3D-B98583BAD5E6`, source `fb62aab`, Actions
[41463797862](https://github.com/letsdothisagainx/Madeira/actions/runs/41463797862).
Steam is now AMD64 and requests `cef.win64/steamwebhelper.exe` with build ID
`1792618285`. AppID 730's local manifest and executable remain present.

## First failure: real address-space exhaustion

Both installed entitlements and the embedded provisioning profile report
`extended-va=0` / `profile-extended-va=0`. The kernel map ends at
`0xfc0000000` (63 GiB). The largest free interval is about 25 GiB. The first
64-bit webhelper fails three fixed 16 GiB random-address requests and then
two contiguous `0x7ffff0000` reservations (32 GiB minus 64 KiB), returning
`STATUS_NO_MEMORY`.

`chrome_elf.dll+0xdc104` deliberately traps during initialization; Wine then
reports initialization failed with breakpoint status `80000003`. This precedes
browser readiness and any CS2 process. It is not evidence that CS2's executable
or login data disappeared. It is not physical RAM exhaustion.

The delivered IPA already requests
`com.apple.developer.kernel.extended-virtual-addressing` in
`app/Madeira/Madeira.entitlements`. Its absence in both the installed signature
and provisioning profile is a signing/profile limitation; another identical
entitlement entry or a larger FEX RAM budget cannot grant it. The iPhone signing
workflow must retain that entitlement and use a provisioning profile that grants
it. The update screen now surfaces that requirement. The app does not fabricate
a reservation, shrink Chromium's returned allocation, disable its checks, or
claim that a profile change has already happened. An extended map is necessary
for this observed layout; successful browser startup still needs a device run.

## Second failure: hybrid ntdll copied into a native child

An i386 child (TID `00bc`, PEB `0x400310000`) then runs native `wow64.dll`.
Its native call reaches a private copy of the session's hybrid ntdll at
`ntdll.dll+0x923d4`. The logged instruction stream contains x86 bytes
`48 8b c4 48 89 58 20 55 ...`, interpreted as ARM64. Illegal-instruction
delivery recurses through a null read in that same foreign loader copy.

`wine_ios_child_main` supported the forward architecture transition only:
an AMD64 child under a native ARM64 session got a fresh hybrid ntdll. All other
children cloned the session ntdll. After Steam migrated to AMD64, that clone
source was hybrid, although an i386 child's native host and a pure ARM64 child
need native ARM64 ntdll.

The loader now records the actual session ntdll PE machine once, independently
of the temporarily mutable startup image information. It clones only compatible
native loader images. In either cross-architecture direction it maps a fresh,
process-owned ntdll of the correct architecture, wires and syncs dispatchers,
TSD offset and FEX arena exports, and publishes its callbacks only after required
exports and machine/CHPE validation succeed. A WoW64 host receives its own
guest32 startup block in its private native ntdll. Parent images and surviving
siblings remain unchanged. No FEX submodule, allocator budget, installed game,
prefix, Steam executable or authentication file is changed by this patch.

The common `cc cc 0f 0b` trap sequence does not identify a BackupRefPtr assertion.
The old unconditional label and interpretation of two raw stack slots were
incorrect for this capture. Diagnostics now report the bytes and raw offsets
with `subsystem=unresolved`, preserving normal exception delivery.

## Validation

The new test compiles the production selector and private loader. It checks
both transition directions, repeated native WoW64 owners, immutable parent and
surviving child data, private startup blocks, EC-only dispatch swaps and
metadata redirects, and failed mappings/machines/exports before publication.
Existing process/alias ownership and thread-retirement checks remain applicable.
The final package gate requires the new child-loader and neutral trap markers.

This patch addresses the secondary native child defect. It does not solve the
missing provisioning entitlement, prove the secondary loop is absent on the
iPhone, or establish that Steam/Chromium/CS2 now starts successfully. Re-signing
with the needed capability, a normal responsive Steam login/Library session,
and authenticated CS2 process creation remain device acceptance work.

## Follow-up: the 16:58 capture tests the new loader

The next capture matches UUID `6A0F494F-A17F-3B9F-A084-5936FC6A1321`, source
`c48b103`. The private native ntdll is selected and reports `ready=1` for the
i386 helper owners. That does not establish successful helper initialization:

* The first native helper faults at `wow64.dll+0x1d124`, storing to `0x480`.
  `process_init` queried `ProcessWow64Information`, received a null PEB32, then
  addressed `WOW64INFO` at `PEB32 + 1`. The Unix current-process query still used
  session-global `wow_peb`, which concurrent child startup/retirement can change.
  It now uses the calling thread's actual WoW64 TEB and native PEB. Native and
  AMD64 callers return zero; remote-query behavior is preserved.
* A later helper calls `kernelbase.dll+0x80004` as ARM64, but the logged bytes are
  x86 (`48 8b c4 48 89 58 20 55 ...`). A correct private ntdll alone does not fix
  the prefix's hybrid `system32` DLL selection. The builtin resolver now selects
  the ARM64 PE version of a Wine hybrid DLL for a native caller, with an explicit
  machine check. Missing/incompatible replacements fail normally. Application
  DLLs, i386 DLLs, AMD64 mappings and hybrid siblings keep their existing paths.

The new regression fixtures execute those production query/resolver paths,
including concurrent process identities, disabled/native overrides, failed
replacement mappings and unaffected sibling architectures. Package validation
requires both new diagnostic markers. No allocator or protection budget changes
are part of this follow-up.

The first Chromium failure still precedes these helper faults: a 32 GiB reserve
cannot fit the observed map (largest gap 31,744 MiB), and the signature/profile
still report extended virtual addressing disabled. Both helper owners do reach
retirement and report zero remaining views. The native-child corrections must be
retested on the phone; Chromium readiness, Library interaction and CS2 launch
remain unverified and blocked by the observed address-space shortage.

## Follow-up: native cleanup re-entered the active syscall frame

The 17:33 capture tests UUID `E119B5B7-610A-3A97-BB6B-EA289FDC6C86`, source
`4693944`. The WoW64 queries now return each child's own PEB32, and native DLL
replacement succeeds. Neither the earlier `0x480` write nor the x86 kernelbase
entry fault recurs. A separate cleanup fault is now exposed:

1. The 32-bit OpenGL helper cannot import its genuinely missing SDL2.dll and
   terminates with `c0000135`. The 32-bit Vulkan helper separately returns 1.
2. Unix exit calls the registered FEX retirement callback directly.
3. The callback frees its call/return stack and decommits an allocator span,
   issuing `NtFreeVirtualMemory` from inside the still-active Unix exit call.
4. The ARM64 syscall dispatcher reloads the same TEB syscall frame and switches
   onto its stack, overwriting the active caller. The native ntdll stub's RET
   then has LR=0; the capture repeats native PC=0 faults before retirement.

The retirement callback's native ARM64 address was valid. The error was the
missing Unix-to-PE transition, not an EC dispatcher slot requiring fabrication.
Both hold-release and retirement callbacks now use Wine's existing nested user
callback transition. It chains a fresh syscall frame, executes the PE callback
on the owned native user stack, and restores the caller's frame and registers
before owner retirement. Invalid stack/owner contexts refuse the callback with
bounded diagnostics. The reused transition also initializes its fresh restore
flags and correctly packs FPCR/FPSR into separate halves of its saved word.

Regression tests execute the production wrapper and ARM64 transitions with
nested syscalls, dirty reused kernel-stack memory, preserved outer frames and
registers, and rejected invalid stacks. This does not supply the missing SDL2
dependency or remove Chromium's genuine 32 GiB reservation failure. Extended VA
is still absent from this capture's signature/profile; Library and CS2 cannot
be called fixed. The next phone run must validate cleanup without a null-PC loop
and independently establish a sufficient signed address map for Chromium.
