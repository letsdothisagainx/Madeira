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
