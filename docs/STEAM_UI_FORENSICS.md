# Genuine Steam UI investigation (2026-10-30)

This branch is a diagnostic candidate. It does **not** establish that Steam's
login/library appears on an iPhone, or identify the complete cause of the hidden
UI. The supplied report excerpts were available; the actual 14,837-line
`steam.exe-2026-10-30_14-47-17.txt`, Steam's CEF log, and installed Valve PE files
were not available in the cloud workspace. An attachment/path was requested.

## Exact native fault identified

The previous IPA from run [40991877110](https://github.com/letsdothisagainx/Madeira/actions/runs/40991877110)
was inspected inside Actions without executing it. Its native dylib has UUID
`C785040B-848D-37AD-985C-832B8923F782`, exactly matching the device report, and
SHA-256 `08009fe81c05e24e505faa090693721aed5848553bc9676bfbf07602822828d5`.
Inspection evidence is in run
[41112452094](https://github.com/letsdothisagainx/Madeira/actions/runs/41112452094).

`invoke_system_apc` starts at unslid `0x11baf5c`. At offset `0x578`, instruction
`0xb9000676` is `str w22, [x19, #4]`; the following instruction is
`stlr w21, [x19]`. These implement `set_async_iosb`'s **32-bit** Information
write followed by the release store of Status in `APC_ASYNC_IO`. A write to
`0x10004` therefore means the completion uses an IOSB pointer of `0x10000`.
The instruction does not address memory relative to x18. x18 being zero does
not by itself identify a TEB failure.

The pointer's producer, the affected pseudo-process and the reason the 32-bit
layout was selected still require the original log and/or the new publication
trace. No slot swap, layout inference from pointer contents, pointer repair,
fallback TEB, or exception suppression has been introduced.

## Observation added to the candidate IPA

* `[steam-ui]`: ShowWindow command/result and unchanged flags, SetWindowPos
  before/after, style, ancestor visibility, parent, owner, owning pid/tid,
  caller tid, surface and the HWND that owns that surface. Only exact
  `steam.exe` and `steamwebhelper.exe` callers are selected. There are 64
  window/process slots and eight records per event kind per slot; show/hide
  transitions retain a separate budget from position churn.
* `[steam-ui-host]`: a read-only snapshot on the UIKit queue after that Wine
  thread queued its frame updates: backing layer, actual hidden/attached
  state, geometry, whether GDI contents exist, Metal layer and compositor
  attachment. It records no text or pixels and never forces a window visible.
* `[iosb-register]`: the existing file/socket publisher's native IOSB and
  selected completion pointer, API name, owning pid/tid, native TEB/PEB,
  guest-window base and WoW64 I/O predicate. The original pointer is returned
  verbatim. Native and WoW64 layouts are not changed.
* `[async-apc]`: the same ownership metadata and wire IOSB before the genuine
  callback, followed by its actual result if it returns. CPU area and TLS slot
  14 are addresses only. Ordinary and low-address observations have separate
  eight-record budgets. No user data or I/O buffer contents are logged.
* `[guard-protect]`: bounded metadata for actual failed Wine PAGE_NOACCESS
  requests, including NTSTATUS, normalized range, view, host page size and
  Mach protection query. It does not execute in the Mach exception path or
  change a protection result. The generic FEX warning is no longer universally
  labelled harmless by the app's log viewer.

The C I/O sources are staged with a diagnostic include; the pinned Wine and
FEX submodule trees remain unchanged. Failed compilation of these staged
producers stops packaging instead of using an old object.

## Other reported symptoms

The existing ShowWindow driver already returns `~0u`, preserving Wine's show
flags. Existing visibility/coordinate tests, including hidden ancestors and a
normal Sign In show, pass. A hidden internal Chromium window is not evidence
that host presentation should make it visible. The new trace distinguishes a
missing show request, Wine visibility, and host layer state without modifying
them. It does not prove Chromium reaches BrowserReady or finishes UI startup.

The Steam launcher already forces CEF single-process mode, refuses `--type=`
children and adds V8/CEF flags. These restrictions have not been changed on a
new hypothesis. Loader-lock timeouts must be correlated with the owning
process, thread 01cc's stack and later progress before diagnosing a permanent
deadlock; no loader lock has been bypassed.

FEX's Windows `AllocatorHooks.h` implements its boolean protection wrapper as
`::VirtualProtect(...) == 0`, whereas `Common/WinAPI/Alloc.cpp` returns
`WinAPIReturn(NtProtectVirtualMemory(...))`, true on success. That can invert
the guard-page success indication and emit the warning after success. The
Apple-native implementation separately tests POSIX `mprotect(...) == 0`,
which is correct. The same message also has two source emitters. Thus the
reported warning cannot establish real protection failure or UI causality
without identifying its emitter and actual status. FEX source has not been
changed; its AGENTS.md disallows AI-generated contributions.

`0xC000001D` alone does not distinguish an unsupported instruction, deliberate
UD2/assertion, or a bad branch. The authentic hardware-helper PC/bytes and
process/thread association remain needed. No illegal instruction is ignored.

Likewise, the SDL2 error needs the genuine gldriverquery import graph,
architecture, current directory and DLL search results. There are no Steam
files in this workspace to inspect. No DLL was downloaded, replaced or
fabricated, and this optional probe's error has not been claimed to cause the
main UI failure.

## Validation and next device capture

The focused tests compile the production diagnostic helpers/ShowWindow
wrapper and Wine's existing IOSB publisher/completion. They check concurrent
budgets, exact image matching, unchanged command/flags/placement/result,
both IOSB layouts, and an invalid completion that still produces a genuine
fault in an isolated child. Existing hidden-parent, child geometry, Dock,
embedded signal and SCM tests remain in CI. The IPA check verifies the
compiled native diagnostics and existing real i386/SCM probes are included.
These are host and artifact tests, not a successful genuine Steam session.

Cold-launch Madeira for a fresh bounded trace budget, then start the genuine
Steam client directly. Preserve the original complete log and, if available,
Steam's CEF/browser startup log. The decisive evidence is the owning pid/tid
for the bad completion, its `[iosb-register]` producer, thread 01cc's progress,
and the show/host records for the real login/library window. The original log
can resolve some of these questions before another device run.

No bundle ID, entitlements, signing configuration, prefix contents, Valve
binaries, Steam/CS2 installation or JIT memory limits are changed by this
branch. Steam UI usability and Dock/CS2 performance still need on-device
verification. Successful Steam or service startup does not guarantee VAC
compatibility; VAC testing remains separate.
