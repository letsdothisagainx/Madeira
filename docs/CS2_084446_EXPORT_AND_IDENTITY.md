# Run export and VM identity correction

Baseline: `d6d40213695db7b1ab0f7a9b1dd95edbcda0d7ec` and the supplied
`madeira-log(20261110-084446).txt` / five-file VAC diagnostics archive.
The device reaches CS2's menu without executable-pool exhaustion. The existing
1152 MiB pool, 768 MiB image arena and 384 MiB code arena remain unchanged.

## Export Run

The run control previously stored its task result, sheet and failure state in
the menu button's SwiftUI state. Dismissing or reconstructing that menu could
remove the presentation owner before asynchronous collection finished. The
controls window also conditioned modal hit testing on active controls. The old
build records no export lifecycle, so the precise failing stage of the supplied
device tap cannot be recovered retrospectively.

The run branch now uses an app-lifetime main-actor coordinator. It captures the
requesting scene, retains the operation and file, and presents a native activity
controller in a temporary window above game controls. It supports landscape
popover anchoring, restores the previous key window, reports bounded errors and
records requested/archive-created/share-presented/failure events. The working
VAC exporter retains its existing UI and archive format.

Run collection now reads and sanitizes bounded chunks into owned private spool
files. Recent-record ordering is staged on disk. ZIP compression streams from
those files with incremental CRCs and data descriptors. The output uses the same
exclusively created, no-follow file descriptor through completion. It does not
materialize a large archive or complete log in memory. Sources are read-only;
partial exports are removed on failure or cancellation. Source-size limits,
redaction and omitted/changed-source metadata remain explicit.

The native UI regression compiles the production presenter and exercises the
actual menu action, disappearing origin, active/ended sessions, landscape,
native Files picker, actual save into the owned host's Documents folder,
cancellation, window restoration and storage failure. Both the supplied ZIP and
the native saved copy require independent CRC and exact payload validation. Its
old-UI fixture is pinned to the literal D6 source. The archive producer alone is
controlled in that test. A simulator save is not a save on the user's iPhone.
See `tests/ios-run-export/README.md`.

## Ordinary Windows compatibility defect

`ios_jit_note_image_unmapped()` invalidates a mapping generation but retains old
addresses for late-return/unwind safety. Previously, `NtQueryVirtualMemory()`
unconditionally used permissive reverse translation before dispatching the
information class or checking the target process. After PE address reuse, a
query about the retained RX copy could consequently describe a replacement DLL.
Remote-process queries could also borrow the caller's alias translation.

Public Basic/Region/MappedFilename/Image queries now require a live mapping,
correct target-process lease/ownership and unchanged mapping generation before
and after the underlying query. Authorized remote filename/image queries retain
the target's genuine mapped-file identity. The canonical target PEB/PID comes
from Wine's server, before public old-WoW64 PEB presentation adjustments. A
blocking, read-only registry lookup validates that owner/PID lease without
adopting the caller into the remote process. No registry lock spans IPC.

Real handles retain their original backend access checks and are rechecked for
close/reuse after IPC. Invalid or wrong-target aliases use the real backend's
answer. Caller-specific low/subfloor address translation stays self-only.
Remote Basic retains its existing target APC path; remote Region remains
unsupported by the existing backend. No new result is fabricated. Private Wine protocols, working-set
buffer contracts, generic unwind translation, allocator/protection policy and
signature/signing-level results are unchanged.

The production-path test executes the pinned old entry point and demonstrates
incorrect replacement-file identity, then tests the correction, concurrent
retirement/reload, real/remote handles, handle reuse, canonical WoW64 identity,
registry contention without ownership adoption, backend errors and private protocols.
This is a demonstrated address-to-file identity bug. No supplied evidence proves
it causes the VAC popup.

## VAC evidence and limits

The supplied run identifies the failing SteamServiceConnect load in x64 Steam
PID 0068, while the selected SteamService.dll has machine type 014c (x86).
The genuine x86 service separately starts, connects to its SCM control pipe and
reports state 4/result 0. Forcing that DLL into the x64 process is incorrect.
Proprietary Steam client/service IPC beyond the observed SCM handshake remains
unmeasured; the failed optional-looking load is not proven harmless or causal.

The available game content checks demonstrate local consistency and embedded
key consistency. They do not authenticate the installation independently against
Valve. Existing **Verify files** requests real Steam `steam://validate/730`;
Steam owns verification, repair and completion. No completed authenticated Steam
verification result or rejected file is present in the supplied evidence.

Steam login, networking certificate authentication, relay readiness and local
loopback are distinct from VAC approval. A successful real VAC-secured server
connection remains the only acceptance test. There is no basis here to name a
specific private Valve requirement or declare secure play impossible. Windows
CS2 under this iOS compatibility stack is not established as a supported secure
environment. No VAC code, game binaries, module visibility, signatures or trust
decisions are modified by these changes.

## Validation and installation

Production files changed: `app/Madeira/RunExportPresentation.swift`,
`SteamGameDiagnostics.swift`, `ContentView.swift`, `RunDiagnostics.swift`,
`SavesAndShortcuts.swift` and the Xcode source list;
`build/ntdll-unix/virtual_ios.c` and `thread_ios.c` for query identity only.
Tests and the isolated native UI workflow accompany those changes.

The host regressions execute actual production Swift exporter/presentation
state and Wine query code. The large-source test uses a generated 256 MiB file
with 64 MiB selected; its RSS figures are host measurements, not iPhone gameplay
or whole-session memory figures. Native UIKit execution and complete packaging
are separate GitHub Actions gates. CI does not establish a real iPhone save,
VAC acceptance, CS2 rendering correctness or an FPS improvement.

Install the new IPA over Madeira with the same existing iPhone signing method
and application identity. Do not uninstall or reset the prefix. Bundle identity,
Steam data, game files, input mappings, 800x450 display and DXMT are unchanged.
These commits are independently revertible; reverting the query correction does
not require reverting export. Reverting UI requires removing its project source
entry together with the presenter and restoring the run button branch.

On the iPhone, exercise Export Run both during gameplay and after stopping,
choose Save to Files, then reopen the resulting ZIP. For VAC, retain the existing
Mark VAC Error and Export VAC Diagnostics flow and report only a genuine secure
server acceptance as success. Graphics/FPS remain unresolved and unmeasured in
this change.
