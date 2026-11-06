# Steam VC++ installation: November 6, 14:15 capture

The capture identifies installed source `d64b6d94627a1ff620445d85c7292d239dcecab7`.
Steam service, browser verification, IPC and AppID 730 installscript startup
work. CS2 itself is not created in this run, so the D3D11 strong-CAS correction
has not yet been retested on the phone.

## Device evidence and the verified source defect

The x64 MSI cabinet callback calls CreateFile with CREATE_ALWAYS, read/write
access, no sharing and normal non-directory synchronous options. Its native
request is FILE_OVERWRITE_IF (5), access `c0100080`, options `60`, for
`C:\windows\system32\vcamp140.dll`. NtCreateFile returns `c000000f`; the
callback reports Win32 error 2, FDICopy fails, InstallFiles returns 1603 and
Burn reports `80070643`. The elevated, cleanroom and original installer chain
genuinely propagate 1603. Individual package rollback/registry outcomes are
not independently captured.

An exact installed-image inspection in Actions 42236108362 verifies native
UUID `7B237A38-148F-33B7-BA12-BFD16B7AC3E9` and SHA-256
`4c47b84a74aca69b14b361cd0100a29596c79207aafe0233a47c06bbe7b5fbe7`.
Its open_fd already adds O_CREAT after readonly-link removal. The old log
prints before retry-open, so adjacent readonly-link messages do not establish
that vcamp's retry succeeded or even that they belong to vcamp.

The production path reproduces an identical failure for a dangling bundle
link: O_CREAT follows the link into its missing old app container and gets
ENOENT, correctly translated to `STATUS_NO_SUCH_FILE`. The same request for an
ordinary absent file in the same existing directory creates a real file.
The existing readonly replacement intentionally handles access/read-only
errors for existing targets, not dangling links. No global errno or NTSTATUS
translation change is appropriate.

Prefix preparation refreshes the selected Wine DLL farms, but an aarch64
bootstrap skips the x64 VC-runtime overlay. MS-only DLL names such as vcamp140
can consequently retain absolute links from an earlier app-container UUID.
The current package preparation requires vcamp140.dll in its genuine VC-runtime
catalog. The captured file's lstat/readlink state is absent from the old log:
this exact on-device link target remains unverified, rather than assumed.

## Focused correction

`StaleRuntimeLinks.h` runs after the root launch is claimed and before client
injection or guest-thread creation. It considers only system32/sysx64 DLL
leaves backed by regular files in the current trusted VC-runtime catalog.
An old target must exactly match this app's historical bundle/container/farm
layout. Directory traversal never follows arbitrary symlinks; permission
errors and reachable foreign link components are refused. Only a proven
missing target is repaired.

The trusted app/prefix anchors are opened directly; the repair does not need
directory-listing access to other app containers. Old-target absence uses
metadata-only checks and permission errors remain unknown, not absent.

The stale link is moved exclusively to a fresh private prefix quarantine,
then its identity and target are rechecked. An unexpected concurrent capture
is restored without overwriting another file, or retained for diagnosis.
Installed regular DLLs, live links, user links and signed bundle bytes are
preserved. The ordinary Wine/MSI create then writes the authentic CAB payload;
no DLL is synthesized, no registry installation is invented and no installer
status is changed.

The wineserver failure probe reports bounded relative system-DLL names,
original errno, parent state and leaf/target state. It preserves errno and
does not change the file operation. Readonly-link logs now identify the unlink
phase accurately instead of claiming that the later open has completed.

## Separate observations and acceptance

The earlier worker's protected-null wide-string read reaches Wine exception
dispatch and that worker exits normally; MSI continues afterward. It is not
established as the cause of this file failure and no exception handling changes
are made. Current DXSETUP starts, but the capture ends before a current exit
result. Replayed older DirectX.log failures are not a result for this attempt.

Host tests compile the production repair on real files and cover ownership,
no-follow traversal, retained quarantine, replacement races, ordinary installed
files and private bounded output. Dedicated Wine integration builds owned
PE32/PE64 clients and actual MSI databases with embedded MSZIP CABs. The original
failure, real NtCreateFile handles, extracted bytes, registration, repair,
rollback and architecture routing are tested in a disposable prefix. Linux
Wine control results do not establish official VC++ success on iOS.

Validation 42240370358 passes Linux and Apple filesystem checks (32 contracts)
and the actual owned Wine MSI/CAB flow. The old request returns `c000000f` and
actual cabinet_copy_file error 2/FDICopy/InstallFiles 1603. After one production
repair, the native request returns success with FILE_CREATED and a real handle;
MsiInstallProduct returns 0, CAB bytes match, and product state is installed.
Repeat repair is a no-op. Genuine MSI repair, uninstall, observed new-file
rollback, sharing denial, invalid parent, readonly and foreign-link controls,
PE32/PE64 placement and an I386 frontend installing an AMD64 component pass.
The test does not claim rollback restores arbitrary overwritten old-file bytes.

A new phone run must confirm the real redistributable completes with genuine
status/registry state, establish the current DirectX result and reach cs2.exe.
Only then can retained-expected atomic recovery, real D3D11/DXGI creation and
the first Metal game frame be accepted. JIT/FEX, pool size, authentication,
graphics configuration and existing game data are unchanged by this patch.
