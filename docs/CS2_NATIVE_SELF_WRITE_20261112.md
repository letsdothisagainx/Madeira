# Native x64 self-write correction, November 12

## Evidence and scope

The `de910d34` phone export shows CS2 process `0380`, thread `0384`, calling
`WriteProcessMemory(NtCurrentProcess(), ..., 5, ...)` after a successful
`NtProtectVirtualMemory` transition. The write returns `STATUS_ACCESS_DENIED`.
The addresses resolve to x64 entries in the shipped Wine USER32, KERNEL32,
SHELL32 and the fresh child-private NTDLL image. The recorded caller resolves
to a KERNELBASE thunk; it does not identify the original requester.

The Unix implementation has a local self-write route for WoW64, but native64
falls through to wineserver. Madeira deliberately denies the remote Mach-task
write path for its same-task pseudo-processes. This also denies these legitimate
current-process writes regardless of their successful protection transition.
The blanket remote-write denial must remain in place.

The correction authorizes a bounded write only to the current owner's original,
private hybrid PE backing. Immutable map-time CodeMap and executable-section
evidence must identify the entire destination as x64. Logical write permissions,
actual RW/nonexecutable backing, owner lease, image generation, pool ownership
and exclusive mapping identity are checked. Shared sections, the global NTDLL
source used for S1 child cloning, native ARM64 instructions, executable-pool
aliases and foreign or unknown owners remain excluded. Existing write-watch
handling runs without the pool lock, followed by full identity revalidation.

Only the original PE backing changes; x64 bytes are never copied into the native
ARM64 executable copy. FEX reads the original x64 stream after reverse translation;
the existing PE instruction-cache flush invalidates translations. The file on
disk and its signature are unchanged. This does not implement arbitrary remote
or cross-process memory writes.

## Actual native Windows reference

Actions run [43150983664](https://github.com/letsdothisagainx/Madeira/actions/runs/43150983664)
executed an independently compiled, owned test DLL on native Windows x86 and x64.
Both completed 86 checks. Direct NtWrite to RX failed with `8000000d`; after a
real EXECUTE_WRITECOPY transition it succeeded with five bytes written.
WriteProcessMemory automatically handled RX, restored protection, and wrote the
actual bytes. Query-only process handles were denied. The owned DLL's SHA256
remained unchanged. These are Windows contract results, not iPhone results.

The production regression executes the actual Unix dispatch and authorization
helpers against private file mappings and real RX/RW control mappings. It also
checks the parser against the four shipped hybrid DLLs, rather than relying
solely on constructed PE headers. Existing WoW64 behavior remains covered.

## Steam service and updater findings

The current export confirms both genuine hardware-updater stages load, exit zero
and fully retire their FEX allocations. The previous production correction is
therefore confirmed on-device; no new updater workaround is introduced.

The current GLE 126 accompanies native64 Steam's attempts to load the official
x86 service DLL. The genuine x86 service separately loads that DLL and performs
SCM and firewall work. This does not establish that every private Steam IPC
operation succeeds, but neither does it justify loading an incompatible DLL or
inventing a missing dependency. Historical pipe errors are not current failures.

Static analysis of the current official service executable also excludes its
RegQueryInfoKey security-size discrepancy as a fix for this path: that output
is never read by the complete registry-checker control flow. No speculative
registry, service, trust or certificate success override is included.

## VAC remains unresolved

No captured trust result identifies a rejected file or a failing Valve check.
The popup marker is evidence of the user's rejection, not its internal cause.
The self-write defect is independently confirmed; a causal link to VAC is not.

[Valve's Trusted Mode documentation](https://help.steampowered.com/en/faqs/view/09a0-4879-4353-ef95)
requires restrictions on third-party interaction and signed DLLs. A public
[Windows-CS2/Proton report](https://github.com/ValveSoftware/csgo-osx-linux/issues/4125)
records the same warning despite reinstalling/verifying, with native Linux
resolving that reporter's case. These sources do not identify Madeira's failed
check or establish an approved Windows/Wine/FEX/iOS secure-play architecture.
No exact Valve-controlled requirement blocking this device has been proven.
Only a legitimate VAC-secured server connection can establish acceptance.

## Installation and rollback

Pool placement, the 1152 MiB total and 768/384 MiB partition, JIT preparation,
Steam launch, graphics, controls, exports and user-data paths are unchanged.
Install over the existing app using the same bundle ID and iPhone signing
method. Do not uninstall or clear its data. To roll back this runtime change,
reinstall the previous IPA over the app; no prefix migration is involved.
On-device self-write behavior, continued startup and actual secure matchmaking
remain to be tested. No FPS or memory improvement is claimed from host CI.
