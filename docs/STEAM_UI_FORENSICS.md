# Steam UI and WoW64 I/O forensics — 2026-10-30

The new candidate fixes a demonstrated memory-corruption defect. It does not
establish that Steam's login/library works on an iPhone. The actual Steam,
SDL2 and CEF binaries remain on the phone; none were replaced or supplied to
the cloud workspace. There is no new CS2 or VAC result.

## Evidence from build 22

The supplied `steam.exe-2026-10-30_15-45-08.txt` has 12,719 lines; `cef_log.txt`
contains several sessions. The newest session is 19:45 UTC (15:45 device time).
Earlier sessions in that CEF file are not evidence of progress in this run.
The captured launch lasts approximately 35 seconds.

[Exact-image inspection](https://github.com/letsdothisagainx/Madeira/actions/runs/41120982687)
reads the IPA from build 22, checks UUID
`FDE23E02-3C8E-38E6-A3DE-499E98412C42`, and reports native image SHA-256
`00e8d622b09999bc0f88d603506d068967ce4d6a2fd9605d8644026a67452ad0`.
`invoke_system_apc` is at unslid `0x11bb65c`; offset `0x6b8` is
`0xb90006f6`, **`str w22, [x23, #4]`**, at image RVA **`0x11bbd14`**.
The log's runtime PC `0x101947d14` minus image base `0x10078c000` agrees.
The originally quoted offset `0x01c3fd14` does not identify this instruction.
The write uses x23, not x18.

### Producer and asynchronous consumer

1. `in_wow64_call()` in this embedded Wine identifies a WoW64 *process* by
   its guest window, including native bootstrap/FEX calls made before FEX
   initializes. Those native calls use a real 16-byte `IO_STATUS_BLOCK`.
2. The former `iosb_client_ptr()` selected `io->Pointer` whenever that
   predicate was true. For a real native IOSB, this union is not an output
   pointer: it can hold uninitialized stack data or an earlier status.
   Only the actual WoW64 file thunk's temporary proxy uses that convention.
3. At lines 3614–3618, genuine i386 **steamsysinfo.exe**, pid `0048`, tid
   `004c`, submits `NtWriteFile` / `server_write_file` with native stack IOSB
   `0x1293fe950`. The producer selects **`0x10000`** instead. Its guest window
   is `0x600000000`, TEB `0x600300000`, CPU area `0x1293ffd20`, TLS14 zero.
   The completion tries the 32-bit Information store at **`0x10004`**.
4. This is not just a helper crash at an unrelated instruction. At line
   3729 a later completion targets **code address `0x301169354`**, with byte
   count **54**. Its Information store writes **`0x00000036`** at
   `0x301169358`. Execution then reaches that invalid word in kernelbase.dll
   and reports `0xC000001D`. A later i386 hardware helper repeats this
   corruption/illegal-instruction sequence near lines 12337–12404.
5. The genuine **i386 SteamWebhelper**, pid `0058`, tid `005c`, also publishes
   native `NtWriteFile` with target `0x10000` at line 4646. The defect affects
   browser startup as well as hardware discovery.

Adding the guest-window base, swapping status fields, checking whether a
pointer looks low, ignoring exceptions, or globally using 32-bit completion
layouts would not correct the producer.

## Implemented I/O correction

The maintained Wine overlay explicitly binds the native temporary IOSB proxy
to the already-converted host address of the guest's 8-byte IOSB, at the real
`iosb_32to64()` boundary. Unbound IOSBs remain native 16-byte structures.

Each `Wow64SystemServiceEx` dispatch owns a native-thread scope with exception
cleanup through `__FINALLY_CTX`. Scopes nest without a fixed depth or heap
allocation. A versioned private `NtSetInformationThread` operation connects the
rebuilt native ARM64 PE producer to the embedded Unix consumer. It rejects a
mixed/unsupported version instead of claiming success. No application pointer
is replaced by a token, and the wineserver wire protocol is unchanged.

`server_async()` records the request's 32/64-bit layout in native-only async
metadata at submission. APC dispatch snapshots that flag **before the genuine
callback can free its metadata**. Delayed completion therefore uses the
original layout even after the syscall scope ends. Native internal ioctl
calls use native status blocks. Genuine status values, byte counts,
asynchronous ownership, faults and guest-pointer conversion remain intact.

Both ends are built together. The IPA build rebuilds the actual
`aarch64-windows/wow64.dll`, checks its machine and ABI marker, and requires
byte-identical copies in the staged app, Xcode bundle and IPA ZIP. The final
linked native dylib must contain the matching consumer. Required changed
native translation units cannot fall back to stale objects after a compiler
failure. The build overlay restores the exact Wine source bytes and refuses
to overwrite concurrent source edits; the submodule pin is unchanged.

## Window and Chromium findings

Steam completes verification, loads steamui.dll, and starts genuine i386
`bin/cef/cef.win7/steamwebhelper.exe`. CrBrowserMain appears. HWND `0x10098`
gets a 655×302 UIKit layer. Its recorded style `0x06cf0000` lacks WS_VISIBLE;
Wine visibility stays zero, the host layer stays hidden, and it has no pixels.
Recorded position operations do not request SWP_SHOWWINDOW. No legitimate
main-window show/presentation is observed for it in this capture. The driver
continues returning Wine's show flags unchanged and honors hidden ancestors.
Forcing this internal window visible would not establish a working login UI.

The newest CEF session reaches display/media initialization and the ordinary
cloud-management-disabled diagnostic, then has no later BrowserReady evidence.
The I/O defect is present in browser startup; fixing it is necessary, but this
short capture does not prove it is the only reason UI initialization stops.
It also does not establish a persistent loader-lock deadlock. Older-session
messages and an active CrBrowserMain are not a completed login/library.

For a controlled on-device comparison, `env.MADEIRA_STEAM_CEF_POLICY=valve`
leaves **Valve's complete webhelper command line and child creation unchanged**:
no Madeira single-process, proxy, V8, feature-list or logging rewrites, and no
Madeira `--type=` rejection in that block. The default retains the established
compatibility switches so the I/O correction can be tested first; unknown
policy values retain that default. `env.MADEIRA_JITLESS=0` remains a separate
single-variable comparison within the default policy. Do not combine these
experiments in the initial run. The old Madeira addition that disabled
PartitionAllocBackupRefPtr has been removed: memory-corruption detection is
left to Valve's own settings. Genuine arguments and authentication are not
rewritten by the Valve comparison policy.

## Executable-memory protection

This capture demonstrates real **Wine-side** PAGE_NOACCESS failures, not merely
a warning string. For example, line 681 requests `0x33fffb000+0x1000` and gets
`STATUS_INVALID_PARAMETER (c000000d)`, with **no Wine view**. Mach's query succeeds
and reports the containing `0x33fff8000+0x4000` mapping as RX (`prot=5`, max=7),
with a 16 KB host page. Other pseudo-processes repeat this pattern. The
EC_CODE allocation path deliberately returns pool carves without Wine views;
`NtProtectVirtualMemory` rejects an absent view before its normal protection
operation. This status is not a failed kernel mprotect return.

Additionally, FEX's Windows allocator boolean wrapper compares WinAPI
`VirtualProtect(...) == 0`, although that API returns true on success. This
can invert the warning's meaning. Its separate Apple/POSIX wrapper is correct.
FEX's `AGENTS.md` disallows AI-generated contributions; FEX source is unchanged.

Neither issue justifies suppressing the warning or reporting false protection
success. Protecting the containing 16 KB page would also remove access from
12 KB that the 4 KB request did not cover. A safe guard-layout change needs
allocator/emitter coordination, not a guessed mprotect call. Bounded ordinary
syscall diagnostics now add the exact code-carve range, owner PEB, live/free
state, whether the request is its last page, and preceding bytes sharing the
host page. They do not change results, protections or JIT limits. Whether
these guard failures impede Chromium remains an on-device question.

## SDL2 and helper loading

The genuine 32-bit `bin/gldriverquery.exe` is found and loaded, then fails its
required **SDL2.dll** import at lines 11377–11383 with `c0000135`. It is a
separate helper process. Steam and SteamWebhelper load **SDL3.dll**; SDL3 does
not satisfy an SDL2 import. The relative helper path correctly resolves under
the Steam root in this log. No installed SDL2 image was supplied, so its actual
location/architecture cannot be established from the cloud checkout alone.

A read-only launch diagnostic now inventories known Steam root/bin/CEF
locations, matches the requested filenames case-insensitively, and reads only
bounded PE headers to report x86/x64/ARM machine values and errors. It records
relative directory labels, not account data, and never scans steamapps or
changes DLL search paths. The next log's `[steam-deps]` records distinguish an
absent Valve DLL, wrong architecture, unreadable file, or loader-resolution
problem. No replacement DLL, SDL alias, Valve file modification, or fabricated
loader/service result is introduced. SDL2 failure's UI causality is unproven.

## Validation and device acceptance

Automated regressions compile the actual patched IOSB publishers, PE conversion
helpers, native controller and APC consumer with ASan/UBSan. They cover native
unions containing `0x10000` and a code address, original NTSTATUS/Information,
32-bit completion canaries, callback-freed metadata, delayed completions after
scope exit, nested scopes, independent threads, scope ordering, exact source
restoration and real invalid-pointer faults in an isolated child. A negative
comparison reproduces the old instruction corruption with byte count 54.
The actual native ARM64 WoW64 DLL is also cross-compiled, rather than relying
only on a model of its C helpers.

CEF policy tests compile the real transformation/gate and check byte-for-byte
preservation under the Valve policy, normal child launches, isolated legacy
behavior, exact image matching and retention of corruption detection. Existing
window tests cover show/hide and hidden ancestors. Packaging tests reject a
stale producer. DLL inventory tests cover architecture, casing, absent/invalid
files, privacy, unchanged contents/timestamps and errno.

GitHub Actions must still build/link/package the iOS app and run the complete
macOS host suite. Only a fresh iPhone run can establish whether native IOSBs
remain native, the corrupt completion/illegal-instruction cascade disappears,
Steam reaches BrowserReady, a real login/library window is legitimately shown
with contents, and interaction works. Capture long enough to distinguish slow
startup from a stall. Preserve the prefix and the existing installation.
Only after that should the user separately test Steam's normal Play button.
Successful Steam UI or service startup does **not** guarantee VAC compatibility.
