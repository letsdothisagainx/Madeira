# Steam window/ThreadState follow-up — 2026-10-31

Source baseline: `cdba6d28818d5cf8b1cd8a2cf09986080d51ace2`. The installed
capture's native UUID `40536065-ABB0-3D17-B6D6-9679BE7DB092` exactly matches
that commit's completed Actions run 41150950178. This preserves the process
isolation, x18, controllers, Wine/JIT, prefix and Steam integration fixes.
No installed data, captured account information or Valve binaries are changed
or committed. The attachment is diagnostic evidence, not build instructions.

## Comparison and proven observations

The Oct 31 064255 capture has 16,567 lines. The Oct 30 233643 raw capture is
available (15,732 lines); the Oct 30 222002 and 210323 captures are available
only through the existing forensic reports. Do not describe report comparison
as reanalysis of their missing raw logs.

| Observation | Oct 30 233643 | Oct 31 064255 |
|---|---:|---:|
| FEX last-page warnings | 110 | 122 |
| Generic Mach UNHANDLED records | 1 | 3 |
| WoW64 reservation refusals | 3 | 4 |
| CEF `Check failed: false` | 1 | 2 |
| Clean executable-pool checks | 0 | 2 |
| `TEXT LOST EXEC` records | 2 | 0 |
| Logged backpatch records | 40 | 40 |

The prior 20,000+ replay cascade, unrecognized x18 encoding and original
null-register fault do not recur. The new native NULL fault is a distinct,
source-confirmed unchecked ThreadState allocation failure. The expected
Stik detach breakpoint is correctly classified/forwarded in this capture.
The two pool checks sample 58 live text pages across 63 mappings (cycles 15
and 30); this establishes sampled integrity, not exhaustive proof of all pages.

## WoW64 ownership and capacity

Root Steam owns B=0x400000000. Sysinfo's B=0x600000000 is released and reaped,
then reused by browser PID 0064 (lines 4691, 4906, 4914). Crashpad owns
B=0x800000000. The hard configured three-slot check refuses driver queries
and Crashpad's monitor child before attempting another actual map reservation.
Later Crashpad retires and B=0x800000000 is reaped/reused (13788–13789,
14858–14876). Thus cleanup is not universally broken. A browser that has
exited logically but still has native Wine threads is correctly quarantined;
reusing that memory early would restore the previous ownership corruption.

The candidate keeps the slot setting, registry ceiling, actual map/headroom
check, candidate band and no-clobber reservations. For a Steam main image only,
the setting becomes a baseline allowing measured expansion. Non-Steam sessions
retain the hard count. `MADEIRA_WOW_ELASTIC=0` restores the hard count for Steam.
A released placeholder is preferred before any fresh reservation, even if it
lies outside the current preferred band. No live/quarantined window is stolen.

Previously a 16 KB end guard obstructed the next 4 GB-aligned window, wasting
nearly 4 GB between owners. Steam can now retain an OWNED predecessor's guard
as the next window's inaccessible NULL prefix and reserve only its free tail
plus a new end guard. A foreign PROT_NONE page does not establish ownership.
The shared page is never unmapped or made accessible. Fixed allocations reject
all registered NULL/overrun guards. The ordinary guest allocation floor is
0x110000. Teardown restores PROT_NONE, preserving a predecessor's shared guard.
The 16..44 GB band can hold seven adjacent windows in a simulated free map;
actual device capacity is lower whenever occupancy/headroom requires it.

Bounded lifecycle diagnostics show generation, held/released/abandoned counts,
configured baseline and elastic policy. Existing explicit bootstrap generation,
last-native-thread retirement and busy-range reaper checks remain authoritative.

## FEX placement and safe initialization

Wine's actual FEX_ONLY reservation is [0xb40000000,0xd40000000), 45..53 GB.
WOW64 rpmalloc still requests [0xc00000000,0xeffffffff], 48..60 GB. Its 16 MB
aligned span request at line 16301 cannot use the overlapping 5 GB because
`fex_arena_covers` formerly admitted only fully contained requirements. The
view-tree gap is physically reserved by Wine; the fallback no-clobber native
map therefore reports EEXIST, skips that region and exhausts its search.
This is an ownership/placement mismatch, not proof of physical RAM exhaustion.

The adapter admits only the exact legacy small-map requirement, from a current
WoW64 owner, when it overlaps the authoritative arena. Existing reserved-area
placement clips both ends to that FEX_ONLY reservation and checks live Wine
views. Generic allocations, native game requests and unrelated bands remain
excluded. The rpmalloc band is not changed after initialization.

`ContextImpl::CreateThread()` already returns NULL on allocation failure.
`BTCpuThreadInit()` then dereferenced it under ThreadCreationMutex. Native
instruction `ldr x20,[x0]` at libwow64fex+0x10284c, x0=0, RIP/RSP=0 confirms
that path. A maintained Madeira build overlay adds a checked initialization
export and consumer: ThreadState/frame, GDT, frontend and call-ret allocation
must succeed before TLS/registry publication. Failure cleans partial state and
CRT state, returns through the mutex, and Wine retires the native thread with
STATUS_NO_MEMORY before fetching guest context or simulating. The native
loader_section is already released by ntdll `init_wow64` before this call.
The legacy void export also cannot continue into simulation after failure.

The pinned FEX/Wine checkouts and upstream ABI remain intact; overlays are
staged/restored with exact-byte checks. Actions rebuilds the actual native
ARM64 `xtajit.dll` and `wow64.dll`, rather than packaging stale checked-in
binaries. Final IPA validation requires checked-init producer/consumer markers
and byte identity with the rebuilt files. The ARM64EC CPU binary used by CS2
is unchanged. Core suballocators can still have other failure modes; this is
not a claim that every allocation in FEX has been made recoverable.

Threads 023c/0240/0244 later time out on guest loader CS 0xfffc91d8, owned by
023c. A fault while holding FEX's global thread-creation mutex can strand
startup/teardown and is removed by the checked path. Causation of every later
guest loader timeout still requires an on-device run. No foreign lock is
released and no guest exception is skipped.

## Chromium, windows and presentation

Startup HWND 0x1002c belongs to Steam PID 0020. It becomes Wine-visible and
has an attached visible 248x80 layer; eight `contents-submitted` observations
start at line 2503. This rules out a universally disconnected compositor.
It does not prove the display scanout or the authenticated library UI works.
Later webhelper HWNDs in PID 0064/01f0 remain hidden and have no submitted
contents. The capture does not establish an actual visible CEF login/library
window with rendered frames. Forcing those helper HWNDs visible is unjustified.

The class trace was reading UNICODE_STRING.Length after NtUserGetClassName,
but Wine returns a character count and leaves Length unchanged. The candidate
uses that return count, so the next capture can distinguish the real Steam CEF
window class from IME, SDL and internal helpers. Ownership/visibility/surface,
layer attachment and frame traces remain enabled with existing budgets.

Both CEF assertions have matching libcef stack candidates:
+0xdf45d7, +0xa1698cb, +0xac855c0, +0xdf41c2, +0x592fcdb, +0x592fcb0,
+0x592f88d, +0x8e6ac0, +0x592f9b8, +0xa1698d9, +0x592f98a, +0xac6d100,
+0xdfce39. These are stack candidates, not a reliable unwind or symbol names.
The second assertion immediately follows crashpad_client_win.cc(547)
`CreateProcess: Internal error (0x54F)` (15415–15423), itself after a refused
window reservation. Crashpad's first attempt later self-terminates when its
server fails to respond (14723), and the browser aborts. Crashpad startup is
therefore an evidenced failing subsystem; resolving the precise Chromium
NOTREACHED call site still needs matching libcef symbols. The renderer runs
guest code before these aborts. No Chromium/VAC/authentication checks or
Crashpad process creation are bypassed.

The inventory confirms gldriverquery.exe is present, machine 014c. Both driver
queries fail CREATE before receiving a child window; a successful child exit
status cannot be inferred. The bounded read-only dependency inventory now also includes both Vulkan query
executables (previously omitted). Existing helper lifecycle traces record raw status,
architecture and owner when they do launch. Further device evidence must show
successful GL/Vulkan query and Crashpad monitor startup after capacity improves.

## Protection, breakpoints and memory limits

The 122 warnings do not count failed kernel mprotect calls. FEX's Windows
boolean wrapper is inverted and supplies a NULL old-protection output. The
WOW64 overlay supplies the required DWORD and returns true on Win32 success.
It does not round protection across a host page, make RX memory writable or
pretend a refused request succeeded. Native bounded guard diagnostics identify
real EC-code failures: no Wine view, STATUS_INVALID_PARAMETER, kernel call not
made, RX/max-RWX host mapping, last logical 4 KB page sharing 12 KB of live code
on a 16 KB host page (e.g. line 13317). A dedicated 16 KB guard/alias layout
remains unresolved; the unchanged ARM64EC producer still uses its old helper.
Both RX and RW aliases need a coordinated guard before hardware guard integrity
can be claimed. Execute permission is not stripped by this candidate.

The guest INT3 at line 13670 is FEX's BRK #0 SIGTRAP trampoline, followed by
normal Wine breakpoint exception termination of PID 0088, status 80000003.
It formerly passed through native fatal diagnostics and dumped a 1 GB JIT pool
before normal dispatch. The candidate recognizes only an owned FEX code carve,
BRK #0, registered self-consistent TEB, TLS14 CurrentFrame=x28 and plausible
i386 RIP/RSP for that owner's guest window. It forwards the ORIGINAL exception
through the existing chain without modifying PC/registers or swallowing it.
Native unknown breakpoints retain fatal diagnostics. The Stik classifier stays.

There are 40 bounded backpatch records in each raw capture; repetition alone
does not prove a new infinite backpatch loop. Swap reports 0 refusals, peak
5948 MB, file use 5955/6144 MB, 5592 MB backed at the last full census. This
remains close to the swap-file limit. Additional live processes may increase
pressure; expansion retains the real VA headroom check but does not guarantee
adequate RAM or disk. No swap limit is raised and no installed data is removed.

## Validation and outstanding device acceptance

Portable ASan/UBSan harnesses execute production placement, adjacent/released
window guards, exact ownership, process isolation, checked FEX init failures,
successful publication, protection return semantics, guest breakpoint validation
and overlay restoration. Sanitizer diagnostics are fatal. The local embedded
suite passes through window coordinates, then stops because Swift is unavailable
on Linux; the complete suite and iOS compilation run on GitHub Actions/macOS.

No post-change device log exists yet. Stable browser/Crashpad lifetime, genuine
CEF login/library frames, input, Steam authentication and CS2 launch remain
unverified. A new capture should show expanded guarded reservations or a
specific real map refusal, FEX arena routing, no NULL ThreadState fault, successful
helper lifetimes, a Wine-visible CEF top-level window and submitted contents.
Pool checks must remain clean. Preserve the current prefix when testing.
