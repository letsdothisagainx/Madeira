# Steam protection and presentation follow-up — 2026-10-30

This candidate continues `663a289` (the signed x18-load/CEF follow-up).
The two attached files are the current 15,732-line Madeira log and the
accumulated CEF log. The requested timestamped current filename was uploaded
as `madeira-log.txt`; its native UUID is
`59125EDC-AD3F-36A7-9B7E-4D2DFF2A7055` (line 233).
The original preceding two Madeira logs are not attached or present in this
workspace. Comparisons with build 22 and build 29 use the checked-in reports
`STEAM_UI_FORENSICS.md` and `STEAM_X18_FORENSICS.md`, not a claimed reanalysis
of those original logs. Logs, credentials, installed data and Valve binaries
are not committed.

## Proven protection findings

There are 110 occurrences of the FEX guard warning. The current log itself
separates **successful** `status=00000000` data-buffer requests (lines 723,
737, 768, 792, 835, etc.) from **rejected** executable-buffer requests
(`c000000d`, e.g. line 706). FEX's Windows allocator returns
`::VirtualProtect(...) == 0` from its boolean wrapper; Windows returns nonzero
on success. Thus the warning count is not a count of failed kernel calls.
The successful data requests can nevertheless leave a partial host page RW:
a logical 4 KB guard within a 16 KB host page is not necessarily a hardware
guard. The separate POSIX allocator's return convention is correct.

For the rejected EC-code request at line 706:

* requested and Wine-normalized range: `0x33fffb000 + 0x1000`;
* live executable carve: `0x33effc000 + 0x1000000`, owner PEB `0x47ffd0000`;
* target is the carve's final guest page, preceded by `0x3000` live bytes in
  its containing host page;
* Mach region: `0x33fff8000 + 0x4000`, current RX (`5`), maximum `7`;
* no Wine view exists: NtProtectVirtualMemory returns
  `STATUS_INVALID_PARAMETER` before reaching set_protection/mprotect.

That status is not POSIX `-1` or an errno. No kernel mprotect return or errno
exists for this rejected request. New bounded guard diagnostics explicitly
say `kernel-call=not-called:no-wine-view`; successful and failed NT requests
have separate budgets. The guard is not installed by rounding outward,
pretending success or making memory RWX.

The `[pool-rot]` observation also needs ownership. Lines 10608 and 13339–13340
show the same pool base `0x305270000` first allocated to oleaut32, then freed
and reused for advapi32. The old checker reads `jit_base` and `text_size` even
from tombstoned entries whose `pe_base` is NULL and size is zero. Consequently,
its `TEXT LOST EXEC` sample at `0x3052c0000` does not prove a **live current
text** page lost execution. The page's RW/max-RW state is real; its attribution
to executable code is not established. The candidate checks current live
ownership and bounds, rechecks the mapping after the Mach query, includes PE
identity/size in remaining warnings and releases returned Mach object rights.
It checks both current and maximum execute permission on live mappings.

A separate source-level defect is corrected in both original and child PE
copy paths. Writable section protection formerly rounded a section onto host
pages without checking all executable sections. Aligning the first writable
section alone cannot establish that every later section is disjoint. The
candidate classifies complete host pages using all PE section extents, retains
RX on shared executable/data pages and uses the existing RW-alias store/atomic
emulator there. Only complete pages owned by this image and containing data
without code receive RW. Bounds and malformed PE metadata fail closed. No RWX
request is added. This prevents the demonstrated class of execute stripping;
it is not claimed as the proven cause of the particular stale-checker record.

The full FEX guard-layout/result correction remains pending the explicit
instruction in `FEX/AGENTS.md`: “AI must not be used to generate code for
contributions to this project.” Authorization to override that instruction
was requested. This candidate does not modify FEX, invert WinAPI semantics
elsewhere, or suppress its warning. Dedicated host-page guards require
coordinated allocator/emitter capacity and lifetime changes, including ordinary
FEX guarded data buffers as well as executable buffers.

## Expected debugger breakpoint

Lines 15297–15329 identify native `jit26_detach+4`, instruction `0xd43e01a0`
(`BRK #0xf00d`), command x16=0. The only `[mach_exc] UNHANDLED` occurrence is
this event. The later SIGTRAP fallback already skips that exact protocol
instruction, but only after a 1,073,741,824-byte JIT dump was generated (line
15364). Physical footprint rises during this dump. That is not a guest crash.

The candidate recognizes native detach/prepare protocol sites and their
expected commands before generic fault processing. It returns the same
`KERN_FAILURE` forwarding reply, preserving the debugger/SIGTRAP chain; it
does not fabricate the requested allocation, advance PC, change registers or
claim that detachment occurred. Expected events do not borrow a Wine TEB or
enter fatal diagnostics. Unknown traps and FEX suspend checks retain their
existing behavior. Genuine unexpected failures retain their dump path.

## Invisible UI: what the evidence establishes

The updater HWND `0x1002c` has actual surface flushes (through line 2760).
Therefore the Wine-to-host bitmap path runs for at least that window.
The genuine browser is pid `0064`, tid `0068`. Its large HWND `0x300b0` has an
attached 655×302 layer, Wine visibility zero, host hidden=1 and contents=0
(lines 11156–11166). Other browser/helper windows have similar records.
There is no captured rendered, visible login/library window or authenticated
interactive result. Hidden helper windows must not be forced visible.

Existing diagnostics cover ShowWindow, SetWindowPos, parent/owner, style,
ancestor visibility and layer attachment. This candidate adds independent
bounded creation, surface allocation and present-request events. For traced
Steam HWNDs the UIKit queue records whether a frame was submitted to a layer,
hidden with contents, awaiting position, filtered by game mode, missing a
compositor or failed CGImage creation. `contents-submitted` means submission
to Core Animation, not proof of physical scanout. These records distinguish
missing Chromium output, hidden output and incorrectly attached composition
on the next device run. Window flags, placement, visibility and input behavior
are unchanged. No browser rendering/compositor root cause is yet proven.

## Chromium NOTREACHED

The current assertion occurs in the Madeira log at line 9403, timestamp
23:35:46.058 UTC. It is not present in the supplied CEF file. That file
contains 11 Chrome startup banners; only the final session starting at line
1511 (23:35:46.465 UTC, 19:35:46 EDT) belongs to this run. It continues through
frame connection and JavaScript context creation, including 98 browser-info
frame messages. Renderer execution in the Madeira log is consistent with
this progress and contradicts treating the assertion as a confirmed total
browser-process failure.

Chromium 126.0.6478.183's
[base/check.cc](https://github.com/chromium/chromium/blob/126.0.6478.183/base/check.cc#L373)
implements `NotReachedError::TriggerNotReached()` at this location, emitting
“NOTREACHED log messages are omitted in official builds.” This is the reporting
shim, not the originating subsystem's source location. The current logs cannot
recover the omitted origin. WSALookupService/mDNS errors, browser visibility
and this NOTREACHED have no established causal relationship.

The staged Wine log observer now retains at most twelve preceding and eight
following Chromium source tags and captures at most two assertion contexts.
It reads the current thread's saved guest32 frame and its own process's loader
list through fault-safe Mach reads, then reports only module+offset stack
candidates. These are explicitly candidates, not a claimed unwind. It does
not print raw stack values, command lines, URLs or log bodies in the context
ring; unreadable state is reported as unresolved. Assertions and process
results are unchanged. No Valve DLL or Chromium assertion is patched.

## Helpers, process windows and memory

The **current** driver-helper failures precede DLL resolution:

| Helper | Current evidence | Result |
| --- | --- | --- |
| gldriverquery64.exe | Native log tid 00e4 | Exit status 0 (line 11212) |
| vulkandriverquery64.exe | tid 01cc; x64 Vulkan loader loads | Exit status 1 (line 13679) |
| gldriverquery.exe | 3/3 configured WoW windows held | Bootstrap `c0000017` / STATUS_NO_MEMORY (11860–11867) |
| vulkandriverquery.exe | Same window limit | Bootstrap `c0000017` (13904–13911) |
| steamwebhelper.exe | Browser pid 0064, crashpad pid 0088 | Genuine i386 module/thread execution; no proven completed UI |

The previous report's SDL2 import error must not be substituted for the current
pre-loader window refusal. The current read-only inventory still finds no SDL2
in the three checked Steam locations; SDL3 is i386 and is not an SDL2 substitute.
The current helper failures prevent confirming whether later imports would
succeed. The installed `MADEIRA_WOW_SMALL_VA_SLOTS=3` limit is respected; raising
it would be an experiment with virtual-address availability, not a demonstrated
DLL fix. There are only three occupied process windows before these helper
requests. Newly bounded exit records identify helper, PID/TID, actual PE
machine when readable, native thread, guest window and genuine raw status.

The final logged swap state is 5,675 MB backed in 718 extents, peak 6,136 MB,
**115 refused allocations**. This is real pressure near the configured 6,144 MB
swap capacity, not evidence that iOS provided the guest a Linux swap subsystem.
No FEX `EXEC ALLOC FAILED` or registry-full record is present. The last sampled
unaligned backpatch count is 2,200, so the 27 printed records are not the total
number of backpatches. Its UI causality is unresolved. Existing thread census,
FEX allocation and protection diagnostics remain active; native thread presence
alone is not a leak or useful renderer progress.

## Validation and device acceptance

New ASan/UBSan checks compile the actual production page policy/protection
routine, protocol classifier, exact helper identity parser, CEF observer and
saved guest32 context reader. Fixtures cover mixed and later executable
sections, four PE subpage alignments, malformed/truncated/overflowing ranges,
exclusive-data protection transitions, existing 32/64-bit STXR/STLXR atomic
success/retry and clobber rejection through the RW alias, unchanged error state, protocol command
mismatches, foreign/FEX/Swift traps, bounded source context, a valid module
candidate, unreadable state and excluded log-body/stack secrets.

Existing x18, registry, IOSB, CEF policy, dependency, UI and geometry tests passed
locally with the Linux sandbox's LeakSanitizer setting disabled. The full local
runner reaches the unavailable Swift compiler; the macOS Actions run is required
for Swift/UIKit/iOS compile and IPA checks. These host tests do not validate an
iPhone, actual GPU scanout, authentication, controllers, CS2 gameplay or VAC.

Install using the same bundle identifier and preserve the existing prefix,
Steam installation, controllers and game library. Capture a fresh launch through
real login/library interaction and then Steam's normal CS2 Play action. Required
acceptance is a legitimately visible window with rendered contents, working
input, genuine Steam authentication, and successful ordinary CS2 launch. No
Steam-authentication or VAC bypass is introduced or implied.
