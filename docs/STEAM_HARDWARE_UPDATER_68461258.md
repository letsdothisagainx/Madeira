# Steam hardware updater launch refusals in the 68461258 run

Evidence: the November 12 Run Diagnostics ZIP supplied for source
`6846125896e84c256ba03be3198092aeecd3544a`. Its `sanitized/madeira-session.log`
retains enough of the process command to recover the exact executable even
though Steam's own console excerpt redacts the quoted path:

`C:\Program Files (x86)\Steam\bin\hardwareupdater\hardwareupdater.exe`

All twelve `--check-for-updates` failures have the same immediate three-record
sequence: `NtCreateUserProcess` names that executable, Madeira logs
`[proc-gate] REFUSING spawn ... (hardwareupdater gate)`, and Steam logs
`Failed to launch executable ... --check-for-updates`.

| Steam console local time, November 11 | Session rows: request / refusal / failure | Calling thread |
| --- | --- | --- |
| 20:53:21 | 24565 / 24566 / 24567 | 025c |
| 20:53:23 | 25582 / 25583 / 25584 | 0214 |
| 20:53:26 | 26531 / 26532 / 26533 | 025c |
| 20:53:29 | 27177 / 27178 / 27179 | 0214 |
| 20:53:31 | 27997 / 27998 / 27999 | 025c |
| 20:53:35 | 29035 / 29036 / 29037 | 0214 |
| 20:53:39 | 30107 / 30108 / 30109 | 025c |
| 20:53:41 | 30757 / 30758 / 30759 | 0214 |
| 20:53:44 | 31867 / 31868 / 31869 | 025c |
| 20:53:48 | 33541 / 33542 / 33543 | 0214 |
| 20:53:50 | 34035 / 34036 / 34037 | 025c |
| 20:53:53 | 35040 / 35041 / 35042 | 0214 |

The `srv-own new_thread` records at session rows 17248 and 19743 identify both
calling threads as children of Steam PID `0068`, created by its main thread
`006c`. The direct request/refusal sequence establishes the failure mechanism;
wall-clock proximity alone is not being used to infer it.

## Confirmed production defect

Baseline `build/ntdll-unix/process_ios.c` includes `hardwareupdater` in a
substring-based executable-name blocklist inside `NtCreateUserProcess`.
The matching branch returns `STATUS_ACCESS_DENIED` before ordinary image
opening, architecture selection, import binding or child execution. The
`ml1357` full-Steam-client exemption allows the first four entries, but
hardwareupdater is entry five and remains refused. Thus these twelve failures
do not establish a missing file, wrong architecture, bad dependency, invalid
environment or failure inside the updater. It never reaches those operations.

The old `ml601` comment justified this gate using JIT-pool churn during a
historical 896 MiB session. It also records that an associated loader probe bug
was corrected separately. That comment is historical evidence, not a current
measurement of the updater or a Windows requirement to prohibit it.

The production correction extends the existing full-Steam-client exception to
the exact `hardwareupdater.exe` filename. It replaces the positional
`b < 4` exception with explicit helper names so array reordering cannot silently
change the policy. A direct Steam parent can reach the ordinary loader; Dock
and other initial parents retain their previous containment. A live updater
tracked beneath the native Steam session can also start the same full image
path. Its canonical owner, PID, live ledger record and Steam ancestry must
match; an untracked, retired, foreign, unrelated-path or Dock process cannot
borrow that exception. The comparison handles the known DOS/NT path spellings,
ASCII case and slash differences without guessing filesystem aliases.
`MADEIRA_PROC_GATE_STEAM=0` and the separate explicit `MADEIRA_SPAWN_BLOCK`
policy still apply. This changes neither the helper's architecture nor its
loader result, update result or exit code. No successful execution is fabricated.

Independent read-only inspection of the current official Steam 1794424036
package measures the helper as AMD64 (`8664`), 8,718,056 bytes, SHA-256
`af546b4d2440c6133f78d3bacebc304cd73531ea8806fc4fe996d165d8929722`.
Its bootloader imports USER32, KERNEL32 and ADVAPI32, and contains a one-file
PyInstaller payload including `python314.dll`. At RVA `0x9593` the real
bootloader calls `CreateProcessW` using its own executable buffer and the
`GetCommandLineW` result. That independently establishes why allowing only the
first Steam-to-updater spawn would be incomplete: extraction is followed by a
same-image child. No Valve executable or payload is changed or executed by the
static inspector. Manifest/package hashes establish download provenance, not a
VAC verdict or independent Authenticode chain validation.

## Installscript and VAC boundaries

Steam's `RunningInstallScript` message is concurrent with these attempts. The
actual installscript process request is separately visible at session row
24224, with a successful `spawn_process` at 24231: Steam's genuine
`bin\SteamService.exe` receives the CS2 `runasadmin.vdf` path. The VDF contents
are not present in this ZIP. Neither temporal proximity nor these records
establishes that hardwareupdater is a required CS2 redistributable or a command
inside that VDF.

The user marks another rejection at `2026-11-12T02:00:49.821Z`, corresponding
to local November 11 21:00:49.821 at the recorded -300 minute offset. That is a
user report, not a captured rejected-file name or proof linking the updater to
VAC. Steam's genuine content update and staged-content verification remain
stronger evidence than the earlier cached hashes, but do not prove secure play.

## Acceptance limits

The official main executable and 16 bundled native components total 15.645 MiB
of PE `SizeOfImage`. This is a static inventory, not a measurement of mapped
modules, executable-pool charge, FEX buffers, physical memory or peak lifetime.
It excludes additional Windows dependencies. It cannot authorize changing the
current pool or physical-memory budget.

Allowing the genuine requested process to reach the normal loader must preserve
real loader errors, real exit codes and its actual update decision. It must not
pretend the updater ran or reported no updates. The new capture cannot show its
post-gate behavior, executable architecture, dependency completion or resource
cost because every attempt was denied before execution.

Keep the 1152 MiB pool, 768/384 MiB partition, generation/lifetime checks and
memory protections. The session's physical-memory peak reaches 5862 MB; this
does not authorize an unmeasured increase or promise that an extra process is
free. Measure the helper's actual lifetime and memory use on the next device
run. No existing game/prefix data or Steam binary needs replacement to correct
the deliberate launch refusal. A genuine secure-server connection remains the
VAC acceptance test.

## Current service evidence and remaining limits

The current `Failed to load Steam Service (GLE 126)` is at November 12
01:52:49 UTC. The native64 client PID `0068`, TID `00b0`, receives two
`c000007b` results followed by two `c0000135` results at session rows 8440–8443,
between local 20:52:49.711 and 20:52:50.033. This matches the previously
inspected official native64 client's attempted executable load of the official
I386 DLL followed by its service-start fallback. A missing transitive import in
the genuine I386 service has not been established. Do not weaken Wine's machine
check or conceal the warning.

The genuine I386 service PID `0054`, worker `0064`, loads the genuine DLL and
executes its workers. It remains alive through the session. The revised Wine
`advapi32.dll` identity is present, and the former unsupported type-12/13 named
security warnings are absent. This establishes that the earlier correction is
in use, not that it caused the lifetime difference or that every private service
operation succeeds. Current SCM pipe waits finish in 490 and 56 ms. No new
private-pipe GLE 2/183 failure is recorded; those entries are historical.

The service's `RegQueryInfoKeyA` security-size notices were checked against
native Windows. A query-only handle legitimately returns success with a zero
security-descriptor size when it lacks `READ_CONTROL`; a handle with both
query/read-control rights returns a real size. The current exported calls do
not expose their granted rights, so the notices alone cannot establish another
service blocker. That investigation does not change any API or trust result in
this build. The native reference is
[Actions 43140421649](https://github.com/letsdothisagainx/Madeira/actions/runs/43140421649).

Steam's genuine depot update and successful commit remain evidence of real
content handling. There is no new evidence of a rejected file, a failed
Authenticode operation, a failing private service request, or the exact
Valve-controlled requirement behind the user-reported VAC popup. The hardware
launch fix must not be reported as a verified VAC correction. A real secure
server remains the only acceptance test.

The focused host regression compiles the literal hash-pinned old gate and the
actual corrected gate, path helpers and Steam child ledger. It reproduces all
twelve old denials, tests the required same-image child, lifetime/owner failures,
full-ledger refusal, explicit blocking, parameter preservation and real error
forwarding, and executes 4,096 concurrent decisions under ASan/UBSan. TEB,
logging and downstream loader transport are controlled edges in that test.
It does not execute the official updater or claim iPhone/VAC success.
