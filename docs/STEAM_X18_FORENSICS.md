# Steam main-thread TEB fault — build 29 follow-up

The supplied `madeira-log(20261030-210323).txt` identifies native image UUID
`F4CD3785-B12A-3B97-99CE-C4E034737C3D`. Its 15,223 lines and the newest
20:59 UTC session in the supplied CEF log are the evidence below. Older CEF
sessions are not evidence of this run's progress. No original logs, account
information or Valve binaries are committed.

## Confirmed fault and correction

At device-log lines 12149 onward, native instruction **`0xb9980e48`** is
**`ldrsw x8, [x18, #0x180c]`**. It loads the signed 32-bit **WowTebOffset**
from the native TEB and sign-extends it into x8. This is a read, not an IOSB
write, a guest address needing a window base, or a reason to map address zero.

The fault is on Steam's **main thread 0024**, not the concurrently starting
32-bit gldriverquery thread 0180. The SEGV record names 0024, and its Mach
registry entry is port `0x14e13`, native TEB `0x47ffc0000`, process `0020`,
PEB `0x47ffd0000`. No registry miss occurs at these faults. The runtime
instruction stream is a **wow64.dll x18 trampoline** at `0x30018c2ec`:

```
mrs   x18, TPIDRRO_EL0
and   x18, x18, #~7
ldr   x18, [x18, #runtime_TSD_slot]
ldrsw x8,  [x18, #0x180c]
b     original_return
```

The patcher recognized LDRSW as an x18 access, but only ordinary 32/64-bit
LDR used the destination as scratch. LDRSW used x18, which iOS may clear
between the TSD load and the field access. The Mach fallback omitted
unsigned-immediate signed loads, so the otherwise recoverable read at
`0x180c` became a real Wine access violation. Steam immediately reports
failed mapping/creation of its Chromium master IPC stream and calls the
condition a stream collision. The log does not prove an object-name collision;
no named sections or prefix files are reset or deleted.

The patcher now uses the already-overwritten destination register for valid
scalar unsigned-immediate loads, including LDRSW/LDRSB/LDRSH. The sequence
loads TSD, TEB and the field through x8; it never needs x18, x17 or the stack.
The opcode, access width, sign extension and return branch are preserved.
Stores, SIMD, prefetch and reserved opcodes cannot enter this path.

The signed-load Mach fallback separately validates the faulting thread's
registered TEB, its Self pointer, PID/TID/PEB, exact instruction offset, and
readability through Mach. It reads the real field and applies A64 sign/zero
extension; it never writes through the null platform register. Invalid or
unreadable state remains unhandled. Diagnostics identify the matched Mach
port and owning TEB/PID/TID without logging TLS payloads. Normally the fixed
patcher prevents this fallback from being needed.

A second, distinct ownership defect is also removed: a registry miss used
the first Wine thread's TEB. This is observed at lines 15079 onward on an
unregistered **native StikDebug detach thread**, not at the Steam LDRSW fault.
Unknown ports now return no Wine TEB. The existing dedicated StikDebug
`BRK #0xf00d` protocol handling remains unchanged. Native faults must not be
attributed to or delivered through an unrelated Wine process.

The previous IOSB correction remains active. New native/guest layout traces
show legitimate guest32 destinations; the former `0x10000` completion/code
corruption pattern does not recur in this capture.

## Chromium fixes and limits

* The access denial at lines 6843–6851 is Madeira's explicit refusal of
  **`--type=crashpad-handler`**. Standalone Steam's genuine crash reporter now
  follows normal Wine process creation with its original arguments and no
  browser-only injections. Dock retains its existing child-process policy.
  Real process creation may still fail with its genuine status.
* Chromium **126.0.6478.183**, `chrome/common/logging_chrome.cc:194–225`,
  accepts an empty `--enable-logging` value, `stderr`, or a child's `handle`;
  the literal **`file` is invalid**. Use bare `--enable-logging`, preserving
  Valve's existing log-file path. The invalid value falls back to the default
  logging destination, so that error alone did not prove UI startup failed.
* The earlier `Check failed: false` is not hidden or bypassed. Its precise
  callsite is not established by that message. This CEF session continues
  through connected frames and JavaScript-context creation after the message.
* Browser single-process/V8/proxy/feature behavior otherwise remains the
  established default. There is no evidence here that switching every process
  to a new mode is the demonstrated fix. The existing opt-in
  `env.MADEIRA_STEAM_CEF_POLICY=valve` still preserves Valve's complete command
  line and permits normal child creation for a controlled comparison.
* Process-role parsing checks actual Windows arguments, quoting, backslashes
  and last-switch precedence. A type substring inside another value cannot
  authorize a child. No sandbox-disabling, certificate, signature,
  authentication or anti-cheat exception is added.

## SDL and Vulkan observations

The device's `[steam-deps]` inventory confirms SDL3.dll is i386 at the Steam
root; SDL2.dll is absent from the checked root, bin and CEF directories.
The genuine 32-bit gldriverquery import fails accordingly. This does not
establish file corruption or justify replacing SDL2 with SDL3.

Chromium loads a Vulkan loader and the 64-bit driver query finds another.
The separate 32-bit vulkandriverquery cannot resolve vulkan-1.dll. Madeira's
32-bit Wine build explicitly uses `--without-vulkan` and omits both
vulkan-1.dll and winevulkan.dll; the 64-bit farm contains a different-architecture
loader. An application-local Chromium loader is not a proven global runtime
for other Steam helpers. The read-only inventory now includes Vulkan loader
names and PE architecture in known Steam locations. No arbitrary DLL is
downloaded, copied between architectures, aliased or treated as successfully
loaded. These probe failures' role in UI startup remains unproven.

## Validation and the next device run

The host regression invokes the **actual production patcher**, then executes
its emitted A64 code under Unicorn while clearing x18 **before every single
instruction**. It checks positive/negative signed word, byte and halfword
loads and ordinary unsigned loads, two TSD/TEB owners, and unchanged x17,
SP (including 8-mod-16), condition flags and return PC. The actual Mach helper
is compiled with Wine's real TEB definition and ASan/UBSan; wrong Self,
missing/unreadable TEB, other bases, nonzero x18, stores, SIMD, prefetch and
reserved encodings decline without changing saved state. FP/LR/XZR
register handling is checked explicitly.

Registry tests exercise unknown native ports, 4,000 thread lifetimes, 12,000
concurrent registrations, exhaustion and reuse: an unknown thread cannot
borrow the first process's TEB. Existing arithmetic/derived-base, I/O,
OpenGL, window visibility, SCM, Dock and controller checks remain in CI.
CEF tests compile the real injection/gate, preserve crashpad/auth arguments,
check quoted and duplicate types, retain Dock's policy, and reject the invalid
logging value. Actions also checks the resulting IPA's native markers and
reports its bundle identifier and UUID.

Device milestones must be genuine:

1. `[steam-cef] request role=browser` / `role=crashpad` records requests;
   subsequent genuine module/thread records establish actual process startup.
2. No repeated LDRSW read at `0x180c`; any fallback `[x18-load]` record must
   name the correct owner. No Chromium master-stream mapping failure.
3. CEF frames/JavaScript contexts progress to Steam's real UI readiness.
4. A real show operation and `[steam-ui-host]` visible, attached rendered
   surface; then usable login/library interaction. Hidden windows are not
   force-shown, and an active browser thread alone is not acceptance.

Test first with the existing settings and capture startup for several minutes
unless it crashes. Keep the prefix and game installation. CI cannot establish
an interactive iPhone UI. Only after that succeeds should Steam's normal Play
button and CS2 be tested separately. Successful UI or service startup does
**not** guarantee VAC compatibility.
