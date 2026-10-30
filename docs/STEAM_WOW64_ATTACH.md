# Genuine Steam client: WoW64 OpenGL attach fault

The supplied report quotes `madeira-log(20261030-020005).txt` and IMG_1318.png.
The full files and a live iPhone were not available in this workspace. Quoted
addresses and the mapped-vgui observation are supplied evidence, not a local
Steam reproduction. No Valve binaries were downloaded or changed.

## First fault and its producer

`0xb98fdd09` decodes to `ldrsw x9,[x8,#0xfdc]`. In the pinned Wine source,
`wow64_thread_attach` is OpenGL's Unix wrapper, not the generic FEX/Wine thread
initializer. It calls `get_teb64((ULONG_PTR)args)`. That helper takes an ULONG,
then dereferences the resulting pointer's `TEB32.WowTebOffset` at offset 0xfdc.
The unpatched helper casts with ULongToPtr and loses the window base.

Madeira's init_teb in virtual_ios.c writes TEB32.Tib.Self as a guest address and
pairs TEB32/TEB64 using signed WowTebOffset values. With window base 0x400000000,
native TEB64 0x47ffc0000 and the 0x2000 peer offset, TEB32 is at host
0x47ffc2000 / guest 0x7ffc2000. FEX's HandleSyscallImpl already widens the outer
Unix-call argument into a host pointer. OpenGL then narrows it to ULONG and
reads 0x7ffc2000+0xfdc, exactly the reported unmapped address. This explains the
pointer producer without treating an unrelated stack warning as proof of a
broken guest stack or allocating fake backing for an invalid low address.

The repository already carries the window-aware get_teb64 and generated
embedded-pointer conversions in patches/wine-opengl-winios.patch. BUILDING.md
required manually applying it. The automated build instead compiled the
unpatched submodule. The build now stages the three native OpenGL files with
that reviewed overlay, without mutating the Wine pin or fetching a registry.
Generated pointer conversions keep handles and bound-buffer offsets unchanged.

The iOS attach wrapper checks that the outer pointer belongs to the current
window and that the resolved native TEB is the calling thread's. It reports an
actual error on an alien pointer or corrupt peer offset. Unmapped addresses
inside the window still take the genuine fault path. No signal-handler or
fault-emulator changes were made. Bounded [wow-gl-attach] enter/leave records
include the owner, current TEB, window, fault-safe mapping/offset read and real
status. The observer never changes mappings, repairs registers or supplies a
replacement TEB, and does not run in a signal handler.

## What the vgui2 error establishes

The supplied log maps vgui2_s.dll before the first attach fault and later reports
STATUS_DLL_NOT_FOUND. The first demonstrated runtime defect is therefore the
OpenGL attach pointer conversion, not absence or corruption of the Valve DLL.
Wine fixup_imports reduces any failed import_dll to STATUS_DLL_NOT_FOUND;
MODULE_InitDLL separately propagates entry-point exceptions and false returns.
A top-level missing-module message alone does not identify the failed stage.

The actual Valve PE dependencies were not supplied, so their precise import
chain and any additional missing imports remain unverified. Do not assume a
specific vgui→OpenGL edge from the symbol alone: thread notifications can also
reach an already-loaded OpenGL module. Correlate the new attach records with
the next full module/exception log. The existing read-only
`tools/check-game-deps.py /path/to/bin/vgui2_s.dll --ship-dir /path/to/i386-windows`
can inspect a supplied local copy; it downloads nothing. Its static import list
cannot prove TLS/DllMain success or resolve every dynamic dependency.

The failed 0x140000000 reservation and stack-ownership diagnostics are retained
as separate observations. This change neither assumes they cause this fault
nor changes the JIT pool size.

## Steam identity and regression evidence

WineProcessBridge explicitly set Thumper's three Steam variables in its default
branch. A standalone steam.exe launch now clears SteamAppId, SteamGameId and
SteamAppPath before Wine snapshots the environment, even with stale direct-game
metadata. Dock and explicit per-game identities retain their behavior. This
addresses standalone client entry; it does not claim to redesign every later
child environment in an already-running desktop session or to fix the fault
by changing identity variables.

The host test compiles the actual staged attach/helper code with Wine's real
TEB layouts. It reproduces the old fault, then verifies paired-TEB initialization
in two separately owned windows, rejects cross-owner arguments and corrupt
peer offsets, and confirms unmapped regions still fault. It also checks that
the Wine checkout is unchanged. The environment test compiles the actual bridge
block and checks standalone Steam, stale metadata, case/path handling, Dock and
direct-game identities.

The bundled i386 `madeira-wow64-probe.exe` loads a synthetic DLL that genuinely
imports opengl32, observes TLS/process attach, creates a thread and observes
TLS/thread attach. This is not Steam or a simulated Valve service. Run it as a
standalone library entry at `C:\windows\syswow64\madeira-wow64-probe.exe`,
not through Dock. Genuine success reports `[wow64-probe] ... result=0`; real
LoadLibrary, export, thread or wait failures remain failures. The artifact gate
checks its i386 machine, TLS callbacks, actual API imports and DLL export.

Host tests and compilation are not an on-device Steam launch. Update the same
app identity without uninstalling, resetting the prefix or reinstalling games.
Request a fresh genuine steam.exe log with [steam-env] and [wow-gl-attach]
records and the actual module-load result; the independent loader probe can
separate Wine initialization from Steam-specific behavior if needed. Only then
retest genuine Steam-managed CS2. Service/client startup does not guarantee VAC
compatibility. No new VAC result, signature change or bypass is claimed.
