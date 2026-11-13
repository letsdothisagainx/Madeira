# CS2 startup recovery after b832

Failing source: `b832fa4a15f84f7357a085f50c0da0bce4a7e944`.
Known multiplayer-capable source: `d73f2583a79f7c402edaec3646f2d0d1d89c0752`.
Evidence: madeira-log(20261113-060310).txt.

## Observed boundary

The complete 1152 MiB JIT pool initializes in 5360 ms. Wine, genuine Steam,
the compatibility browser and Chromium shared sections initialize. The Steam
command retains `-applaunch 730 -condebug`, and the installation is ready.
No `cs2.exe` creation occurs in this session. Its 3285 MiB peak is not evidence
of a game-rendering failure or a memory-limit termination.

The observer attaches at 00:58:12.979 and receives its first store evaluation
at 00:58:13.715 (`apps=true`, `store=false`). Renderer thread 020c then remains
parked on the same libcef address from approximately 00:58:14. Later evaluation
timeouts establish missing renderer progress; they do not identify the lock
owner or prove that the observer caused the stall. The initial missing Chromium
sections are subsequently created and opened successfully.

Steam launch/observer/bridge sources and CEF policy were unchanged between d73
and b832. The early CEF assertion also exists in the successful recording.
There is no basis for new IPC success substitution, different CEF flags, a
replacement launcher, or a game-file repair.

## Production recovery

Commit a1c41bf1 introduced two startup-sensitive Wine/FEX changes alongside
the independent DXMT metadata correction. This recovery restores both startup
paths to d73 rather than carrying uncertain changes into another phone test:

* The native sync build no longer applies `stage-fastsync-timeout.py`. Its
  actual finite/infinite waits, server fallbacks, APC handling and dispatch
  therefore compile from the same d73 sources. Compile failure still stops
  the build instead of permitting a stale sync object.
* The WOW64 tracker returns to its original `std::optional` storage, mutex,
  initialization and notification paths. The complete staged WOW64 module is
  checked against the d73 source hash. ARM64EC retains its pre-existing d73
  owner-heap tracker. Final packaging requires the matching capabilities;
  it does not claim the reverted WOW64 heap capability.

The timeout experiment had an observable scope defect: it changed finite
server-fallback timeout pointers/values even while fastsync was unarmed or
could not supply an eligible cell. The failing run never logs fastsync arming.
The captured b832 function fails the fallback-transparency regression; d73
passes it. A corrected helper is retained for tests but remains **inactive**
in production. Its active-spin deadline improvements are not enabled by this
recovery build.

This proves restoration of the affected code paths. It does not prove which
particular changed operation caused libcef to park indefinitely. Tracker
initialization succeeded in the failing log, but initialization alone cannot
exonerate every later callback. Restoring both recent control-plane changes
prioritizes the working launch over an inconclusive single-change experiment.

## Preserved behavior and validation

DXMT's writable metadata owners remain enabled. The failed session loads
neither D3D11 nor D3D9. Both DXGI loads return through DllMain and continue into
adapter/software rendering setup. No new DXMT initialization deadlock is
established. Buffer-cache policy, texture handling and GPU lifetime rules are
unchanged.

The recovery also preserves JIT placement/preparation, the 768/384 MiB arenas,
genuine Steam updates and launch arguments, browser binaries and IPC, UDP,
Steam services, input, display configuration and Export Run. It changes no
prefix, account, installation, manifest, setting, save or Valve binary.

Focused checks cover the captured b832 fallback failure, d73 source hashes,
production overlay exclusion, both FEX ABI/package contracts, and the retained
DXMT storage/lifetime tests. Build success cannot establish Steam UI readiness
or a genuine CS2 launch on iPhone. Those remain device acceptance steps, followed
by remote sign-on, responsive team selection, frame timing and physical footprint.

Install over the existing app with the same signing identity and bundle ID.
No data migration is required. The d73 IPA can be installed in place as a
rollback without uninstalling Madeira.
