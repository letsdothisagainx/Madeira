# Steam launch rejection and dialog repaint, 2026-11-02

The `140242` capture's native UUID is
`3F129B21-1B31-3566-ADA0-3EF1E91CF4D6`, matching
[run 41451119142](https://github.com/letsdothisagainx/Madeira/actions/runs/41451119142),
source head `2c4a3e7be918777af3e7f3dc94c34bac4c92bd1e`.
The Library presents frames and the passive observer receives replies for
several minutes after the Play rejection. A zero FPS overlay is not a browser
liveness test.

## The launch rejection

The native Steam callback supplies `AppError_47` for the CS2-shaped launch
action. Steam's own `OnGameActionShowError` code parses `AppError_N` and calls
`ShowAppLaunchErrorDialogInternal`, which localizes `Steam_AppUpdateError_N`.
Valve's English resource defines `Steam_AppUpdateError_47` as **Steam client
outdated**. Error 46 is separately **Create game process failed**.
This is not an invented Windows error translation. References:

- [Valve UI resources mirrored by SteamTracking](https://github.com/SteamDatabase/SteamTracking/blob/6b238f051b07371ea3af4312636821859708e4b5/ClientExtracted/steamui/localization/steamui_english.json)
- The previously inspected `chunk~2dcc5aaf7.js` callback and localization
  dispatch, also named in this capture's CEF stack.
- In this capture the updater requests `steam_client_win32`, reports installed
  and available version `1769731672`, and no `cs2.exe` creation follows Play.
  Local manifest and executable presence do not prove launch prerequisites
  passed or a game process was attempted.

The architecture trace reports an i386 client under WoW64 on native ARM64;
`IsWow64Process` returns true. Madeira already loads AMD64 programs through
ARM64EC/FEX (including the graphics helper). Do not turn that API report into
a fictitious AMD64 native OS or confuse the 32-bit Steam binary with a
32-bit-only Wine installation.

[Read-only official-package inspection, run 41460193081](https://github.com/letsdothisagainx/Madeira/actions/runs/41460193081)
retrieved Valve's HTTPS `steam_client_win64` manifest, version `1792618285`.
Its bootstrap package contains only `steam.exe`, machine `8664` (AMD64):

- Package: `steam_win64.zip.9ddc7f402ba9bec08b7dbee2cf6ee37d21e1b4e0`,
  2,692,595 bytes, SHA-256
  `9a5aba7f8b5341344717f4a07027ac128e6913bb918454672e843fb5f7e61468`.
- Executable SHA-256:
  `f8a4ca44008c516eebecafaa4bc26772b2a6eb0fef8034bce56a3311e21ab705`.

`Update Windows Steam` is available in Steam settings and the developer action
strip. It operates only while Wine and launch preparation are inactive. It
verifies the packaged 64-bit Wine/FEX components, downloads the pinned genuine
bootstrap from Valve with no redirects, checks both hashes, keeps the original
launcher backup, and atomically replaces only `steam.exe`. The original bytes
and idle state are rechecked after downloading. Existing modern launchers,
changed files, conflicting backups and symlink destinations are refused.
Valve's launcher then owns the full official client update on the next normal
Steam start. No installed-build metadata, game appmanifest, registry, account
data, licensing result or mandatory update check is rewritten. Dock's pinned
component installer and its ABI checks are unchanged.

This provides a genuine migration path. It does not establish that the new
client or its current CEF build runs successfully on this phone, or that
`AppError_47` is the only launch prerequisite still outstanding.

## The black dialog

The SDL parent `0x2016a` receives a new 640x256 backing immediately before
being shown. Its three submitted images remain empty/black. Its CEF children
have no separate drawable surface, so they must paint into the parent's
surface. The main Library keeps presenting independently.

`apply_window_pos` marks backing replacement with `SWP_FRAMECHANGED`.
Madeira queued `RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN` only
in game mode. Desktop mode has no native expose event to replace that missing
notification. The new hook queues these ordinary paints for a visible genuine
desktop surface on show/replacement, retaining the existing game path. It
does not show windows, redirect input, allocate child surfaces, run guest paint
callbacks inline, or manufacture dialog contents. Hidden/empty/dummy surfaces
are excluded. `[surface-expose-v1]` records the actual redraw return value.

The regression test executes the production hook and reproduces the lost
backing with the old game-only gate as a negative control. Its paint queue is
a fixture, not Chromium. The test proves the missing notification is repaired;
the phone must establish whether this is sufficient for this CEF popup.

## Validation and device acceptance

- Host checks cover 128 backing replacements, deferred child repaint, hidden
  helpers, ordinary movement, game mode, failed redraw and log bounds.
- The production bootstrap transaction is tested with real PE headers, partial
  headers, running sessions, changed originals, conflicting backups, symlinks,
  and preserved game/authentication fixture bytes.
- Existing alias lifetime, SWP context, thread retirement, FEX ownership,
  IOSB, handoff, controller and compositor checks remain applicable. Runtime
  architecture-reporting code and FEX/Wine submodule revisions are unchanged.
- The compiled package gate requires both new integration markers as well as
  all existing protection, ownership and ABI markers.

On the iPhone, first confirm the existing Library remains interactive and a
Play error dialog draws its real text/buttons and receives taps. Then close
the Wine session, use **Update Windows Steam**, and start Windows Steam to
finish Valve's update. Confirm saved login, normal restart handoff, five
minutes of responsive Library use, and a legitimate CS2 process creation after
Play. Any new loader/dependency/VAC refusal must be reported as returned. A CI
pass or a successful bootstrap download is not proof of a CS2 launch.
