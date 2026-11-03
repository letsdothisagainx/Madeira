#!/usr/bin/env python3
"""Materialize launch wiring against tracked app sources; never change app/."""
from pathlib import Path
import difflib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
out = HERE / 'candidate'
patches = []

def replace_once(text, old, new):
    assert text.count(old) == 1, old[:160]
    return text.replace(old, new, 1)

def emit(relative, text, original=None):
    path = out / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if original is None:
        original = (ROOT / relative).read_text() if (ROOT / relative).exists() else ''
    patches.append(''.join(difflib.unified_diff(original.splitlines(True), text.splitlines(True),
        fromfile='a/' + relative if original else '/dev/null', tofile='b/' + relative)))

path = 'app/Madeira/ContentView.swift'
source = (ROOT / path).read_text()
s = replace_once(source, '    @ObservedObject private var library = LibraryModel.shared\n    /// "Use New Interface"',
    '    @ObservedObject private var library = LibraryModel.shared\n'
    '    @ObservedObject private var steamBrowserLaunch = SteamNativeBrowserLaunch.shared\n    /// "Use New Interface"')
s = replace_once(s, '        .alert("Restart Madeira", isPresented: $showFrontendRestart) {',
    '        .disabled(steamBrowserLaunch.busy || SteamBrowserRuntime.busy)\n'
    '        .alert("Restart Madeira", isPresented: $showFrontendRestart) {')
s = replace_once(s, '    private func launchPendingShortcut() {\n',
    '    private func launchPendingShortcut() {\n'
    '        guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy else { return }\n')
s = replace_once(s, '    private func launchLibraryEntry(_ entry: LibraryEntry) {\n',
    '    private func launchLibraryEntry(_ entry: LibraryEntry) {\n'
    '        guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy else {\n'
    '            library.error = "Wait for Steam browser preparation to finish."; return\n'
    '        }\n')
old = '    private func startLibraryEntry(_ entry: LibraryEntry, epicReady: Bool = false, remember: Bool = true, preferences: LibraryEntry? = nil, nativeSteamClient: Bool = false) {\n'
new = '''    private func startLibraryEntry(_ entry: LibraryEntry, epicReady: Bool = false, remember: Bool = true, preferences: LibraryEntry? = nil, nativeSteamClient: Bool = false, nativeSteamBrowser: SteamNativeBrowserLaunch.Prepared? = nil) {
        guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy else {
            library.error = "Wait for Steam browser preparation to finish."; return
        }
        if nativeSteamClient && nativeSteamBrowser == nil {
            prepareNativeSteamBrowser { selected in
                startLibraryEntry(entry, epicReady: epicReady, remember: remember, preferences: preferences,
                                  nativeSteamClient: true, nativeSteamBrowser: selected)
            }
            return
        }
'''
s = replace_once(s, old, new)
s = replace_once(s, '        entry.configureLaunch()\n', '''        if nativeSteamClient {
            guard nativeSteamPreparationIdle(), jit_check_debugged() else {
                library.error = "The launch state changed while Steam's browser was prepared. Enable JIT and try again."
                return
            }
        }
        entry.configureLaunch()
''')
s = replace_once(s, '        runWineFullSequence(profile: effectiveProfile, nativeSteamClient: nativeSteamClient)\n',
    '        runWineFullSequence(profile: effectiveProfile, nativeSteamClient: nativeSteamClient, nativeSteamBrowser: nativeSteamBrowser)\n')
anchor = '    /// Full sequence: allocate JIT pool, start wineserver, start Wine.\n'
helpers = '''    private func nativeSteamPreparationIdle() -> Bool {
        wine_process_is_running() == 0 && wineserver_is_running() == 0 &&
        library.current == nil && !SteamOwnedLibrary.shared.wineSessionActive &&
        !SteamClientUpdateModel.shared.busy
    }

    /// Complete the download and file transaction before any session is begun.
    /// Failure is shown directly and never starts the incompatible helper.
    private func prepareNativeSteamBrowser(_ continuation: @escaping (SteamNativeBrowserLaunch.Prepared) -> Void) {
        do {
            let preparation = try steamBrowserLaunch.begin(
                drive: SteamNativeBrowserLaunch.appDrive, resourceRoot: Bundle.main.resourceURL,
                idle: { nativeSteamPreparationIdle() }, progress: { logStore.log($0) })
            Task { @MainActor in
                do {
                    let selected = try await preparation.value
                    guard nativeSteamPreparationIdle(), jit_check_debugged() else {
                        throw SteamNativeBrowserLaunchFiles.Failure.active
                    }
                    if library.enabled, LibraryModel.sessionsThisRun > 0, MadeiraConfig.flag("MADEIRA_ONE_SESSION_PER_RUN") {
                        library.restartNotice = LibraryModel.restartMessage
                        return
                    }
                    // No suspension between this recheck and begin/sessionChanged.
                    continuation(selected)
                } catch {
                    library.error = error.localizedDescription
                    logStore.log("Steam browser preparation failed: " + error.localizedDescription, level: .error)
                }
            }
        } catch {
            library.error = error.localizedDescription
            logStore.log("Steam browser preparation failed: " + error.localizedDescription, level: .error)
        }
    }

'''
s = replace_once(s, anchor, helpers + anchor)
s = replace_once(s, '    private func runWineFullSequence(profile: LibraryEntry? = nil, nativeSteamClient: Bool = false) {\n',
    '''    private func runWineFullSequence(profile: LibraryEntry? = nil, nativeSteamClient: Bool = false, nativeSteamBrowser: SteamNativeBrowserLaunch.Prepared? = nil) {
        guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy else {
            logStore.log("Wait for Steam browser preparation to finish before starting Wine.", level: .error)
            if profile != nil { LibraryModel.shared.launchFailed() }
            return
        }
        if nativeSteamClient && nativeSteamBrowser == nil {
            prepareNativeSteamBrowser { selected in
                runWineFullSequence(profile: profile, nativeSteamClient: true, nativeSteamBrowser: selected)
            }
            return
        }
''')
worker_anchor = '''            } else {
                _ = try? MadeiraConfig.applyGame(nil)   // no library game: no game's own lines
            }

            // Step 1: Allocate JIT pool (BRK suspends entire process)
'''
worker_export = '''            } else {
                _ = try? MadeiraConfig.applyGame(nil)   // no library game: no game's own lines
            }

            // Reassert the immutable selected paths after profile environment,
            // before JIT/server startup. Both later cfg loops honor these locks.
            do {
                try SteamNativeBrowserLaunchFiles.export(native: nativeSteamClient, prepared: nativeSteamBrowser,
                    get: { getenv($0).map { String(cString: $0) } },
                    set: { setenv($0, $1, 1) == 0 }, unset: { unsetenv($0) })
            } catch {
                let message = error.localizedDescription
                logStore.log("Steam's verified browser launch could not be configured.", level: .error)
                DispatchQueue.main.async {
                    heartbeat.invalidate(); ws_log_quiet = 0; logStore.uiPaused = false
                    LibraryModel.shared.launchFailed(message)
                    MadeiraDock.cleanup(); SteamOwnedLibrary.shared.dockEnded()
                    SteamOwnedLibrary.shared.sessionChanged(active: false)
                    EpicLibrary.shared.sessionChanged(active: false)
                }
                return
            }

            // Step 1: Allocate JIT pool (BRK suspends entire process)
'''
s = replace_once(s, worker_anchor, worker_export)
s = replace_once(s, '    private func startDock(_ game: DockGame, compactPool: Bool, profile: LibraryEntry? = nil) {\n',
    '''    private func startDock(_ game: DockGame, compactPool: Bool, profile: LibraryEntry? = nil) {
        guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy else {
            library.error = "Wait for Steam browser preparation to finish."; return
        }
''')
s = replace_once(s, '            let options = await SteamOwnedLibrary.shared.launchOptions(appID: game.id)\n',
    '''            let options = await SteamOwnedLibrary.shared.launchOptions(appID: game.id)
            guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy else {
                library.error = "Wait for Steam browser preparation to finish."; return
            }
''')
s = replace_once(s, '                guard StikJITHelper.ready, wine_process_is_running() == 0, wineserver_is_running() == 0,\n',
    '                guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy,\n'
    '                      StikJITHelper.ready, wine_process_is_running() == 0, wineserver_is_running() == 0,\n')
old = '''        if nativeSteamClient { setenv("MADEIRA_NATIVE_STEAM_LAUNCH", "1", 1) }
        else { unsetenv("MADEIRA_NATIVE_STEAM_LAUNCH") }
'''
new = '''        // The launch worker exported and locked this native signal and the
        // verified helper/cache pair after applying the profile, before the
        // wineserver started. No config can enable or replace this selection.
'''
s = replace_once(s, old, new)
s = replace_once(s, '            unsetenv("MADEIRA_NATIVE_STEAM_LAUNCH")\n            SteamLibraryDiagnostics.shared.stop()\n',
    '            unsetenv("MADEIRA_NATIVE_STEAM_LAUNCH")\n'
    '            unsetenv("MADEIRA_HTMLIPC_HELPER"); unsetenv("MADEIRA_HTMLIPC_CACHE_DIR")\n'
    '            SteamLibraryDiagnostics.shared.stop()\n')
emit(path, s, source)

path = 'app/Madeira/SteamClientUpdate.swift'
source = (ROOT / path).read_text()
s = replace_once(source, '        wine_process_is_running() == 0 && wineserver_is_running() == 0 &&\n',
    '        !SteamNativeBrowserLaunch.shared.busy && !SteamBrowserRuntime.busy &&\n'
    '        wine_process_is_running() == 0 && wineserver_is_running() == 0 &&\n')
emit(path, s, source)

path = 'app/Madeira.xcodeproj/project.pbxproj'
source = (ROOT / path).read_text()
assert 'A1000FA1' not in source and 'A2000FA1' not in source and 'A1000FA2' not in source and 'A2000FA2' not in source
s = source
for number, name in [('1', 'SteamBrowserRuntime'), ('2', 'SteamNativeBrowserLaunch')]:
    s = replace_once(s, '\t\tA1000523 /* SteamRuntime.swift in Sources */ =',
        f'\t\tA1000FA{number} /* {name}.swift in Sources */ = {{isa = PBXBuildFile; fileRef = A2000FA{number} /* {name}.swift */; }};\n'
        '\t\tA1000523 /* SteamRuntime.swift in Sources */ =')
    s = replace_once(s, '\t\tA2000523 /* SteamRuntime.swift */ =',
        f'\t\tA2000FA{number} /* {name}.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = "{name}.swift"; sourceTree = "<group>"; }};\n'
        '\t\tA2000523 /* SteamRuntime.swift */ =')
    s = replace_once(s, '\t\t\t\tA2000523 /* SteamRuntime.swift */,',
        f'\t\t\t\tA2000FA{number} /* {name}.swift */,\n\t\t\t\tA2000523 /* SteamRuntime.swift */,')
    s = replace_once(s, '\t\t\t\tA1000523 /* SteamRuntime.swift in Sources */,',
        f'\t\t\t\tA1000FA{number} /* {name}.swift in Sources */,\n\t\t\t\tA1000523 /* SteamRuntime.swift in Sources */,')
emit(path, s, source)
emit('app/Madeira/SteamRuntime.swift', (HERE / 'SteamRuntime.swift.candidate').read_text())
emit('app/Madeira/SteamBrowserRuntime.swift', (HERE / 'SteamBrowserRuntime.swift').read_text(), '')
emit('app/Madeira/SteamNativeBrowserLaunch.swift', (HERE / 'SteamNativeBrowserLaunch.swift').read_text(), '')
(HERE / 'app-launch-wiring.patch').write_text(''.join(patches))
print('Prepared work-only app source/project candidates and combined app-launch-wiring.patch')
