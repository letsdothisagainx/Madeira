#!/usr/bin/env python3
"""Check work-only app integration ordering and parse candidate Swift syntax.

The separate cache/native harnesses compile and run the new production helpers.
This check parses the actual modified ContentView and project wiring; it does
not claim a complete iOS app typecheck/link or real Steam UI execution.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--require-swift', action='store_true')
parser.add_argument('--app-activated', action='store_true', help='inspect applied sources without regenerating/applying a patch')
args = parser.parse_args()
tracked = ['app/Madeira/ContentView.swift', 'app/Madeira/SteamClientUpdate.swift',
           'app/Madeira/SteamRuntime.swift', 'app/Madeira.xcodeproj/project.pbxproj']
before = {name: (ROOT / name).read_bytes() for name in tracked}
if args.app_activated:
    candidate = ROOT
else:
    subprocess.run([os.sys.executable, str(HERE / 'prepare-app-candidates.py')], cwd=ROOT, check=True)
    assert before == {name: (ROOT / name).read_bytes() for name in tracked}
    subprocess.run(['git', 'apply', '--check', str(HERE / 'app-launch-wiring.patch')], cwd=ROOT, check=True)
    candidate = HERE / 'candidate'
content = (candidate / 'app/Madeira/ContentView.swift').read_text()
update = (candidate / 'app/Madeira/SteamClientUpdate.swift').read_text()
project = (candidate / 'app/Madeira.xcodeproj/project.pbxproj').read_text()
native = (HERE / 'SteamNativeBrowserLaunch.swift').read_text()
bridge = (ROOT / 'app/Madeira/WineProcessBridge.m').read_text()

def between(start, end):
    return content.split(start, 1)[1].split(end, 1)[0]

start = between('    private func startLibraryEntry(', '    /// madeira-bcd: LibraryPrefs')
assert start.index('if nativeSteamClient && nativeSteamBrowser == nil') < start.index('entry.configureLaunch()') < start.index('library.begin(')
assert 'nativeSteamBrowser: nativeSteamBrowser)' in start
assert start.index('guard nativeSteamPreparationIdle(), jit_check_debugged()') < start.index('library.begin(')
full = between('    private func runWineFullSequence(', '    /// Madeira Dock: hand the stored sign-in')
assert full.index('if nativeSteamClient && nativeSteamBrowser == nil') < full.index('SteamOwnedLibrary.shared.sessionChanged(active: true)')
assert 'self.startWineProcess(nativeSteamClient: nativeSteamClient)' in full
assert full.index('profile.applyEnvironment()') < full.index('SteamNativeBrowserLaunchFiles.export(') < full.index('self.startWineserver()')
assert full.index('SteamNativeBrowserLaunchFiles.export(') < full.index('StikJITHelper.allocatePool(')
assert 'heartbeat.invalidate(); ws_log_quiet = 0; logStore.uiPaused = false' in full
assert 'SteamOwnedLibrary.shared.sessionChanged(active: false)' in full
helper = between('    private func prepareNativeSteamBrowser(', '    /// Full sequence:')
assert helper.index('steamBrowserLaunch.begin(') < helper.index('Task { @MainActor in')
assert helper.index('try await preparation.value') < helper.index('guard nativeSteamPreparationIdle(), jit_check_debugged()') < helper.index('continuation(selected)')
assert 'library.error = error.localizedDescription' in helper
assert 'MADEIRA_ONE_SESSION_PER_RUN' in helper
idle = between('    private func nativeSteamPreparationIdle()', '    /// Complete the download')
for text in ['wine_process_is_running() == 0', 'wineserver_is_running() == 0', 'library.current == nil',
             '!SteamOwnedLibrary.shared.wineSessionActive', '!SteamClientUpdateModel.shared.busy']:
    assert text in idle
for name in ['launchPendingShortcut', 'launchLibraryEntry', 'startLibraryEntry', 'startDock', 'runWineFullSequence']:
    body = content.split('    private func ' + name + '(', 1)[1]
    assert 'guard !steamBrowserLaunch.busy, !SteamBrowserRuntime.busy' in body[:750], name
dock = between('    private func startDock(', '    private func prepareSteamLaunch()')
assert dock.index('let options = await ') < dock.index('guard !steamBrowserLaunch.busy', dock.index('let options = await ')) < dock.index('await SteamOwnedLibrary.shared.prepareDock()')
assert dock.index('await SteamOwnedLibrary.shared.prepareDock()') < dock.index('guard !steamBrowserLaunch.busy', dock.index('await SteamOwnedLibrary.shared.prepareDock()')) < dock.index('try MadeiraDock.writeHandoff(')
assert '.disabled(steamBrowserLaunch.busy || SteamBrowserRuntime.busy)' in content
assert '!SteamNativeBrowserLaunch.shared.busy && !SteamBrowserRuntime.busy' in update
process = between('    private func startWineProcess(', '    private func testDualMapping()')
assert 'verified helper/cache pair after applying the profile' in process
assert 'unsetenv("MADEIRA_HTMLIPC_HELPER"); unsetenv("MADEIRA_HTMLIPC_CACHE_DIR")' in process
assert 'guard native else { return }' in native and 'MADEIRA_ENV_LOCKED' in native
assert bridge.count('if (madeira_env_is_locked(k.UTF8String))') == 2
assert native.index('busy = true\n') < native.index('return Task { @MainActor in')
assert 'let bridgeName = "madeira-htmlipc-bridge.dll"' in native
assert 'let manifestName = "madeira-htmlipc-bridge.manifest.json"' in native
for name in ['SteamBrowserRuntime', 'SteamNativeBrowserLaunch']:
    assert f'{name}.swift in Sources */ =' in project
    assert f'path = "{name}.swift";' in project
    assert (candidate / f'app/Madeira/{name}.swift').read_text() == (HERE / f'{name}.swift').read_text()
assert 'lastKnownFileType = folder; path = "arm64ec-windows";' in project
if not args.app_activated:
    assert 'SteamNativeBrowserLaunch' not in before['app/Madeira/ContentView.swift'].decode(), 'candidate activated unexpectedly'
print('PASS work-only app wiring: prepare before session/configuration, synchronous launch reservation, immutable worker token, updater/Dock/shortcut race guards, exact environment lock export, source/project inclusion, tracked app retained')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('FAIL --require-swift: Swift toolchain unavailable')
    print('SKIP candidate app Swift syntax parse: no toolchain; full new-source compile is in the two independent helper harnesses')
    raise SystemExit(0)
swift_sources = [candidate / 'app/Madeira' / name for name in [
    'ContentView.swift', 'SteamClientUpdate.swift', 'SteamRuntime.swift',
    'SteamBrowserRuntime.swift', 'SteamNativeBrowserLaunch.swift']]
subprocess.run([swift, '-frontend', '-parse', *map(str, swift_sources)], check=True)
print('PASS candidate app Swift syntax parse; complete iOS app build/link and real Steam UI remain separate gates')
