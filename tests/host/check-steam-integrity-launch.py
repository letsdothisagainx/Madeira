#!/usr/bin/env python3
"""Execute the production non-gating audit scheduler and diagnostic flag policy."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--require-swift', action='store_true')
args = p.parse_args()
source = ROOT / 'app/Madeira/SteamIntegrityDiagnostics.swift'
view = (ROOT / 'app/Madeira/ContentView.swift').read_text()
model = (ROOT / 'app/Madeira/SteamOwnedLibrary.swift').read_text()
project = (ROOT / 'app/Madeira.xcodeproj/project.pbxproj').read_text()
assert 'SteamIntegrityDiagnostics.swift in Sources' in project
assert 'SteamContentIntegrity.swift in Sources' in project
assert 'SteamIntegrityDiagnostics.shared.schedule(appID: appID' in view
assert 'wine_process_is_running() == 0 && wineserver_is_running() == 0' in view
assert 'shouldContinue: idle' in view
assert 'didSet { SteamIntegrityDiagnostics.shared.setDownloadActive(active != nil) }' in model
assert 'SteamIntegrityDiagnostics.configureEnvironment(nativeSteam: nativeSteamClient, appID: profile?.steamAppID' in view
assert 'LogStore' not in source.read_text(), 'pure scheduler uses the passed reporter'
swift = shutil.which('swiftc')
if not swift:
    assert not args.require_swift, 'Swift compiler required'
    print('PASS app audit wiring; actual scheduling/concurrency requires Swift CI')
    raise SystemExit(0)

code = r'''
import Foundation
import Dispatch

final class Observed: @unchecked Sendable {
    let mutex = NSLock()
    var calls = 0
    var lines: [String] = []
    func note(_ line: String) { mutex.lock(); lines.append(line); mutex.unlock() }
    func ran() { mutex.lock(); calls += 1; mutex.unlock() }
}
func blocked(_ queue: DispatchQueue) -> DispatchSemaphore {
    let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
    queue.async { started.signal(); release.wait() }
    assert(started.wait(timeout: .now() + 5) == .success)
    return release
}

var env = ["SteamAppId":"existing", "SteamGameId":"existing", "SteamAppPath":"existing"]
func flag(_ native: Bool, _ id: Int?) {
    SteamIntegrityDiagnostics.configureEnvironment(nativeSteam: native, appID: id,
        get: { env[$0] }, set: { env[$0] = $1 }, unset: { env.removeValue(forKey: $0) })
}
flag(true, 730); assert(env["MADEIRA_TRUST_DIAGNOSTICS"] == "1")
env["MADEIRA_TRUST_DIAGNOSTICS"] = "0"; flag(true, 730)
assert(env["MADEIRA_TRUST_DIAGNOSTICS"] == "0")
flag(true, 42); assert(env["MADEIRA_TRUST_DIAGNOSTICS"] == nil)
env["MADEIRA_TRUST_DIAGNOSTICS"] = "1"; flag(false, 730)
assert(env["MADEIRA_TRUST_DIAGNOSTICS"] == nil)
flag(true, nil); assert(env.count == 3 && env.values.allSatisfy { $0 == "existing" })

let observed = Observed(), scheduler = SteamIntegrityDiagnostics()
let queue = DispatchQueue(label: "owned-audit-test"), release = blocked(queue)
assert(!scheduler.schedule(appID: 42, idle: { true }, work: { _ in fatalError() }, log: { _ in }, queue: queue))
assert(!scheduler.schedule(appID: 730, idle: { false }, work: { _ in fatalError() }, log: { _ in }, queue: queue))
DispatchQueue.concurrentPerform(iterations: 64) { _ in
    scheduler.schedule(appID: 730, idle: { true }, work: { idle in
        assert(idle()); observed.ran(); return (0..<40).map { "fixed-audit-record-\($0)" }
    }, log: { observed.note($0) }, queue: queue)
}
// The caller returns while the queue is blocked; no audit or launch wait occurs.
assert(observed.calls == 0 && observed.lines.isEmpty)
release.signal(); queue.sync { }
assert(observed.calls == 1 && observed.lines.count == 32)

let busy = SteamIntegrityDiagnostics(), seen = Observed()
let queue2 = DispatchQueue(label: "owned-audit-stop"), release2 = blocked(queue2)
assert(busy.schedule(appID: 730, idle: { true }, work: { _ in fatalError() }, log: { seen.note($0) }, queue: queue2))
busy.setDownloadActive(true); release2.signal(); queue2.sync { }
assert(seen.calls == 0 && seen.lines.count == 1 && seen.lines[0].contains("stopped-unmeasured"))
busy.setDownloadActive(false)
assert(busy.schedule(appID: 730, idle: { true }, work: { idle in
    assert(idle()); busy.setDownloadActive(true); assert(!idle())
    seen.ran(); return ["[steam-content-audit-v1] state=stopped-unmeasured trust=unmeasured"]
}, log: { line in seen.note(line); busy.setDownloadActive(false) }, queue: queue2))
queue2.sync { }
assert(seen.calls == 1 && seen.lines.count == 2)
print("PASS production audit scheduler: async/no-wait, one job under64-way contention, runtime/download cancellation, retry after queued stop,32-line cap and reentrant reporter")
print("PASS diagnostic flag: only native730 defaults enabled, explicit0 honored, other sessions clear it, actual Steam identity untouched")
'''
with tempfile.TemporaryDirectory(prefix='madeira-audit-launch-') as folder:
    tmp = Path(folder)
    main = tmp / 'main.swift'; main.write_text(code)
    executable = tmp / 'test'
    subprocess.run([swift, '-swift-version', '5', '-sanitize=address', str(source), str(main), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
